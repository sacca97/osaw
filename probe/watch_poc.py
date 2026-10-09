#!/usr/bin/env python3
"""Linux Python Apple Watch setup PoC: PIN, bond, activation and initial sync."""
import argparse
import asyncio
import math
from contextlib import ExitStack
from datetime import datetime, timezone
import getpass
import json
import logging
import os
from pathlib import Path
import re
import secrets
import struct
import sys
import time
from magnet_probe import MAGNET_CID, magnet, parse_magnet, positive_seconds


def seconds_or_unlimited(value):
    """0 means no limit; otherwise the usual positive duration."""
    return math.inf if float(value) == 0 else positive_seconds(value)



def ids_timeout(setup_timeout):
    """IdsSession adds and compares this value, so 'no limit' is a very large number, not None."""
    return 1e9 if setup_timeout == math.inf else setup_timeout


def setup_payload(service_data):
    if len(service_data) < 3 or service_data[:2] != b'\x25\xfe' or service_data[2] & 0x7f != 6:
        return None
    offset, end = 3, len(service_data)
    if service_data[2] & 0x80:
        if len(service_data) < 4:
            raise ValueError('Short Watch setup advertisement')
        offset, end = 4, 4 + (service_data[3] & 31)
        if end > len(service_data):
            raise ValueError('Invalid Watch setup advertisement length')
    result = service_data[offset:end]
    if len(result) != 12 or result[0] & 0xe0 != 0x20 or result[1] >> 5 != 4:
        raise ValueError('Unsupported Watch setup advertisement profile')
    return result


def setup_product(data):
    metadata = data[5:]
    return f'Watch{((metadata[0] & 3) << 5) | (metadata[1] >> 3)},{((metadata[1] & 7) << 4) | (metadata[2] >> 4)}'


def watch_candidate(advertisement):
    from bumble.core import AdvertisingData
    # Bumble joins active scan responses to their connectable advertisements.
    if not advertisement.is_connectable:
        return None
    for raw in advertisement.data.get_all(AdvertisingData.SERVICE_DATA_16_BIT_UUID, raw=True):
        try:
            data = setup_payload(raw)
        except ValueError:
            continue
        if data:
            return {'address': advertisement.address, 'rssi': advertisement.rssi,
                    'product': setup_product(data), 'setup': data}
    return None


def service_record(sid, name):
    encoded = name.encode() + b'\0'
    return struct.pack('<HBB', sid, 1, len(encoded)) + encoded + b'\x01'


async def select_watch(candidates, prompt=input):
    if not candidates:
        raise ValueError('No supported setup-mode Apple Watch was discovered')
    if len(candidates) == 1:
        return candidates[0]
    for number, watch in enumerate(candidates, 1):
        print(f"{number}. {watch['product']} — {watch['address']} (RSSI {watch['rssi']} dBm)", flush=True)
    while True:
        choice = await asyncio.to_thread(prompt, f'Select Watch [1–{len(candidates)}]: ')
        if choice.isdecimal() and 1 <= int(choice) <= len(candidates):
            return candidates[int(choice) - 1]
        print('Enter one of the Watch numbers above.', flush=True)


async def finish_bond(connection, acknowledge, timeout):
    """Wait for durable keys and identity assignment, not just SMP's early future."""
    completed = asyncio.get_running_loop().create_future()
    def paired(*details):
        if not completed.done():
            completed.set_result(None)
    def failed(reason):
        if not completed.done():
            completed.set_exception(ConnectionError(f'Bluetooth pairing failed: {reason}'))
    def disconnected(*details):
        if not completed.done():
            completed.set_exception(ConnectionError('Watch disconnected during bonding'))
    listeners = {'pairing': paired, 'pairing_failure': failed, 'disconnection': disconnected}
    for event, callback in listeners.items():
        connection.on(event, callback)
    bond_task = asyncio.create_task(connection.pair())
    async def acknowledge_after_start():
        # Start local SMP before yielding the enrollment acknowledgement.
        await asyncio.sleep(0)
        await acknowledge()
    ack_task = asyncio.create_task(acknowledge_after_start())
    try:
        async with asyncio.timeout(timeout):
            await asyncio.gather(bond_task, ack_task, completed)
    finally:
        bond_task.cancel()
        ack_task.cancel()
        completed.cancel()
        await asyncio.gather(bond_task, ack_task, completed, return_exceptions=True)
        for event, callback in listeners.items():
            connection.remove_listener(event, callback)


async def run(args):
    from bumble.device import Device
    from bumble.hci import Address, HCI_LE_1M_PHY
    from bumble.keys import JsonKeyStore
    from bumble.pairing import PairingConfig, PairingDelegate
    from bumble.smp import OobContext, OobSharedData
    from bumble.snoop import BtSnooper
    from bumble.transport import open_transport
    from activation import ActivationProxy
    from pairing_session import IkeSession
    from pairing_store import Store, user_owned
    from normal_link import NormalLink, accept_prelude, prelude
    from ids_session import IdsSession
    from setup_flow import SetupFlow
    from watch_link import Ertm, RelayLink

    os.umask(0o077)
    store = None if args.scan else Store(args.state)
    if store and not args.resume and 'peer_notifies' in store.data:
        raise ValueError('State already contains Watch keys. Use --resume; for an erased Watch select a new --state directory.')
    if store and args.resume and not store.data.get('bonded'):
        raise ValueError('--resume requires an existing authenticated Bluetooth bond in the selected state directory')
    if args.resume and not args.peer:
        args.peer = store.data.get('peer_address')
        args.address_type = store.data.get('peer_address_type', 'random')
        if not args.peer:
            raise ValueError('Saved bond has no peer identity; this older state needs an explicit --peer')
    run_dir = args.output / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + secrets.token_hex(4))
    run_dir.mkdir(parents=True, mode=0o700)
    user_owned(args.output)
    user_owned(run_dir)
    print(f'Private run artifacts: {run_dir.resolve()}', flush=True)
    with ExitStack() as files:
        def private_file(name, mode):
            fd = os.open(run_dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            user_owned(run_dir / name)
            return files.enter_context(os.fdopen(fd, mode, buffering=0 if 'b' in mode else -1))
        events = private_file('events.jsonl', 'w')
        snoop = private_file('hci.btsnoop', 'wb')
        def record(event, **fields):
            events.write(json.dumps({'event': event, 'epoch': time.time(), **fields}) + '\n')
            events.flush()
            stamp = datetime.now().strftime('%H:%M:%S')
            details = ' '.join(f'{key}={fields[key]}' for key in
                               ('lane', 'port', 'type', 'length', 'command', 'sequence', 'stream', 'correlated', 'flags', 'operation', 'version', 'error', 'error_function', 'error_line', 'stage', 'ids_phase', 'ertm_pending', 'ids_lanes', 'peer_info', 'local_info_ack', 'info_replies_pending')
                               if key in fields)
            print(f'{stamp} {event.replace("_", " ")} {details}'.rstrip(), flush=True)
        record('start', transport=args.transport, peer=args.peer, resume=args.resume, hardware_validated=False)
        connection = normal = ids = pairing_link = relay = proxy = transport = signal_task = None
        heartbeat_task = None
        setup_flow = None
        handlers = {}
        async def heartbeat():
            while True:
                await asyncio.sleep(10)
                record('progress', stage=store.data.get('stage', 'scan') if store else 'scan',
                       ertm_pending=sum(handler.pending is not None for handler in handlers.values()),
                       ids_lanes=len(ids.lanes) if ids else 0,
                       ids_phase=ids.phase if ids else 'not_started',
                       ids_hello=bool(ids and ids.peer_hello),
                       **({'peer_info': setup_flow.peer_info,
                           'local_info_ack': setup_flow.local_info_ack,
                           'info_replies_pending': len(setup_flow.local_info_sequences)}
                          if setup_flow else {}))
        try:
            transport = await open_transport(args.transport)
            await transport.__aenter__()
            address = Address(store.key('host_address').hex()) if store else Address.generate_static_address()
            device = Device.with_hci('Watch Python PoC', address, transport.source, transport.sink)
            device.host.snooper = BtSnooper(snoop)
            if store:
                device.irk = store.key('host_irk')
                device.keystore = JsonKeyStore(namespace=store.data['host_address'], filename=str(store.directory / 'bond.json'))
            await device.power_on()
            record('controller_ready', address=str(device.random_address))
            heartbeat_task = asyncio.create_task(heartbeat())
            setup = bytes.fromhex(args.setup_data) if args.setup_data else None
            seen_setup = asyncio.Event()
            scan_addresses = set()
            candidates = {}
            def advertisement(adv):
                nonlocal setup
                selected = args.peer and str(adv.address).split('/')[0].upper() == args.peer.upper()
                if args.peer and not args.scan and not selected:
                    return
                if args.scan and adv.address not in scan_addresses:
                    scan_addresses.add(adv.address)
                    print(f'{adv.address} type={int(adv.address.address_type)} RSSI={adv.rssi}', flush=True)
                candidate = watch_candidate(adv)
                if candidate:
                    candidates[adv.address] = candidate
                    if args.scan:
                        print(f"{adv.address} type={int(adv.address.address_type)} RSSI={adv.rssi} "
                              f"{candidate['product']} setup-data={candidate['setup'].hex()}", flush=True)
                    elif selected or not args.peer:
                        setup = candidate['setup']
                        seen_setup.set()
            device.on('advertisement', advertisement)
            if args.scan or not args.peer or (not args.resume and setup is None):
                if not args.scan:
                    record('discovering_setup_watches')
                # Keep scanning, stopping and connecting in Bumble's automatic HCI mode.
                await device.start_scanning(active=True, scanning_phys=[HCI_LE_1M_PHY])
                try:
                    if args.scan:
                        await asyncio.sleep(args.timeout)
                        return
                    await asyncio.wait_for(seen_setup.wait(), args.timeout)
                    if not args.peer:
                        await asyncio.sleep(2)  # Gather any simultaneous candidates before selecting.
                except TimeoutError:
                    raise TimeoutError('No supported setup-mode Watch found; wake manual pairing and retry') from None
                finally:
                    await device.stop_scanning()
                if not args.peer:
                    selected = await select_watch(list(candidates.values()))
                    args.peer = str(selected['address']).split('/')[0]
                    args.address_type = 'public' if int(selected['address'].address_type) in (0, 2) else 'random'
                    setup = selected['setup']
                    print(f"Selected {selected['product']} — {selected['address']} (RSSI {selected['rssi']} dBm)", flush=True)
                    record('watch_selected', peer=args.peer, address_type=args.address_type, product=selected['product'])
            if setup is not None and len(setup) != 12:
                raise ValueError('Setup advertisement must contain exactly twelve bytes')
            if setup is not None:
                setup_payload(b'\x25\xfe\x06' + setup)
            product = args.product or (store.data.get('watch_product') if args.resume else setup_product(setup))
            if not product:
                raise ValueError('Resume needs saved Watch product or --product')
            if not args.resume:
                store.save(setup_data=setup.hex(), watch_product=product)
            incoming = asyncio.Queue(maxsize=256)
            opening_channels = {}
            smp_allowed = False
            oob = OobContext()
            peer_oob = None
            negotiated_key_size = None
            def pairing_config(_):
                if not smp_allowed or peer_oob is None:
                    raise ValueError('SMP must follow authenticated PIN key enrollment')
                return PairingConfig(sc=True, mitm=True, bonding=True,
                    identity_address_type=PairingConfig.AddressType.RANDOM,
                    delegate=PairingDelegate(io_capability=PairingDelegate.IoCapability.NO_OUTPUT_NO_INPUT),
                    oob=PairingConfig.OobConfig(our_context=oob, peer_data=peer_oob, legacy_context=None))
            device.pairing_config_factory = pairing_config
            manager = device.l2cap_channel_manager
            original = manager.on_pdu
            def on_pdu(conn, cid, pdu):
                nonlocal negotiated_key_size
                error = None
                if cid == 6:
                    if not smp_allowed:
                        error = RuntimeError('Watch initiated SMP before authenticated enrollment')
                    elif pdu and pdu[0] in (1, 2):
                        if len(pdu) != 7 or pdu[4] != 16:
                            error = ValueError('Watch did not negotiate a 128-bit Bluetooth encryption key')
                        else:
                            negotiated_key_size = pdu[4]
                if error:
                    incoming.put_nowait(error)
                    for handler in handlers.values():
                        handler.fail(error)
                elif cid in handlers:
                    handlers[cid].feed(pdu)
                elif cid in opening_channels:
                    pending = opening_channels[cid]
                    if len(pending) >= 256:
                        incoming.put_nowait(ValueError('Pending Magnet channel receive queue exceeded limit'))
                    else:
                        pending.append(bytes(pdu))
                else:
                    original(conn, cid, pdu)
            manager.on_pdu = on_pdu
            manager.register_fixed_channel(MAGNET_CID, lambda handle, pdu: incoming.put_nowait(pdu))
            peer = Address(args.peer, Address.PUBLIC_DEVICE_ADDRESS if args.address_type == 'public' else Address.RANDOM_DEVICE_ADDRESS)
            if args.resume:
                record('finding_bonded_watch', peer=args.peer)
            # Bumble resolves saved identities by scanning with the bond's IRK;
            # its resolution scan currently does not apply connect's timeout.
            connection = await asyncio.wait_for(device.connect(peer, timeout=args.timeout), args.timeout)
            def disconnected(*details):
                error = ConnectionError('Watch disconnected')
                incoming.put_nowait(error)
                for handler in handlers.values():
                    handler.fail(error)
                if ids:
                    ids.fail(error)
            connection.on('disconnection', disconnected)
            version = None
            remote_features = 0
            async def expected(op):
                nonlocal version, remote_features
                async with asyncio.timeout(args.timeout if op is not None else None):
                    while True:
                        packet = await incoming.get()
                        if isinstance(packet, Exception):
                            raise packet
                        code, body = parse_magnet(packet)
                        if code == 9:
                            if len(body) < 5 or body[0] != 11:
                                raise ValueError('Unsupported Watch Magnet version')
                            version, remote_features = body[0], int.from_bytes(body[1:5], 'little')
                        elif code == 0x70:
                            offset = int(datetime.now().astimezone().utcoffset().total_seconds() / 60)
                            connection.send_l2cap_pdu(MAGNET_CID, magnet(0x71, struct.pack('<QQh', time.time_ns(), time.monotonic_ns(), offset)))
                            connection.send_l2cap_pdu(MAGNET_CID, magnet(0x72, struct.pack('<QII', time.monotonic_ns(), 1, 1)))
                        elif code == 8:
                            raise ValueError('Watch reported Magnet signaling error')
                        if code == op:
                            return body
            connection.send_l2cap_pdu(MAGNET_CID, magnet(9, b'\x0b\x21\x15\0\0'))
            await expected(9)
            async def channel(sid, cid, name, added=False):
                body = service_record(sid, name)
                if not added:
                    body = bytes([1, len(body)]) + body
                connection.send_l2cap_pdu(MAGNET_CID, magnet(5 if added else 1, body))
                common = await expected(2)
                if common != struct.pack('<BH', 1, sid):
                    raise ValueError('Watch did not accept the requested Magnet service')
                # HCI can deliver acceptance and first data before this coroutine
                # resumes. Reserve the receive CID before requesting the channel.
                opening_channels[cid] = []
                try:
                    connection.send_l2cap_pdu(MAGNET_CID, magnet(3, struct.pack('<HH', cid, sid)))
                    accepted = await expected(4)
                    if len(accepted) != 5:
                        raise ValueError('Malformed Magnet channel acceptance')
                    status, service, tx_cid = struct.unpack('<BHH', accepted)
                    if status or service != sid or tx_cid < 64 or any(h.tx_cid == tx_cid for h in handlers.values()):
                        raise ValueError('Watch rejected the requested Magnet channel')
                    ertm = Ertm(connection, tx_cid, record, args.timeout)
                    handlers[cid] = ertm
                    for packet in opening_channels[cid]:
                        ertm.feed(packet)
                finally:
                    del opening_channels[cid]
                record('channel_accepted', service=name, rx_cid=cid, tx_cid=tx_cid)
                return ertm
            if args.resume:
                smp_allowed = True
                await asyncio.wait_for(connection.encrypt(), args.timeout)
                if not connection.is_encrypted:
                    raise ValueError('Stored Bluetooth bond did not encrypt the link')
                ertm = await channel(2, 65, 'com.apple.terminusLink')
            else:
                ertm = await channel(1, 64, 'com.apple.terminusPairing')
                pairing_link = RelayLink(ertm, record, args.timeout)
                control = IkeSession(pairing_link, record)
                await control.establish()
                await control.control_authenticate()
                salt = await control.request_pin_salt()
                print('Enter the six-digit PIN shown by the selected Watch.', flush=True)
                pin = await asyncio.to_thread(getpass.getpass, 'Watch PIN: ')
                pairing = IkeSession(pairing_link, record, pairing=True)
                await pairing.establish()
                await pairing.pin_authenticate(pin, salt, setup)
                pin = None
                batch = store.local_notifies(oob.share(), 'iPhone', '23G71')
                notes, peer_mid = await pairing.private_exchange(None, None, 5, batch=batch)
                record('peer_enrollment_received',
                       notifies={f'0x{tag:04x}': len(value) for tag, value in notes.items()},
                       peer_request=peer_mid is not None)
                store.enroll_peer(notes)
                data = notes[0xc547]
                peer_oob = OobSharedData(r=data[1:17], c=data[18:34])
                smp_allowed = True
                await finish_bond(connection, lambda: pairing.acknowledge(peer_mid), args.timeout)
                # Older HCI encryption-change events omit key size (Bumble reports 0).
                if (not connection.is_encrypted or not connection.authenticated or not connection.sc
                        or negotiated_key_size != 16 or connection.encryption_key_size not in (0, 16)):
                    raise ValueError('Bluetooth pairing was not authenticated 128-bit LE Secure Connections')
                saved_bond = await device.keystore.get(str(connection.peer_address))
                if saved_bond is None or saved_bond.ltk is None or not saved_bond.ltk.authenticated or len(saved_bond.ltk.value) != 16:
                    raise ValueError('Authenticated Bluetooth bond was not persisted')
                store.save(stage='bonded', bonded=True,
                    peer_address=str(connection.peer_address).split('/')[0],
                    peer_address_type='public' if int(connection.peer_address.address_type) in (0, 2) else 'random')
                record('bluetooth_bond_confirmed')
                await pairing_link.close()
                pairing_link = None
                ertm = await channel(2, 65, 'com.apple.terminusLink', added=True)
            signal_task = asyncio.create_task(expected(None))
            def signal_done(task):
                if not task.cancelled() and task.exception():
                    error = task.exception()
                    for handler in handlers.values():
                        handler.fail(error)
                    if ids:
                        ids.fail(error)
            signal_task.add_done_callback(signal_done)
            local = prelude(paired=args.resume or store.data.get('paired', False))
            await ertm.send(local)
            remote = await asyncio.wait_for(ertm.receive(), args.timeout)
            accept_prelude(remote, local)
            record('normal_prelude_accepted')
            relay = RelayLink(ertm, record, args.timeout)
            normal = NormalLink(relay, record, store, local, remote)
            await normal.start()
            ids = IdsSession(normal, store, record, ids_timeout(args.setup_timeout),
                             listen_only=args.control_mode == 'listen' or (args.control_mode == 'auto' and args.resume),
                             allow_wake_recovery=args.control_mode == 'auto' and args.resume)
            await ids.start()
            proxy = ActivationProxy(record, store.directory)
            setup_flow = SetupFlow(ids, store, record, proxy, product, args.language, args.locale, args.timezone)
            async with asyncio.timeout(None if args.setup_timeout == math.inf else args.setup_timeout):
                await setup_flow.run()
            print(('Watch confirmed its initialized setup.' if setup_flow.reconnecting else
                   'Watch reported activation, isSetup and initial-sync completion.') +
                  ' Check the watch face and open built-in apps; physical usability is still unverified.', flush=True)
            if args.hold:
                print('Keeping the companion connected until interrupted.' if args.hold == math.inf else
                      f'Keeping the companion connected for {args.hold:g} seconds.', flush=True)
                try:
                    async with asyncio.timeout(None if args.hold == math.inf else args.hold):
                        while True:
                            await setup_flow.accept(await ids.receive())
                            await setup_flow.advance()
                except TimeoutError:
                    if ids.error:
                        raise ids.error
        except BaseException as error:
            record('aborted', error=type(error).__name__, message=str(error))
            raise
        finally:
            if heartbeat_task:
                heartbeat_task.cancel()
                await asyncio.gather(heartbeat_task, return_exceptions=True)
            if signal_task:
                signal_task.cancel()
                await asyncio.gather(signal_task, return_exceptions=True)
            if proxy:
                proxy.close()
            for resource in (ids, normal, relay, pairing_link):
                if resource:
                    try:
                        await resource.close()
                    except Exception as error:
                        record('cleanup_failed', resource=type(resource).__name__, error=type(error).__name__)
            if connection:
                try:
                    await asyncio.wait_for(connection.disconnect(), 5)
                except Exception:
                    pass
            if store:
                for name in ('bond.json', 'bond.json.tmp'):
                    path = store.directory / name
                    if path.exists():
                        user_owned(path)
            if transport:
                await transport.__aexit__(None, None, None)
            snoop.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--scan', action='store_true', help='Only list advertisements; default discovers and sets up the Watch')
    action.add_argument('--peer', help='Optional explicit Watch MAC; default discovers and selects a setup-mode Watch')
    parser.add_argument('--resume', action='store_true', help='Reuse the selected state and Bluetooth bond')
    parser.add_argument('--state', type=Path, default=Path('runs/pairing'))
    parser.add_argument('--output', type=Path, default=Path('runs'))
    parser.add_argument('--transport', default='hci-socket:0')
    parser.add_argument('--address-type', choices=('random', 'public'), default='random')
    parser.add_argument('--setup-data', help='Diagnostic twelve-byte hex override with --peer; normally discovered automatically')
    parser.add_argument('--product', help='Expected Watch product, otherwise decoded from setup advertisement')
    parser.add_argument('--timeout', type=positive_seconds, default=30)
    parser.add_argument('--setup-timeout', type=seconds_or_unlimited, default=900,
                        help='seconds for each setup wait, 0 for no limit')
    parser.add_argument('--control-mode', choices=('auto', 'initiate', 'listen'), default='auto',
                        help='ids-control startup: initiate SYNs it, listen waits for the Watch; auto listens with --resume')
    parser.add_argument('--hold', type=seconds_or_unlimited, default=300,
                        help='seconds to stay connected after setup, 0 to stay until interrupted')
    parser.add_argument('--language', default='en-US')
    parser.add_argument('--locale', default='en_US')
    parser.add_argument('--timezone', default='UTC')
    args = parser.parse_args()
    if args.peer and not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', args.peer):
        parser.error('--peer must be a Bluetooth MAC')
    if args.setup_data and not re.fullmatch(r'[0-9a-fA-F]{24}', args.setup_data):
        parser.error('--setup-data must be exactly twelve bytes in hex')
    if args.resume and args.scan:
        parser.error('--resume cannot be combined with --scan')
    if args.setup_data and not args.peer:
        parser.error('--setup-data is a diagnostic override requiring --peer; automatic discovery collects it normally')
    if args.product and not re.fullmatch(r'Watch\d+,\d+', args.product):
        parser.error('--product must look like Watch7,14')
    if sys.platform != 'linux':
        parser.error('Live scan/setup requires Linux (raw HCI and /dev/net/tun); --help and offline checks work on macOS')
    logging.basicConfig(level=logging.WARNING)
    try:
        asyncio.run(run(args))
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print(f'PoC stopped: {type(error).__name__}: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
