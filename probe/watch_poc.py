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
import secrets
import struct
import sys
import time
from magnet_probe import MAGNET_CID, magnet, parse_magnet, positive_seconds


def seconds_or_unlimited(value):
    """0 means no limit; otherwise the usual positive duration."""
    return math.inf if float(value) == 0 else positive_seconds(value)



def ids_timeout(setup_timeout):
    """Preserve an indefinite application deadline."""
    return setup_timeout


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
    from relay_proxy import RelayProxy
    from setup_flow import SetupFlow
    from watch_link import Ertm, RelayLink

    os.umask(0o077)
    # Reuse durable identities; a reset Watch always gets a separate directory.
    saved = []
    for path in args.output.glob('pairing*/pairing.json'):
        data = json.loads(path.read_text())
        if data.get('bonded') and data.get('peer_address') and data.get('watch_product'):
            saved.append(path)
    saved.sort(key=lambda path: path.stat().st_mtime_ns, reverse=True)
    choice = 0
    if saved:
        print('0. Pair a reset Watch (preserves existing bonds)', flush=True)
        for number, path in enumerate(saved, 1):
            data = json.loads(path.read_text())
            print(f"{number}. Reconnect {data['watch_product']} — {data['peer_address']} ({path.parent.name})", flush=True)
        while True:
            answer = await asyncio.to_thread(input, 'Watch [1]: ')
            if not answer:
                choice = 1
                break
            if answer.isdecimal() and 0 <= int(answer) <= len(saved):
                choice = int(answer)
                break
            print(f'Enter a number from 0 to {len(saved)}.', flush=True)
    args.resume = choice != 0
    args.state = (saved[choice - 1].parent if args.resume else
                  args.output / (datetime.now(timezone.utc).strftime('pairing-%Y%m%dT%H%M%SZ-') + secrets.token_hex(4)))
    store = Store(args.state)
    print(f'Private pairing state: {store.directory.resolve()}', flush=True)
    if args.resume:
        args.peer = store.data['peer_address']
        args.address_type = store.data.get('peer_address_type', 'random')
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
        library_log = logging.StreamHandler(private_file('library.log', 'w'))
        library_log.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
        logging.getLogger().addHandler(library_log)
        files.callback(logging.getLogger().removeHandler, library_log)
        status_labels = {
            'start': 'Starting companion',
            'controller_ready': 'Bluetooth controller ready',
            'finding_bonded_watch': 'Connecting to saved Watch',
            'watch_selected': 'Watch selected',
            'channel_accepted': 'Watch transport connected',
            'pin_authenticated': 'PIN authenticated',
            'bluetooth_bond_confirmed': 'Bluetooth bond confirmed',
            'normal_link_ready': 'Authenticated Watch link connected',
            'ids_lanes_ready': 'Companion channels connected',
            'ids_transport_busy': 'Companion traffic busy; continuing service handling',
            'normal_tun_backpressure': 'Bluetooth forwarding busy; applying backpressure',
            'proxy_announcement_acknowledged': 'Proxy announcement acknowledged',
            'relay_proxy_connected': 'Internet relay connected',
            'ids_device_info_verified': 'Watch device info verified',
            'watch_activation_confirmed': 'Watch activation confirmed',
            'setup_protocol_complete': 'Watch setup confirmed',
            'reconnected_to_initialized_watch': 'Reconnected to initialized Watch',
        }
        displayed_status = set()
        def record(event, **fields):
            events.write(json.dumps({'event': event, 'epoch': time.time(), **fields}) + '\n')
            events.flush()
            if not args.verbose:
                label = status_labels.get(event)
                if event == 'timesync_answered' and fields.get('message_type') == 8:
                    label = 'Clock update queued'
                if event == 'ble_connection_parameters':
                    label = f"Bluetooth interval: {fields['interval_ms']:g} ms"
                if event == 'ota_message_received':
                    errors = fields.get('error_field_details', {}).get('archived_errors', [])
                    label = 'Update scan response received'
                    if errors:
                        last = errors[-1]
                        label = f"Update scan failed: {last.get('reason', last.get('result_name', last.get('domain', 'error')))} ({last['code']})"
                if event == 'aborted' or event.endswith('_failed'):
                    label = event.replace('_', ' ')
                    if fields.get('error'):
                        label += ': ' + fields['error']
                # Repeated flows/errors stay in the files without flooding the console.
                if label and label not in displayed_status:
                    displayed_status.add(label)
                    print(f'{datetime.now():%H:%M:%S} {label}', flush=True)
                return
            stamp = datetime.now().strftime('%H:%M:%S')
            details = ' '.join(f'{key}={fields[key]}' for key in
                               ('lane', 'port', 'type', 'length', 'command', 'sequence', 'stream', 'correlated', 'flags', 'operation', 'version', 'error', 'error_function', 'error_line', 'stage', 'ids_phase', 'ertm_pending', 'ids_lanes', 'peer_info', 'local_info_ack', 'info_replies_pending',
                                'mode', 'response', 'success_present', 'accepted', 'success',
                                'phone_minimum', 'phone_maximum', 'watch_version', 'property_count', 'properties',
                                'state_name', 'timestamp', 'applied', 'state', 'watch_setup_present', 'watch_is_setup',
                                'activation', 'sync_complete', 'completion_ack', 'watch_sync_progress',
                                'watch_global_progress', 'client_sync_progress', 'payload_format',
                                'numeric_fields', 'bundle_id', 'error_domain', 'archived_errors',
                                'field_summary', 'application_handler', 'response_expected',
                                'error_details', 'error_field_details', 'collection_counts', 'notify', 'message_id',
                                'endpoint', 'address', 'proxy_flags', 'ike_ack', 'host', 'service',
                                'bytes_to_upstream', 'bytes_to_watch', 'errno', 'phase', 'proxy_probe',
                                'destination', 'source_port', 'direction', 'prefix_format',
                                'bytes_from_watch', 'bytes_from_upstream', 'protocol', 'count',
                                'message_type', 'host_unix', 'host_monotonic', 'timezone',
                                'remote_mach', 'remote_rtc', 'uncertainty', 'time_source',
                                'tcp_pending', 'waited_seconds', 'queued_packets',
                                'ertm_window', 'ertm_mps', 'ertm_tx_frames', 'ertm_acked', 'ertm_retransmissions',
                                'interval_ms', 'requested_interval_ms', 'latency', 'supervision_timeout_ms')
                               if key in fields)
            print(f'{stamp} {event.replace("_", " ")} {details}'.rstrip(), flush=True)
        record('start', transport=args.transport, peer=args.peer, resume=args.resume,
               proxy_probe=args.proxy_probe, hardware_validated=False)
        connection = normal = ids = pairing_link = relay = proxy = transport = signal_task = None
        relay_proxy = None
        heartbeat_task = None
        setup_flow = None
        handlers = {}
        async def heartbeat():
            while True:
                await asyncio.sleep(10)
                record('progress', stage=store.data.get('stage', 'scan') if store else 'scan',
                       ertm_pending=sum(len(handler.unacknowledged) for handler in handlers.values()),
                       ertm_tx_frames=sum(handler.tx_frames for handler in handlers.values()),
                       ertm_acked=sum(handler.tx_acknowledged for handler in handlers.values()),
                       ertm_retransmissions=sum(handler.tx_retransmissions for handler in handlers.values()),
                       ids_lanes=len(ids.lanes) if ids else 0,
                       ids_phase=ids.phase if ids else 'not_started',
                       ids_hello=bool(ids and ids.peer_hello),
                       **({'peer_info': setup_flow.peer_info,
                           'local_info_ack': setup_flow.local_info_ack,
                           'info_replies_pending': len(setup_flow.local_info_sequences),
                           **setup_flow.diagnostic_status()}
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
                raise ValueError('Saved bond has no Watch product')
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
                    normal_channel = name == 'com.apple.terminusLink'
                    ertm = Ertm(connection, tx_cid, record, args.timeout,
                                window=args.ertm_window if normal_channel else 1,
                                mps=args.ertm_mps if normal_channel else 1000)
                    handlers[cid] = ertm
                    for packet in opening_channels[cid]:
                        ertm.feed(packet)
                finally:
                    del opening_channels[cid]
                record('channel_accepted', service=name, rx_cid=cid, tx_cid=tx_cid,
                       ertm_window=ertm.window, ertm_mps=ertm.mps)
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
            def record_connection_parameters():
                parameters = connection.parameters
                record('ble_connection_parameters', interval_ms=parameters.connection_interval,
                       latency=parameters.peripheral_latency,
                       supervision_timeout_ms=parameters.supervision_timeout)
            record_connection_parameters()
            connection.on(connection.EVENT_CONNECTION_PARAMETERS_UPDATE, record_connection_parameters)
            if args.connection_interval_ms is not None:
                record('ble_parameters_update_requested', requested_interval_ms=args.connection_interval_ms)
                try:
                    await asyncio.wait_for(connection.update_parameters(
                        connection_interval_min=args.connection_interval_ms,
                        connection_interval_max=args.connection_interval_ms,
                        max_latency=0, supervision_timeout=2000), min(args.timeout, 5))
                except Exception as error:
                    record('ble_parameters_update_failed', error=type(error).__name__,
                           requested_interval_ms=args.connection_interval_ms, reason=str(error))
                # A rejected request leaves the actual controller parameters in place.
                record_connection_parameters()
            relay_proxy = RelayProxy(record, [normal.sessions[lane].local_address for lane in ('d', 'c')])
            await relay_proxy.start()
            ids = IdsSession(normal, store, record, ids_timeout(args.setup_timeout),
                             listen_only=args.control_mode == 'listen' or (args.control_mode == 'auto' and args.resume),
                             allow_wake_recovery=args.control_mode == 'auto' and args.resume)
            await ids.start()
            if not relay_proxy.bound_addresses:
                raise OSError('Companion relay requires a bound listener')
            # Prefer the D endpoint, while native senders prefer C for the IKE notify.
            endpoint = relay_proxy.bound_addresses[0]
            try:
                await normal.announce_proxy(endpoint, relay_proxy.port)
            except TimeoutError as error:
                record('proxy_announcement_failed', error=type(error).__name__,
                       endpoint=endpoint, port=relay_proxy.port, ike_ack=False)
                # Keep the diagnostic session alive to observe late Watch flows.
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
            if relay_proxy:
                await relay_proxy.close()
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
    parser.add_argument('--transport', default='hci-socket:0',
                        help='Linux HCI transport (default: hci-socket:0)')
    parser.add_argument('--connection-interval-ms', type=float, choices=(7.5, 15.0, 30.0),
                        help='Request a shorter BLE interval; rejection preserves the current link')
    parser.set_defaults(scan=False, peer=None, resume=False, proxy_probe=True,
                        verbose=os.environ.get('OSAW_VERBOSE') == '1',
                        ertm_window=32, ertm_mps=2042,
                        output=Path(__file__).resolve().parent / 'runs',
                        address_type='random', setup_data=None, product=None,
                        timeout=30, setup_timeout=math.inf, control_mode='auto',
                        activation_lock='stop', hold=math.inf,
                        language='en-US', locale='en_US', timezone='Europe/Paris')
    args = parser.parse_args()
    if not args.transport.startswith('hci-socket:') or not args.transport[11:].isdecimal():
        parser.error('--transport must be hci-socket:<controller index>')
    if sys.platform != 'linux':
        parser.error('Live scan/setup requires Linux (raw HCI and /dev/net/tun); --help and offline checks work on macOS')
    logging.basicConfig(level=logging.WARNING,
                        handlers=[logging.StreamHandler()] if args.verbose else [logging.NullHandler()])
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
