#!/usr/bin/env python3
"""LE Magnet transport probe for the observed watchOS 26.4 profile.

Negotiates version, services and directional channels. With --send-sa-init,
also sends one freshly built IKE_SA_INIT over NRLP on the negotiated pairing
channel and logs whatever comes back. Does not perform PIN authentication,
install bonds, complete the ML-KEM/IKE_INTERMEDIATE round, or complete watch
setup -- use watch_poc.py for full setup; see probe/README.md.
"""

import argparse
import asyncio
from contextlib import ExitStack
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import secrets
import struct
import sys
import time


MAGNET_CID = 0x003A
# Public transport advertisement from original Bluetooth frame 695.
# Includes wp.nearby because its role as a pairing prerequisite is unresolved.
SERVICE_ADVERTISEMENT = bytes.fromhex(
    '013100020f0500020a77702e6e65617262790000'
    '1f0800011a636f6d2e6170706c652e7465726d696e757350616972696e670001'
)
SERVICES = {5: 'wp.nearby', 8: 'com.apple.terminusPairing'}


def magnet(opcode, body):
    if opcode == 9:
        return bytes((opcode, len(body))) + body
    return bytes((opcode,)) + struct.pack('<H', len(body)) + body


def parse_magnet(pdu):
    if not pdu:
        raise ValueError('Empty Magnet PDU')
    header = 2 if pdu[0] == 9 else 3
    if len(pdu) < header:
        raise ValueError('Short Magnet header')
    length = pdu[1] if header == 2 else struct.unpack_from('<H', pdu, 1)[0]
    if length != len(pdu) - header:
        raise ValueError('Magnet declared length does not match payload')
    return pdu[0], pdu[header:]


def positive_seconds(value):
    result = float(value)
    if not 0 < result <= 3600:
        raise argparse.ArgumentTypeError('Use a duration greater than 0 and at most 3600 seconds')
    return result


def dynamic_cid(value):
    result = int(value, 0)
    if not 0x0040 <= result <= 0xFFFF:
        raise argparse.ArgumentTypeError('CID must be in 0x0040..0xffff')
    return result


async def run(args):
    # Defer dependencies so --help works even before installation.
    from bumble.device import Device
    from bumble.hci import Address, HCI_LE_1M_PHY
    from bumble.snoop import BtSnooper
    from bumble.transport import open_transport
    import bumble
    import ike_sa_init  # needs `cryptography`, deferred for the same reason
    import nrlp

    run_dir = args.output / (
        datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + secrets.token_hex(4)
    )
    run_dir.mkdir(parents=True, mode=0o700)
    print(f'Artifacts: {run_dir.resolve()}', flush=True)
    started = time.monotonic()

    with ExitStack() as files:
        def private_file(name, mode):
            fd = os.open(run_dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            return files.enter_context(os.fdopen(fd, mode))

        events = private_file('events.jsonl', 'w')
        snoop = private_file('hci.btsnoop', 'wb')

        def record(event, **fields):
            entry = dict(event=event, epoch=time.time(), elapsed=time.monotonic() - started, **fields)
            events.write(json.dumps(entry) + '\n')
            events.flush()

        record('start', transport=args.transport, peer=args.peer,
               address_type=args.address_type, bumble_source=bumble.__file__,
               bumble_version=getattr(bumble, '__version__', 'unknown'),
               mutation=args.mutation)
        try:
            async with await open_transport(args.transport) as transport:
                # Fresh static random host address; no reference iPhone identity.
                raw_address = bytearray(secrets.token_bytes(6))
                raw_address[0] |= 0xC0
                own_address = Address(raw_address.hex())
                device = Device.with_hci('Watch Magnet probe', own_address,
                                         transport.source, transport.sink)
                device.host.snooper = BtSnooper(snoop)
                await device.power_on()
                record('controller_ready', host_address=str(device.random_address))

                if args.scan:
                    def advertisement(adv):
                        record('advertisement', address=str(adv.address),
                               address_type=int(adv.address.address_type),
                               connectable=adv.is_connectable, rssi=adv.rssi,
                               data=adv.data.to_string())
                        print(f'{adv.address} type={adv.address.address_type} '
                              f'connectable={adv.is_connectable} RSSI={adv.rssi} '
                              f'{adv.data.to_string()}', flush=True)

                    device.on('advertisement', advertisement)
                    await device.start_scanning(legacy=True, active=False,
                                                scanning_phys=[HCI_LE_1M_PHY])
                    try:
                        await asyncio.sleep(args.timeout)
                    finally:
                        await device.stop_scanning()
                    record('scan_complete')
                    return

                incoming = asyncio.Queue()
                connection = None
                disconnected = False

                def receive(handle, pdu):
                    record('l2cap_rx', handle=handle, cid=MAGNET_CID, payload=pdu.hex())
                    incoming.put_nowait(pdu)

                def on_disconnect(*details):
                    nonlocal disconnected
                    disconnected = True
                    record('disconnected', details=[str(value) for value in details])
                    incoming.put_nowait(ConnectionError('Watch disconnected during negotiation'))

                def unexpected_smp(handle, pdu):
                    record('unexpected_smp', handle=handle, payload=pdu.hex())
                    incoming.put_nowait(RuntimeError('SMP arrived before implemented IKE authentication'))

                # Register only the real fixed channels. Apple's Magnet-
                # negotiated data CIDs are NOT standard L2CAP fixed channels;
                # calling register_fixed_channel for one of them would corrupt
                # the fixed-channel capability bitmap Bumble reports to the
                # peer (ChannelManager builds it as
                # sum(1 << cid for cid in self.fixed_channels), a 64-bit
                # field, so a high dynamic CID overflows/corrupts it).
                # Instead, wrap ChannelManager.on_pdu itself: check our own
                # dynamic-CID table first, fall through to the original
                # (unmodified) dispatch for everything else (signaling, ATT,
                # SMP, Magnet). This was verified against bumble==0.0.235's
                # actual l2cap.py/device.py source, not assumed.
                manager = device.l2cap_channel_manager
                manager.register_fixed_channel(MAGNET_CID, receive)
                manager.register_fixed_channel(0x0006, unexpected_smp)
                dynamic_cid_handlers = {}
                original_on_pdu = manager.on_pdu

                def patched_on_pdu(conn, cid, pdu):
                    handler = dynamic_cid_handlers.get(cid)
                    if handler is not None:
                        handler(conn.handle, pdu)
                        return
                    original_on_pdu(conn, cid, pdu)

                manager.on_pdu = patched_on_pdu
                peer = Address(args.peer, Address.PUBLIC_DEVICE_ADDRESS
                               if args.address_type == 'public' else Address.RANDOM_DEVICE_ADDRESS)
                connection = await device.connect(peer, timeout=args.timeout)
                connection.on('disconnection', on_disconnect)
                record('connected', handle=connection.handle, peer=str(connection.peer_address))

                def send(pdu):
                    record('l2cap_tx', handle=connection.handle, cid=MAGNET_CID, payload=pdu.hex())
                    connection.send_l2cap_pdu(MAGNET_CID, pdu)

                async def expected(opcode):
                    # One deadline per stage; unsolicited traffic cannot extend it.
                    async with asyncio.timeout(args.timeout):
                        while True:
                            pdu = await incoming.get()
                            if isinstance(pdu, Exception):
                                raise pdu
                            command, body = parse_magnet(pdu)
                            if command == opcode:
                                return body
                            # Exact duplicate replies cannot extend the stage
                            # deadline; other state changes need investigation.
                            if command == 9 and peer_version is not None and body == peer_version:
                                record('duplicate_version_reply')
                                continue
                            if command == 2 and peer_services is not None and body == peer_services:
                                record('duplicate_services_reply')
                                continue
                            raise ValueError(f'Unexpected Magnet command 0x{command:02x}; expected 0x{opcode:02x}')

                try:
                    peer_version = None
                    peer_services = None
                    if args.mutation == 'omit-version':
                        record('message_omitted', stage='version')
                    else:
                        version_request = magnet(9, b'' if args.mutation == 'empty-version'
                                                 else b'\x0b' + bytes.fromhex(args.version_flags))
                        send(version_request)
                        if args.mutation == 'repeat-version':
                            send(version_request)
                        peer_version = await expected(9)
                        if len(peer_version) != 5 or peer_version[0] != 0x0B:
                            raise ValueError('Peer does not match the observed Magnet version 0x0b')
                        record('version_accepted', version=peer_version[0], flags=peer_version[1:].hex())

                    if args.mutation == 'omit-services':
                        record('message_omitted', stage='services')
                    else:
                        advertisement_request = (
                            magnet(1, b'\x00') if args.mutation == 'empty-services'
                            else SERVICE_ADVERTISEMENT
                        )
                        send(advertisement_request)
                        if args.mutation == 'repeat-services':
                            send(advertisement_request)
                        peer_services = await expected(2)
                        if not peer_services or len(peer_services) != 1 + 2 * peer_services[0]:
                            raise ValueError('Malformed Magnet service acknowledgement')
                        service_ids = struct.unpack_from('<' + 'H' * peer_services[0], peer_services, 1)
                        advertised_ids = set() if args.mutation == 'empty-services' else set(SERVICES)
                        if len(service_ids) != len(advertised_ids) or set(service_ids) != advertised_ids:
                            raise ValueError(f'Unexpected acknowledged service IDs: {service_ids}')
                        record('services_accepted', services=list(service_ids))

                    local_cids = {5: args.nearby_cid, 8: args.pairing_cid}
                    for sid, cid in local_cids.items():
                        body = (
                            b'' if sid == 8 and args.mutation == 'empty-pairing-channel'
                            else struct.pack('<HH', cid, sid)
                        )
                        send(magnet(3, body))

                    peer_cids = {}
                    while len(peer_cids) < len(local_cids):
                        reply = await expected(4)
                        if len(reply) != 5:
                            raise ValueError('Malformed Magnet channel acknowledgement')
                        status, sid, cid = struct.unpack('<BHH', reply)
                        if (status or sid not in local_cids or sid in peer_cids
                                or cid < 0x0040 or cid in peer_cids.values()):
                            raise ValueError(f'Unexpected channel acknowledgement: status={status}, service={sid}, cid={cid:#x}')
                        peer_cids[sid] = cid
                        record('channel_accepted', service=SERVICES[sid],
                               local_receive_cid=local_cids[sid], peer_receive_cid=cid)

                    record('transport_negotiated', authenticated=False,
                           mutation=args.mutation, version_acknowledged=peer_version is not None,
                           advertised_service_acknowledged=peer_services is not None)
                    print(f'Magnet and pairing channel negotiated: '
                          f'RX={local_cids[8]:#06x}, TX={peer_cids[8]:#06x}. '
                          'PIN authentication is not implemented.', flush=True)
                    if args.mutation != 'baseline':
                        print(f'Experimental variant: {args.mutation}; see logged stages. '
                              'Channel acceptance does not establish setup bypass.', flush=True)

                    if args.send_sa_init and args.mutation == 'baseline':
                        pairing_rx_cid = local_cids[8]
                        pairing_tx_cid = peer_cids[8]
                        nrlp_state = nrlp.SequenceState()
                        nrlp_incoming = asyncio.Queue()
                        dynamic_cid_handlers[pairing_rx_cid] = (
                            lambda handle, pdu: (
                                record('nrlp_rx', handle=handle, cid=pairing_rx_cid, payload=pdu.hex()),
                                nrlp_incoming.put_nowait(pdu),
                            )
                        )

                        # NOTE: NAT_DETECTION_SOURCE_IP/DESTINATION_IP (RFC
                        # 7296 2.23) are defined for IKE-over-UDP/IP. This
                        # transport is IKE tunneled over Bluetooth NRLP with
                        # no IP layer at this stage, so what address/port a
                        # real watch expects (if it inspects this field at
                        # all) is UNKNOWN -- not verified against the real
                        # capture, unlike the SA proposal bytes. Using
                        # 0.0.0.0:0 placeholders; NAT-D is advisory in
                        # standard IKE (it only affects whether an
                        # implementation applies NAT-T UDP encapsulation) so
                        # this is a reasoned low-risk guess, not a confirmed
                        # value. If the watch rejects SA_INIT outright, this
                        # field is one of the first places to suspect.
                        sa_init_msg, x448_private_key = ike_sa_init.SaInitMessage.fresh(
                            local_addr='0.0.0.0', remote_addr='0.0.0.0',
                        )
                        sa_init_wire = sa_init_msg.build()
                        record('sa_init_built', initiator_spi=sa_init_msg.initiator_spi.hex(),
                               length=len(sa_init_wire))

                        pdu = nrlp.build_pdu(sa_init_wire, nrlp_state)
                        record('nrlp_tx', handle=connection.handle, cid=pairing_tx_cid,
                               payload=pdu.hex())
                        connection.send_l2cap_pdu(pairing_tx_cid, pdu)
                        print(f'Sent IKE_SA_INIT ({len(sa_init_wire)} bytes) over NRLP on '
                              f'CID {pairing_tx_cid:#06x}. This has not been validated against '
                              'real hardware; see probe/README.md before trusting the response.',
                              flush=True)

                        try:
                            async with asyncio.timeout(args.timeout):
                                reply_pdu = await nrlp_incoming.get()
                        except TimeoutError:
                            record('sa_init_no_reply')
                            print('No reply received within the timeout.', flush=True)
                        else:
                            parsed = nrlp.parse_pdu(reply_pdu)
                            record('nrlp_reply_parsed', **{
                                k: (v.hex() if isinstance(v, bytes) else v)
                                for k, v in parsed.items()
                            })
                            if parsed.get('msg_type') == nrlp.IKE_MESSAGE_TYPE and parsed.get('checksum_ok'):
                                header = ike_sa_init.parse_header(parsed['payload'])
                                record('ike_reply_header', **{
                                    k: (v.hex() if isinstance(v, bytes) else v)
                                    for k, v in header.items()
                                })
                                print(f"Reply parsed as IKE, exchange_type={header['exchange_type']}, "
                                      f"responder_spi={header['responder_spi'].hex()}. "
                                      'Completing the ECDH/ML-KEM exchange and the rest of the '
                                      'handshake is the next manual step -- see probe/README.md.',
                                      flush=True)
                            else:
                                print(f'Reply did not parse as a complete, checksum-valid IKE NRLP '
                                      f'message: {parsed}', flush=True)
                finally:
                    if connection is not None and not disconnected:
                        try:
                            await asyncio.wait_for(connection.disconnect(), 5)
                        except Exception as error:
                            record('disconnect_error', message=str(error))
                    snoop.flush()
        except BaseException as error:
            record('aborted', error=type(error).__name__, message=str(error))
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--scan', action='store_true', help='List advertisements without connecting')
    action.add_argument('--peer', help='Current watch Bluetooth MAC, e.g. AA:BB:CC:DD:EE:FF')
    parser.add_argument('--transport', default='hci-socket:0', help='Bumble transport; default hci-socket:0')
    parser.add_argument('--address-type', choices=('random', 'public'), default='random')
    parser.add_argument('--timeout', type=positive_seconds, default=15)
    parser.add_argument('--nearby-cid', type=dynamic_cid, default=0x0040)
    parser.add_argument('--pairing-cid', type=dynamic_cid, default=0x0041)
    parser.add_argument('--version-flags', default='33150000', help='Four observed capability bytes, hex')
    parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parent.parent / 'runs')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--send-sa-init', action='store_true',
        help='After channel negotiation, also send one freshly built IKE_SA_INIT over NRLP '
             'and log any reply. Opt-in: this is the first live protocol step past negotiation '
             'and has not been validated against real hardware. Ignored with --mutation.')
    parser.add_argument('--mutation', default='baseline', choices=(
        'baseline', 'omit-version', 'empty-version', 'repeat-version',
        'omit-services', 'empty-services', 'repeat-services', 'empty-pairing-channel'),
        help='One controlled pre-authentication mutation per run; default baseline')
    args = parser.parse_args()
    if args.peer and not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', args.peer):
        parser.error('--peer must be a Bluetooth MAC; use --address-type separately')
    if args.nearby_cid == args.pairing_cid:
        parser.error('Receive CIDs must be distinct')
    if args.scan and args.mutation != 'baseline':
        parser.error('--mutation requires --peer; scanning sends no Magnet messages')
    if not re.fullmatch(r'[0-9A-Fa-f]{8}', args.version_flags):
        parser.error('--version-flags must contain exactly four bytes as eight hex digits')
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.WARNING)
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print(f'Probe stopped: {type(error).__name__}: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
