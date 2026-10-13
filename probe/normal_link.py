"""Normal terminus link and native Linux IPv6/TCP stack through a private TUN.

Only two authenticated point-to-point routes are installed. Closing the TUN
removes the interface and its addresses/routes; the host default route is untouched.
"""
import asyncio
import fcntl
import ipaddress
import os
import struct
import subprocess
import sys
import time
from nrlp import inet_checksum
from normal_crypto import OrdinarySession, validate_ipv6
from pairing_session import tlvs
from pairing_store import class_c
from ike_wire import chain, notify, notifications, payloads, read_header


def prelude(identifier=bytes(16), paired=False):
    body = b'TERMINUS' + bytes([1, 20 if paired else 13]) + b'\0\x18\x04\0\x10' + identifier + b'\x05\0\x02\0\0'
    return body + struct.pack('>H', inet_checksum(body))


def accept_prelude(packet, local):
    if len(packet) != 38 or packet[:9] != b'TERMINUS\x01' or packet[9] not in (13, 20) or packet[10:12] != b'\0\x18' or inet_checksum(packet[:-2]) != struct.unpack('>H', packet[-2:])[0]:
        raise ValueError('Invalid normal-link prelude')
    fields = tlvs(packet[12:-2])
    if set(fields) != {4, 5} or len(fields[4]) != 16 or fields[5] not in (b'\0\0', b'\0\x01'):
        raise ValueError('Unsupported normal-link UUID or TLS flags')
    # Both sides must agree: pairing states 13 and 20 cannot mix.
    if packet[9] != local[9]:
        raise ValueError(f'Incompatible normal-link pairing states {local[9]}/{packet[9]}')
    if local[15:31] >= fields[4]:
        raise ValueError('Peer elected us responder; this PoC requires the initiator role')
    return fields[4]


def decode_lowpan(data, source_d, destination_d):
    """Apple's inline-NH IPHC forms used by NetworkRelay."""
    offset = 0
    def take(size):
        nonlocal offset
        if offset + size > len(data):
            raise ValueError('Truncated NetworkRelay IPHC packet')
        value = data[offset:offset + size]
        offset += size
        return value
    first, second = take(2)
    if first & 0xe0 != 0x60 or first & 4 or second & 0x80:
        raise ValueError('Unsupported NetworkRelay IPHC dispatch, next header or context extension')
    flow = (first >> 3) & 3
    if flow not in (2, 3):
        raise ValueError('Unsupported NetworkRelay IPHC traffic flow')
    traffic = take(1)[0] if flow == 2 else 0
    nxt = take(1)[0]
    hop_mode = first & 3
    hop = (0, 1, 64, 255)[hop_mode] if hop_mode else take(1)[0]
    def address(context, stateful, mode):
        if mode == 3:
            return context
        if not stateful and mode == 0:
            return take(16)
        value = bytearray(context if stateful else bytes.fromhex('fe800000000000000000000000000000'))
        if mode == 1:
            value[8:] = take(8)
        elif mode == 2:
            if not stateful:
                value[11:13] = b'\xff\xfe'
            value[14:] = take(2)
        return bytes(value)
    if second == 0x33:
        src, dst = source_d, destination_d
    elif second == 0x66:
        src, dst = bytearray(source_d), bytearray(destination_d)
        src[8:10], dst[8:10] = take(2), take(2)
        src, dst = bytes(src), bytes(dst)
    elif second == 0x30:
        src, dst = take(16), destination_d
    elif second == 0x03:
        src, dst = source_d, take(16)
    elif second == 0:
        dst, src = take(16), take(16)  # Apple's full-inline order.
    else:
        src = address(source_d, bool(second & 0x40), (second >> 4) & 3)
        if second & 8:
            mode = second & 3
            if second & 4:
                raise ValueError('Unsupported stateful NetworkRelay multicast compression')
            if mode == 0:
                dst = take(16)
            else:
                value = bytearray(16)
                value[0] = 0xff
                value[1] = 2 if mode == 3 else take(1)[0]
                count = {1: 5, 2: 3, 3: 1}[mode]
                value[-count:] = take(count)
                dst = bytes(value)
        else:
            dst = address(destination_d, bool(second & 4), second & 3)
    body = data[offset:]
    return struct.pack('>IHBB', 0x60000000 | traffic << 20, len(body), nxt, hop) + src + dst + body


class Tun:
    def __init__(self, local_d, remote_d, local_c, remote_c):
        if sys.platform != 'linux':
            raise RuntimeError('Live setup currently requires Linux with /dev/net/tun and raw Bluetooth access')
        self.fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
        self.tasks = set()
        self.error = None
        try:
            configured = fcntl.ioctl(self.fd, 0x400454ca, struct.pack('16sH', b'watchpoc%d', 0x1001))
            self.name = configured[:16].split(b'\0')[0].decode('ascii')
            subprocess.run(['ip', 'link', 'set', 'dev', self.name, 'mtu', '1280', 'up'], check=True, capture_output=True)
            for local, remote in ((local_d, remote_d), (local_c, remote_c)):
                local, remote = str(ipaddress.IPv6Address(local)), str(ipaddress.IPv6Address(remote))
                subprocess.run(['ip', '-6', 'addr', 'add', local + '/128', 'dev', self.name, 'nodad'], check=True, capture_output=True)
                subprocess.run(['ip', '-6', 'route', 'add', remote + '/128', 'dev', self.name, 'src', local], check=True, capture_output=True)
        except BaseException:
            os.close(self.fd)
            raise

    def start(self, on_packet, on_error, record=None):
        self.queue = asyncio.Queue(maxsize=256)
        self.read_paused = False
        self.backpressure_count = 0
        def failed(error):
            if self.error is None:
                self.error = error
                asyncio.get_running_loop().remove_reader(self.fd)
                on_error(error)
        def readable():
            try:
                packet = os.read(self.fd, 65536)
                self.queue.put_nowait(packet)
                if self.queue.full():
                    asyncio.get_running_loop().remove_reader(self.fd)
                    self.read_paused = True
                    self.backpressure_count += 1
                    if record and self.backpressure_count & (self.backpressure_count - 1) == 0:
                        record('normal_tun_backpressure', count=self.backpressure_count,
                               queued_packets=self.queue.qsize())
            except BlockingIOError:
                pass
            except Exception as error:
                failed(error)
        async def pump():
            try:
                while True:
                    packet = await self.queue.get()
                    if self.read_paused and self.error is None:
                        asyncio.get_running_loop().add_reader(self.fd, readable)
                        self.read_paused = False
                    await on_packet(packet)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                failed(error)
        asyncio.get_running_loop().add_reader(self.fd, readable)
        self.task = asyncio.create_task(pump())

    def deliver(self, ipv6):
        if self.error:
            raise self.error
        try:
            if os.write(self.fd, ipv6) != len(ipv6):
                raise IOError('Partial TUN packet write')
        except BlockingIOError:
            raise IOError('TUN receive queue is full') from None

    async def close(self):
        asyncio.get_running_loop().remove_reader(self.fd)
        self.task.cancel()
        await asyncio.gather(self.task, return_exceptions=True)
        os.close(self.fd)


class NormalLink:
    def __init__(self, link, record, store, local_prelude, remote_prelude):
        self.link, self.record, self.store = link, record, store
        self.sessions, self.pending_ip = {}, []
        self.tun = None
        self.accept_ip = False
        self.request_cache = {}
        # Authentication consumed D IDs 2..4 and C ID 2.
        self.next_notify_id = {'d': 5, 'c': 3}
        self.seen_tcp = set()
        self.local_prelude, self.remote_prelude = local_prelude, remote_prelude
        self.error = self.on_error = None

    def fail(self, error):
        if self.error is None:
            self.error = error
            self.record('normal_link_failed', error=type(error).__name__)
            if self.on_error:
                self.on_error(error)

    async def start(self):
        self.link.on_message = self.incoming
        self.link.on_error = self.fail
        for lane in ('d', 'c'):
            session = OrdinarySession(self.link, self.record, self.store, lane, self.local_prelude, self.remote_prelude)
            await session.establish()
            self.sessions[lane] = session
            await session.authenticate()
            if lane == 'd':
                await asyncio.wait_for(session.remote_unlocked.wait(), self.link.timeout)
        d, c = self.sessions['d'], self.sessions['c']
        if class_c(d.local_address) != c.local_address or class_c(d.remote_address) != c.remote_address:
            raise ValueError('Class-C/D address assignments disagree')
        self.tun = Tun(d.local_address, d.remote_address, c.local_address, c.remote_address)
        self.tun.start(self.outgoing, self.fail, self.record)
        self.store.save(stage='normal_link_ready')
        self.record('normal_link_ready', interface=self.tun.name)

    async def announce(self):
        """Called after IDS listeners exist, before inviting Watch traffic."""
        self.accept_ip = True
        for packet in self.pending_ip:
            self.tun.deliver(packet)
        self.pending_ip.clear()
        for kind, payload in self.link.deferred:
            await self.incoming(kind, payload)
        self.link.deferred.clear()
        d = self.sessions['d']
        self.record('link_director_announcements_started')
        identifier = time.time_ns() // 1000 - time.monotonic_ns() // 2000
        for kind, value in ((1, b''), (6, b'\x01')):
            mid = self.next_notify_id['d']
            self.next_notify_id['d'] += 1
            message = struct.pack('>BBHIQ', 2, 0, 3 + len(value), 0, identifier) + bytes([kind]) + struct.pack('>H', len(value)) + value
            first, plain = await d.exchange(37, mid, 41, chain([(41, notify(0xc60e, message))]))
            if first or plain:
                raise ValueError('Expected empty LinkDirector announcement receipt')
            identifier += 1
        self.record('link_director_announcements_confirmed')
        for lane, session in self.sessions.items():
            source, destination = session.local_address, session.remote_address
            payload = b'\x88\0\0\0\x20\0\0\0' + source
            pseudo = source + destination + struct.pack('>I3xB', len(payload), 58)
            payload = payload[:2] + struct.pack('>H', inet_checksum(pseudo + payload)) + payload[4:]
            packet = struct.pack('>IHBB', 0x60000000, len(payload), 58, 255) + source + destination + payload
            await self.outgoing(packet)
            self.record('normal_neighbor_advertised', lane=lane)

    async def announce_proxy(self, address, port):
        """Experimental legacy C60D endpoint; an IKE receipt proves delivery only."""
        address = ipaddress.IPv6Address(address)
        if address.packed not in [session.local_address for session in self.sessions.values()]:
            raise ValueError('Proxy endpoint must belong to the normal link')
        if not 1 <= port <= 65535:
            raise ValueError('Invalid proxy port')
        lane = 'c' if 'c' in self.sessions else 'd'
        mid = self.next_notify_id[lane]
        self.next_notify_id[lane] += 1
        # Native NRTLV tag 51: uint64 flags, bit 0 = forwardNonMatchingTraffic.
        criteria = struct.pack('>BHQ', 51, 8, 1)
        body = address.packed + struct.pack('>H', port) + criteria
        fields = dict(lane=lane, message_id=mid, notify=0xc60d,
                      endpoint=str(address), port=port, proxy_flags=1, length=len(body))
        self.record('proxy_announcement_sent', **fields)
        first, plain = await self.sessions[lane].exchange(37, mid, 41, chain([(41, notify(0xc60d, body))]))
        if first or plain:
            raise ValueError('Expected empty proxy announcement receipt')
        self.record('proxy_announcement_acknowledged', **fields, ike_ack=True)

    def note_tcp(self, packet):
        """Record each distinct Watch flow once, so any gateway target/port is visible."""
        if len(self.seen_tcp) >= 256:
            return
        next_header = packet[6]
        if next_header == 6:
            event, protocol = 'watch_tcp_flow', 'tcp'
        elif next_header == 17:
            event, protocol = 'watch_udp_flow', 'udp'
        else:
            return
        if len(packet) < 44:
            return
        key = (packet[24:40], next_header, int.from_bytes(packet[42:44], 'big'))
        if key in self.seen_tcp:
            return
        self.seen_tcp.add(key)
        self.record(event, protocol=protocol,
                    destination=str(ipaddress.IPv6Address(packet[24:40])), port=key[2],
                    source=str(ipaddress.IPv6Address(packet[8:24])),
                    source_port=int.from_bytes(packet[40:42], 'big'))

    async def incoming(self, kind, data):
        if kind == 4:
            spi_i, _, _, exchange, flags, mid = read_header(data)
            session = next((s for s in self.sessions.values() if s.initial.initiator_spi == spi_i), None)
            if session is None or exchange != 37:
                return False
            if flags == 32:
                # Responses to our requests stay in RelayLink's exchange queue.
                return False
            if flags != 0:
                raise ValueError('Invalid ordinary INFORMATIONAL direction')
            opened = session.protected.open(data, 37, mid, response=False)
            if opened is None:
                return True
            first, plain = opened
            parts = payloads(first, plain)
            notes = notifications(parts)
            if 0xbdd9 in notes and notes[0xbdd9] != self.remote_prelude:
                raise ValueError('Watch changed its authenticated normal-link prelude')
            if notes.get(0xbe3d) == b'\x80':
                session.remote_unlocked.set()
            if any(tag == 42 for tag, _, _ in parts):
                raise ConnectionError('Watch deleted an ordinary IKE SA')
            key = (spi_i, mid)
            if key in self.request_cache:
                previous, reply = self.request_cache[key]
                if previous != plain:
                    raise ValueError('Conflicting ordinary IKE request retransmission')
            else:
                if len(self.request_cache) >= 256:
                    raise ValueError('Ordinary IKE request cache exceeded; reconnect')
                reply = session.protected.seal(37, mid, 0, b'', response=True)
                self.request_cache[key] = plain, reply
            for packet in reply:
                await self.link.send(packet)
            return True
        if kind == 5:
            self.record('network_relay_control', length=len(data))
            return True
        if kind == 2:
            if data and data[0] >> 4 == 4:
                # NRLP type 2 carries either IP version. This tunnel supports
                # IPv6 ESP only; unsupported IPv4 packets must not abort it.
                header_length = (data[0] & 15) * 4
                if (len(data) < 20 or header_length < 20 or header_length > len(data)
                        or int.from_bytes(data[2:4], 'big') != len(data)):
                    raise ValueError('Invalid NRLP IPv4 envelope')
                self.unsupported_ipv4 = getattr(self, 'unsupported_ipv4', 0) + 1
                if self.unsupported_ipv4 <= 8:
                    self.record('normal_ipv4_unsupported_dropped', length=len(data),
                                protocol=data[9], count=self.unsupported_ipv4)
                return True
            packet = data
        elif 100 <= kind <= 105:
            lane = 'c' if kind >= 104 else 'd'
            session = self.sessions.get(lane)
            if session is None or not hasattr(session, 'esp'):
                return False
            packet = (struct.pack('>IHBB', 0x60000000 | ((2 if kind & 1 else 0) << 20), len(data),
                                 6 if kind in (102, 103) else 50, 64)
                      + session.remote_address + session.local_address + data)
        elif kind == 3:
            session = self.sessions.get('d')
            if session is None or not hasattr(session, 'esp'):
                return False
            packet = decode_lowpan(data, session.remote_address, session.local_address)
        else:
            raise ValueError('Unsupported NetworkRelay IP compression')
        validate_ipv6(packet)
        if packet[6] != 50:
            raise ValueError('Refusing unauthenticated clear traffic on the normal link')
        multicast = packet[24] == 0xff
        session = next((s for s in self.sessions.values() if hasattr(s, 'esp')
                        and packet[40:44] == s.esp.rx_spi
                        and (multicast or (packet[8:24] == s.remote_address and packet[24:40] == s.local_address))), None)
        if session is None:
            # RFC 4303: ESP for an unknown SPI is discarded. The Watch can start ESP for a lane whose IKE_AUTH we have
            # not completed yet; TCP retransmits the dropped packets.
            self.unmatched_esp = getattr(self, 'unmatched_esp', 0) + 1
            if self.unmatched_esp <= 8:
                self.record('normal_esp_unmatched_dropped', spi=packet[40:44].hex(), count=self.unmatched_esp)
            return True
        clear = session.esp.open(packet)
        if clear is None or multicast:
            return True
        self.note_tcp(clear)
        if self.tun and self.accept_ip:
            self.tun.deliver(clear)
        else:
            if len(self.pending_ip) >= 128:
                raise ValueError('Early IP queue exceeds limit')
            self.pending_ip.append(clear)
        return True

    async def outgoing(self, packet):
        if not packet or packet[0] >> 4 != 6:
            return
        validate_ipv6(packet)
        session = next((s for s in self.sessions.values() if packet[8:24] == s.local_address and packet[24:40] == s.remote_address), None)
        if session is None:
            return  # kernel multicast/neighbor discovery is not part of this tunnel
        encrypted = session.esp.seal(packet)
        traffic = (encrypted[0] & 15) << 4 | encrypted[1] >> 4
        if traffic in (0, 2) and encrypted[:4] == struct.pack('>I', 0x60000000 | traffic << 20) and encrypted[7] == 64:
            kind = (104 if session.lane == 'c' else 100) + (1 if traffic == 2 else 0)
            await self.link.send_message(kind, encrypted[40:])
        else:
            await self.link.send_message(2, encrypted)

    async def close(self):
        if self.tun:
            await self.tun.close()
