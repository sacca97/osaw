"""NWSC signatures, IDS control setup and Alloy socket-pair framing."""
import struct
import uuid
import zlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from pairing_session import encode_tlvs, tlvs

MAX_FRAME = 1024 * 1024


class Cursor:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, size):
        if size < 0 or size > len(self.data) - self.offset:
            raise ValueError('Truncated IDS field')
        value = self.data[self.offset:self.offset + size]
        self.offset += size
        return value

    def number(self, size):
        return int.from_bytes(self.take(size), 'big')

    def string(self, size=4):
        return self.take(self.number(size)).decode('utf-8', errors='strict')

    def end(self):
        if self.offset != len(self.data):
            raise ValueError('Trailing IDS bytes')


def string(value, size=4):
    value = value.encode()
    if len(value) > 65535:
        raise ValueError('IDS string exceeds limit')
    return len(value).to_bytes(size, 'big') + value


def nwsc_start(port, sequence, service, private, request_uuid=None):
    service = service.encode()
    if not 1 <= len(service) <= 255:
        raise ValueError('Invalid NWSC service length')
    prefix = struct.pack('>HHQ', 91 + len(service), port, sequence) + (request_uuid or uuid.uuid4().bytes) + bytes([len(service)]) + service
    signature = private.sign(prefix + bytes(64))
    return prefix + signature


def nwsc_accept(frame, peer_key):
    if len(frame) < 94 or int.from_bytes(frame[:2], 'big') != len(frame) - 2:
        raise ValueError('Invalid NWSC request')
    size = frame[28]
    if len(frame) != 93 + size or not size:
        raise ValueError('Malformed NWSC service')
    ed25519.Ed25519PublicKey.from_public_bytes(peer_key).verify(frame[-64:], frame[:-64] + bytes(64))
    return frame[29:29 + size].decode(), int.from_bytes(frame[4:12], 'big')


def nwsc_feedback(sequence, key, accepted=True):
    return struct.pack('>HBBQ', 42, 0x80 if accepted else 0x40, 0, sequence) + key


def nwsc_probe(port, sequence, private):
    transcript = struct.pack('>HHQ', 79, port, sequence) + bytes(69)
    return transcript[:16] + private.sign(transcript) + transcript[80:]


def parse_nwsc_feedback(frame):
    if len(frame) != 44 or frame[:2] != b'\0\x2a' or frame[3] or frame[2] not in (0, 0x40, 0x80):
        raise ValueError('Invalid NWSC feedback')
    return frame[2], int.from_bytes(frame[4:12], 'big'), frame[12:]


def control_frame(body):
    if not 1 <= len(body) <= 65535:
        raise ValueError('Invalid IDS control size')
    return struct.pack('>H', len(body)) + body


def hello(device_id, instance_id):
    body = b'\x01' + b''.join(string(value, 2) for value in ('5', 'iPhone OS', '26.6', '23G71', 'iPhone18,1'))
    body += struct.pack('>I', 26) + encode_tlvs({0: struct.pack('>I', 25), 1: struct.pack('>I', 27),
        2: instance_id.bytes, 5: uuid.UUID(device_id).bytes, 3: struct.pack('>Q', 0xbff), 4: struct.pack('>H', 32)})
    return control_frame(body)


def parse_hello(body):
    c = Cursor(body)
    if c.number(1) != 1:
        raise ValueError('Expected IDS Hello')
    values = [c.string(2) for _ in range(5)]
    version = c.number(4)
    fields = tlvs(c.take(len(body) - c.offset))
    if len(fields.get(2, b'')) != 16 or len(fields.get(5, b'')) != 16:
        raise ValueError('IDS Hello lacks peer identifiers')
    low, high = (int.from_bytes(fields.get(n, bytes(4)), 'big') for n in (0, 1))
    if (low or high) and max(low, 25) > min(high, 27):
        raise ValueError('IDS pairing compatibility ranges do not overlap')
    return {'profile': values, 'version': version, 'instance': uuid.UUID(bytes=fields[2]),
            'device': uuid.UUID(bytes=fields[5]), 'minimum': low, 'maximum': high}


def setup_message(local_port, remote_port, guid, peer_guid, name, contribution, ssrc, seq):
    values = [guid, peer_guid or '', 'idstest', 'localdelivery', name]
    encoded = [value.encode() for value in values]
    body = struct.pack('>BBHH5HIHH', 6, 6, local_port, remote_port, *[len(v) for v in encoded], ssrc, seq, len(contribution))
    return control_frame(body + b''.join(encoded) + contribution)


def plain_setup_reply(incoming, guid):
    values = [guid, incoming['guid'], incoming.get('account', 'idstest'),
              incoming.get('service', 'localdelivery'), incoming['name']]
    encoded = [value.encode() for value in values]
    body = struct.pack('>BBHH5H', incoming['kind'], 6, incoming['local_port'],
                       incoming['remote_port'], *[len(value) for value in encoded])
    body += b''.join(encoded)
    if incoming['kind'] == 13:
        body += incoming['direct_flags']
    return control_frame(body)


def parse_setup(body):
    c = Cursor(body)
    kind, protocol, local, remote = c.number(1), c.number(1), c.number(2), c.number(2)
    if kind not in (2, 6, 13) or protocol != 6:
        raise ValueError('Unsupported IDS Setup transport')
    sizes = [c.number(2) for _ in range(5)]
    ssrc, seq, key_size = (c.number(4), c.number(2), c.number(2)) if kind == 6 else (0, 0, 0)
    guid, peer, account, service, name = [c.take(size).decode() for size in sizes]
    uuid.UUID(guid)
    if peer:
        uuid.UUID(peer)
    key = c.take(key_size)
    direct_flags = c.take(8) if kind == 13 else b''
    c.end()
    if kind == 6 and len(key) != 60:
        raise ValueError('Invalid IDS Setup route or key contribution')
    return {'kind': kind, 'local_port': local, 'remote_port': remote, 'guid': guid, 'peer_guid': peer,
            'name': name, 'key': key, 'ssrc': ssrc, 'seq': seq,
            'account': account, 'service': service, 'direct_flags': direct_flags}


def frame(command, body):
    if len(body) > MAX_FRAME - 5:
        raise ValueError('IDS frame exceeds limit')
    return bytes([command]) + struct.pack('>I', len(body)) + body


def application(sequence, stream, topic, message_id, payload, protobuf_type=None, flags=0, peer='', response=False, include_topic=True,
                command=None, expiry=None):
    """command overrides the untyped Data command (e.g. 6 for Dictionary); flag 8 appends a uint32 expiry."""
    prefix = struct.pack('>IHB', sequence, stream, flags | (16 if include_topic else 0)) + string(peer) + string(message_id)
    if include_topic:
        prefix += string(topic)
    tail = struct.pack('>I', expiry or 0) if flags & 8 else b''
    if protobuf_type is None:
        return frame(0 if command is None else command, prefix + payload + tail)
    return frame(3, prefix + struct.pack('>HHI', protobuf_type, int(response), len(payload)) + payload + tail)


def parse_application(command, body, maps, allow_unmapped=False):
    c = Cursor(body)
    sequence, stream, flags = c.number(4), c.number(2), c.number(1)
    if flags & ~0x3f:
        raise ValueError('Unsupported IDS application flags')
    peer, identifier = c.string(), c.string()
    uuid.UUID(identifier)
    if peer:
        uuid.UUID(peer)
    topic = c.string() if flags & 16 else maps.get(stream)
    if topic is None and not allow_unmapped:
        raise ValueError('IDS topic has no ServiceMap')
    if flags & 16:
        maps[stream] = topic
    kind, response = None, False
    if command == 3:
        kind, response = c.number(2), c.number(2)
        if response not in (0, 1):
            raise ValueError('Invalid IDS response marker')
        payload = c.take(c.number(4))
    else:
        payload = c.take(len(body) - c.offset - (4 if flags & 8 else 0))
    if flags & 8:
        c.number(4)
    c.end()
    compressed = payload[:2] == b'\x1f\x8b' or payload[:2] in (b'\x78\x01', b'\x78\x5e', b'\x78\x9c', b'\x78\xda')
    if command == 22 and payload[:3] == b'\x01\x1f\x8b':
        pass  # Legacy resource header: its initial data has no BE64 offset.
    elif command == 22 and flags & 2 and not compressed:
        if len(payload) < 10:
            raise ValueError('Truncated compressed resource offset')
        payload = payload[:8] + decompress(payload[8:])
    elif flags & 2 or compressed:
        payload = decompress(payload)
    return {'sequence': sequence, 'stream': stream, 'flags': flags, 'peer': peer, 'id': identifier,
            'topic': topic, 'type': kind, 'response': bool(response), 'payload': payload, 'command': command}


def decompress(payload):
    decoder = zlib.decompressobj(31 if payload[:2] == b'\x1f\x8b' else 15)
    plain = decoder.decompress(payload, MAX_FRAME + 1)
    if len(plain) > MAX_FRAME or not decoder.eof or decoder.unused_data:
        raise ValueError('Invalid or excessive compressed IDS payload')
    return plain
