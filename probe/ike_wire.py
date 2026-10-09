"""Bounded IKEv2 payload and encrypted-fragment codecs for the Apple profile."""

import secrets
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ike_keys import decrypt_sk_payload

MAX_PLAINTEXT = 16384


def header(spi_i, spi_r, first, exchange, flags, mid, length):
    if len(spi_i) != 8 or len(spi_r) != 8:
        raise ValueError('Invalid IKE SPI length')
    return struct.pack('>8s8sBBBBII', spi_i, spi_r, first, 0x20, exchange, flags, mid, length)


def read_header(wire):
    if not 28 <= len(wire) <= MAX_PLAINTEXT + 256:
        raise ValueError('Invalid IKE packet length')
    spi_i, spi_r, first, version, exchange, flags, mid, length = struct.unpack('>8s8sBBBBII', wire[:28])
    if version != 0x20 or length != len(wire):
        raise ValueError('Invalid IKE version or declared length')
    return spi_i, spi_r, first, exchange, flags, mid


def chain(parts):
    return b''.join(struct.pack('>BBH', parts[n + 1][0] if n + 1 < len(parts) else 0,
                               0, 4 + len(body)) + body
                    for n, (_, body) in enumerate(parts))


def payloads(first, data):
    if len(data) > MAX_PLAINTEXT:
        raise ValueError('IKE payload chain exceeds limit')
    out, offset = [], 0
    while first:
        if offset + 4 > len(data) or len(out) >= 64:
            raise ValueError('Truncated or excessive IKE payload chain')
        nxt, flags, length = struct.unpack_from('>BBH', data, offset)
        if length < 4 or offset + length > len(data):
            raise ValueError('Invalid IKE payload length')
        out.append((first, flags, data[offset + 4:offset + length]))
        offset += length
        first = nxt
    if offset != len(data):
        raise ValueError('Trailing IKE payload data')
    return out


def notify(kind, data=b'', protocol=0):
    return struct.pack('>BBH', protocol, 0, kind) + data


def notifications(parts):
    result = {}
    for kind, flags, body in parts:
        if kind != 41:
            if flags & 0x80:
                raise ValueError('Unsupported critical IKE payload')
            continue
        if len(body) < 4 or body[1] or body[0] not in (0, 1, 3):
            raise ValueError('Invalid IKE notification')
        code = struct.unpack_from('>H', body, 2)[0]
        if code < 0x4000:
            raise ValueError(f'Watch rejected exchange: notify 0x{code:04x}')
        if code in result:
            raise ValueError('Duplicate IKE notification')
        result[code] = body[4:]
    return result


def unique(parts, kind):
    values = [body for tag, _, body in parts if tag == kind]
    if len(values) != 1:
        raise ValueError(f'Expected one IKE payload of type {kind}')
    return values[0]


class Protected:
    def __init__(self, spi_i, spi_r, keys, local_initiator=True):
        self.spi_i, self.spi_r, self.keys = spi_i, spi_r, keys
        self.local_initiator = local_initiator
        self.iv = secrets.randbits(64)
        self.fragments = {}

    def seal(self, exchange, mid, first, plaintext, response=False, max_packet=1280):
        if len(plaintext) > MAX_PLAINTEXT:
            raise ValueError('Encrypted IKE plaintext exceeds limit')
        flags = (8 if self.local_initiator else 0) | (32 if response else 0)
        key = self.keys.sk_ei if self.local_initiator else self.keys.sk_er
        fragmented = len(plaintext) + 57 > max_packet
        size = max_packet - 61 if fragmented else max_packet - 57
        if size <= 0:
            raise ValueError('Invalid IKE packet ceiling')
        chunks = [plaintext[n:n + size] for n in range(0, len(plaintext), size)] or [b'']
        packets = []
        for n, chunk in enumerate(chunks, 1):
            protected_kind = 53 if fragmented else 46
            extra = struct.pack('>HH', n, len(chunks)) if fragmented else b''
            generic = struct.pack('>BBH', first if n == 1 else 0, 0, 29 + len(extra) + len(chunk))
            aad = header(self.spi_i, self.spi_r, protected_kind, exchange, flags, mid,
                         28 + len(generic) + len(extra) + 25 + len(chunk)) + generic + extra
            self.iv += 1
            if self.iv >= 1 << 64:
                raise ValueError('IKE IV counter exhausted')
            iv = self.iv.to_bytes(8, 'big')
            packets.append(aad + iv + AESGCM(key[:32]).encrypt(key[32:] + iv, chunk + b'\0', aad))
        return packets

    def open(self, packet, exchange, mid, response=True):
        spi_i, spi_r, first, ex, flags, message = read_header(packet)
        wanted_flags = (0 if self.local_initiator else 8) | (32 if response else 0)
        if (spi_i, spi_r, ex, flags, message) != (self.spi_i, self.spi_r, exchange, wanted_flags, mid):
            raise ValueError('IKE response SPI, direction, exchange or message ID mismatch')
        if first not in (46, 53) or len(packet) < (61 if first == 53 else 57):
            raise ValueError('Expected an encrypted IKE payload')
        inner, payload_flags, length = struct.unpack_from('>BBH', packet, 28)
        if length != len(packet) - 28 or payload_flags & 0x7f:
            raise ValueError('Malformed encrypted IKE payload')
        split = 36 if first == 53 else 32
        key = self.keys.sk_er if self.local_initiator else self.keys.sk_ei
        plain = decrypt_sk_payload(key, packet[split:], packet[:split])
        if first == 46:
            return inner, plain
        number, count = struct.unpack_from('>HH', packet, 32)
        if not 1 <= number <= count <= 32 or (number != 1 and inner):
            raise ValueError('Invalid IKE encrypted-fragment numbering')
        slot = self.fragments.setdefault((ex, flags, message), {'count': count, 'parts': {}})
        if slot['count'] != count:
            raise ValueError('Changed IKE encrypted-fragment count')
        item = (inner, plain)
        if number in slot['parts'] and slot['parts'][number] != item:
            raise ValueError('Conflicting duplicate IKE encrypted fragment')
        slot['parts'][number] = item
        if sum(len(value[1]) for value in slot['parts'].values()) > MAX_PLAINTEXT:
            raise ValueError('IKE reassembly exceeds limit')
        if len(slot['parts']) != count:
            return None
        del self.fragments[(ex, flags, message)]
        return slot['parts'][1][0], b''.join(slot['parts'][n][1] for n in range(1, count + 1))
