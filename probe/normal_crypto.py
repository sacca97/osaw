"""Encrypted identifiers (RFC 9180), Ed25519 ordinary IKE and Apple ESP-IIV."""
import asyncio
import hmac
import secrets
import struct
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ike_keys import prf_plus
from ike_wire import chain, notify, notifications, payloads, unique
from pairing_session import IkeSession
from pairing_store import class_c

TS = bytes.fromhex('02000000080000280000ffff' + '00' * 16 + 'ff' * 16 + '070000100000ffff00000000ffffffff')
CHILD_OFFER = bytes.fromhex('0300000c0100001e800e0100030000080100001f0000000805000000')
CHILD_SELECT = bytes.fromhex('0300000c0100001e800e01000000000805000000')
ED_AUTH = bytes.fromhex('0e00000007300506032b6570')


def extract(salt, value, suite, label, algorithm):
    return hmac.digest(salt, b'HPKE-v1' + suite + label + value, algorithm)


def expand(key, value, suite, label, size, algorithm):
    context = struct.pack('>H', size) + b'HPKE-v1' + suite + label + value
    out, block, n = b'', b'', 1
    while len(out) < size:
        block = hmac.digest(key, block + context + bytes([n]), algorithm)
        out += block
        n += 1
    return out[:size]


def hpke_schedule(dh, enc, recipient, nonces, spis):
    kem, suite = b'KEM\0\x20', b'HPKE\0\x20\0\x03\0\x02'
    eae = extract(b'', dh, kem, b'eae_prk', 'sha256')
    shared = expand(eae, enc + recipient, kem, b'shared_secret', 32, 'sha256')
    context = (b'\x01' + extract(b'', spis, suite, b'psk_id_hash', 'sha512')
               + extract(b'', b'Encrypted Identifier for IKEv2', suite, b'info_hash', 'sha512'))
    secret = extract(shared, nonces, suite, b'secret', 'sha512')
    return (expand(secret, context, suite, b'key', 32, 'sha512'),
            expand(secret, context, suite, b'base_nonce', 12, 'sha512'))


def seal_identifier(public, identity_uuid, service, nonces, spis):
    private = x25519.X25519PrivateKey.generate()
    enc = private.public_key().public_bytes_raw()
    key, nonce = hpke_schedule(private.exchange(x25519.X25519PublicKey.from_public_bytes(public)),
                              enc, public, nonces, spis)
    plain = b'\x01' + identity_uuid + secrets.token_bytes(79)
    return b'\x0b\0\0\0' + enc + AESGCM(key).encrypt(nonce, plain, service)


def open_identifier(private, identity_uuid, service, nonces, spis, encoded):
    if len(encoded) != 148 or encoded[:4] != b'\x0b\0\0\0':
        raise ValueError(f'Invalid encrypted IKE identifier: got {len(encoded)} bytes, '
                         f'ID type {encoded[0] if encoded else None}; expected 148 bytes, ID type 11')
    enc, ciphertext = encoded[4:36], encoded[36:]
    key, nonce = hpke_schedule(private.exchange(x25519.X25519PublicKey.from_public_bytes(enc)),
                              enc, private.public_key().public_bytes_raw(), nonces, spis)
    plain = AESGCM(key).decrypt(nonce, ciphertext, service)
    if len(plain) != 96 or not hmac.compare_digest(plain[:17], b'\x01' + identity_uuid):
        raise ValueError('Encrypted identifier names another pairing record')


class Esp:
    def __init__(self, keys, ni, nr, spi_i, spi_r):
        material = prf_plus(keys.sk_d, ni + nr, 72)
        self.tx_key, self.rx_key = material[:36], material[36:]
        self.tx_spi, self.rx_spi = spi_r, spi_i
        self.sequence = [0] * 4
        self.highest, self.seen = [0] * 4, [0] * 4

    def seal(self, ipv6):
        validate_ipv6(ipv6)
        dscp = ((ipv6[0] & 15) << 4 | ipv6[1] >> 4) >> 2
        tc = 1 if dscp == 8 else 2 if dscp in (26, 32, 34, 40) else 3 if dscp in (46, 48) else 0
        self.sequence[tc] += 1
        if self.sequence[tc] >= 1 << 30:
            raise RuntimeError('ESP sequence exhausted; reconnect to rekey')
        number = (tc << 30) | self.sequence[tc]
        aad = self.tx_spi + struct.pack('>I', number)
        plain = ipv6[40:]
        pad = -(len(plain) + 2) % 4
        plain += bytes(range(1, pad + 1)) + bytes([pad, ipv6[6]])
        nonce = self.tx_key[32:] + bytes(4) + struct.pack('>I', number)
        return ipv6[:4] + struct.pack('>HBB', len(plain) + 24, 50, ipv6[7]) + ipv6[8:40] + aad + AESGCM(self.tx_key[:32]).encrypt(nonce, plain, aad)

    def open(self, ipv6):
        validate_ipv6(ipv6)
        wire = ipv6[40:]
        if ipv6[6] != 50 or len(wire) < 26 or wire[:4] != self.rx_spi:
            raise ValueError('Invalid ESP SPI or packet length')
        number = struct.unpack_from('>I', wire, 4)[0]
        tc, seq = number >> 30, number & 0x3fffffff
        highest = self.highest[tc]
        distance = highest - seq
        if not seq or distance >= 16 or (distance >= 0 and self.seen[tc] >> distance & 1):
            return None  # replay: don't deliver, don't change window
        plain = AESGCM(self.rx_key[:32]).decrypt(self.rx_key[32:] + bytes(4) + wire[4:8], wire[8:], wire[:8])
        if len(plain) < 2 or plain[-2] + 2 > len(plain):
            raise ValueError('Invalid ESP padding length')
        pad, nxt = plain[-2:]
        # Arbitrary authenticated padding is accepted, including length
        # concealment. Only Pad Length bounds the payload after GCM verification.
        if seq > highest:
            self.seen[tc] = 1 if seq - highest >= 16 else ((self.seen[tc] << (seq - highest)) | 1) & 0xffff
            self.highest[tc] = seq
        else:
            self.seen[tc] |= 1 << distance
        payload = plain[:len(plain) - pad - 2]
        return ipv6[:4] + struct.pack('>HBB', len(payload), nxt, ipv6[7]) + ipv6[8:40] + payload


def validate_ipv6(packet):
    if len(packet) < 40 or packet[0] >> 4 != 6 or struct.unpack_from('>H', packet, 4)[0] != len(packet) - 40:
        raise ValueError('Invalid IPv6 packet')


class OrdinarySession(IkeSession):
    def __init__(self, link, record, store, lane, prelude, remote_prelude):
        super().__init__(link, record, ordinary=True)
        self.store, self.lane, self.prelude = store, lane, prelude
        self.remote_prelude = remote_prelude
        self.service = b'com.apple.networkrelay.companionlink.class' + lane.upper().encode()
        self.remote_unlocked = asyncio.Event()

    async def authenticate(self):
        peer = self.store.peer_notifies()
        nonces = self.initial.nonce + self.peer_nonce
        spis = self.initial.initiator_spi + self.spi_r
        idi = seal_identifier(peer[0xc4af][16:], peer[0xc4af][:16], self.service, nonces, spis)
        auth = ED_AUTH + self.store.sign(self.lane).sign(self.signed_octets(idi))
        spi_i = secrets.token_bytes(4)
        cfg = b'\x01\0\0\0' + struct.pack('>HH', 0x6566, 16) + bytes(16) + struct.pack('>HH', 0x6567, 16) + bytes(16)
        sa = struct.pack('>BBHBBBB', 0, 0, 40, 1, 3, 4, 3) + spi_i + CHILD_OFFER
        parts = [(35, idi), (41, notify(0x4000)), (36, b'\x0b\0\0\0' + self.service), (39, auth),
                 (47, cfg), *[(41, notify(code)) for code in (0x4007, 0x400a, 0x400b)],
                 (33, sa), (44, TS), (45, TS), (41, notify(0xc350))]
        first, response = await self.exchange(35, 2, 35, chain(parts))
        parts = payloads(first, response)
        notes = notifications(parts)
        idr = unique(parts, 36)
        self.record('ordinary_ike_identifier_received', lane=self.lane,
                    length=len(idr), id_type=idr[0] if idr else None,
                    key_id_header=idr[:4] == b'\x0b\0\0\0',
                    service_id=idr == b'\x0b\0\0\0' + self.service)
        # The responder identity is validated as a plain
        # service KEY_ID here; only the initiator's IDi is HPKE encrypted.
        if idr != b'\x0b\0\0\0' + self.service:
            raise ValueError('Ordinary responder IKE identifier does not match the requested service')
        auth = unique(parts, 39)
        if len(auth) != len(ED_AUTH) + 64 or auth[:len(ED_AUTH)] != ED_AUTH:
            raise ValueError('Invalid Ed25519 IKE AUTH algorithm')
        ed25519.Ed25519PublicKey.from_public_bytes(self.store.peer_keys(self.lane)[1]).verify(auth[len(ED_AUTH):], self.signed_octets(idr, True))
        selected = unique(parts, 33)
        if len(selected) != 32 or selected[:8] != bytes.fromhex('0000002001030402') or selected[12:] != CHILD_SELECT or not any(selected[8:12]):
            raise ValueError('Watch did not select ESP AES-GCM-256 implicit IV')
        if unique(parts, 44) != TS or unique(parts, 45) != TS or any(notes.get(code) != b'' for code in (0x4007, 0x400a, 0x400b, 0xc350)):
            raise ValueError('Unexpected ESP mode or traffic selectors')
        if notes.get(0xbdd9) != self.remote_prelude:
            raise ValueError('Ordinary AUTH metadata does not match the Watch prelude')
        cfg = unique(parts, 47)
        if len(cfg) != 44 or cfg[:4] != b'\x02\0\0\0' or cfg[4:8] != b'\x65\x66\0\x10' or cfg[24:28] != b'\x65\x67\0\x10':
            raise ValueError('Invalid inner address assignment')
        self.local_address, self.remote_address = cfg[8:24], cfg[28:44]
        d_local = self.local_address[:9] + b'\x0d' + self.local_address[10:]
        d_remote = self.remote_address[:9] + b'\x0d' + self.remote_address[10:]
        class_c(d_local)
        class_c(d_remote)
        if self.local_address == self.remote_address:
            raise ValueError('Inner endpoint addresses collide')
        self.esp = Esp(self.keys, self.initial.nonce, self.peer_nonce, spi_i, selected[8:12])
        if notes.get(0xbe3d) == b'\x80':
            self.remote_unlocked.set()
        # Authoritative assignment follows the elected role, not provisional addresses.
        self.store.save(addresses=[d_local.hex(), d_remote.hex()])
        self.record('normal_ike_authenticated', lane=self.lane)
        if self.lane == 'c':
            return
        metadata = {0xbdda: b'\0\x18', 0xbddb: b'iPhone', 0xbddc: b'23G71', 0xbdde: b'\x01',
                    0xbe3d: b'\x80', 0xbddd: bytes(8), 0xc8c9: b'\x01', 0xbdd9: self.prelude,
                    0xc671: d_local, 0xc672: d_remote, 0xc67b: class_c(d_local), 0xc67c: class_c(d_remote),
                    0xbddf: self.store.data['ids_id'].encode()}
        first, plain = await self.exchange(37, 3, 41, chain([(41, notify(code, value)) for code, value in metadata.items()]))
        if first or plain:
            raise ValueError('Expected empty authenticated metadata receipt')
        first, plain = await self.exchange(37, 4, 41, chain([(41, notify(0xbe3d, b'\x80'))]))
        if first or plain:
            raise ValueError('Expected empty Class-C unlock receipt')
