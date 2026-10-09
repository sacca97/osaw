"""Control SA, PIN selection, SPAKE2+/PPK authentication and private notifies.

All transport is supplied by a link with request(packets, accept) and send(packet).
Session keys and decrypted bodies are never passed to the event logger.
"""

from dataclasses import replace
import hmac
import struct

from cryptography.hazmat.primitives.asymmetric import x448, mlkem

from ike_keys import derive_sa_init_keys, extend_with_additional_ke, prf
from ike_intermediate import build_ke_payload
from ike_sa_init import SaInitMessage
from ike_wire import Protected, chain, header, notifications, notify, payloads, read_header, unique
from pairing_crypto import CONTROL_ID, IDI, PIN_ID, SpakeProver, derive_pin


def tlvs(data):
    result, offset = {}, 0
    while offset < len(data):
        if offset + 3 > len(data):
            raise ValueError('Truncated NRTLV header')
        kind, length = struct.unpack_from('>BH', data, offset)
        offset += 3
        if offset + length > len(data) or kind in result:
            raise ValueError('Invalid or duplicate NRTLV')
        result[kind] = data[offset:offset + length]
        offset += length
    return result


def encode_tlvs(values):
    return b''.join(struct.pack('>BH', key, len(value)) + value for key, value in values.items())


def selected_profile(body, kem=37):
    if len(body) < 8 or body[:2] != b'\0\0' or struct.unpack_from('>H', body, 2)[0] != len(body):
        raise ValueError('Invalid selected SA proposal')
    if body[4:8] != b'\x01\x01\0\x04':
        raise ValueError('Unexpected IKE proposal or transform count')
    found, offset = set(), 8
    for n in range(4):
        if offset + 8 > len(body):
            raise ValueError('Truncated IKE transform')
        nxt, reserved, size, kind, reserved2, number = struct.unpack_from('>BBHBBH', body, offset)
        if size < 8 or offset + size > len(body) or reserved or reserved2 or nxt != (3 if n < 3 else 0):
            raise ValueError('Invalid IKE transform')
        transform = kind, number, body[offset + 8:offset + size]
        if transform in found:
            raise ValueError('Duplicate selected IKE transform')
        found.add(transform)
        offset += size
    if offset != len(body) or found != {(1, 20, b'\x80\x0e\x01\0'), (2, 7, b''), (6, kem, b''), (4, 32, b'')}:
        raise ValueError('Watch selected an unsupported IKE profile')


class IkeSession:
    def __init__(self, link, record, pairing=False, ordinary=False):
        self.link, self.record, self.pairing = link, record, pairing
        self.ordinary = ordinary
        self.kem = 36 if ordinary else 37
        self.initial, self.private = SaInitMessage.fresh('0.0.0.0', '0.0.0.0')
        self.initial_wire = self.initial.build(pairing=pairing, bluetooth=True, ordinary=ordinary)
        self.peer_wire = self.peer_nonce = self.spi_r = self.keys = self.protected = None

    async def establish(self):
        previous_session_reported = False
        def accept_sa(packet):
            nonlocal previous_session_reported
            spi_i, spi_r, first, exchange, flags, mid = read_header(packet)
            if spi_i != self.initial.initiator_spi:
                if not previous_session_reported:
                    self.record('ike_other_session_message', exchange=exchange, message=mid)
                    previous_session_reported = True
                return None
            if exchange != 34 or flags != 32 or mid != 0 or not any(spi_r):
                raise ValueError('Unexpected SA_INIT response header')
            parts = payloads(first, packet[28:])
            selected_profile(unique(parts, 33), self.kem)
            ke, nonce = unique(parts, 34), unique(parts, 40)
            if len(ke) != 60 or ke[:4] != b'\0\x20\0\0' or len(nonce) != 32:
                raise ValueError('Invalid X448 key or nonce')
            offered = notifications(parts)
            if 0x4036 not in offered or (not self.ordinary and 0x4022 not in offered):
                raise ValueError('Watch did not accept childless/intermediate IKE')
            if self.ordinary and offered.get(0x402f) != b'\0\x05':
                raise ValueError('Watch did not accept Ed25519 signatures')
            if self.pairing and (offered.get(0x4028) != b'\x2a\xf9' or offered.get(0x4033) != b''):
                raise ValueError('Watch did not accept SPAKE2+ and mandatory PPK')
            return spi_r, ke[4:], nonce, packet

        self.spi_r, public, self.peer_nonce, self.peer_wire = await self.link.request([self.initial_wire], accept_sa)
        shared = self.private.exchange(x448.X448PublicKey.from_public_bytes(public))
        self.private = None
        self.keys = derive_sa_init_keys(shared, self.initial.nonce, self.peer_nonce,
                                        self.initial.initiator_spi, self.spi_r)
        self.protected = Protected(self.initial.initiator_spi, self.spi_r, self.keys)
        self.record('ike_sa_init_accepted', pairing=self.pairing)
        kem_type = mlkem.MLKEM768PrivateKey if self.ordinary else mlkem.MLKEM1024PrivateKey
        kem_private = kem_type.generate()
        public = kem_private.public_key().public_bytes_raw()
        plain = build_ke_payload(self.kem, public)
        self.int_i = self.intermediate_auth(plain, 34, False)
        first, response = await self.exchange(43, 1, 34, plain)
        parts = payloads(first, response)
        if len(parts) != 1 or parts[0][:2] != (34, 0):
            raise ValueError('Unexpected ML-KEM response chain')
        ke = parts[0][2]
        if len(ke) != (1092 if self.ordinary else 1572) or ke[:4] != struct.pack('>HH', self.kem, 0):
            raise ValueError('Invalid ML-KEM response')
        self.int_r = self.intermediate_auth(response, first, True)
        shared = kem_private.decapsulate(ke[4:])
        self.keys = extend_with_additional_ke(self.keys, shared, self.initial.nonce,
                                              self.peer_nonce, self.initial.initiator_spi, self.spi_r)
        self.protected.keys = self.keys
        self.record('ike_hybrid_keys_derived', pairing=self.pairing)

    def intermediate_auth(self, plain, first, responder):
        canonical = header(self.initial.initiator_spi, self.spi_r, 46, 43,
                           32 if responder else 8, 1, len(plain) + 32)
        canonical += struct.pack('>BBH', first, 0, len(plain) + 4) + plain
        return prf(self.keys.sk_pr if responder else self.keys.sk_pi, canonical)

    async def exchange(self, ex, mid, first, plain):
        packets = self.protected.seal(ex, mid, first, plain)
        def accept(packet):
            spi_i, spi_r, _, exchange, flags, message = read_header(packet)
            if spi_i != self.initial.initiator_spi:
                return None
            if flags == 32 and message < mid:
                return None  # retransmission of an already accepted exchange
            return self.protected.open(packet, ex, mid)
        return await self.link.request(packets, accept)

    def signed_octets(self, idi, responder=False):
        return ((self.peer_wire if responder else self.initial_wire)
                + (self.initial.nonce if responder else self.peer_nonce)
                + prf(self.keys.sk_pr if responder else self.keys.sk_pi, idi)
                + self.int_i + self.int_r + struct.pack('>I', 2))

    async def control_authenticate(self):
        auth = prf(prf(self.keys.sk_pi, b'Key Pad for IKEv2'), self.signed_octets(IDI))
        plain = chain([(35, IDI), (41, notify(0x4000)), (36, CONTROL_ID), (39, b'\x0d\0\0\0' + auth)])
        first, response = await self.exchange(35, 2, 35, plain)
        parts = payloads(first, response)
        notifications(parts)
        if unique(parts, 36) != CONTROL_ID:
            raise ValueError('Incorrect control-session responder identity')
        expected = prf(prf(self.keys.sk_pr, b'Key Pad for IKEv2'), self.signed_octets(CONTROL_ID, True))
        if not hmac.compare_digest(unique(parts, 39), b'\x0d\0\0\0' + expected):
            raise ValueError('Control-session NULL AUTH failed')
        self.record('control_session_established', peer_identity_authenticated=False)

    async def private_exchange(self, code, data, mid, batch=None):
        parts = [(41, notify(tag, value)) for tag, value in batch.items()] if batch else [(41, notify(code, data))]
        packets = self.protected.seal(37, mid, 41, chain(parts))
        def accept(packet):
            spi_i, spi_r, _, exchange, flags, message = read_header(packet)
            if spi_i != self.initial.initiator_spi:
                return None
            if exchange != 37 or flags not in (0, 32) or (flags == 32 and message != mid):
                return None
            opened = self.protected.open(packet, 37, message, response=flags == 32)
            if opened is None:
                return None
            first, plain = opened
            if first == 0 and not plain and flags == 32:
                return None
            notes = notifications(payloads(first, plain))
            if flags == 0:
                # Send this only after the caller validates/persists private material.
                return notes, message
            return notes, None
        return await self.link.request(packets, accept)

    async def acknowledge(self, peer_mid):
        if peer_mid is not None:
            for packet in self.protected.seal(37, peer_mid, 0, b'', response=True):
                await self.link.send(packet)

    async def request_pin_salt(self):
        notes, peer_mid = await self.private_exchange(0xc545, encode_tlvs({1: b'\x02'}), 3)
        if 0xc546 not in notes:
            raise ValueError('Watch did not supply an auth-method response')
        values = tlvs(notes[0xc546])
        if values.get(1) != b'\x02' or not 32 <= len(values.get(2, b'')) <= 1024:
            raise ValueError('Watch did not supply a valid PIN salt')
        await self.acknowledge(peer_mid)
        self.record('pin_salt_received', length=len(values[2]))
        return values[2]

    async def pin_authenticate(self, pin, salt, setup_data):
        seed, ppk = derive_pin(pin, salt, setup_data)
        self.keys = replace(self.keys, sk_d=prf(ppk, self.keys.sk_d + b'\x01'),
                            sk_pi=prf(ppk, self.keys.sk_pi + b'\x01'), sk_pr=prf(ppk, self.keys.sk_pr + b'\x01'))
        self.protected.keys = self.keys
        prover = SpakeProver(seed, self.initial.nonce + self.peer_nonce,
                             self.initial.initiator_spi + self.spi_r)
        try:
            plain = chain([(35, IDI), (41, notify(0x4000)), (36, PIN_ID),
                           (49, prover.share), (41, notify(0x4034, b'\x01'))])
            first, response = await self.exchange(35, 2, 35, plain)
            parts = payloads(first, response)
            notifications(parts)
            if unique(parts, 36) != PIN_ID:
                raise ValueError('Incorrect PIN responder identity')
            watch_share = unique(parts, 49)
            tag = prover.accept_share(watch_share)
            first, response = await self.exchange(35, 3, 49, chain([(49, tag)]))
            parts = payloads(first, response)
            if len(parts) != 1 or parts[0][:2] != (49, 0):
                raise ValueError('Invalid SPAKE2+ confirmation chain')
            shared_key = prover.finish(parts[0][2])
            auth = prf(shared_key, self.signed_octets(IDI) + prf(self.keys.sk_pi, prover.share + watch_share))
            first, response = await self.exchange(35, 4, 39,
                chain([(39, b'\x0c\0\0\0' + auth), (41, notify(0x4034, b'\x01'))]))
            parts = payloads(first, response)
            notes = notifications(parts)
            if 0x4034 not in notes or notes[0x4034] not in (b'', b'\x01'):
                raise ValueError('Watch omitted mandatory PPK identity')
            expected = prf(shared_key, self.signed_octets(PIN_ID, True) + prf(self.keys.sk_pr, watch_share + prover.share))
            if not hmac.compare_digest(unique(parts, 39), b'\x0c\0\0\0' + expected):
                raise ValueError('Watch PIN-session AUTH failed')
            self.record('pin_authenticated', authenticated=True)
            return self
        finally:
            prover.destroy()
