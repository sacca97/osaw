"""Apple salted-PIN / SPAKE2+ profile, using native P-256 arithmetic.

Protocol notes: see docs/protocol-overview.md.
"""

import hashlib
import hmac
import secrets
import struct

from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ORDER = int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 16)
IDI = b'\x0d\0\0\0'
CONTROL_ID = b'\x0b\0\0\0com.apple.networkrelay.companionlink.pairing.control'
PIN_ID = b'\x0b\0\0\0com.apple.networkrelay.companionlink.pairing.auth.saltedPin'
M = ECC.import_key(bytes.fromhex('02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f'), curve_name='P-256').pointQ
N = ECC.import_key(bytes.fromhex('03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49'), curve_name='P-256').pointQ
G = ECC.construct(curve='P-256', d=1).pointQ


def hkdf(ikm, salt, info, length, sha512=False):
    return HKDF(algorithm=hashes.SHA512() if sha512 else hashes.SHA256(),
                length=length, salt=salt, info=info).derive(ikm)


def derive_pin(pin, salt, setup_data):
    if not isinstance(pin, str) or len(pin) != 6 or any(c not in '0123456789' for c in pin):
        raise ValueError('PIN must contain six decimal digits')
    if len(salt) < 32 or len(salt) > 1024 or len(setup_data) != 12:
        raise ValueError('Invalid PIN salt or setup advertisement')
    pin_key = hashlib.pbkdf2_hmac('sha256', struct.pack('>I', int(pin)), salt, 1600000, 32)
    seed = pin_key + setup_data
    return seed, hkdf(seed, salt, b'Derived IKEv2 PPK for terminus device pairing', 64, True)


def point_bytes(point):
    if point.is_point_at_infinity():
        raise ValueError('SPAKE2+ point is the identity')
    return b'\x04' + int(point.x).to_bytes(32, 'big') + int(point.y).to_bytes(32, 'big')


class SpakeProver:
    def __init__(self, seed, nonces, spis, idi=IDI, idr=PIN_ID):
        expanded = hkdf(seed, nonces, b'SPAKE2+ Authentication for IKEv2', 80)
        self.w0, self.w1 = ((int.from_bytes(expanded[n:n + 40], 'big') % (ORDER - 1)) + 1
                            for n in (0, 40))
        self.ephemeral = secrets.randbelow(ORDER - 1) + 1
        self.share = point_bytes(G * self.ephemeral + M * self.w0)
        self.context, self.idi, self.idr = spis, idi, idr
        self.expected_tag = self.shared_key = None
        self.destroyed = False

    def accept_share(self, encoded):
        if self.destroyed or self.expected_tag is not None or len(encoded) != 65 or encoded[0] != 4:
            raise ValueError('Invalid or repeated SPAKE2+ share')
        peer = ECC.import_key(encoded, curve_name='P-256').pointQ
        adjusted = peer + -(N * self.w0)
        z = point_bytes(adjusted * self.ephemeral)
        v = point_bytes(adjusted * self.w1)
        fields = (self.context, self.idi, self.idr, point_bytes(M), point_bytes(N),
                  self.share, encoded, z, v, self.w0.to_bytes(32, 'big'))
        transcript = b''.join(struct.pack('<Q', len(value)) + value for value in fields)
        main = hashlib.sha256(transcript).digest()
        confirmation = hkdf(main, b'', b'ConfirmationKeys', 64)
        self.expected_tag = hmac.digest(confirmation[32:], self.share, 'sha256')
        self.shared_key = hkdf(main, b'', b'SharedKey', 32)
        return hmac.digest(confirmation[:32], encoded, 'sha256')

    def finish(self, confirmation):
        try:
            if self.expected_tag is None or not hmac.compare_digest(self.expected_tag, confirmation):
                raise ValueError('Watch SPAKE2+ confirmation failed')
            return self.shared_key
        finally:
            self.destroy()

    def destroy(self):
        self.destroyed = True
        self.w0 = self.w1 = self.ephemeral = 0
        self.expected_tag = self.shared_key = None
