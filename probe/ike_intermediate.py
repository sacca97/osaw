"""IKE_INTERMEDIATE message builder/parser carrying the ML-KEM-1024
additional key exchange, per RFC 9370 Section 2.2.2 and the observed wire
profile.

Per RFC 9370 2.2.2: "The former 'Diffie-Hellman Group Num' (now called 'Key
Exchange Method') field in the KEi(n) and KEr(n) payloads MUST match the n-th
negotiated additional key exchange." For this watch's single-additional-KE
proposal that is transform ID 37 (ML-KEM-1024; see the SA proposal in
ike_sa_init.py). This module builds that KE(n) payload and wraps it in the
standard SK (Encrypted and Authenticated) payload using ike_keys.py.

Scope: builds/parses the plaintext-before-encryption KE(1) payload and the
SK wrapper. Does not open a socket or speak Magnet/NRLP. Not yet validated
against real hardware traffic -- there is no decrypted capture to check it
against; validated here only by internal self-consistency (see
tests/test_ike_intermediate.py).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import mlkem

from ike_keys import IkeSaInitKeys, decrypt_sk_payload, encrypt_sk_payload

PAYLOAD_NONE = 0
PAYLOAD_KE = 34
EXCHANGE_IKE_INTERMEDIATE = 43

# Transform ID for ML-KEM-1024 as the additional key exchange, observed in
# the reference phone's SA_INIT proposal (transform type 6, id 37).
ADDITIONAL_KE_METHOD_ML_KEM_1024 = 37


def _payload_header(next_payload: int, body: bytes) -> bytes:
    return struct.pack(">BBH", next_payload, 0, 4 + len(body))


def build_ke_payload(method_id: int, key_exchange_data: bytes) -> bytes:
    """A KE payload per RFC 7296 3.4, with the repurposed group-number field
    (RFC 9370 2.2.2) holding the additional-KE method/transform ID instead of
    a Diffie-Hellman group number."""
    body = struct.pack(">HH", method_id, 0) + key_exchange_data
    return _payload_header(PAYLOAD_NONE, body) + body


def parse_ke_payload(data: bytes) -> tuple[int, bytes]:
    method_id = struct.unpack(">H", data[4:6])[0]
    plen = struct.unpack(">H", data[2:4])[0]
    key_exchange_data = data[8:plen]
    return method_id, key_exchange_data


def build_sk_wrapped_intermediate(
    spi_i: bytes,
    spi_r: bytes,
    message_id: int,
    is_initiator: bool,
    ke_payload: bytes,
    keys: IkeSaInitKeys,
) -> bytes:
    """Wrap a KE(n) payload in an SK payload inside an IKE_INTERMEDIATE
    message. Uses SK_ei (initiator->responder) or SK_er, matching the
    direction this message travels, per RFC 7296 2.14."""
    sk_key = keys.sk_ei if is_initiator else keys.sk_er
    flags = 0x08 if is_initiator else 0x00
    plaintext = ke_payload  # the KE(n) payload is the SK payload's plaintext

    # AES-GCM sizing is deterministic (IV(8) + plaintext + 1-byte Pad Length
    # + ICV(16); see ike_keys.encrypt_sk_payload's docstring for the Pad
    # Length field), so the final header length is known before encrypting --
    # build the real on-wire header/SK-generic-header once and use them
    # directly as AAD (RFC 5282 5.1: AAD is the unencrypted IKE header,
    # length included).
    sk_body_len = 8 + len(plaintext) + 1 + 16  # IV + ciphertext + pad-length byte + ICV
    total_len = 28 + 4 + sk_body_len  # IKE header + SK generic header + SK body
    header = struct.pack(
        ">8s8sBBBBII",
        spi_i, spi_r, 46, 0x20, EXCHANGE_IKE_INTERMEDIATE, flags, message_id, total_len,
    )
    sk_generic_hdr = struct.pack(">BBH", PAYLOAD_KE, 0, 4 + sk_body_len)
    aad = header + sk_generic_hdr
    encrypted_body = encrypt_sk_payload(sk_key, plaintext, aad)
    assert len(encrypted_body) == sk_body_len
    return header + sk_generic_hdr + encrypted_body


def unwrap_sk_intermediate(wire: bytes, keys: IkeSaInitKeys, is_initiator_message: bool) -> bytes:
    """Inverse of build_sk_wrapped_intermediate: returns the decrypted inner
    payload bytes (here, a KE(n) payload)."""
    header = wire[:28]
    sk_generic_hdr = wire[28:32]
    sk_body = wire[32:]
    aad = header + sk_generic_hdr
    sk_key = keys.sk_ei if is_initiator_message else keys.sk_er
    return decrypt_sk_payload(sk_key, sk_body, aad)


@dataclass
class MlKem1024Round:
    """Helper bundling the ML-KEM-1024 half of an additional-KE round."""

    @staticmethod
    def initiator_generate() -> tuple[mlkem.MLKEM1024PrivateKey, bytes]:
        sk = mlkem.MLKEM1024PrivateKey.generate()
        return sk, sk.public_key().public_bytes_raw()

    @staticmethod
    def responder_encapsulate(initiator_pub_bytes: bytes) -> tuple[bytes, bytes]:
        """Returns (shared_secret, ciphertext_to_send_back)."""
        pk = mlkem.MLKEM1024PublicKey.from_public_bytes(initiator_pub_bytes)
        shared_secret, ciphertext = pk.encapsulate()
        return shared_secret, ciphertext

    @staticmethod
    def initiator_decapsulate(sk: mlkem.MLKEM1024PrivateKey, ciphertext: bytes) -> bytes:
        return sk.decapsulate(ciphertext)
