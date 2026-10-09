"""Standard IKEv2 SA_INIT key derivation and SK-payload (en/de)cryption.

This module implements only standard, publicly specified IKEv2 mechanics --
RFC 7296 Section 2.14 (SKEYSEED / prf+ keying material), RFC 9370 Section
2.2.2 (updating SKEYSEED for each additional key exchange, e.g. the
ML-KEM-1024 round), and the AES-GCM Encrypted payload format (RFC 7296 3.14 +
RFC 5282) -- using the PRF and cipher confirmed on the wire for this watch
(PRF_HMAC_SHA2_512, ENCR_AES_GCM_16 with a 256-bit key; see
the author's analysis). None of this is Apple-private.

The RFC 9370 formula was fetched and read directly from
https://www.rfc-editor.org/rfc/rfc9370.txt (Section 2.2.2) rather than
implemented from memory, specifically because a first attempt to recall it
was wrong in a way that would have silently produced incorrect keys:

    SKEYSEED(n) = prf(SK_d(n-1), SK(n) | Ni | Nr)
    {SK_d(n) | SK_ai(n) | SK_ar(n) | SK_ei(n) | SK_er(n) | SK_pi(n) |
     SK_pr(n)} = prf+(SKEYSEED(n), Ni | Nr | SPIi | SPIr)

where SK(n) is the n-th additional key exchange's shared secret (here, the
ML-KEM-1024 shared secret) and SK_d(n-1) is the previous round's SK_d (round
0 being the base IKE_SA_INIT derivation below). The RFC text also
independently corroborates a static-analysis finding: "The former 'Diffie-Hellman Group Num' ... field in
the KEi(n) and KEr(n) payloads MUST match the n-th negotiated additional key
exchange" -- i.e. the KE payload's group-number field is repurposed to carry
the Key Exchange Method transform ID (37 for ML-KEM-1024), exactly as
inferred from `-[NEIKEv2IntermediatePacket filloutPayloads]`.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PRF_HASH = hashlib.sha512  # PRF_HMAC_SHA2_512, as negotiated on the wire
PRF_OUTPUT_LEN = 64  # SHA-512 digest size; also this PRF's fixed round size
ENCR_KEY_LEN = 32  # ENCR_AES_GCM_16, 256-bit key (observed Key Length attr)
INTEG_KEY_LEN = 0  # AEAD ciphers fold integrity into the cipher; no SK_a
SALT_LEN = 4  # RFC 5282: 4-byte salt per direction, prepended to the IV
ICV_LEN = 16  # AES-GCM with a 16-octet ICV, per the negotiated transform


def prf(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, PRF_HASH).digest()


def prf_plus(key: bytes, seed: bytes, length: int) -> bytes:
    """RFC 7296 2.13: T1 = prf(key, seed | 0x01); Tn = prf(key, T(n-1) | seed | n)."""
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = prf(key, t + seed + bytes([counter]))
        out += t
        counter += 1
    return out[:length]


@dataclass
class IkeSaInitKeys:
    sk_d: bytes
    sk_ai: bytes
    sk_ar: bytes
    sk_ei: bytes
    sk_er: bytes
    sk_pi: bytes
    sk_pr: bytes


def derive_sa_init_keys(
    shared_secret: bytes,
    ni: bytes,
    nr: bytes,
    spi_i: bytes,
    spi_r: bytes,
) -> IkeSaInitKeys:
    """RFC 7296 Section 2.14, for an AEAD cipher (so SK_a* are zero-length
    per RFC 5282 Section 5.2 -- an AEAD transform provides no separate
    integrity key, the AEAD tag covers that).

        SKEYSEED = prf(Ni | Nr, g^ir)
        {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
            = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
    """
    if len(spi_i) != 8 or len(spi_r) != 8:
        raise ValueError("SPIs must be 8 bytes each")
    skeyseed = prf(ni + nr, shared_secret)
    total_len = (
        PRF_OUTPUT_LEN  # SK_d (sized to the PRF's preferred key length; using
        # the PRF output length here, matching common practice for
        # PRF_HMAC_SHA2_512 used as its own key-derivation function)
        + 2 * INTEG_KEY_LEN
        + 2 * (ENCR_KEY_LEN + SALT_LEN)
        + 2 * PRF_OUTPUT_LEN
    )
    keymat = prf_plus(skeyseed, ni + nr + spi_i + spi_r, total_len)

    off = 0

    def take(n):
        nonlocal off
        v = keymat[off : off + n]
        off += n
        return v

    sk_d = take(PRF_OUTPUT_LEN)
    sk_ai = take(INTEG_KEY_LEN)
    sk_ar = take(INTEG_KEY_LEN)
    sk_ei = take(ENCR_KEY_LEN + SALT_LEN)
    sk_er = take(ENCR_KEY_LEN + SALT_LEN)
    sk_pi = take(PRF_OUTPUT_LEN)
    sk_pr = take(PRF_OUTPUT_LEN)
    assert off == total_len
    return IkeSaInitKeys(sk_d, sk_ai, sk_ar, sk_ei, sk_er, sk_pi, sk_pr)


def extend_with_additional_ke(
    prev_keys: IkeSaInitKeys,
    additional_shared_secret: bytes,
    ni: bytes,
    nr: bytes,
    spi_i: bytes,
    spi_r: bytes,
) -> IkeSaInitKeys:
    """RFC 9370 Section 2.2.2: fold one additional key exchange's shared
    secret (SK(n), e.g. the ML-KEM-1024 shared secret) into updated keying
    material, using the previous round's SK_d as the PRF key:

        SKEYSEED(n) = prf(SK_d(n-1), SK(n) | Ni | Nr)
        {SK_d(n) | ... | SK_pr(n)} = prf+(SKEYSEED(n), Ni | Nr | SPIi | SPIr)

    Call once per additional key exchange, in order, chaining each call's
    result into the next (round 0 is `derive_sa_init_keys`'s output). Ni/Nr/
    SPIi/SPIr stay the ones from the original IKE_SA_INIT throughout.
    """
    skeyseed_n = prf(prev_keys.sk_d, additional_shared_secret + ni + nr)
    total_len = PRF_OUTPUT_LEN + 2 * INTEG_KEY_LEN + 2 * (ENCR_KEY_LEN + SALT_LEN) + 2 * PRF_OUTPUT_LEN
    keymat = prf_plus(skeyseed_n, ni + nr + spi_i + spi_r, total_len)

    off = 0

    def take(n):
        nonlocal off
        v = keymat[off : off + n]
        off += n
        return v

    sk_d = take(PRF_OUTPUT_LEN)
    sk_ai = take(INTEG_KEY_LEN)
    sk_ar = take(INTEG_KEY_LEN)
    sk_ei = take(ENCR_KEY_LEN + SALT_LEN)
    sk_er = take(ENCR_KEY_LEN + SALT_LEN)
    sk_pi = take(PRF_OUTPUT_LEN)
    sk_pr = take(PRF_OUTPUT_LEN)
    assert off == total_len
    return IkeSaInitKeys(sk_d, sk_ai, sk_ar, sk_ei, sk_er, sk_pi, sk_pr)


def encrypt_sk_payload(sk_e_and_salt: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    """RFC 5282: AEAD Encrypted payload body = IV(8) | ciphertext | ICV(16).
    `sk_e_and_salt` is SK_ei or SK_er (key || 4-byte salt). The nonce is the
    4-byte salt concatenated with an 8-byte explicit IV.

    Per RFC 5282 Section 3 ("Payloads to be encrypted with the Padding (if
    any) and the Pad Length"), the data actually covered by the AEAD cipher
    is the caller's plaintext plus a trailing 1-byte Pad Length field (with
    no padding, that byte is 0x00) -- not the caller's plaintext alone. A
    first draft of this function omitted that byte; the gap was caught by
    comparing a built message's total length (1632) against the real
    reference capture's IKE_INTERMEDIATE length (1633, frame 3 of a
    private capture) -- a 1-byte discrepancy that pointed
    straight at this field once checked against the RFC text."""
    key, salt = sk_e_and_salt[:ENCR_KEY_LEN], sk_e_and_salt[ENCR_KEY_LEN:]
    iv = os.urandom(8)
    nonce = salt + iv
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext + b"\x00", associated_data)
    return iv + ct_and_tag  # ct_and_tag already ends with the 16-byte ICV


def decrypt_sk_payload(sk_e_and_salt: bytes, body: bytes, associated_data: bytes) -> bytes:
    key, salt = sk_e_and_salt[:ENCR_KEY_LEN], sk_e_and_salt[ENCR_KEY_LEN:]
    iv, ct_and_tag = body[:8], body[8:]
    nonce = salt + iv
    aesgcm = AESGCM(key)
    padded = aesgcm.decrypt(nonce, ct_and_tag, associated_data)
    if not padded:
        raise ValueError("Encrypted payload has no pad-length byte")
    pad_length = padded[-1]
    if pad_length >= len(padded):
        raise ValueError("Encrypted payload padding exceeds plaintext")
    return padded[: len(padded) - 1 - pad_length]
