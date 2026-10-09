#!/usr/bin/env python3
"""Self-consistency oracle for probe/ike_keys.py. No watch contact: derives
IKE SA_INIT keys twice (as "initiator-side" and "responder-side" would, from
identical shared inputs) and checks every derived key matches, then checks
AES-GCM wrap/unwrap round-trips and that wrong keys/associated-data fail
closed. This validates the RFC 7296 2.14 implementation in isolation; it does
not confirm Apple's exact SK_d sizing convention against real traffic (there
is no way to check that without a decrypted capture or instrumented device).
"""
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ike_keys import (  # noqa: E402
    decrypt_sk_payload,
    derive_sa_init_keys,
    encrypt_sk_payload,
    extend_with_additional_ke,
)
from cryptography.hazmat.primitives.asymmetric import mlkem  # noqa: E402


def main():
    shared_secret = secrets.token_bytes(56)  # X448 ECDH output size
    ni, nr = secrets.token_bytes(32), secrets.token_bytes(32)
    spi_i, spi_r = secrets.token_bytes(8), secrets.token_bytes(8)

    keys_a = derive_sa_init_keys(shared_secret, ni, nr, spi_i, spi_r)
    keys_b = derive_sa_init_keys(shared_secret, ni, nr, spi_i, spi_r)

    same = (
        keys_a.sk_d == keys_b.sk_d
        and keys_a.sk_ei == keys_b.sk_ei
        and keys_a.sk_er == keys_b.sk_er
        and keys_a.sk_pi == keys_b.sk_pi
        and keys_a.sk_pr == keys_b.sk_pr
    )
    print("Two independent derivations from identical inputs match:", same)

    distinct = keys_a.sk_ei != keys_a.sk_er and keys_a.sk_pi != keys_a.sk_pr
    print("Initiator/responder keys are distinct from each other:", distinct)

    plaintext = b"IKE_AUTH identification payload, as a stand-in"
    aad = b"fake-ike-header-bytes"
    ct = encrypt_sk_payload(keys_a.sk_ei, plaintext, aad)
    pt_back = decrypt_sk_payload(keys_b.sk_ei, ct, aad)
    roundtrip_ok = pt_back == plaintext
    print("AES-GCM SK payload round-trips correctly:", roundtrip_ok)

    failed_closed = True
    try:
        decrypt_sk_payload(keys_a.sk_er, ct, aad)  # wrong key (er instead of ei)
        failed_closed = False
    except Exception:
        pass
    try:
        decrypt_sk_payload(keys_b.sk_ei, ct, b"tampered-aad")
        failed_closed = False
    except Exception:
        pass
    print("Wrong key / tampered AAD correctly rejected:", failed_closed)

    print("\n=== RFC 9370 additional-key-exchange update (ML-KEM-1024) ===")
    # Real ML-KEM-1024 encaps/decaps as the "n=1" additional key exchange,
    # done by each side independently (as the real initiator/responder
    # would), to get SK(1) -- then fold it into round-0 keys per RFC 9370.
    dk_sk = mlkem.MLKEM1024PrivateKey.generate()
    ek_bytes = dk_sk.public_key().public_bytes_raw()
    pk_initiator_side = mlkem.MLKEM1024PublicKey.from_public_bytes(ek_bytes)
    sk1_initiator, ct = pk_initiator_side.encapsulate()
    sk1_responder = dk_sk.decapsulate(ct)
    kem_agrees = sk1_initiator == sk1_responder
    print("ML-KEM-1024 encaps/decaps shared secret agrees:", kem_agrees)

    round1_a = extend_with_additional_ke(keys_a, sk1_initiator, ni, nr, spi_i, spi_r)
    round1_b = extend_with_additional_ke(keys_b, sk1_responder, ni, nr, spi_i, spi_r)
    round1_same = (
        round1_a.sk_d == round1_b.sk_d
        and round1_a.sk_ei == round1_b.sk_ei
        and round1_a.sk_pi == round1_b.sk_pi
    )
    print("Round-1 (post-ML-KEM) keys agree between both sides:", round1_same)
    round1_differs_from_round0 = round1_a.sk_ei != keys_a.sk_ei and round1_a.sk_d != keys_a.sk_d
    print("Round-1 keys differ from round-0 keys:", round1_differs_from_round0)

    # Chain a second additional-KE round to confirm the chaining logic (not
    # exercised by this watch's single-ML-KEM proposal, but part of the RFC
    # mechanism and worth checking generalizes correctly).
    fake_sk2 = secrets.token_bytes(32)
    round2_a = extend_with_additional_ke(round1_a, fake_sk2, ni, nr, spi_i, spi_r)
    round2_b = extend_with_additional_ke(round1_b, fake_sk2, ni, nr, spi_i, spi_r)
    round2_same = round2_a.sk_d == round2_b.sk_d and round2_a.sk_ei == round2_b.sk_ei
    print("Chained round-2 keys agree between both sides:", round2_same)

    rfc9370_ok = kem_agrees and round1_same and round1_differs_from_round0 and round2_same

    ok = same and distinct and roundtrip_ok and failed_closed and rfc9370_ok
    print("\nOVERALL:", "CONSISTENT" if ok else "INCONSISTENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
