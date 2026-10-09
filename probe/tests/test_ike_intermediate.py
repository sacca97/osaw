#!/usr/bin/env python3
"""Self-consistency test for probe/ike_intermediate.py. No watch contact.
Simulates one full IKE_INTERMEDIATE round carrying the ML-KEM-1024 additional
key exchange between two independently-acting sides, and checks:
  1. the KE(1) payload round-trips through build/parse correctly
  2. the SK wrapper round-trips through encrypt/decrypt correctly
  3. both sides' ML-KEM-1024 shared secrets agree
  4. both sides derive identical RFC 9370 round-1 keys from it
  5. the wrapped message is independently recognized by tshark as a valid
     Encrypted-and-Authenticated IKE_INTERMEDIATE message (structure only --
     tshark cannot decrypt it without the keys, nor should it need to)
"""
import secrets
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ike_intermediate import (  # noqa: E402
    ADDITIONAL_KE_METHOD_ML_KEM_1024,
    MlKem1024Round,
    build_ke_payload,
    build_sk_wrapped_intermediate,
    parse_ke_payload,
    unwrap_sk_intermediate,
)
from ike_keys import derive_sa_init_keys, extend_with_additional_ke  # noqa: E402


def wrap_udp_ip(payload: bytes, src="198.18.0.1", dst="198.18.0.2", sport=500, dport=500) -> bytes:
    def ip_to_bytes(s):
        return bytes(int(x) for x in s.split("."))

    udp_len = 8 + len(payload)
    udp = struct.pack(">HHHH", sport, dport, udp_len, 0) + payload
    total_len = 20 + udp_len
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_len, 1, 0, 64, 17, 0,
                      ip_to_bytes(src), ip_to_bytes(dst))
    return ip + udp


def write_pcap(packets, path):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for i, pkt in enumerate(packets):
            f.write(struct.pack("<IIII", 0, i, len(pkt), len(pkt)))
            f.write(pkt)


def main():
    spi_i, spi_r = secrets.token_bytes(8), secrets.token_bytes(8)
    ni, nr = secrets.token_bytes(32), secrets.token_bytes(32)
    ecdh_shared_secret = secrets.token_bytes(56)  # stand-in for the X448 result

    keys_i = derive_sa_init_keys(ecdh_shared_secret, ni, nr, spi_i, spi_r)
    keys_r = derive_sa_init_keys(ecdh_shared_secret, ni, nr, spi_i, spi_r)
    print("Round-0 keys agree between sides:", keys_i.sk_ei == keys_r.sk_ei)

    # --- Initiator builds KE(1) with a fresh ML-KEM-1024 keypair ---
    mlkem_sk, mlkem_pub = MlKem1024Round.initiator_generate()
    ke1_i = build_ke_payload(ADDITIONAL_KE_METHOD_ML_KEM_1024, mlkem_pub)
    method_check, data_check = parse_ke_payload(ke1_i)
    ke_roundtrip_ok = method_check == ADDITIONAL_KE_METHOD_ML_KEM_1024 and data_check == mlkem_pub
    print("KE(1) payload build/parse round-trips:", ke_roundtrip_ok)

    wire_i = build_sk_wrapped_intermediate(spi_i, spi_r, 1, True, ke1_i, keys_i)
    print(f"Built initiator IKE_INTERMEDIATE: {len(wire_i)} bytes")
    # The real reference phone's first IKE_INTERMEDIATE (frame 3 of a
    # private capture) has ISAKMP length 1633. Matching that
    # exactly is a meaningful independent check: it means the SK-payload
    # framing (IV + ciphertext + 1-byte Pad Length + 16-byte ICV, RFC 5282)
    # is byte-accurate, not just plausible-looking.
    size_matches_reference = len(wire_i) == 1633
    print("Matches real reference capture's IKE_INTERMEDIATE length (1633):", size_matches_reference)

    # --- Responder unwraps, encapsulates, replies ---
    decrypted_i = unwrap_sk_intermediate(wire_i, keys_r, is_initiator_message=True)
    sk_decrypt_ok = decrypted_i == ke1_i
    print("Responder decrypts initiator's KE(1) correctly:", sk_decrypt_ok)
    r_method, r_data = parse_ke_payload(decrypted_i)

    shared_secret_r, ciphertext = MlKem1024Round.responder_encapsulate(r_data)
    ke1_r = build_ke_payload(ADDITIONAL_KE_METHOD_ML_KEM_1024, ciphertext)
    wire_r = build_sk_wrapped_intermediate(spi_i, spi_r, 1, False, ke1_r, keys_r)

    # --- Initiator unwraps the response, decapsulates ---
    decrypted_r = unwrap_sk_intermediate(wire_r, keys_i, is_initiator_message=False)
    i_method, i_ct = parse_ke_payload(decrypted_r)
    shared_secret_i = MlKem1024Round.initiator_decapsulate(mlkem_sk, i_ct)

    kem_agrees = shared_secret_i == shared_secret_r
    print("Both sides' ML-KEM-1024 shared secrets agree:", kem_agrees)

    # --- Both fold SK(1) into round-1 keys per RFC 9370 ---
    round1_i = extend_with_additional_ke(keys_i, shared_secret_i, ni, nr, spi_i, spi_r)
    round1_r = extend_with_additional_ke(keys_r, shared_secret_r, ni, nr, spi_i, spi_r)
    round1_agrees = round1_i.sk_ei == round1_r.sk_ei and round1_i.sk_d == round1_r.sk_d
    print("Both sides derive identical RFC 9370 round-1 keys:", round1_agrees)

    # --- Independent structural check via tshark ---
    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
        write_pcap([wrap_udp_ip(wire_i)], tmp.name)
        out = subprocess.run(["tshark", "-r", tmp.name, "-V"], capture_output=True, text=True)
    tshark_ok = (
        out.returncode == 0
        and "Exchange type: IKE_INTERMEDIATE (43)" in out.stdout
        and "Encrypted and Authenticated" in out.stdout
    )
    print("tshark recognizes it as a valid Encrypted IKE_INTERMEDIATE message:", tshark_ok)

    ok = all([ke_roundtrip_ok, sk_decrypt_ok, kem_agrees, round1_agrees, tshark_ok, size_matches_reference])
    print("\nOVERALL:", "CONSISTENT" if ok else "INCONSISTENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
