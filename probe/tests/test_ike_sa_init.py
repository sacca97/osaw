#!/usr/bin/env python3
"""Self-test for probe/ike_sa_init.py. No watch contact: builds a message,
wraps it in a synthetic pcap (198.18.0.1/.2, UDP 500), and checks it two independent ways:
  1. structurally, with this directory's parse_sa_init.py
  2. independently, by asking tshark/Wireshark's own ISAKMP dissector
Then confirms the SA proposal bytes match the real reference capture's own
IKE_SA_INIT (a private capture, skipped when absent), extracted fresh each run
rather than hardcoded.

Run: python3 probe/tests/test_ike_sa_init.py
Requires: pip install cryptography. tshark and a private reference capture are optional extras.
"""
import re
import struct
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "probe"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ike_sa_init import SA_PROPOSAL_BODY, SaInitMessage  # noqa: E402
import parse_sa_init  # noqa: E402

REFERENCE_PCAP = ROOT / "analysis" / "bluetooth-ike.pcap"


def wrap_udp_ip(payload: bytes, src="198.18.0.1", dst="198.18.0.2", sport=500, dport=500) -> bytes:
    def ip_to_bytes(s):
        return bytes(int(x) for x in s.split("."))

    udp_len = 8 + len(payload)
    udp = struct.pack(">HHHH", sport, dport, udp_len, 0) + payload
    total_len = 20 + udp_len
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total_len, 1, 0, 64, 17, 0,
        ip_to_bytes(src), ip_to_bytes(dst),
    )
    return ip + udp


def write_pcap(packets: list, path: str):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for i, pkt in enumerate(packets):
            f.write(struct.pack("<IIII", 0, i, len(pkt), len(pkt)))
            f.write(pkt)


def extract_reference_frame1() -> bytes:
    """Read frame 1 from the optional private reference capture."""
    out = subprocess.run(
        ["tshark", "-r", str(REFERENCE_PCAP), "-Y", "frame.number==1", "-x"],
        capture_output=True, text=True, check=True,
    )
    hexbytes = []
    for line in out.stdout.splitlines():
        m = re.match(r"^[0-9a-f]{4}\s+((?:[0-9a-f]{2}\s)+)", line)
        if m:
            hexbytes += m.group(1).split()
    return bytes.fromhex("".join(hexbytes))


def main():
    msg, sk = SaInitMessage.fresh(local_addr="198.18.0.1", remote_addr="198.18.0.2")
    wire = msg.build()
    print(f"Built SA_INIT: {len(wire)} bytes, ISPI={msg.initiator_spi.hex()}")

    frame = wrap_udp_ip(wire)
    ok = True

    print("\n=== Our own structural parser ===")
    parse_sa_init.parse(frame)

    if shutil.which("tshark"):
        with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
            write_pcap([frame], tmp.name)
            print("\n=== tshark's independent ISAKMP dissector ===")
            out = subprocess.run(["tshark", "-r", tmp.name, "-V"], capture_output=True, text=True)
            if out.returncode != 0:
                print("tshark FAILED:", out.stderr)
                return 1
            text = out.stdout
        ok &= "Internet Security Association and Key Management Protocol" in text
        ok &= "Exchange type: IKE_SA_INIT (34)" in text
        print("tshark recognized as valid ISAKMP/IKE_SA_INIT:", ok)
        for line in text.splitlines():
            s = line.strip()
            if any(k in s for k in ("Next payload:", "Exchange type:", "Transform ", "Transform ID",
                                    "Diffie-Hellman Group", "Key Length", "Notification", "Notify Message Type")):
                print(" ", s)
    else:
        print("\n(skipped: tshark's dissector check needs tshark on PATH)")

    embedded_in_ours = SA_PROPOSAL_BODY in wire
    print(f"\nSA_PROPOSAL_BODY found verbatim in our built message: {embedded_in_ours}")
    ok &= embedded_in_ours

    if shutil.which("tshark") and REFERENCE_PCAP.exists():
        print("\n=== Compare SA proposal against a reference capture ===")
        matches_reference = SA_PROPOSAL_BODY in extract_reference_frame1()
        print(f"SA_PROPOSAL_BODY found verbatim in reference frame 1: {matches_reference}")
        ok &= matches_reference
    else:
        print("(skipped: comparison with a private reference capture; set up analysis/bluetooth-ike.pcap to enable it)")

    print("\nOVERALL:", "CONSISTENT" if ok else "INCONSISTENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
