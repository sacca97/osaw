#!/usr/bin/env python3
"""Precise structural parser for a captured IKE_SA_INIT, to avoid hand-counting
bytes when building an encoder that mirrors it. Read-only; no watch contact."""
import struct
import sys

PAYLOAD_NAMES = {
    0: "NONE", 33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT",
    38: "CERTREQ", 39: "AUTH", 40: "Ni/Nr", 41: "N", 42: "D", 43: "V",
    44: "TSi", 45: "TSr", 46: "SK", 47: "CP", 48: "EAP", 49: "GSPM",
}


def parse(data: bytes):
    ip_ihl = (data[0] & 0x0F) * 4
    udp_off = ip_ihl
    isakmp_off = udp_off + 8
    hdr = data[isakmp_off:isakmp_off + 28]
    ispi, rspi, next_payload, ver, exch, flags, msgid, length = struct.unpack(
        ">8s8sBBBBII", hdr
    )
    print(f"ISAKMP header: ISPI={ispi.hex()} RSPI={rspi.hex()} ver={ver:#x} "
          f"exch={exch} flags={flags:#x} msgid={msgid} length={length}")
    off = isakmp_off + 28
    np = next_payload
    while np != 0:
        gh = data[off:off + 4]
        payload_next, crit_reserved, plen = gh[0], gh[1], struct.unpack(">H", gh[2:4])[0]
        body = data[off + 4: off + plen]
        name = PAYLOAD_NAMES.get(np, f"0x{np:02x}")
        print(f"\n[{name}] off={off} len={plen} next={payload_next} body_hex={body.hex()}")
        if np == 33:  # SA
            parse_sa(body)
        elif np == 34:  # KE
            group = struct.unpack(">H", body[0:2])[0]
            print(f"  DH/KE group={group} key_len={len(body)-4}")
        elif np == 40:  # Nonce
            print(f"  nonce_len={len(body)}")
        elif np == 41:  # Notify
            proto, spisize, ntype = body[0], body[1], struct.unpack(">H", body[2:4])[0]
            ndata = body[4:]
            print(f"  proto={proto} spisize={spisize} notify_type={ntype:#06x} "
                  f"data_len={len(ndata)} data={ndata.hex()}")
        off += plen
        np = payload_next


def parse_sa(body: bytes):
    off = 0
    while off < len(body):
        next_prop, _, plen, pnum, proto, spisz, ntrans = struct.unpack(
            ">BBHBBBB", body[off:off + 8]
        )
        print(f"  Proposal #{pnum} proto={proto} spisize={spisz} "
              f"num_transforms={ntrans} proplen={plen}")
        toff = off + 8
        tend = off + plen
        while toff < tend:
            last_t, _, tlen, ttype, _, tid = struct.unpack(
                ">BBHBBH", body[toff:toff + 8]
            )
            attrs = body[toff + 8: toff + tlen]
            print(f"    Transform type={ttype} id={tid} len={tlen} attrs={attrs.hex()}")
            toff += tlen
        off += plen


if __name__ == "__main__":
    data = open(sys.argv[1] if len(sys.argv) > 1 else "/tmp/frame1.bin", "rb").read()
    parse(data)
