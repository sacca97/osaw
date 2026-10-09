"""IKE_SA_INIT wire builder for the captured and companion Bluetooth profiles.

The default reproduces the reference phone's 264-byte offer. Bluetooth mode
uses zero NAT-D fields; pairing adds SPAKE2+/PPK capabilities,
and ordinary mode offers ML-KEM-768 and Ed25519. The live exchanges and
subsequent ML-KEM/AUTH rounds are implemented in pairing_session.py.
"""

from __future__ import annotations

import hashlib
import secrets
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import x448

# -- Payload type numbers (RFC 7296 Section 3.1) --
PAYLOAD_NONE = 0
PAYLOAD_SA = 33
PAYLOAD_KE = 34
PAYLOAD_NONCE = 40
PAYLOAD_NOTIFY = 41

EXCHANGE_IKE_SA_INIT = 34

# DH/KE group numbers (IANA "Transform Type 4 - Diffie-Hellman Group")
DH_GROUP_CURVE448 = 32
DH_GROUP_X25519 = 31

# The exact SA proposal body observed from the reference phone's SA_INIT
# (frame 1 of a private capture). One proposal, six transforms:
#   ENCR_AES_GCM_16 (id 20) with Key Length attribute = 256
#   ENCR_CHACHA20_POLY1305 (id 28)
#   PRF_HMAC_SHA2_512 (id 7)
#   transform type 6, id 37  -- the observed wire encoding for the
#     ML-KEM-1024 hybrid "additional key exchange" offer. Not the RFC 9370
#     standardized transform type (8); this is Apple's own wire value, read
#     directly off the capture, not assumed from the RFC.
#   D-H group 32 (Curve448)
#   D-H group 31 (X25519)
# This is a capability offer, not session-specific, so it is reused verbatim.
SA_PROPOSAL_BODY = bytes.fromhex(
    "0000003c010100060300000c01000014800e0100030000080100001c"
    "0300000802000007030000080600002503000008040000200000000804"
    "00001f"
)

NOTIFY_NAT_DETECTION_SOURCE_IP = 0x4004
NOTIFY_NAT_DETECTION_DESTINATION_IP = 0x4005
NOTIFY_IKEV2_FRAGMENTATION_SUPPORTED = 0x402E
NOTIFY_INTERMEDIATE_EXCHANGE_SUPPORTED = 0x4036

# The two empty capability-flag notifies are safe to reuse verbatim: no data,
# pure "I support this" markers, identical for every session.
_EMPTY_CAPABILITY_NOTIFIES = (
    struct.pack(">BBH", 0, 0, NOTIFY_IKEV2_FRAGMENTATION_SUPPORTED),
    struct.pack(">BBH", 0, 0, NOTIFY_INTERMEDIATE_EXCHANGE_SUPPORTED),
)


def _nat_detection_hash(spi_i: bytes, spi_r: bytes, ip: str, port: int) -> bytes:
    """RFC 7296 Section 2.23: SHA-1(SPIi | SPIr | address | port)."""
    addr_bytes = bytes(int(x) for x in ip.split("."))
    return hashlib.sha1(spi_i + spi_r + addr_bytes + struct.pack(">H", port)).digest()


def _payload_header(next_payload: int, body: bytes) -> bytes:
    return struct.pack(">BBH", next_payload, 0, 4 + len(body))


@dataclass
class SaInitMessage:
    initiator_spi: bytes
    x448_public_key: bytes
    nonce: bytes
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    message_id: int = 0

    def __post_init__(self):
        if len(self.initiator_spi) != 8:
            raise ValueError("initiator_spi must be 8 bytes")
        if len(self.x448_public_key) != 56:
            raise ValueError("X448 public key must be 56 bytes")
        if not (16 <= len(self.nonce) <= 256):
            raise ValueError("nonce must be 16..256 bytes per RFC 7296 2.10")

    def build(self, pairing: bool = False, bluetooth: bool = False, ordinary: bool = False) -> bytes:
        proposal = SA_PROPOSAL_BODY
        if ordinary:
            proposal = proposal.replace(bytes.fromhex('06000025'), bytes.fromhex('06000024'))
        sa_payload = _payload_header(PAYLOAD_KE, proposal) + proposal

        ke_body = struct.pack(">HH", DH_GROUP_CURVE448, 0) + self.x448_public_key
        ke_payload = _payload_header(PAYLOAD_NONCE, ke_body) + ke_body

        nonce_payload = _payload_header(PAYLOAD_NOTIFY, self.nonce) + self.nonce

        # Responder SPI is still all-zero at this point in the exchange (we
        # are the initiator sending the first message), per RFC 7296 2.23.
        spi_r = b"\x00" * 8
        nat_src = struct.pack(">BBH", 0, 0, NOTIFY_NAT_DETECTION_SOURCE_IP) + (
            _nat_detection_hash(self.initiator_spi, spi_r, self.local_addr, self.local_port)
        )
        nat_dst = struct.pack(">BBH", 0, 0, NOTIFY_NAT_DETECTION_DESTINATION_IP) + (
            _nat_detection_hash(self.initiator_spi, spi_r, self.remote_addr, self.remote_port)
        )
        if bluetooth:
            # The Bluetooth profile uses zero NAT-D data.
            nat_src = struct.pack('>BBH', 0, 0, NOTIFY_NAT_DETECTION_SOURCE_IP) + bytes(20)
            nat_dst = struct.pack('>BBH', 0, 0, NOTIFY_NAT_DETECTION_DESTINATION_IP) + bytes(20)
        notify_bodies = [nat_src, nat_dst, _EMPTY_CAPABILITY_NOTIFIES[0]]
        if pairing:
            notify_bodies.extend((struct.pack('>BBH', 0, 0, 0x4028) + b'\x2a\xf9',
                                  struct.pack('>BBH', 0, 0, 0x4033)))
        if ordinary:
            notify_bodies.append(struct.pack('>BBH', 0, 0, 0x402f) + b'\0\x05')
        notify_bodies.append(_EMPTY_CAPABILITY_NOTIFIES[1])
        notifies = []
        for i, nbody in enumerate(notify_bodies):
            nxt = PAYLOAD_NOTIFY if i < len(notify_bodies) - 1 else PAYLOAD_NONE
            notifies.append(_payload_header(nxt, nbody) + nbody)
        notify_payloads = b"".join(notifies)

        body = sa_payload + ke_payload + nonce_payload + notify_payloads
        length = 28 + len(body)
        header = struct.pack(
            ">8s8sBBBBII",
            self.initiator_spi,
            b"\x00" * 8,
            PAYLOAD_SA,
            0x20,
            EXCHANGE_IKE_SA_INIT,
            0x08,  # initiator bit set, no higher version, request
            self.message_id,
            length,
        )
        return header + body

    @classmethod
    def fresh(
        cls,
        local_addr: str,
        remote_addr: str,
        local_port: int = 500,
        remote_port: int = 500,
    ) -> tuple["SaInitMessage", x448.X448PrivateKey]:
        """Build a fresh SA_INIT with a freshly generated X448 keypair and
        random nonce. Returns the message plus the private key (needed later
        to complete the ECDH once a responder's KE payload is received).
        Real local/remote addresses are required now, since they feed the
        NAT_DETECTION_* hashes (RFC 7296 2.23) -- unlike the SA proposal,
        these cannot be a fixed reused constant."""
        sk = x448.X448PrivateKey.generate()
        pub = sk.public_key().public_bytes_raw()
        spi = secrets.token_bytes(8)
        nonce = secrets.token_bytes(32)
        return (
            cls(
                initiator_spi=spi,
                x448_public_key=pub,
                nonce=nonce,
                local_addr=local_addr,
                local_port=local_port,
                remote_addr=remote_addr,
                remote_port=remote_port,
            ),
            sk,
        )


def parse_header(data: bytes) -> dict:
    ispi, rspi, next_payload, ver, exch, flags, msgid, length = struct.unpack(
        ">8s8sBBBBII", data[:28]
    )
    return dict(
        initiator_spi=ispi,
        responder_spi=rspi,
        next_payload=next_payload,
        version=ver,
        exchange_type=exch,
        flags=flags,
        message_id=msgid,
        length=length,
    )
