"""NRLP framing and bounded stream reassembly for NetworkRelay.

Types 1..5 use an Internet checksum; bulk types 100..105 use the header
check ``length XOR (type << 4)``. Both rules match the complete reference
capture.

Legacy unsegmented PDU helpers below retain the two-byte ERTM prefix. Live sequence/ACK/retransmission handling is in watch_link.py:
I-frame TxSeq occupies bits 1..6, Final bit 7, ReqSeq bits 8..13 and SAR
bits 14..15 of the little-endian control word. NRLP spans those SDUs.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

IKE_MESSAGE_TYPE = 0x04


def inet_checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum (one's-complement 16-bit), confirmed as
    the algorithm behind terminusd's `os_inet_checksum` call for NRLP's
    trailer -- see static-findings-23H30.md. Returns the complemented value,
    exactly what the wire trailer stores (not the raw running sum)."""
    if len(data) % 2:
        data = data + b"\x00"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


@dataclass
class SequenceState:
    """Per-logical-channel sequence/ack bookkeeping for one direction pair."""

    next_send_seq: int = 0
    next_expected_from_peer: int = 0  # the ACK value we advertise

    def on_sent(self) -> int:
        """Call when sending a non-echo data frame; returns the seq to use."""
        seq = self.next_send_seq
        self.next_send_seq = (self.next_send_seq + 1) % 64
        return seq

    def on_received(self, peer_seq: int) -> None:
        """Call after accepting a non-echo frame from the peer, in order."""
        self.next_expected_from_peer = (peer_seq + 1) % 64


def build_inner_message(payload: bytes, msg_type: int = IKE_MESSAGE_TYPE) -> bytes:
    if not (0 <= len(payload) <= 16384):
        raise ValueError("payload length out of the observed 0..16384 range")
    header = struct.pack("!BH", msg_type, len(payload))
    body = header + payload
    trailer = struct.pack("!H", trailer_value(msg_type, len(payload), body))
    return body + trailer


def parse_inner_message(data: bytes) -> tuple[int, bytes, bool]:
    """Returns (type, payload, checksum_ok). Raises ValueError if `data`
    doesn't even contain a complete header+payload+trailer."""
    if len(data) < 5:
        raise ValueError("too short for an NRLP inner message")
    msg_type, length = struct.unpack_from("!BH", data)
    total = length + 5
    if len(data) < total:
        raise ValueError(f"incomplete: need {total} bytes, have {len(data)}")
    body = data[: 3 + length]
    payload = data[3 : 3 + length]
    observed = struct.unpack_from("!H", data, 3 + length)[0]
    return msg_type, payload, trailer_value(msg_type, length, body) == observed


def trailer_value(kind, length, body):
    return (length ^ (kind << 4)) & 0xffff if 100 <= kind <= 105 else inet_checksum(body)


class Stream:
    """One bounded, ordered SDU stream; ERTM handles reliability underneath."""
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data):
        self.buffer.extend(data)
        if len(self.buffer) > 131080:
            raise ValueError('NRLP stream buffer exceeded limit')
        messages = []
        while self.buffer:
            if self.buffer[0] == 0:  # PAD0 has no length or trailer
                del self.buffer[0]
                continue
            if len(self.buffer) < 3:
                break
            kind, length = struct.unpack_from('>BH', self.buffer)
            if kind not in (1, 2, 3, 4, 5, 100, 101, 102, 103, 104, 105):
                raise ValueError('Unsupported NRLP message type')
            total = length + 5
            if len(self.buffer) < total:
                break
            kind, payload, valid = parse_inner_message(self.buffer[:total])
            if not valid:
                raise ValueError('Invalid NRLP trailer')
            del self.buffer[:total]
            if kind != 1:
                messages.append((kind, bytes(payload)))
        return messages


def build_pdu(payload: bytes, state: SequenceState, echo: bool = False,
              msg_type: int = IKE_MESSAGE_TYPE) -> bytes:
    """Build one complete L2CAP PDU body carrying a single inner message.
    Does not split across multiple PDUs for payloads too large for one ACL
    buffer -- the real traffic does fragment large IKE messages (observed:
    the first ~1.6KB IKE message spans several PDUs), which this module
    does not yet implement; see the module docstring's scope note."""
    seq = 0 if echo else state.on_sent()
    prefix_byte0 = (seq << 1) | (1 if echo else 0)
    prefix_byte1 = state.next_expected_from_peer
    inner = build_inner_message(payload, msg_type)
    return bytes([prefix_byte0, prefix_byte1]) + inner


def parse_pdu(data: bytes) -> dict:
    """Parse one PDU's prefix and, if present, a single complete inner
    message. Does not handle reassembly of a message spanning multiple PDUs
    -- see extract_bluetooth.py's streaming reassembly loop for that logic,
    which this module's constants/functions are designed to drop into."""
    if len(data) < 2:
        raise ValueError("PDU too short to contain the 2-byte prefix")
    echo = bool(data[0] & 1)
    seq = (data[0] & 0x7E) >> 1
    ack = data[1]
    result = dict(echo=echo, seq=seq, ack=ack, chunk=data[2:])
    if not echo and len(data) >= 7:
        try:
            msg_type, payload, checksum_ok = parse_inner_message(data[2:])
            result.update(msg_type=msg_type, payload=payload, checksum_ok=checksum_ok)
        except ValueError:
            pass  # incomplete message in this PDU; caller must reassemble
    return result
