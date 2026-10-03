"""TCP segment codec and sequence arithmetic.

Sequence numbers are 32-bit and wrap. Every comparison must therefore be made
on the *signed difference*, never on the raw values -- ``a < b`` is wrong the
moment a connection crosses 2**32, and the resulting bug is close to
undebuggable. The helpers below are written once here and must never be
inlined at a call site.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntFlag

from usernet.errors import ProtocolParseError
from usernet.net import ipv4
from usernet.net.checksum import checksum, ones_complement_sum, pseudo_header_sum

HEADER = struct.Struct("!HHIIBBHHH")
MIN_HEADER_LEN = 20
_CHECKSUM = struct.Struct("!H")

# The window field is 16 bits. Never put more than this on the wire: claiming a
# window we cannot honour invites the peer to overrun the receive buffer.
# Anything larger is expressed through the window-scale option instead.
MAX_WINDOW = 0xFFFF

# RFC 7323 4.3: a shift above 14 must be clamped, never honoured, so the
# advertisable window stays below 2**30 and sequence comparisons keep working.
MAX_WINDOW_SCALE = 14

SEQ_MASK = 0xFFFFFFFF
_SEQ_SIGN = 0x80000000
_SEQ_SPACE = 0x100000000


class Flag(IntFlag):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


# Option kinds
OPT_END = 0
OPT_NOP = 1
OPT_MSS = 2
OPT_WINDOW_SCALE = 3
OPT_SACK_PERMITTED = 4
OPT_SACK = 5
OPT_TIMESTAMP = 8

DEFAULT_MSS = 536  # RFC 1122 floor, used when the peer offers no MSS option


# --- sequence arithmetic ---------------------------------------------------


def seq_diff(a: int, b: int) -> int:
    """``a - b`` as a signed 32-bit distance."""
    delta = (a - b) & SEQ_MASK
    return delta - _SEQ_SPACE if delta & _SEQ_SIGN else delta


def seq_lt(a: int, b: int) -> bool:
    return seq_diff(a, b) < 0


def seq_leq(a: int, b: int) -> bool:
    return seq_diff(a, b) <= 0


def seq_gt(a: int, b: int) -> bool:
    return seq_diff(a, b) > 0


def seq_geq(a: int, b: int) -> bool:
    return seq_diff(a, b) >= 0


def seq_add(a: int, n: int) -> int:
    return (a + n) & SEQ_MASK


# --- segments --------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TcpSegment:
    """A TCP segment as fields: what :func:`parse_tcp` returns, and what a
    TCB emits for the stack to encode.

    Options are reduced to the few we act on. Anything else -- timestamps,
    SACK blocks -- is parsed for length and skipped, so an unexpected option
    can never desynchronise the option walk. Of these, only ``mss`` and
    ``window_scale`` are ever sent.
    """

    source_port: int
    destination_port: int
    seq: int
    ack: int
    flags: Flag
    window: int
    payload: bytes
    mss: int | None = None
    window_scale: int | None = None
    sack_permitted: bool = False

    @property
    def segment_length(self) -> int:
        """Sequence space consumed: payload plus one each for SYN and FIN."""
        length = len(self.payload)
        if self.flags & Flag.SYN:
            length += 1
        if self.flags & Flag.FIN:
            length += 1
        return length

    def has(self, flag: Flag) -> bool:
        return bool(self.flags & flag)


def parse_tcp(data: bytes | memoryview) -> TcpSegment:
    """Parse a TCP segment. Raises :class:`ProtocolParseError` if malformed."""
    view = memoryview(data)
    if len(view) < MIN_HEADER_LEN:
        raise ProtocolParseError(f"TCP segment is {len(view)} bytes, minimum is {MIN_HEADER_LEN}")

    (
        source_port,
        destination_port,
        seq,
        ack,
        offset_reserved,
        flags,
        window,
        _checksum,
        _urgent,
    ) = HEADER.unpack_from(view)

    data_offset = (offset_reserved >> 4) * 4
    if data_offset < MIN_HEADER_LEN:
        raise ProtocolParseError(f"TCP data offset {data_offset} is below the minimum")
    if data_offset > len(view):
        raise ProtocolParseError(f"TCP data offset {data_offset} exceeds the segment")

    mss, window_scale, sack_permitted = _parse_options(view[MIN_HEADER_LEN:data_offset])

    return TcpSegment(
        source_port=source_port,
        destination_port=destination_port,
        seq=seq,
        ack=ack,
        flags=Flag(flags),
        window=window,
        payload=bytes(view[data_offset:]),
        mss=mss,
        window_scale=window_scale,
        sack_permitted=sack_permitted,
    )


def _parse_options(view: memoryview) -> tuple[int | None, int | None, bool]:
    mss: int | None = None
    window_scale: int | None = None
    sack_permitted = False

    index = 0
    end = len(view)
    while index < end:
        kind = view[index]
        if kind == OPT_END:
            break
        if kind == OPT_NOP:
            index += 1
            continue

        # Every other option is length-prefixed. A length below 2 would not
        # advance the walk and is the classic infinite-loop bug.
        if index + 1 >= end:
            break
        length = view[index + 1]
        if length < 2 or index + length > end:
            break

        if kind == OPT_MSS and length == 4:
            mss = int.from_bytes(view[index + 2 : index + 4], "big")
        elif kind == OPT_WINDOW_SCALE and length == 3:
            window_scale = min(view[index + 2], MAX_WINDOW_SCALE)
        elif kind == OPT_SACK_PERMITTED and length == 2:
            sack_permitted = True

        index += length

    return mss, window_scale, sack_permitted


def build_tcp(
    *,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    seq: int,
    ack: int,
    flags: Flag,
    window: int,
    payload: bytes = b"",
    mss: int | None = None,
    window_scale: int | None = None,
) -> bytes:
    """Build a TCP segment, including its pseudo-header checksum.

    ``mss`` and ``window_scale`` are only meaningful on a SYN; both are
    negotiated once and never restated.
    """
    options = _options(mss, window_scale)
    segment = bytearray(MIN_HEADER_LEN + len(options) + len(payload))
    _pack_into(
        segment,
        0,
        ipv4.packed_address(source_ip),
        ipv4.packed_address(destination_ip),
        source_port,
        destination_port,
        seq,
        ack,
        flags,
        window,
        options,
        payload,
    )
    return bytes(segment)


def build_tcp_ipv4(
    *,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    seq: int,
    ack: int,
    flags: Flag,
    window: int,
    payload: bytes = b"",
    mss: int | None = None,
    window_scale: int | None = None,
    identification: int = 0,
) -> bytes:
    """A TCP segment in its IPv4 packet: :func:`build_tcp` inside
    :func:`~usernet.net.ipv4.build_ipv4`, built in one buffer.

    Byte for byte the same as composing the two, but the payload is copied
    once rather than once per layer. This is the send path for every segment
    the stack emits, so those copies were much of its cost.
    """
    options = _options(mss, window_scale)
    source = ipv4.packed_address(source_ip)
    destination = ipv4.packed_address(destination_ip)
    packet = bytearray(ipv4.MIN_HEADER_LEN + MIN_HEADER_LEN + len(options) + len(payload))
    _pack_into(
        packet,
        ipv4.MIN_HEADER_LEN,
        source,
        destination,
        source_port,
        destination_port,
        seq,
        ack,
        flags,
        window,
        options,
        payload,
    )
    ipv4.pack_header_into(
        packet,
        source=source,
        destination=destination,
        protocol=ipv4.PROTO_TCP,
        identification=identification,
    )
    return bytes(packet)


def _options(mss: int | None, window_scale: int | None) -> bytes:
    options = b""
    if mss is not None:
        options += struct.pack("!BBH", OPT_MSS, 4, mss)
    if window_scale is not None:
        # Led by a NOP so the pair lands on a 4-byte boundary, which is what
        # every real stack emits and therefore what middleboxes expect.
        options += struct.pack("!BBBB", OPT_NOP, OPT_WINDOW_SCALE, 3, window_scale)
    # Options must be padded to a 4-byte boundary with NOPs/EOL.
    if len(options) % 4:
        options += b"\x00" * (4 - len(options) % 4)
    return options


def _pack_into(
    buffer: bytearray,
    offset: int,
    source: bytes,
    destination: bytes,
    source_port: int,
    destination_port: int,
    seq: int,
    ack: int,
    flags: Flag,
    window: int,
    options: bytes,
    payload: bytes,
) -> None:
    """Write a whole segment from ``offset`` to the end of ``buffer``, checksum
    included. The one place the TCP header layout is written down."""
    header_length = MIN_HEADER_LEN + len(options)
    HEADER.pack_into(
        buffer,
        offset,
        source_port,
        destination_port,
        seq & SEQ_MASK,
        ack & SEQ_MASK,
        (header_length // 4) << 4,
        int(flags),
        window,
        0,  # checksum, filled in below
        0,  # urgent pointer
    )
    start = offset + MIN_HEADER_LEN
    buffer[start : start + len(options)] = options
    buffer[offset + header_length :] = payload

    partial = pseudo_header_sum(source, destination, proto=6, length=len(buffer) - offset)
    with memoryview(buffer) as view:
        computed = checksum(view[offset:], partial)
    _CHECKSUM.pack_into(buffer, offset + 16, computed)


def verify_tcp_checksum(source_ip: str, destination_ip: str, segment: bytes | memoryview) -> bool:
    partial = pseudo_header_sum(
        ipv4.packed_address(source_ip),
        ipv4.packed_address(destination_ip),
        proto=6,
        length=len(segment),
    )
    return ones_complement_sum(segment, partial) == 0xFFFF
