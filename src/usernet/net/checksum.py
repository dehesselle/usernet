"""RFC 1071 ones-complement checksums.

Used by IPv4, ICMP, TCP, and UDP. This runs on every packet in both
directions, so the ``struct.Struct`` objects are cached rather than rebuilt
per call and everything takes a ``memoryview`` to avoid slicing copies.
"""

from __future__ import annotations

import struct

# struct.Struct objects for "!<n>H", built once per distinct word count. Packet
# sizes cluster tightly around the MSS, so this cache stays small in practice.
_WORD_STRUCTS: dict[int, struct.Struct] = {}


def _words(count: int) -> struct.Struct:
    s = _WORD_STRUCTS.get(count)
    if s is None:
        s = struct.Struct(f"!{count}H")
        _WORD_STRUCTS[count] = s
    return s


def ones_complement_sum(data: bytes | memoryview, initial: int = 0) -> int:
    """Sum ``data`` as big-endian 16-bit words with end-around carry.

    ``initial`` chains sums across non-contiguous regions -- a pseudo-header
    and a payload, say -- without concatenating them first.

    An odd trailing byte is padded on the right with zero, per RFC 1071, so it
    contributes as the *high* half of the final word.
    """
    view = memoryview(data)
    n = len(view)
    total = initial

    full = n >> 1
    if full:
        total += sum(_words(full).unpack_from(view))
    if n & 1:
        total += view[n - 1] << 8

    # Fold carries. Two passes always suffice: the first can itself carry, but
    # only ever by one.
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return total


def checksum(data: bytes | memoryview, initial: int = 0) -> int:
    """The RFC 1071 checksum: the ones-complement of the ones-complement sum."""
    return ~ones_complement_sum(data, initial) & 0xFFFF


def pseudo_header_sum(src: bytes, dst: bytes, proto: int, length: int) -> int:
    """Partial sum of the IPv4 pseudo-header for TCP/UDP checksums.

    ``src`` and ``dst`` are the 4-byte packed addresses; ``length`` is the
    transport header plus payload, excluding the IP header.
    """
    return ones_complement_sum(src + dst + struct.pack("!BBH", 0, proto, length))


def verify(data: bytes | memoryview, initial: int = 0) -> bool:
    """True if ``data`` carries a valid checksum in place.

    Summing a correct block including its own checksum field yields 0xFFFF, so
    the complement is zero.
    """
    return checksum(data, initial) == 0
