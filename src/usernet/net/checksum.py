# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""RFC 1071 ones-complement checksums.

Used by IPv4, ICMP, TCP, and UDP. This runs on every packet in both
directions, so the sum is computed without a Python-level loop over words:
read as one big-endian integer, the data *is* the sum of its 16-bit words
weighted by powers of 2**16, and since 2**16 is congruent to 1 modulo 0xFFFF,
every weight drops out. One ``int.from_bytes`` and one remainder by a
single-digit divisor -- both linear-time in C -- replace unpacking and adding
every word.
"""

from __future__ import annotations

import struct


def ones_complement_sum(data: bytes | memoryview, initial: int = 0) -> int:
    """Sum ``data`` as big-endian 16-bit words with end-around carry.

    ``initial`` chains sums across non-contiguous regions -- a pseudo-header
    and a payload, say -- without concatenating them first.

    An odd trailing byte is padded on the right with zero, per RFC 1071, so it
    contributes as the *high* half of the final word.
    """
    view = memoryview(data)
    value = int.from_bytes(view, "big")
    if len(view) & 1:
        value <<= 8
    total = value + initial
    # End-around carry is arithmetic modulo 0xFFFF, except that the result
    # lives in 1..0xFFFF rather than 0..0xFFFE: a positive sum never folds to
    # zero. Only an all-zero input, with nothing chained in, sums to 0.
    if not total:
        return 0
    return total % 0xFFFF or 0xFFFF


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
