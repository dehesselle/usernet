# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""RFC 1071 checksum tests."""

from __future__ import annotations

import struct

from hypothesis import given
from hypothesis import strategies as st

from usernet.net.checksum import checksum, ones_complement_sum, pseudo_header_sum, verify


def test_rfc1071_worked_example() -> None:
    """The byte sequence from RFC 1071 section 3, with its published sum."""
    data = bytes([0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7])
    assert ones_complement_sum(data) == 0xDDF2
    assert checksum(data) == 0x220D


def test_real_ipv4_header() -> None:
    """A header captured from the wire verifies, and we reproduce its checksum."""
    header = bytes.fromhex("4500003c1c464000400600000a0000010a0000c7")
    # Checksum field is zeroed above; summing the ten words gives 0xF650.
    assert checksum(header) == 0x09AF

    with_checksum = header[:10] + struct.pack("!H", 0x09AF) + header[12:]
    assert verify(with_checksum)


def test_odd_length_pads_on_the_right() -> None:
    """A trailing odd byte is the high half of the final word, not the low."""
    assert ones_complement_sum(b"\xab") == ones_complement_sum(b"\xab\x00")
    assert ones_complement_sum(b"\xab") != ones_complement_sum(b"\x00\xab")


def test_empty_input() -> None:
    assert ones_complement_sum(b"") == 0
    assert checksum(b"") == 0xFFFF


def test_initial_chains_across_regions() -> None:
    """Chaining lets a pseudo-header and payload be summed without joining them."""
    a, b = b"\x01\x02\x03\x04", b"\x05\x06\x07"
    assert ones_complement_sum(b, ones_complement_sum(a)) == ones_complement_sum(a + b)


def test_pseudo_header_matches_manual_layout() -> None:
    src = bytes([10, 0, 0, 1])
    dst = bytes([10, 0, 0, 199])
    expected = ones_complement_sum(src + dst + b"\x00\x06" + struct.pack("!H", 40))
    assert pseudo_header_sum(src, dst, proto=6, length=40) == expected


# The fold-to-zero property requires the checksum field to sit at an even
# offset, otherwise appending it re-pairs the payload's trailing odd byte and
# changes every word after it. Real headers always satisfy this -- the IPv4,
# TCP, UDP, and ICMP checksum fields are all 16-bit aligned -- so the
# strategies below keep the payload even-length rather than the code
# pretending an unaligned checksum could work.
_even_binary = st.binary(max_size=2048).map(lambda b: b if len(b) % 2 == 0 else b + b"\x00")


@given(_even_binary)
def test_roundtrip_verifies(payload: bytes) -> None:
    """A block carrying its own checksum always verifies."""
    block = payload + struct.pack("!H", checksum(payload))
    assert verify(block)


@given(
    _even_binary.filter(lambda b: len(b) > 0),
    st.integers(0, 4095),
    st.integers(0, 7),
)
def test_single_bit_flip_is_detected(payload: bytes, index: int, bit: int) -> None:
    """The whole point of a checksum: corruption must not verify."""
    block = bytearray(payload + struct.pack("!H", checksum(payload)))
    pos = index % len(payload)
    block[pos] ^= 1 << bit
    assert not verify(block)


@given(st.binary(max_size=1024))
def test_sum_is_never_out_of_range(payload: bytes) -> None:
    assert 0 <= ones_complement_sum(payload) <= 0xFFFF
    assert 0 <= checksum(payload) <= 0xFFFF


def _word_sum(data: bytes, initial: int = 0) -> int:
    """RFC 1071 taken literally: add the words, fold the carries back in.

    The oracle for the arithmetic shortcut in ``ones_complement_sum``, kept
    deliberately naive so that it is obviously right.
    """
    if len(data) % 2:
        data += b"\x00"
    total = initial + sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return total


@given(st.binary(max_size=4096), st.integers(0, 0xFFFF))
def test_matches_the_literal_word_sum(payload: bytes, initial: int) -> None:
    assert ones_complement_sum(payload, initial) == _word_sum(payload, initial)


def test_matches_the_literal_word_sum_at_the_edges() -> None:
    """The values where folding and the modulus could disagree: sums that are
    exact multiples of 0xFFFF, all-ones, and zero with and without a chain."""
    for payload, initial in [
        (b"", 0),
        (b"", 0xFFFF),
        (b"\x00\x00", 0),
        (b"\x00\x00", 1),
        (b"\xff\xff", 0),
        (b"\xff\xff" * 2, 0),
        (b"\xff\xfe\x00\x01", 0),
        (b"\xff\xff", 0xFFFF),
        (b"\xff", 0xFF),
        (b"\xff\xff" * 32768, 0),
    ]:
        assert ones_complement_sum(payload, initial) == _word_sum(payload, initial), (
            payload[:8],
            initial,
        )
