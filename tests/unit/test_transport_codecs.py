# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The TCP and UDP codecs, for any input.

Parsing is the first thing untrusted bytes meet. Whatever they are, the only
exception allowed out is ProtocolParseError; and whatever we build must parse
back to what went in and carry a checksum that catches any single flipped bit.
"""

from __future__ import annotations

import contextlib
import struct

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from tests.unit.test_stack_fuzz import tcp_option
from usernet.errors import ProtocolParseError
from usernet.net.tcp import (
    MAX_WINDOW_SCALE,
    SEQ_MASK,
    build_tcp,
    parse_tcp,
    verify_tcp_checksum,
)
from usernet.net.udp import build_udp, parse_udp, verify_udp_checksum

LOCAL_IP = "172.29.29.5"
REMOTE_IP = "10.221.188.32"

ports = st.integers(0, 0xFFFF)


def flip(data: bytes, bit: int) -> bytes:
    index, shift = divmod(bit % (8 * len(data)), 8)
    return data[:index] + bytes([data[index] ^ (1 << shift)]) + data[index + 1 :]


# --- TCP ---------------------------------------------------------------------


@given(st.binary(max_size=120))
def test_tcp_parsing_raises_only_parse_errors(data: bytes) -> None:
    with contextlib.suppress(ProtocolParseError):
        segment = parse_tcp(data)
        assert len(segment.payload) <= len(data) - 20


@given(
    options=st.lists(tcp_option, max_size=16).map(b"".join),
    payload=st.binary(max_size=40),
)
def test_any_option_walk_terminates_within_the_header(options: bytes, payload: bytes) -> None:
    """Lying lengths, unknown kinds, truncated options: the walk must end, stay
    inside the options, and clamp what it reports."""
    options = options[:40]
    options += b"\x00" * (-len(options) % 4)
    header = struct.pack("!HHIIBBHHH", 1, 2, 3, 4, (5 + len(options) // 4) << 4, 0, 0, 0, 0)

    segment = parse_tcp(header + options + payload)

    assert segment.payload == payload
    assert segment.window_scale is None or 0 <= segment.window_scale <= MAX_WINDOW_SCALE
    assert segment.mss is None or 0 <= segment.mss <= 0xFFFF


@pytest.mark.parametrize(
    "options",
    [
        b"\x01\x01\x02\x04",  # MSS: kind and length, no value
        b"\x01\x02\x04\x05",  # MSS: one byte of two
        b"\x01\x01\x03\x03",  # window scale: no shift
        b"\x01\x01\x01\x08",  # timestamp: kind only
    ],
    ids=["mss-bare", "mss-half", "window-scale", "kind-only"],
)
def test_an_option_cut_off_by_the_header_is_ignored(options: bytes) -> None:
    """The header ends mid-option. Reading on would take the value from the
    payload, or from beyond the segment altogether."""
    header = struct.pack("!HHIIBBHHH", 1, 2, 3, 4, (5 + len(options) // 4) << 4, 0, 0, 0, 0)

    segment = parse_tcp(header + options + b"\xff\xff")

    assert (segment.mss, segment.window_scale) == (None, None)
    assert segment.payload == b"\xff\xff"


@given(
    source_port=ports,
    destination_port=ports,
    seq=st.integers(0, SEQ_MASK),
    ack=st.integers(0, SEQ_MASK),
    flags=st.integers(0, 0xFF),
    window=st.integers(0, 0xFFFF),
    payload=st.binary(max_size=200),
    mss=st.one_of(st.none(), st.integers(0, 0xFFFF)),
    window_scale=st.one_of(st.none(), st.integers(0, MAX_WINDOW_SCALE)),
)
def test_a_built_segment_parses_back_to_its_fields(
    source_port: int,
    destination_port: int,
    seq: int,
    ack: int,
    flags: int,
    window: int,
    payload: bytes,
    mss: int | None,
    window_scale: int | None,
) -> None:
    built = build_tcp(
        source_ip=LOCAL_IP,
        destination_ip=REMOTE_IP,
        source_port=source_port,
        destination_port=destination_port,
        seq=seq,
        ack=ack,
        flags=flags,
        window=window,
        payload=payload,
        mss=mss,
        window_scale=window_scale,
    )
    segment = parse_tcp(built)

    assert (segment.source_port, segment.destination_port) == (source_port, destination_port)
    assert (segment.seq, segment.ack, segment.flags) == (seq, ack, flags)
    assert (segment.window, segment.payload) == (window, payload)
    assert (segment.mss, segment.window_scale) == (mss, window_scale)
    assert verify_tcp_checksum(LOCAL_IP, REMOTE_IP, built)


@given(payload=st.binary(max_size=200), bit=st.integers(min_value=0))
def test_any_single_flipped_bit_fails_the_tcp_checksum(payload: bytes, bit: int) -> None:
    built = build_tcp(
        source_ip=LOCAL_IP,
        destination_ip=REMOTE_IP,
        source_port=51000,
        destination_port=443,
        seq=1,
        ack=2,
        flags=0x18,
        window=1000,
        payload=payload,
    )
    assert not verify_tcp_checksum(LOCAL_IP, REMOTE_IP, flip(built, bit))


# --- UDP ---------------------------------------------------------------------


@given(st.binary(max_size=64))
def test_udp_parsing_raises_only_parse_errors(data: bytes) -> None:
    try:
        datagram = parse_udp(data)
    except ProtocolParseError:
        return
    # The declared length can only shorten the payload, never extend it.
    assert len(datagram.payload) <= len(data) - 8


@given(source_port=ports, destination_port=ports, payload=st.binary(max_size=200))
def test_a_built_datagram_parses_back_to_its_fields(
    source_port: int, destination_port: int, payload: bytes
) -> None:
    built = build_udp(
        source_ip=LOCAL_IP,
        destination_ip=REMOTE_IP,
        source_port=source_port,
        destination_port=destination_port,
        payload=payload,
    )
    datagram = parse_udp(built)

    assert (datagram.source_port, datagram.destination_port) == (source_port, destination_port)
    assert datagram.payload == payload
    assert built[6:8] != b"\x00\x00", "a computed zero must go out as 0xFFFF"
    assert verify_udp_checksum(LOCAL_IP, REMOTE_IP, built)


@given(payload=st.binary(max_size=200), bit=st.integers(min_value=0))
def test_any_single_flipped_bit_fails_the_udp_checksum(payload: bytes, bit: int) -> None:
    built = build_udp(
        source_ip=LOCAL_IP,
        destination_ip=REMOTE_IP,
        source_port=5353,
        destination_port=53,
        payload=payload,
    )
    damaged = flip(built, bit)
    assume(damaged[6:8] != b"\x00\x00")  # a zero checksum means "not computed"
    assert not verify_udp_checksum(LOCAL_IP, REMOTE_IP, damaged)
