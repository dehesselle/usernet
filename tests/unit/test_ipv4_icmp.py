# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""IPv4 and ICMP codecs.

These parse bytes that arrive from inside the tunnel, so the hostile-input
properties are a security control, not merely a correctness one.
"""

from __future__ import annotations

import contextlib
import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from usernet.errors import ProtocolParseError
from usernet.net.icmp import (
    DEST_UNREACHABLE,
    ECHO_REPLY,
    ECHO_REQUEST,
    FRAGMENTATION_NEEDED,
    build_echo_reply,
    build_echo_request,
    parse_icmp,
    quoted_headers,
    quoted_tcp_sequence,
)
from usernet.net.icmp import verify_checksum as verify_icmp
from usernet.net.ipv4 import (
    MIN_HEADER_LEN,
    PROTO_ICMP,
    PROTO_TCP,
    build_ipv4,
    dotted_address,
    packed_address,
    parse_ipv4,
    verify_header_checksum,
)

# --- IPv4 ------------------------------------------------------------------


def test_build_and_parse_roundtrip() -> None:
    packet = build_ipv4(
        source="10.20.30.40",
        destination="10.221.188.5",
        protocol=PROTO_ICMP,
        payload=b"payload",
        identification=1234,
    )
    header, payload = parse_ipv4(packet)

    assert header.source == "10.20.30.40"
    assert header.destination == "10.221.188.5"
    assert header.protocol == PROTO_ICMP
    assert header.identification == 1234
    assert header.ttl == 64
    assert header.total_length == MIN_HEADER_LEN + len(b"payload")
    assert bytes(payload) == b"payload"


def test_built_packets_carry_a_valid_checksum() -> None:
    packet = build_ipv4(
        source="1.2.3.4", destination="5.6.7.8", protocol=PROTO_TCP, payload=b"\x00" * 20
    )
    assert verify_header_checksum(packet)


def test_dont_fragment_is_set_by_default() -> None:
    """We size everything from the tunnel MTU and never fragment on send."""
    header, _ = parse_ipv4(
        build_ipv4(source="1.2.3.4", destination="5.6.7.8", protocol=1, payload=b"")
    )
    assert header.flags & 0x2
    assert not header.is_fragment


def test_fragment_detection() -> None:
    packet = bytearray(
        build_ipv4(source="1.2.3.4", destination="5.6.7.8", protocol=1, payload=b"x" * 8)
    )
    struct.pack_into("!H", packet, 6, 0x2000 | 185)  # MF set, offset 185*8
    header, _ = parse_ipv4(bytes(packet))

    assert header.is_fragment
    assert header.fragment_offset == 185 * 8


def test_payload_is_bounded_by_total_length() -> None:
    """Trailing bytes past the declared length are not payload."""
    packet = build_ipv4(source="1.2.3.4", destination="5.6.7.8", protocol=1, payload=b"real")
    _, payload = parse_ipv4(packet + b"TRAILINGGARBAGE")
    assert bytes(payload) == b"real"


def test_truncated_packet_does_not_over_read() -> None:
    """A declared length longer than the data must not hand back a long view."""
    packet = build_ipv4(source="1.2.3.4", destination="5.6.7.8", protocol=1, payload=b"x" * 40)
    header, payload = parse_ipv4(packet[:30])
    assert header.total_length == 30
    assert len(payload) == 10


@pytest.mark.parametrize(
    ("packet", "match"),
    [
        (b"", "minimum"),
        (b"\x45" + b"\x00" * 10, "minimum"),
        (b"\x60" + b"\x00" * 25, "not IPv4"),
        (b"\x44" + b"\x00" * 25, "below the minimum"),  # IHL of 4 words
    ],
)
def test_malformed_packets_raise_parse_errors(packet: bytes, match: str) -> None:
    with pytest.raises(ProtocolParseError, match=match):
        parse_ipv4(packet)


@given(st.binary(max_size=200))
def test_arbitrary_bytes_raise_only_protocol_parse_error(data: bytes) -> None:
    with contextlib.suppress(ProtocolParseError):
        header, payload = parse_ipv4(data)
        assert len(payload) >= 0
        assert header.total_length <= len(data)


# --- ICMP ------------------------------------------------------------------


def test_echo_request_roundtrip() -> None:
    message = parse_icmp(build_echo_request(0xBEEF, 7, b"usernet"))

    assert message.type == ECHO_REQUEST
    assert message.code == 0
    assert message.ident == 0xBEEF
    assert message.sequence == 7
    assert message.payload == b"usernet"
    assert not message.is_echo_reply


def test_echo_reply_is_recognised() -> None:
    assert parse_icmp(build_echo_reply(1, 2)).is_echo_reply


def test_built_messages_carry_a_valid_checksum() -> None:
    assert verify_icmp(build_echo_request(1, 1, b"x" * 32))
    assert verify_icmp(build_echo_reply(0xFFFF, 0xFFFF, b""))


def test_corrupted_message_fails_checksum() -> None:
    message = bytearray(build_echo_request(1, 1, b"payload"))
    message[-1] ^= 0xFF
    assert not verify_icmp(message)


def test_fragmentation_needed_reports_the_next_hop_mtu() -> None:
    """Code 4 is the mitigation for the silent-hang failure mode."""
    raw = struct.pack("!BBHHH", DEST_UNREACHABLE, FRAGMENTATION_NEEDED, 0, 0, 1400)
    message = parse_icmp(raw)

    assert message.next_hop_mtu == 1400
    assert not message.is_hard_error  # code 4 is soft: clamp MSS, do not abort


@pytest.mark.parametrize("code", [2, 3, 9, 10, 13])
def test_rfc1122_hard_error_codes_fail_fast(code: int) -> None:
    """Turns a 15-second connect timeout into an instant, accurate error."""
    message = parse_icmp(struct.pack("!BBHHH", DEST_UNREACHABLE, code, 0, 0, 0))
    assert message.is_hard_error


@pytest.mark.parametrize("code", [0, 1, 5, 11, 12])
def test_other_unreachable_codes_are_soft(code: int) -> None:
    """Transient routing blips must not tear down an established connection."""
    message = parse_icmp(struct.pack("!BBHHH", DEST_UNREACHABLE, code, 0, 0, 0))
    assert not message.is_hard_error


def test_echo_reply_is_never_a_hard_error() -> None:
    assert not parse_icmp(build_echo_reply(1, 1)).is_hard_error


def test_quoted_headers_identify_the_offending_socket() -> None:
    """ICMP errors quote the IP header plus eight bytes: exactly the ports."""
    original = build_ipv4(
        source="10.20.30.40",
        destination="10.221.188.5",
        protocol=PROTO_TCP,
        payload=struct.pack("!HH", 51000, 443) + b"\x00" * 4,
    )
    error = struct.pack("!BBHHH", DEST_UNREACHABLE, 3, 0, 0, 0) + original

    assert quoted_headers(parse_icmp(error)) == ("10.20.30.40", "10.221.188.5", 51000, 443)


def test_quoted_headers_returns_none_for_echo() -> None:
    assert quoted_headers(parse_icmp(build_echo_reply(1, 1))) is None


def test_quoted_headers_survives_a_truncated_quote() -> None:
    error = struct.pack("!BBHHH", DEST_UNREACHABLE, 3, 0, 0, 0) + b"\x45\x00"
    assert quoted_headers(parse_icmp(error)) is None


def test_quoted_tcp_sequence_ends_the_eight_quoted_bytes() -> None:
    original = build_ipv4(
        source="10.20.30.40",
        destination="10.221.188.5",
        protocol=PROTO_TCP,
        payload=struct.pack("!HHI", 51000, 443, 0xDEADBEEF),
    )
    error = struct.pack("!BBHHH", DEST_UNREACHABLE, 3, 0, 0, 0) + original

    assert quoted_tcp_sequence(parse_icmp(error)) == 0xDEADBEEF


def test_quoted_tcp_sequence_needs_all_eight_bytes() -> None:
    original = build_ipv4(
        source="10.20.30.40",
        destination="10.221.188.5",
        protocol=PROTO_TCP,
        payload=struct.pack("!HH", 51000, 443) + b"\x00\x00",
    )
    error = struct.pack("!BBHHH", DEST_UNREACHABLE, 3, 0, 0, 0) + original

    assert quoted_tcp_sequence(parse_icmp(error)) is None


@pytest.mark.parametrize("data", [b"", b"\x08", b"\x08\x00\x00\x00\x00\x00\x00"])
def test_short_icmp_messages_raise(data: bytes) -> None:
    with pytest.raises(ProtocolParseError, match="minimum"):
        parse_icmp(data)


@given(st.binary(max_size=200))
def test_icmp_arbitrary_bytes_raise_only_protocol_parse_error(data: bytes) -> None:
    with contextlib.suppress(ProtocolParseError):
        parse_icmp(data)


@given(
    st.integers(0, 0xFFFF),
    st.integers(0, 0xFFFF),
    st.binary(max_size=512),
)
def test_echo_roundtrip_property(ident: int, sequence: int, payload: bytes) -> None:
    message = parse_icmp(build_echo_request(ident, sequence, payload))
    assert (message.ident, message.sequence, message.payload) == (ident, sequence, payload)
    assert message.type == ECHO_REQUEST
    assert message.type != ECHO_REPLY


# --- address conversion ----------------------------------------------------


@pytest.mark.parametrize("address", ["10.0.0", "10.0.0.1.2", "256.0.0.1", "example.com", ""])
def test_a_malformed_address_is_refused_not_packed(address: str) -> None:
    """The header packs addresses with ``4s``, which pads or truncates
    whatever it is given. The cache must not cost us the validation."""
    for _ in range(2):  # and not on a second call either, from the cache
        with pytest.raises(ValueError):
            packed_address(address)


@given(st.binary(min_size=4, max_size=4))
def test_address_conversion_round_trips(raw: bytes) -> None:
    assert packed_address(dotted_address(raw)) == raw


def test_the_address_caches_are_bounded() -> None:
    """Source addresses come off the tunnel; a peer must not be able to grow
    a cache without limit by varying them."""
    assert packed_address.cache_info().maxsize is not None
    assert dotted_address.cache_info().maxsize is not None
