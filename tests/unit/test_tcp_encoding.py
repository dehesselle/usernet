"""Encoding outbound TCP: the fused builder and what the stack puts on the wire.

``build_tcp_ipv4`` exists only to save copies; it must never mean different
bytes. The composition of the two single-layer builders is its oracle.
"""

from __future__ import annotations

import pytest

from usernet.net.ipv4 import PROTO_TCP, build_ipv4, parse_ipv4, verify_header_checksum
from usernet.net.stack import PyStack, StackConfig
from usernet.net.tcp import (
    Flag,
    TcpSegment,
    build_tcp,
    build_tcp_ipv4,
    flag_names,
    parse_tcp,
    seq_add,
    verify_tcp_checksum,
)

LOCAL_IP = "172.29.29.5"
REMOTE_IP = "10.221.188.32"

CASES = {
    "syn with options": dict(flags=Flag.SYN, mss=1366, window_scale=4),
    "syn with mss only": dict(flags=Flag.SYN, mss=536),
    "bare ack": dict(flags=Flag.ACK),
    "data": dict(flags=Flag.ACK | Flag.PSH, payload=bytes(range(256)) * 5 + b"odd"),
    "fin": dict(flags=Flag.FIN | Flag.ACK),
    "rst": dict(flags=Flag.RST | Flag.ACK),
}


@pytest.mark.parametrize("fields", CASES.values(), ids=CASES.keys())
def test_the_fused_builder_matches_the_two_layers_composed(fields: dict[str, object]) -> None:
    common: dict[str, object] = dict(
        source_ip=LOCAL_IP,
        destination_ip=REMOTE_IP,
        source_port=51000,
        destination_port=443,
        seq=0xFFFFFFF0,  # close to the wrap, where masking matters
        ack=123456,
        window=0xFFFF,
        **fields,
    )
    composed = build_ipv4(
        source=LOCAL_IP,
        destination=REMOTE_IP,
        protocol=PROTO_TCP,
        payload=build_tcp(**common),  # type: ignore[arg-type]
        identification=4242,
    )
    fused = build_tcp_ipv4(**common, identification=4242)  # type: ignore[arg-type]
    assert fused == composed


def test_everything_the_stack_sends_carries_valid_checksums() -> None:
    """A whole connection's worth of output -- SYN, ACK, data, FIN -- checked
    at both layers, and numbered with a fresh IP identification each."""
    stack = PyStack(StackConfig(local_ip=LOCAL_IP, rng=lambda: 7))
    sid = stack.tcp_connect((REMOTE_IP, 443))
    stack.start_connect(sid, 0)
    (syn,) = stack.take_output()
    header, view = parse_ipv4(syn)
    ours = parse_tcp(view)

    synack = build_ipv4(
        source=REMOTE_IP,
        destination=LOCAL_IP,
        protocol=PROTO_TCP,
        payload=build_tcp(
            source_ip=REMOTE_IP,
            destination_ip=LOCAL_IP,
            source_port=443,
            destination_port=ours.source_port,
            seq=9000,
            ack=seq_add(ours.seq, 1),
            flags=Flag.SYN | Flag.ACK,
            window=0xFFFF,
            mss=1300,
        ),
    )
    stack.handle_input(synack, 1)
    stack.tcp_send(sid, memoryview(b"checksummed payload" * 100), 2)
    stack.tcp_close(sid, 3)
    packets = [syn, *stack.take_output()]

    assert len(packets) >= 4
    identifications = []
    for packet in packets:
        header, view = parse_ipv4(packet)
        assert verify_header_checksum(packet), "bad IP checksum"
        assert verify_tcp_checksum(header.source, header.destination, view), "bad TCP checksum"
        identifications.append(header.identification)
    assert len(set(identifications)) == len(identifications)


# --- flags -----------------------------------------------------------------


def test_parsed_flags_are_a_plain_int() -> None:
    """Not an enum: IntFlag builds a new member on every ``&``, and that was a
    quarter of a bulk download. A quiet return to it would cost all of that
    again without failing anything else."""
    segment = parse_tcp(
        build_tcp(
            source_ip=REMOTE_IP,
            destination_ip=LOCAL_IP,
            source_port=443,
            destination_port=51000,
            seq=1,
            ack=1,
            flags=Flag.SYN | Flag.ACK,
            window=0xFFFF,
        )
    )
    assert type(segment.flags) is int
    assert segment.flags == Flag.SYN | Flag.ACK


@pytest.mark.parametrize(
    ("flags", "names"),
    [
        (Flag.SYN, "SYN"),
        (Flag.ACK | Flag.SYN, "SYN|ACK"),
        (Flag.FIN | Flag.ACK | Flag.PSH, "FIN|PSH|ACK"),
        (0, "0"),
        (0xFF, "FIN|SYN|RST|PSH|ACK|URG|ECE|CWR"),
    ],
)
def test_flag_names(flags: int, names: str) -> None:
    assert flag_names(flags) == names


def test_a_segment_prints_its_flags_by_name() -> None:
    segment = TcpSegment(1, 2, 3, 4, Flag.SYN | Flag.ACK, 5, b"")
    assert "flags=SYN|ACK," in repr(segment)
    assert repr(segment).startswith("TcpSegment(source_port=1, destination_port=2, seq=3,")
