"""The packet trace the L3 conformance suite prints when a test fails.

Worth testing on its own, and worth testing here rather than there: the
conformance suite only runs on Linux, but a broken formatter would be
discovered at the exact moment it is needed most -- explaining a failure on a
machine the author cannot reach. This module is pure and platform-independent,
so it can be proven anywhere.
"""

from __future__ import annotations

from tests.conformance.trace import PacketTrace
from usernet.net.icmp import build_echo_request
from usernet.net.ipv4 import PROTO_ICMP, PROTO_TCP, build_ipv4
from usernet.net.tcp import Flag, build_tcp

US = "10.99.0.2"
KERNEL = "10.99.0.1"


def tcp_packet(
    *,
    source: str = US,
    destination: str = KERNEL,
    source_port: int = 49153,
    destination_port: int = 8080,
    seq: int,
    ack: int = 0,
    flags: int,
    window: int = 65535,
    payload: bytes = b"",
    mss: int | None = None,
    window_scale: int | None = None,
) -> bytes:
    segment = build_tcp(
        source_ip=source,
        destination_ip=destination,
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
    return build_ipv4(
        source=source,
        destination=destination,
        protocol=PROTO_TCP,
        payload=segment,
        identification=1,
    )


def handshake(trace: PacketTrace) -> None:
    """The three-way handshake, in the direction the conformance suite sees it."""
    trace.record(True, tcp_packet(seq=1_000_000, flags=Flag.SYN, mss=1460, window_scale=3))
    trace.record(
        False,
        tcp_packet(
            source=KERNEL,
            destination=US,
            source_port=8080,
            destination_port=49153,
            seq=2_000_000,
            ack=1_000_001,
            flags=Flag.SYN | Flag.ACK,
            mss=1460,
            window_scale=7,
        ),
    )


def test_sequence_numbers_are_relative_to_each_direction() -> None:
    """Absolute ISNs are random ten-digit numbers, and comparing two of them by
    eye is how an off-by-one survives a review."""
    trace = PacketTrace()
    handshake(trace)
    trace.record(True, tcp_packet(seq=1_000_001, ack=2_000_001, flags=Flag.ACK))

    syn, syn_ack, ack = trace.lines()
    assert "seq=0" in syn, syn  # our SYN, relative to itself
    assert "seq=0 ack=1" in syn_ack, syn_ack  # theirs, acking ours
    assert "seq=1 ack=1" in ack, ack


def test_options_are_shown_because_a_missing_one_is_the_bug() -> None:
    trace = PacketTrace()
    handshake(trace)
    text = trace.dump("x")
    assert "mss=1460 ws=3" in text
    assert "ws=7" in text


def test_flags_are_rendered_as_letters() -> None:
    trace = PacketTrace()
    trace.record(True, tcp_packet(seq=1, flags=Flag.SYN))
    trace.record(True, tcp_packet(seq=2, ack=1, flags=Flag.FIN | Flag.ACK))
    trace.record(True, tcp_packet(seq=3, ack=1, flags=Flag.RST))
    syn, fin_ack, reset = trace.lines()
    assert "[S  ]" in syn
    assert "[AF ]" in fin_ack
    assert "[R  ]" in reset


def test_a_value_with_no_recorded_isn_is_marked_absolute() -> None:
    """Traces are a bounded ring, so the SYN may have scrolled away. Silently
    printing a huge 'relative' number would be worse than admitting it."""
    trace = PacketTrace()
    trace.record(True, tcp_packet(seq=500, ack=999, flags=Flag.ACK))
    assert "ack=*999" in trace.dump("x")


def test_payload_length_is_reported() -> None:
    trace = PacketTrace()
    handshake(trace)
    trace.record(True, tcp_packet(seq=1_000_001, ack=2_000_001, flags=Flag.ACK, payload=b"x" * 40))
    assert "len=40" in trace.lines()[-1]


def test_icmp_is_described_too() -> None:
    """The first thing to check when nothing works is whether ping got through."""
    trace = PacketTrace()
    packet = build_ipv4(
        source=US,
        destination=KERNEL,
        protocol=PROTO_ICMP,
        payload=build_echo_request(0x1234, 7, b"usernet"),
        identification=1,
    )
    trace.record(True, packet)
    text = trace.dump("x")
    assert "echo-request" in text
    assert "seq=7" in text


def test_an_unparseable_packet_does_not_break_the_trace() -> None:
    """A trace is printed while something is already wrong; raising from the
    formatter would destroy the only evidence."""
    trace = PacketTrace()
    trace.record(False, b"\x45\x00\x03")
    trace.record(False, b"")
    assert "unparseable" in trace.dump("x")


def test_the_summary_counts_both_directions() -> None:
    trace = PacketTrace()
    handshake(trace)
    header = trace.dump("a test")
    assert "a test" in header
    assert "1 sent, 1 received" in header


def test_the_ring_is_bounded() -> None:
    """These run for a megabyte at a time; an unbounded trace would be the
    memory bug rather than the diagnosis of one."""
    trace = PacketTrace(limit=10)
    for index in range(100):
        trace.record(True, tcp_packet(seq=index, flags=Flag.ACK))
    assert len(trace.lines()) == 10
    assert len(trace.packets) == 10
    assert trace.sent == 100, "the counters must survive what the ring drops"
