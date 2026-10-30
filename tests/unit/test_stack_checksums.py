# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Received checksums are verified at every layer, not only the IP header.

RFC 1122 4.2.2.7 (RFC 9293 MUST-3): a TCP receiver MUST check the checksum.
RFC 1122 4.1.3.4: a UDP datagram with a non-zero, invalid checksum MUST be
silently discarded. Every corruption below leaves the IP header intact, so
these packets pass the one check the stack used to make.
"""

from __future__ import annotations

from usernet.net import icmp
from usernet.net.events import IcmpEchoReply, PacketDropped, UdpReceived
from usernet.net.ipv4 import PROTO_ICMP, PROTO_TCP, PROTO_UDP, build_ipv4, parse_ipv4
from usernet.net.stack import PyStack, StackConfig
from usernet.net.tcb import State
from usernet.net.tcp import Flag, build_tcp, parse_tcp, seq_add
from usernet.net.udp import build_udp

LOCAL_IP = "172.29.29.5"
REMOTE_IP = "10.221.188.32"
REMOTE_PORT = 443
PEER_ISN = 9000


def corrupt(packet: bytes) -> bytes:
    """Flip one bit in the last byte: payload, never the IP header."""
    return packet[:-1] + bytes([packet[-1] ^ 0x01])


def ip(protocol: int, payload: bytes) -> bytes:
    return build_ipv4(source=REMOTE_IP, destination=LOCAL_IP, protocol=protocol, payload=payload)


class Connection:
    """A stack with one socket, driven by hand as the remote peer."""

    def __init__(self, **config: object) -> None:
        self.stack = PyStack(StackConfig(local_ip=LOCAL_IP, rng=lambda: 7, **config))  # type: ignore[arg-type]
        self.stack.trace_drops = True
        self.sid = self.stack.tcp_connect((REMOTE_IP, REMOTE_PORT))
        self.stack.start_connect(self.sid, 0)
        (syn,) = self.stack.take_output()
        ours = parse_tcp(parse_ipv4(syn)[1])
        self.local_port = ours.source_port
        self.isn = ours.seq

    def segment(self, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
        return ip(
            PROTO_TCP,
            build_tcp(
                source_ip=REMOTE_IP,
                destination_ip=LOCAL_IP,
                source_port=REMOTE_PORT,
                destination_port=self.local_port,
                seq=seq,
                ack=ack,
                flags=flags,
                window=0xFFFF,
                payload=payload,
                mss=1300 if flags & Flag.SYN else None,
            ),
        )

    def synack(self) -> bytes:
        return self.segment(PEER_ISN, seq_add(self.isn, 1), Flag.SYN | Flag.ACK)

    def establish(self) -> None:
        self.stack.handle_input(self.synack(), 1)
        assert self.stack.tcp_state(self.sid) is State.ESTABLISHED
        self.stack.take_output()
        self.stack.take_events()

    def drops(self) -> list[str]:
        return [e.reason for e in self.stack.take_events() if isinstance(e, PacketDropped)]


def test_a_damaged_data_segment_is_dropped_and_its_resend_accepted() -> None:
    conn = Connection()
    conn.establish()
    data = conn.segment(seq_add(PEER_ISN, 1), seq_add(conn.isn, 1), Flag.ACK | Flag.PSH, b"intact")

    conn.stack.handle_input(corrupt(data), 2)
    assert conn.drops() == ["bad-tcp-checksum"]
    assert conn.stack.tcp_rx_available(conn.sid) == 0
    assert conn.stack.take_output() == [], "a damaged segment must not even be ACKed"

    conn.stack.handle_input(data, 3)  # the peer's retransmission
    assert conn.stack.tcp_recv(conn.sid, 100, 3) == b"intact"


def test_a_damaged_synack_does_not_complete_the_handshake() -> None:
    conn = Connection()
    conn.stack.handle_input(corrupt(conn.synack()), 1)
    assert conn.drops() == ["bad-tcp-checksum"]
    assert conn.stack.tcp_state(conn.sid) is State.SYN_SENT


def test_verification_can_be_turned_off() -> None:
    """For tests that feed hand-made packets; never in production."""
    conn = Connection(verify_checksums=False)
    conn.establish()
    data = conn.segment(seq_add(PEER_ISN, 1), seq_add(conn.isn, 1), Flag.ACK | Flag.PSH, b"intact")
    conn.stack.handle_input(corrupt(data), 2)
    assert conn.stack.tcp_rx_available(conn.sid) == 6


def udp_datagram(payload: bytes, *, zero_checksum: bool = False) -> bytes:
    datagram = build_udp(
        source_ip=REMOTE_IP,
        destination_ip=LOCAL_IP,
        source_port=53,
        destination_port=5353,
        payload=payload,
    )
    if zero_checksum:
        datagram = datagram[:6] + b"\x00\x00" + datagram[8:]
    return ip(PROTO_UDP, datagram)


def test_a_damaged_udp_datagram_is_dropped() -> None:
    stack = PyStack(StackConfig(local_ip=LOCAL_IP))
    stack.trace_drops = True
    sid = stack.udp_open(5353)
    stack.handle_input(corrupt(udp_datagram(b"answer")), 0)
    events = stack.take_events()
    assert [e.reason for e in events if isinstance(e, PacketDropped)] == ["bad-udp-checksum"]
    assert stack.udp_recv_from(sid) is None


def test_a_udp_datagram_without_a_checksum_is_delivered() -> None:
    """Zero means the sender computed none, which IPv4 UDP allows."""
    stack = PyStack(StackConfig(local_ip=LOCAL_IP))
    sid = stack.udp_open(5353)
    stack.handle_input(udp_datagram(b"answer", zero_checksum=True), 0)
    assert any(isinstance(e, UdpReceived) for e in stack.take_events())
    assert stack.udp_recv_from(sid) == ((REMOTE_IP, 53), b"answer")


def test_a_damaged_echo_reply_is_dropped() -> None:
    stack = PyStack(StackConfig(local_ip=LOCAL_IP))
    stack.trace_drops = True
    reply = ip(PROTO_ICMP, icmp.build_echo_reply(7, 1, b"usernet"))

    stack.handle_input(corrupt(reply), 0)
    events = stack.take_events()
    assert [e.reason for e in events if isinstance(e, PacketDropped)] == ["bad-icmp-checksum"]
    assert not any(isinstance(e, IcmpEchoReply) for e in events)

    stack.handle_input(reply, 1)
    assert any(isinstance(e, IcmpEchoReply) for e in stack.take_events())
