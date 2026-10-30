# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""ICMP errors that concern one of our connections.

A router on the path quotes the start of a packet we sent; the quote is how the
error finds its socket, and the sequence number in it must be one still in
flight (RFC 5927). Fragmentation-needed clamps that connection's MSS, a hard
error fails a connect at once instead of after the connect timeout, and
everything else changes nothing.
"""

from __future__ import annotations

import struct

import pytest

from tests.unit.test_stack_checksums import LOCAL_IP, REMOTE_IP, REMOTE_PORT, Connection
from usernet.errors import ConnectionRefused, HostUnreachable, NetworkError
from usernet.net import icmp
from usernet.net.checksum import checksum
from usernet.net.events import PacketDropped, SocketError
from usernet.net.ipv4 import PROTO_ICMP, PROTO_TCP, build_ipv4, parse_ipv4
from usernet.net.tcb import State, TcbConfig
from usernet.net.tcp import seq_add

ROUTER_IP = "10.221.0.1"


def icmp_error(
    connection: Connection,
    *,
    message_type: int = icmp.DEST_UNREACHABLE,
    code: int,
    mtu: int = 0,
    local_port: int | None = None,
    seq: int | None = None,
) -> bytes:
    """An ICMP error from a router, quoting a segment we sent: our SYN unless
    ``seq`` says otherwise."""
    quoted = build_ipv4(
        source=LOCAL_IP,
        destination=REMOTE_IP,
        protocol=PROTO_TCP,
        payload=struct.pack(
            "!HHI",
            local_port or connection.local_port,
            REMOTE_PORT,
            connection.isn if seq is None else seq,
        ),
    )
    message = bytearray(struct.pack("!BBHHH", message_type, code, 0, 0, mtu) + quoted)
    struct.pack_into("!H", message, 2, checksum(message))
    return build_ipv4(
        source=ROUTER_IP, destination=LOCAL_IP, protocol=PROTO_ICMP, payload=bytes(message)
    )


def errors(connection: Connection) -> list[Exception]:
    return [e.error for e in connection.stack.take_events() if isinstance(e, SocketError)]


def established_with_data_in_flight() -> tuple[Connection, int]:
    """A connection with one unacknowledged segment, and its sequence number:
    the only kind of segment an error may concern once connected."""
    connection = Connection()
    connection.establish()
    connection.stack.tcp_send(connection.sid, memoryview(b"m" * 100), 2)
    connection.stack.take_output()
    return connection, seq_add(connection.isn, 1)


def peer_mss(connection: Connection) -> int:
    return connection.stack._tcbs[connection.sid].peer_mss


# --- fragmentation needed ----------------------------------------------------


def test_fragmentation_needed_clamps_the_mss_of_what_follows() -> None:
    connection, seq = established_with_data_in_flight()
    stack = connection.stack

    stack.handle_input(icmp_error(connection, code=icmp.FRAGMENTATION_NEEDED, mtu=1000, seq=seq), 2)
    assert "pmtu-clamp" in connection.drops()

    stack.tcp_send(connection.sid, memoryview(b"m" * 5000), 3)
    sent = stack.take_output()
    assert sent
    assert max(len(packet) for packet in sent) <= 1000
    assert stack.tcp_state(connection.sid) is State.ESTABLISHED


@pytest.mark.parametrize("mtu", [0, 68, 575])
def test_an_implausibly_small_mtu_clamps_no_lower_than_the_rfc_floor(mtu: int) -> None:
    """An MTU of zero is what pre-RFC 1191 routers send. A tiny one is either
    that or a forgery; neither may shrink segments below 536 bytes."""
    connection, seq = established_with_data_in_flight()

    connection.stack.handle_input(
        icmp_error(connection, code=icmp.FRAGMENTATION_NEEDED, mtu=mtu, seq=seq), 2
    )

    assert peer_mss(connection) == 536


@pytest.mark.parametrize("mtu", [9000, 300])
def test_fragmentation_needed_never_raises_the_mss(mtu: int) -> None:
    """Not above what the connection uses, and not to the RFC floor either
    when the connection's own MSS is below it: that comes from the tunnel."""
    connection, seq = established_with_data_in_flight()
    before = peer_mss(connection)

    connection.stack.handle_input(
        icmp_error(connection, code=icmp.FRAGMENTATION_NEEDED, mtu=mtu, seq=seq), 2
    )

    assert peer_mss(connection) == min(before, max(536, mtu - 40))


def test_fragmentation_needed_does_not_raise_a_small_configured_mss() -> None:
    connection = Connection(tcb=TcbConfig(mss=400))
    connection.establish()
    connection.stack.tcp_send(connection.sid, memoryview(b"m" * 100), 2)
    connection.stack.take_output()

    connection.stack.handle_input(
        icmp_error(
            connection, code=icmp.FRAGMENTATION_NEEDED, mtu=300, seq=seq_add(connection.isn, 1)
        ),
        2,
    )

    assert peer_mss(connection) == 400


@pytest.mark.parametrize(
    "offset", [-1, 100, 5000, 2**31 - 1], ids=["acknowledged", "unsent", "far", "opposite"]
)
def test_fragmentation_needed_for_a_segment_not_in_flight_is_ignored(offset: int) -> None:
    """RFC 5927 4.1. The four-tuple can be guessed; the sequence number of a
    segment in flight cannot, and without it a forged error shrinks any
    connection's segments at will."""
    connection, seq = established_with_data_in_flight()
    before = peer_mss(connection)

    connection.stack.handle_input(
        icmp_error(connection, code=icmp.FRAGMENTATION_NEEDED, mtu=600, seq=seq_add(seq, offset)),
        3,
    )

    assert peer_mss(connection) == before
    assert connection.drops() == ["icmp-stale"]


# --- hard and soft errors ----------------------------------------------------


@pytest.mark.parametrize(
    ("code", "expected"),
    [(3, ConnectionRefused), (2, HostUnreachable), (13, HostUnreachable)],
    ids=["port", "protocol", "prohibited"],
)
def test_a_hard_error_fails_the_connect_with_its_own_cause(
    code: int, expected: type[NetworkError]
) -> None:
    """One error, of the right type: the socket's error is what the
    application raises, and "reset" would name the wrong cause."""
    connection = Connection()

    connection.stack.handle_input(icmp_error(connection, code=code), 2)

    (error,) = errors(connection)
    assert type(error) is expected
    assert connection.stack.tcp_state(connection.sid) is None


def test_a_hard_error_quoting_another_syn_is_ignored() -> None:
    connection = Connection()

    connection.stack.handle_input(
        icmp_error(connection, code=3, seq=seq_add(connection.isn, 12345)), 2
    )

    assert errors(connection) == []
    assert connection.stack.tcp_state(connection.sid) is State.SYN_SENT


@pytest.mark.parametrize("code", [0, 1, 5, 11, 12])
def test_a_soft_error_leaves_the_connect_running(code: int) -> None:
    """RFC 1122 4.2.3.9: these may be transient, so the SYN keeps trying."""
    connection = Connection()

    connection.stack.handle_input(icmp_error(connection, code=code), 2)

    assert errors(connection) == []
    assert connection.stack.tcp_state(connection.sid) is State.SYN_SENT


def test_a_hard_error_does_not_abort_an_established_connection() -> None:
    """Only a connect fails fast. An established connection rides it out,
    as Linux does, rather than dying on one router's word."""
    connection, seq = established_with_data_in_flight()

    connection.stack.handle_input(icmp_error(connection, code=3, seq=seq), 2)

    assert errors(connection) == []
    assert connection.stack.tcp_state(connection.sid) is State.ESTABLISHED


def test_time_exceeded_changes_nothing() -> None:
    connection = Connection()

    connection.stack.handle_input(
        icmp_error(connection, message_type=icmp.TIME_EXCEEDED, code=0), 2
    )

    assert errors(connection) == []
    assert connection.stack.tcp_state(connection.sid) is State.SYN_SENT


# --- errors that are not ours ------------------------------------------------


def test_an_error_quoting_another_connection_is_ignored() -> None:
    connection = Connection()

    connection.stack.handle_input(
        icmp_error(connection, code=3, local_port=connection.local_port ^ 1), 2
    )

    assert errors(connection) == []
    assert connection.stack.tcp_state(connection.sid) is State.SYN_SENT


def test_an_error_with_a_truncated_quote_is_ignored() -> None:
    connection = Connection()
    packet = icmp_error(connection, code=3)
    _header, message = parse_ipv4(packet)
    short = bytearray(message[: icmp.HEADER_LEN + 20 + 2])  # cut inside the ports
    struct.pack_into("!H", short, 2, 0)
    struct.pack_into("!H", short, 2, checksum(short))

    connection.stack.handle_input(
        build_ipv4(source=ROUTER_IP, destination=LOCAL_IP, protocol=PROTO_ICMP, payload=short), 2
    )

    assert errors(connection) == []
    assert connection.stack.tcp_state(connection.sid) is State.SYN_SENT
    assert not any(isinstance(e, PacketDropped) for e in connection.stack.take_events())
