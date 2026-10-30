# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""ICMP errors that concern one of our connections.

A router on the path quotes the start of a packet we sent; the quote is how the
error finds its socket. Fragmentation-needed clamps that connection's MSS, a
hard error fails a connect at once instead of after the connect timeout, and
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
from usernet.net.tcb import State

ROUTER_IP = "10.221.0.1"


def icmp_error(
    connection: Connection,
    *,
    message_type: int = icmp.DEST_UNREACHABLE,
    code: int,
    mtu: int = 0,
    local_port: int | None = None,
) -> bytes:
    """An ICMP error from a router, quoting a segment we sent."""
    quoted = build_ipv4(
        source=LOCAL_IP,
        destination=REMOTE_IP,
        protocol=PROTO_TCP,
        payload=struct.pack(
            "!HHI", local_port or connection.local_port, REMOTE_PORT, connection.isn
        ),
    )
    message = bytearray(struct.pack("!BBHHH", message_type, code, 0, 0, mtu) + quoted)
    struct.pack_into("!H", message, 2, checksum(message))
    return build_ipv4(
        source=ROUTER_IP, destination=LOCAL_IP, protocol=PROTO_ICMP, payload=bytes(message)
    )


def errors(connection: Connection) -> list[Exception]:
    return [e.error for e in connection.stack.take_events() if isinstance(e, SocketError)]


# --- fragmentation needed ----------------------------------------------------


def test_fragmentation_needed_clamps_the_mss_of_what_follows() -> None:
    connection = Connection()
    connection.establish()
    stack = connection.stack

    stack.handle_input(icmp_error(connection, code=icmp.FRAGMENTATION_NEEDED, mtu=1000), 2)
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
    connection = Connection()
    connection.establish()

    connection.stack.handle_input(
        icmp_error(connection, code=icmp.FRAGMENTATION_NEEDED, mtu=mtu), 2
    )

    assert connection.stack._tcbs[connection.sid].peer_mss == 536


def test_fragmentation_needed_never_raises_the_mss() -> None:
    connection = Connection()
    connection.establish()
    before = connection.stack._tcbs[connection.sid].peer_mss

    connection.stack.handle_input(
        icmp_error(connection, code=icmp.FRAGMENTATION_NEEDED, mtu=9000), 2
    )

    assert connection.stack._tcbs[connection.sid].peer_mss == before


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
    connection = Connection()
    connection.establish()

    connection.stack.handle_input(icmp_error(connection, code=3), 2)

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
