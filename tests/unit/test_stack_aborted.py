# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""A connection we aborted is still answered, so its peer lets go of it.

Our RST carries SND.NXT. A peer that never received the data before it holds
RCV.NXT lower, and RFC 5961 has it answer with a challenge ACK rather than
reset. Found by the conformance suite under 2% loss, where the kernel kept
the connection because nobody answered that ACK.
"""

from __future__ import annotations

from tests.unit.test_stack_checksums import PEER_ISN, REMOTE_IP, REMOTE_PORT, Connection
from usernet.net.ipv4 import parse_ipv4
from usernet.net.tcb import TcbConfig
from usernet.net.tcp import Flag, TcpSegment, parse_tcp, seq_add


def aborted_with_data_in_flight(**config: object) -> Connection:
    connection = Connection(**config)
    connection.establish()
    connection.stack.tcp_send(connection.sid, memoryview(b"partial request"), 2)
    connection.stack.tcp_abort(connection.sid, 2)
    sent = [parse_tcp(parse_ipv4(packet)[1]) for packet in connection.stack.take_output()]
    assert [s.flags & Flag.RST for s in sent][-1], "the abort sent no RST"
    connection.stack.take_events()
    return connection


def replies(connection: Connection) -> list[TcpSegment]:
    return [parse_tcp(parse_ipv4(packet)[1]) for packet in connection.stack.take_output()]


def test_a_challenge_ack_gets_a_reset_at_the_sequence_it_names() -> None:
    """The peer never got the data, so its RCV.NXT is just past our SYN."""
    connection = aborted_with_data_in_flight()
    challenge_ack = seq_add(connection.isn, 1)

    connection.stack.handle_input(
        connection.segment(seq_add(PEER_ISN, 1), challenge_ack, Flag.ACK), 3
    )

    (reset,) = replies(connection)
    assert reset.flags == Flag.RST
    assert reset.seq == challenge_ack
    assert (reset.source_port, reset.destination_port) == (connection.local_port, REMOTE_PORT)


def test_a_peer_still_sending_after_a_lost_reset_is_reset() -> None:
    connection = aborted_with_data_in_flight()
    ack = seq_add(connection.isn, 16)

    connection.stack.handle_input(
        connection.segment(seq_add(PEER_ISN, 1), ack, Flag.ACK | Flag.PSH, b"response"), 3
    )

    (reset,) = replies(connection)
    assert (reset.flags, reset.seq) == (Flag.RST, ack)


def test_a_reset_is_never_answered() -> None:
    connection = aborted_with_data_in_flight()

    connection.stack.handle_input(
        connection.segment(seq_add(PEER_ISN, 1), seq_add(connection.isn, 1), Flag.RST | Flag.ACK),
        3,
    )

    assert replies(connection) == []


def test_the_four_tuple_is_answered_only_as_long_as_time_wait() -> None:
    """Aborted at 2, so answered until 1002 and not after."""
    connection = aborted_with_data_in_flight(tcb=TcbConfig(time_wait_ms=1000))
    challenge = connection.segment(seq_add(PEER_ISN, 1), seq_add(connection.isn, 1), Flag.ACK)

    connection.stack.handle_input(challenge, 1001)
    assert len(replies(connection)) == 1
    connection.stack.handle_input(challenge, 1002)
    assert replies(connection) == [], "answered after TIME_WAIT would have ended"
    assert connection.drops()[-1] == "no-socket"


def test_a_four_tuple_never_aborted_stays_silent() -> None:
    """The reason for silence -- a scanner learns nothing -- still holds for
    every four-tuple whose peer has not already talked to us."""
    connection = aborted_with_data_in_flight()
    connection.local_port ^= 1  # the next segment goes to a neighbouring port

    connection.stack.handle_input(connection.segment(seq_add(PEER_ISN, 1), 1, Flag.ACK), 3)

    assert replies(connection) == []
    assert connection.drops() == ["no-socket"]


def test_a_connection_the_peer_reset_is_not_remembered() -> None:
    """We sent no RST, so there is nothing for the peer to challenge."""
    connection = Connection()
    connection.establish()
    connection.stack.handle_input(
        connection.segment(seq_add(PEER_ISN, 1), seq_add(connection.isn, 1), Flag.RST), 2
    )
    connection.stack.take_events()

    connection.stack.handle_input(
        connection.segment(seq_add(PEER_ISN, 1), seq_add(connection.isn, 1), Flag.ACK), 3
    )

    assert replies(connection) == []


def test_a_new_connection_does_not_reuse_an_aborted_four_tuple() -> None:
    """If our RST was lost the peer still has that connection, and a SYN on
    its four-tuple would draw the old connection's ACK, not a SYN-ACK."""
    connection = aborted_with_data_in_flight()
    stack = connection.stack
    stack._next_port = connection.local_port

    sid = stack.tcp_connect((REMOTE_IP, REMOTE_PORT))

    assert stack._tcbs[sid].local_port != connection.local_port


def test_the_memory_is_bounded_by_the_socket_limit() -> None:
    connection = Connection(max_sockets=4)
    stack = connection.stack
    for _ in range(20):
        sid = stack.tcp_connect((REMOTE_IP, REMOTE_PORT))
        stack.start_connect(sid, 1)
        stack.tcp_abort(sid, 1)

    assert len(stack._aborted) <= 4
