# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The stack against hostile packets.

Everything handle_input sees came off a tunnel, and anything behind the
gateway can put bytes there. Whatever arrives, the stack must not raise, must
not create state for it, and must answer -- if at all -- with a well-formed
packet of its own.

Random bytes alone would test only the first check: almost none of them carry
a valid checksum. So Hypothesis builds packets field by field, lying in
whichever fields it likes, and then usually signs them with correct checksums,
which is what carries the lies through to the parsers behind.
"""

from __future__ import annotations

import struct

from hypothesis import given
from hypothesis import strategies as st

from tests.unit.test_stack_checksums import LOCAL_IP, REMOTE_IP, REMOTE_PORT, Connection
from usernet.net import icmp
from usernet.net.checksum import checksum, pseudo_header_sum
from usernet.net.events import Event
from usernet.net.ipv4 import (
    PROTO_ICMP,
    PROTO_TCP,
    PROTO_UDP,
    build_ipv4,
    packed_address,
    parse_ipv4,
    verify_header_checksum,
)
from usernet.net.stack import PyStack
from usernet.net.tcp import SEQ_MASK, seq_add, verify_tcp_checksum
from usernet.net.udp import verify_udp_checksum

UDP_PORT = 5353
IN_FLIGHT = 3000  # bytes the connection has sent and not had acknowledged
STRANGER_IP = "10.0.0.1"

TCP_HEADER = struct.Struct("!HHIIBBHHH")
UDP_HEADER = struct.Struct("!HHHH")
ICMP_HEADER = struct.Struct("!BBHI")
IP_HEADER = struct.Struct("!BBHHHBBH4s4s")


def mostly(usual: object, *others: object) -> st.SearchStrategy[object]:
    """``usual`` seven times in eight, whatever the number of alternatives.

    A packet has a dozen fields that can lie. Lie in each too often and
    nearly every packet is dropped at the first check, never reaching the
    code behind it -- which is where the interesting failures live.

    Not ``one_of`` with the usual value repeated: Hypothesis merges equal
    branches, and the usual value then came up one time in seventeen.
    """
    return st.integers(0, 7).flatmap(
        lambda n: st.sampled_from(others) if n == 3 else st.just(usual)
    )


# --- transport payloads ------------------------------------------------------

tcp_option = st.one_of(
    st.just(b"\x00"),
    st.just(b"\x01"),
    st.integers(0, 0xFFFF).map(lambda v: b"\x02\x04" + v.to_bytes(2, "big")),
    st.integers(0, 0xFF).map(lambda v: b"\x03\x03" + bytes([v])),
    st.just(b"\x04\x02"),
    # Well-formed, of any kind.
    st.tuples(st.integers(0, 0xFF), st.binary(max_size=10)).map(
        lambda kb: bytes([kb[0], len(kb[1]) + 2]) + kb[1]
    ),
    # A length that lies: zero, one, or past the end of the options.
    st.tuples(st.integers(0, 0xFF), st.integers(0, 0xFF)).map(bytes),
)


@st.composite
def tcp_segment(draw: st.DrawFn, connection: Connection) -> bytes:
    tcb = connection.stack._tcbs.get(connection.sid)
    near_rcv = tcb.rcv_nxt if tcb is not None else 0
    near_snd = tcb.snd_una if tcb is not None else 0

    ports = draw(mostly((REMOTE_PORT, connection.local_port), None))
    if ports is None:
        ports = (draw(st.integers(0, 0xFFFF)), draw(st.integers(0, 0xFFFF)))
    seq = draw(
        st.one_of(
            st.integers(-100, 70_000).map(lambda d: seq_add(near_rcv, d)),
            st.integers(0, SEQ_MASK),
        )
    )
    ack = draw(
        st.one_of(
            st.integers(-100, 100).map(lambda d: seq_add(near_snd, d)),
            st.integers(0, SEQ_MASK),
        )
    )
    options = draw(st.lists(tcp_option, max_size=12).map(b"".join))[:40]
    # Padding would hand a truncated option the bytes it is missing, so the
    # options are as often cut at the boundary, leaving one hanging off the end.
    if draw(st.booleans()):
        options += b"\x00" * (-len(options) % 4)
    else:
        options = options[: len(options) - len(options) % 4]
    offset = draw(mostly(5 + len(options) // 4, *range(16)))
    flags = draw(st.integers(0, 0xFF))
    window = draw(st.integers(0, 0xFFFF))
    payload = draw(st.binary(max_size=64))

    segment = bytearray(
        TCP_HEADER.pack(*ports, seq, ack, offset << 4, flags, window, 0, 0) + options + payload
    )
    if draw(mostly(True, False)):
        partial = pseudo_header_sum(
            packed_address(REMOTE_IP), packed_address(LOCAL_IP), PROTO_TCP, len(segment)
        )
        struct.pack_into("!H", segment, 16, checksum(segment, partial))
    return bytes(segment)


@st.composite
def udp_datagram(draw: st.DrawFn) -> bytes:
    source_port = draw(st.integers(0, 0xFFFF))
    destination_port = draw(mostly(UDP_PORT, 0, draw(st.integers(0, 0xFFFF))))
    payload = draw(st.binary(max_size=64))
    length = draw(mostly(8 + len(payload), *range(8), draw(st.integers(0, 0xFFFF))))
    datagram = bytearray(UDP_HEADER.pack(source_port, destination_port, length, 0) + payload)
    how = draw(mostly("sign", "unsigned", "garbage"))
    if how == "sign":
        partial = pseudo_header_sum(
            packed_address(REMOTE_IP), packed_address(LOCAL_IP), PROTO_UDP, len(datagram)
        )
        struct.pack_into("!H", datagram, 6, checksum(datagram, partial) or 0xFFFF)
    elif how == "garbage":
        struct.pack_into("!H", datagram, 6, draw(st.integers(1, 0xFFFF)))
    return bytes(datagram)


@st.composite
def icmp_message(draw: st.DrawFn, connection: Connection) -> bytes:
    message_type = draw(
        mostly(
            draw(st.sampled_from([icmp.ECHO_REQUEST, icmp.DEST_UNREACHABLE, icmp.TIME_EXCEEDED])),
            *range(0x100),
        )
    )
    code = draw(mostly(draw(st.sampled_from([3, icmp.FRAGMENTATION_NEEDED])), *range(0x100)))
    rest = draw(st.integers(0, 0xFFFFFFFF))
    if message_type in (icmp.DEST_UNREACHABLE, icmp.TIME_EXCEEDED) and draw(st.booleans()):
        # Quoting our own connection, and mostly a segment still in flight,
        # so the error reaches its socket and gets past RFC 5927's check.
        in_flight = seq_add(connection.isn, 1)
        seq = draw(mostly(in_flight, connection.isn, seq_add(in_flight, IN_FLIGHT), 0))
        quoted = build_ipv4(
            source=LOCAL_IP,
            destination=REMOTE_IP,
            protocol=PROTO_TCP,
            payload=struct.pack("!HHI", connection.local_port, REMOTE_PORT, seq),
        )
        body = quoted[: draw(mostly(len(quoted), *range(len(quoted))))]
    else:
        body = draw(st.binary(max_size=64))
    message = bytearray(ICMP_HEADER.pack(message_type, code, 0, rest) + body)
    if draw(mostly(True, False)):
        struct.pack_into("!H", message, 2, checksum(message))
    return bytes(message)


# --- the IP layer around them ------------------------------------------------


@st.composite
def packet(draw: st.DrawFn, connection: Connection) -> tuple[bytes, bool]:
    """A packet, and whether its IP header is intact enough to be answered."""
    protocol = draw(
        mostly(draw(st.sampled_from([PROTO_TCP, PROTO_UDP, PROTO_ICMP])), *range(0x100))
    )
    if protocol == PROTO_TCP:
        payload = draw(tcp_segment(connection))
    elif protocol == PROTO_UDP:
        payload = draw(udp_datagram())
    elif protocol == PROTO_ICMP:
        payload = draw(icmp_message(connection))
    else:
        payload = draw(st.binary(max_size=64))

    words = draw(mostly(0, *range(11)))
    options = draw(st.binary(min_size=4 * words, max_size=4 * words))
    version = draw(mostly(4, 0, 6, 15))
    ihl = draw(mostly(5 + words, *range(16)))
    total = 20 + len(options) + len(payload)
    total_length = draw(mostly(total, 0, 20, draw(st.integers(0, 0xFFFF))))
    flags_fragment = draw(mostly(0x4000, 0, 0x2000, draw(st.integers(0, 0xFFFF))))
    source = draw(mostly(REMOTE_IP, STRANGER_IP))
    destination = draw(mostly(LOCAL_IP, "10.0.0.99", "255.255.255.255"))

    header = bytearray(
        IP_HEADER.pack(
            version << 4 | ihl,
            0,
            total_length,
            draw(st.integers(0, 0xFFFF)),
            flags_fragment,
            draw(st.integers(0, 0xFF)),
            protocol,
            0,
            packed_address(source),
            packed_address(destination),
        )
        + options
    )
    signed = draw(mostly(True, False))
    if signed:
        struct.pack_into("!H", header, 10, checksum(header))
    data = bytes(header) + payload
    cut = draw(mostly(None, draw(st.integers(0, len(data)))))
    if cut is not None:
        data = data[:cut]
    return data, signed and version == 4


# --- what must hold ----------------------------------------------------------


def check_output(stack: PyStack) -> None:
    """Whatever we send is ours, intact, and fits the link."""
    for out in stack.take_output():
        assert len(out) <= stack.config.mtu
        assert verify_header_checksum(out)
        header, payload = parse_ipv4(out)
        assert header.source == LOCAL_IP
        if header.protocol == PROTO_TCP:
            assert header.destination == REMOTE_IP
            assert verify_tcp_checksum(LOCAL_IP, header.destination, payload)
        elif header.protocol == PROTO_UDP:
            assert verify_udp_checksum(LOCAL_IP, header.destination, payload)
        else:
            assert header.protocol == PROTO_ICMP
            assert icmp.verify_checksum(payload)


def check_state(connection: Connection, udp: object) -> None:
    """Nothing that arrives may create a socket."""
    stack = connection.stack
    assert set(stack._tcbs) <= {connection.sid}
    assert len(stack._by_tuple) == len(stack._tcbs)
    assert list(stack._udp) == [udp]
    assert all(isinstance(event, Event) for event in stack.take_events())


@given(st.data())
def test_hostile_packets_are_survived(data: st.DataObject) -> None:
    connection = Connection()
    connection.establish()
    stack = connection.stack
    # Unacknowledged data, so that ACKs and ICMP errors have something to
    # concern.
    stack.tcp_send(connection.sid, memoryview(b"f" * IN_FLIGHT), 1)
    stack.take_output()
    udp = stack.udp_open(UDP_PORT)

    now = 1
    for _ in range(data.draw(st.integers(1, 30), label="packets")):
        now += data.draw(st.integers(0, 2000), label="delay")
        raw, intact = data.draw(packet(connection), label="packet")
        stack.handle_input(raw, now)
        if not intact:
            assert stack.take_output() == [], "answered a packet with a broken IP header"
        check_output(stack)
        stack.poll(now)
        check_output(stack)
        check_state(connection, udp)
        while stack.udp_recv_from(udp) is not None:
            pass


@given(st.binary(max_size=1500))
def test_random_bytes_are_survived(raw: bytes) -> None:
    connection = Connection()
    connection.establish()
    udp = connection.stack.udp_open(UDP_PORT)
    connection.stack.handle_input(raw, 1)
    check_output(connection.stack)
    check_state(connection, udp)
