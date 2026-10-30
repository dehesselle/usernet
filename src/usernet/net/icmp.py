# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""ICMP codec -- echo, and the unreachable errors that matter.

Echo is the fastest possible "is this tunnel actually carrying traffic" check,
which is why it lands before TCP. Destination-unreachable parsing matters
because it turns a fifteen-second connect timeout into an instant, accurate
error, and because code 4 (fragmentation needed) is the mitigation for the
silent-hang failure mode.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from usernet.errors import ProtocolParseError
from usernet.net.checksum import checksum

HEADER = struct.Struct("!BBHHH")
HEADER_LEN = 8

ECHO_REPLY = 0
DEST_UNREACHABLE = 3
ECHO_REQUEST = 8
TIME_EXCEEDED = 11

# Codes of DEST_UNREACHABLE that RFC 1122 4.2.3.9 treats as hard errors during
# connection establishment: report them immediately instead of waiting out the
# connect timeout.
#
# Code 4 is deliberately excluded even though the RFC lists it. Fragmentation-
# needed is the path-MTU signal, and the correct response is to clamp that
# connection's MSS and retransmit -- aborting on it would turn a recoverable
# MTU mismatch into a dead connection.
FRAGMENTATION_NEEDED = 4
HARD_ERROR_CODES = frozenset({2, 3, 9, 10, 13})


@dataclass(frozen=True, slots=True)
class IcmpMessage:
    """A parsed ICMP message.

    ``ident`` and ``sequence`` are only meaningful for echo; for
    destination-unreachable the second 32-bit word carries the next-hop MTU in
    its low half instead, exposed as :attr:`next_hop_mtu`.
    """

    type: int
    code: int
    ident: int
    sequence: int
    payload: bytes

    @property
    def is_echo_reply(self) -> bool:
        return self.type == ECHO_REPLY

    @property
    def next_hop_mtu(self) -> int | None:
        """The MTU advertised by a fragmentation-needed message."""
        if self.type == DEST_UNREACHABLE and self.code == FRAGMENTATION_NEEDED:
            return self.sequence
        return None

    @property
    def is_hard_error(self) -> bool:
        return self.type == DEST_UNREACHABLE and self.code in HARD_ERROR_CODES


def parse_icmp(data: bytes | memoryview) -> IcmpMessage:
    view = memoryview(data)
    if len(view) < HEADER_LEN:
        raise ProtocolParseError(f"ICMP message is {len(view)} bytes, minimum is {HEADER_LEN}")

    message_type, code, _checksum, ident, sequence = HEADER.unpack_from(view)
    return IcmpMessage(
        type=message_type,
        code=code,
        ident=ident,
        sequence=sequence,
        payload=bytes(view[HEADER_LEN:]),
    )


def verify_checksum(data: bytes | memoryview) -> bool:
    """ICMP checksums cover the whole message, with no pseudo-header."""
    return checksum(data) == 0


def build_echo_request(ident: int, sequence: int, payload: bytes = b"") -> bytes:
    return _build(ECHO_REQUEST, 0, ident, sequence, payload)


def build_echo_reply(ident: int, sequence: int, payload: bytes = b"") -> bytes:
    return _build(ECHO_REPLY, 0, ident, sequence, payload)


def _build(message_type: int, code: int, ident: int, sequence: int, payload: bytes) -> bytes:
    header = HEADER.pack(message_type, code, 0, ident, sequence)
    computed = checksum(header + payload)
    return header[:2] + struct.pack("!H", computed) + header[4:] + payload


def quoted_headers(message: IcmpMessage) -> tuple[str, str, int, int] | None:
    """Recover the (source, destination, source port, destination port) of the
    datagram that provoked an ICMP error.

    Error messages quote the offending IP header plus its first eight bytes,
    which for TCP and UDP is exactly the two port numbers -- enough to find
    the socket the error belongs to.
    """
    from usernet.net.ipv4 import parse_ipv4  # local import keeps the modules acyclic

    if message.type not in (DEST_UNREACHABLE, TIME_EXCEEDED):
        return None
    try:
        header, payload = parse_ipv4(message.payload)
    except ProtocolParseError:
        return None
    if len(payload) < 4:
        return None
    source_port, destination_port = struct.unpack_from("!HH", payload)
    return header.source, header.destination, source_port, destination_port


def quoted_tcp_sequence(message: IcmpMessage) -> int | None:
    """The sequence number of the TCP segment an ICMP error quotes.

    The eight quoted bytes end with it, so every error that names a TCP
    socket also says which segment provoked it.
    """
    from usernet.net.ipv4 import parse_ipv4

    try:
        _header, payload = parse_ipv4(message.payload)
    except ProtocolParseError:
        return None
    if len(payload) < 8:
        return None
    (sequence,) = struct.unpack_from("!I", payload, 4)
    return int(sequence)
