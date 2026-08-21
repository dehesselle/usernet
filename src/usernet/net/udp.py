"""UDP codec.

Deliberately thin. The only consumer for now is diagnostics; in-tunnel DNS is
not being built, because the gateway this was developed against advertises no
DNS servers at all and sets ``Tunnel-All-DNS: false``.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

from usernet.errors import ProtocolParseError
from usernet.net.checksum import checksum, ones_complement_sum, pseudo_header_sum

HEADER = struct.Struct("!HHHH")
HEADER_LEN = 8
PROTO_UDP = 17


@dataclass(frozen=True, slots=True)
class UdpDatagram:
    source_port: int
    destination_port: int
    payload: bytes


def parse_udp(data: bytes | memoryview) -> UdpDatagram:
    view = memoryview(data)
    if len(view) < HEADER_LEN:
        raise ProtocolParseError(f"UDP datagram is {len(view)} bytes, minimum is {HEADER_LEN}")

    source_port, destination_port, length, _checksum = HEADER.unpack_from(view)
    if length < HEADER_LEN:
        raise ProtocolParseError(f"UDP length field {length} is below the header size")

    # Trust the wire over the declared length, as with IPv4.
    end = min(length, len(view))
    return UdpDatagram(
        source_port=source_port,
        destination_port=destination_port,
        payload=bytes(view[HEADER_LEN:end]),
    )


def build_udp(
    *,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    payload: bytes,
) -> bytes:
    length = HEADER_LEN + len(payload)
    header = HEADER.pack(source_port, destination_port, length, 0)
    partial = pseudo_header_sum(
        ipaddress.IPv4Address(source_ip).packed,
        ipaddress.IPv4Address(destination_ip).packed,
        proto=PROTO_UDP,
        length=length,
    )
    computed = checksum(header + payload, partial)
    # A computed checksum of zero must be transmitted as 0xFFFF, since zero
    # means "not computed" in UDP.
    if computed == 0:
        computed = 0xFFFF
    return header[:6] + struct.pack("!H", computed) + payload


def verify_udp_checksum(source_ip: str, destination_ip: str, datagram: bytes | memoryview) -> bool:
    """A zero checksum means the sender did not compute one; accept it."""
    view = memoryview(datagram)
    if len(view) < HEADER_LEN:
        return False
    if view[6] == 0 and view[7] == 0:
        return True
    partial = pseudo_header_sum(
        ipaddress.IPv4Address(source_ip).packed,
        ipaddress.IPv4Address(destination_ip).packed,
        proto=PROTO_UDP,
        length=len(view),
    )
    return ones_complement_sum(view, partial) == 0xFFFF
