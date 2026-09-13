"""IPv4 header codec.

Sans-IO, so addresses go through :mod:`ipaddress` rather than ``socket``.
Runs on every packet in both directions, so the ``struct.Struct`` is built
once and parsing returns a ``memoryview`` of the payload rather than a copy.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

from usernet.errors import ProtocolParseError
from usernet.net.checksum import checksum

HEADER = struct.Struct("!BBHHHBBH4s4s")
MIN_HEADER_LEN = 20
DEFAULT_TTL = 64

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

FLAG_DONT_FRAGMENT = 0x2
FLAG_MORE_FRAGMENTS = 0x1


@dataclass(frozen=True, slots=True)
class Ipv4Header:
    """A parsed IPv4 header."""

    source: str
    destination: str
    protocol: int
    header_length: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int

    @property
    def is_fragment(self) -> bool:
        """True for any packet that is part of a fragmented datagram.

        We set DF on everything we send and keep our MSS below the tunnel MTU,
        so inbound fragments should never occur; they are dropped and logged
        loudly rather than reassembled.
        """
        return bool(self.flags & FLAG_MORE_FRAGMENTS) or self.fragment_offset != 0


def parse_ipv4(packet: bytes | memoryview) -> tuple[Ipv4Header, memoryview]:
    """Parse an IPv4 packet into its header and a view of the payload.

    Raises :class:`ProtocolParseError` for anything malformed -- these bytes
    come off the tunnel and are entirely untrusted.
    """
    view = memoryview(packet)
    if len(view) < MIN_HEADER_LEN:
        raise ProtocolParseError(f"IPv4 packet is {len(view)} bytes, minimum is {MIN_HEADER_LEN}")

    version_ihl = view[0]
    if version_ihl >> 4 != 4:
        raise ProtocolParseError(f"not IPv4: version field is {version_ihl >> 4}")

    header_length = (version_ihl & 0x0F) * 4
    if header_length < MIN_HEADER_LEN:
        raise ProtocolParseError(f"IPv4 header length {header_length} is below the minimum")
    if header_length > len(view):
        raise ProtocolParseError(f"IPv4 header length {header_length} exceeds the packet")

    (
        _version_ihl,
        _dscp,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        _checksum,
        source,
        destination,
    ) = HEADER.unpack_from(view)

    # Trust the wire length over the declared one: a truncated packet would
    # otherwise hand callers a payload view running past the real data.
    if total_length > len(view):
        total_length = len(view)

    header = Ipv4Header(
        source=str(ipaddress.IPv4Address(source)),
        destination=str(ipaddress.IPv4Address(destination)),
        protocol=protocol,
        header_length=header_length,
        total_length=total_length,
        identification=identification,
        flags=flags_fragment >> 13,
        fragment_offset=(flags_fragment & 0x1FFF) * 8,
        ttl=ttl,
    )
    return header, view[header_length:total_length]


def verify_header_checksum(packet: bytes | memoryview) -> bool:
    view = memoryview(packet)
    header_length = (view[0] & 0x0F) * 4
    if header_length < MIN_HEADER_LEN or header_length > len(view):
        return False
    return checksum(view[:header_length]) == 0


def build_ipv4(
    *,
    source: str,
    destination: str,
    protocol: int,
    payload: bytes,
    identification: int = 0,
    ttl: int = DEFAULT_TTL,
    dont_fragment: bool = True,
) -> bytes:
    """Build an IPv4 packet.

    ``dont_fragment`` defaults to true: we size everything from the tunnel MTU
    and never fragment on send, which is what lets path-MTU problems surface
    as ICMP frag-needed rather than as silent corruption.
    """
    flags_fragment = (FLAG_DONT_FRAGMENT << 13) if dont_fragment else 0
    total_length = MIN_HEADER_LEN + len(payload)

    header = HEADER.pack(
        0x45,  # version 4, 5 words of header (no options)
        0,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        0,  # checksum, filled in below
        ipaddress.IPv4Address(source).packed,
        ipaddress.IPv4Address(destination).packed,
    )
    computed = checksum(header)
    return header[:10] + struct.pack("!H", computed) + header[12:] + payload
