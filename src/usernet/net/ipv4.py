# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""IPv4 header codec.

Sans-IO, so addresses go through :mod:`ipaddress` rather than ``socket`` --
always by way of :func:`packed_address` and :func:`dotted_address`, which
cache the conversion.
Runs on every packet in both directions, so the ``struct.Struct`` is built
once and parsing returns a ``memoryview`` of the payload rather than a copy.
"""

from __future__ import annotations

import functools
import ipaddress
import struct
from dataclasses import dataclass

from usernet.errors import ProtocolParseError
from usernet.net.checksum import checksum

HEADER = struct.Struct("!BBHHHBBH4s4s")
_CHECKSUM = struct.Struct("!H")
MIN_HEADER_LEN = 20
DEFAULT_TTL = 64

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

FLAG_DONT_FRAGMENT = 0x2
FLAG_MORE_FRAGMENTS = 0x1


@functools.lru_cache(maxsize=1024)
def packed_address(address: str) -> bytes:
    """``"10.0.0.1"`` as its 4 wire bytes, validated as :mod:`ipaddress` does.

    Every packet converts its two addresses, they are nearly always the same
    few, and :mod:`ipaddress` takes microseconds each time -- in the profile
    of a bulk transfer it was the largest single cost after enum flags.
    Cached, so the validation still happens, once per address. Bounded,
    because some of these addresses come off the tunnel and are the peer's to
    choose. Raises for anything that is not a dotted quad: the header is
    packed with ``4s``, which would silently pad or truncate it.
    """
    return ipaddress.IPv4Address(address).packed


@functools.lru_cache(maxsize=1024)
def dotted_address(packed: bytes) -> str:
    """4 wire bytes as ``"10.0.0.1"``; the inverse of :func:`packed_address`."""
    return str(ipaddress.IPv4Address(packed))


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
        source=dotted_address(source),
        destination=dotted_address(destination),
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
    packet = bytearray(MIN_HEADER_LEN + len(payload))
    packet[MIN_HEADER_LEN:] = payload
    pack_header_into(
        packet,
        source=packed_address(source),
        destination=packed_address(destination),
        protocol=protocol,
        identification=identification,
        ttl=ttl,
        dont_fragment=dont_fragment,
    )
    return bytes(packet)


def pack_header_into(
    packet: bytearray,
    *,
    source: bytes,
    destination: bytes,
    protocol: int,
    identification: int = 0,
    ttl: int = DEFAULT_TTL,
    dont_fragment: bool = True,
) -> None:
    """Write the header, checksum included, over the first 20 bytes of ``packet``.

    The payload must already be in place behind it: the total length is taken
    from the buffer. Every IPv4 packet we send has its header written here, so
    the layout exists exactly once, whichever builder assembles the packet.
    """
    HEADER.pack_into(
        packet,
        0,
        0x45,  # version 4, 5 words of header (no options)
        0,
        len(packet),
        identification,
        (FLAG_DONT_FRAGMENT << 13) if dont_fragment else 0,
        ttl,
        protocol,
        0,  # checksum, filled in below
        source,
        destination,
    )
    with memoryview(packet) as view:
        computed = checksum(view[:MIN_HEADER_LEN])
    _CHECKSUM.pack_into(packet, 10, computed)
