"""The seam between a tunnel and the stack that rides on it.

Everything below this module -- the sans-IO stack, the driver, the SOCKS
server -- is written against :class:`IpLink` and nothing else. A tunnel is
whatever can carry raw IPv4 packets in both directions and say what address it
assigned us: CSTP over TLS in ``pyac``, WireGuard over DERP in ``pyts``, a
Linux tun device in the conformance tests, an in-memory queue in the unit
tests. None of those appear in this package's imports, which is the point.

:class:`LinkConfig` is a ``Protocol`` rather than a base class deliberately. A
tunnel's configuration object is mostly tunnel-specific -- DPD timers, rekey
methods, DERP regions -- and only a handful of fields are the stack's business.
Structural typing lets those objects stay whole instead of being split in two
or forced into an inheritance chain that means nothing to them.
"""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@runtime_checkable
class LinkConfig(Protocol):
    """The part of a tunnel's configuration the stack actually reads."""

    @property
    def address(self) -> str:
        """Our address inside the tunnel, as dotted quad."""
        ...

    @property
    def netmask(self) -> str:
        """Its netmask. ``255.255.255.255`` when the tunnel assigns a bare host
        address and there is no on-link subnet at all."""
        ...

    @property
    def mtu(self) -> int:
        """The largest IP packet the tunnel will carry."""
        ...

    @property
    def split_include(self) -> tuple[ipaddress.IPv4Network, ...]:
        """Destinations the tunnel carries. Empty means all of them."""
        ...

    @property
    def split_exclude(self) -> tuple[ipaddress.IPv4Network, ...]:
        """Destinations it refuses, which win over ``split_include``."""
        ...


@dataclass(frozen=True, slots=True)
class SimpleLinkConfig:
    """A :class:`LinkConfig` for links that have nothing more to say.

    Tests and minimal links use this; a real tunnel is expected to satisfy the
    protocol with its own richer object instead.
    """

    address: str
    netmask: str = "255.255.255.255"
    mtu: int = 1500
    split_include: tuple[ipaddress.IPv4Network, ...] = ()
    split_exclude: tuple[ipaddress.IPv4Network, ...] = ()


@runtime_checkable
class IpLink(Protocol):
    """A bidirectional channel carrying raw IPv4 packets."""

    @property
    def config(self) -> LinkConfig:
        """The tunnel's parameters: address, netmask, MTU, routes."""
        ...

    @property
    def wake(self) -> asyncio.Event:
        """Set whenever inbound packets arrive, so the driver can wait on it."""
        ...

    def send(self, packet: bytes) -> None:
        """Queue one IP packet. Non-blocking; the writer task coalesces."""
        ...

    def take_inbound(self) -> list[bytes]:
        """Drain every IP packet received since the last call."""
        ...

    @property
    def closed(self) -> asyncio.Event:
        """Set when the link is finished; :attr:`close_reason` says why."""
        ...

    @property
    def close_reason(self) -> str: ...

    async def aclose(self) -> None:
        """Shut the link down cleanly."""
        ...
