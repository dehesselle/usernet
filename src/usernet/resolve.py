"""Turning names into addresses the tunnel can reach.

A resolver is any async ``str -> str`` callable, handed to the
:class:`~usernet.runtime.driver.Driver` (and so to everything dialing through
it) or to the SOCKS server alone. Which one a tunnel should have is the
tunnel's business: MagicDNS for a tailnet, a fixed table for a VPN whose
gateway offers no DNS at all, nothing for a link that wants names refused.

**There is never a fallback to the host's resolver.** That would send
tunnel-internal names to whatever DNS the machine happens to use, and dial
whatever public record happened to match.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Awaitable, Callable, Mapping

from usernet.errors import ResolveError

Resolver = Callable[[str], Awaitable[str]]
"""Turns a hostname into an address the tunnel can reach.

Raises :class:`~usernet.errors.ResolveError` when it cannot, with a message
written for whoever is reading a terminal: it becomes the SOCKS rejection or
the connect error, and that is all the user ever sees.
"""


def is_address(host: str) -> bool:
    """Whether ``host`` is an IPv4 literal, and so needs no resolving."""
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        return False
    return True


def normalize(name: str) -> str:
    """The form names are compared in: lowercase, without the root dot."""
    return name.strip().rstrip(".").lower()


class StaticResolver:
    """A fixed name-to-address table, the ``/etc/hosts`` of one tunnel.

    For networks whose machines have fixed addresses and no DNS to ask.
    Matching is exact after :func:`normalize` -- no wildcards, no search
    domain -- because anything cleverer is the beginning of a DNS
    implementation, and a name missing from the table is a mistake the user
    should see rather than one a guess should paper over.
    """

    def __init__(self, hosts: Mapping[str, str], *, source: str = "the host table") -> None:
        """``source`` names the table in error messages, e.g. a config file section."""
        self.source = source
        self._hosts: dict[str, str] = {}
        for name, address in hosts.items():
            key = normalize(name)
            if not key:
                raise ValueError(f"{source}: empty host name")
            if is_address(key):
                raise ValueError(f"{source}: {name!r} is an address, not a name")
            if not is_address(address):
                raise ValueError(f"{source}: {name!r} maps to {address!r}, not an IPv4 address")
            self._hosts[key] = address

    @property
    def hosts(self) -> dict[str, str]:
        return dict(self._hosts)

    def lookup(self, host: str) -> str | None:
        """The address for ``host``, ``host`` itself if it is one, else None."""
        if is_address(host):
            return host
        return self._hosts.get(normalize(host))

    def resolve(self, host: str) -> str:
        """The same as awaiting the resolver, for callers that check up front."""
        address = self.lookup(host)
        if address is None:
            raise ResolveError(
                f"cannot resolve {host!r}: it is not in {self.source}, and names are "
                f"never sent to the host's resolver"
            )
        return address

    async def __call__(self, host: str) -> str:
        return self.resolve(host)
