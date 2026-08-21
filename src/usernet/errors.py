"""Exception hierarchy for usernet.

Every error raised below the tunnel derives from :class:`UsernetError`. The
``NetworkError`` branch mirrors the errors an ordinary socket would raise, so
the SOCKS5 layer can map them onto reply codes with a single table.

A tunnel implementation on top of this package (``pyac``, ``pyts``) roots its
own hierarchy here, so that ``except`` on its base class keeps catching stack
and socket failures too. What must *not* happen is the inverse: nothing in this
package may know what a gateway, a tailnet, or a login is.
"""

from __future__ import annotations


class UsernetError(Exception):
    """Base class for every error this package raises."""


class ProtocolParseError(UsernetError):
    """Malformed input from the network, the tunnel, or a SOCKS client.

    Parsers raise only this. Never let ``IndexError``, ``struct.error``, or
    ``UnicodeDecodeError`` escape a parser -- callers cannot distinguish those
    from genuine bugs.
    """


# --- network (socket-level, mapped onto SOCKS5 reply codes) ----------------


class NetworkError(UsernetError):
    """Base for errors on a connection carried by the tunnel."""


class ConnectionRefused(NetworkError):
    """RST in response to SYN, or an ICMP hard error during connect."""


class ConnectionReset(NetworkError):
    """RST on an established connection."""


class ConnectionTimeout(NetworkError):
    """Connect timed out, or retransmission backoff was exhausted."""


class HostUnreachable(NetworkError):
    """ICMP destination unreachable, or the name did not resolve."""


class RouteNotAllowed(NetworkError):
    """The destination lies outside the tunnel's split-tunnel scope.

    Raised eagerly rather than letting the peer drop the packets silently,
    which would otherwise surface as an unexplained connect timeout.
    """

    def __init__(self, dst: str) -> None:
        super().__init__(
            f"{dst} is outside the tunnel's split-include routes; "
            f"use --route-policy all or --route-add to override"
        )
        self.dst = dst


class ResolveError(NetworkError):
    """In-tunnel DNS resolution failed."""
