# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Events the sans-IO stack emits for the asyncio driver to dispatch.

All events are frozen and slotted: the driver drains them after every stack
call, so they are allocated on hot paths and must stay cheap.

Readable/Writable are *edge* events -- emitted on the transition from empty to
non-empty (or full to non-full), not repeated while the condition holds. The
driver must therefore never drop an event, and consumers must drain to
exhaustion rather than assuming one event means one buffer's worth of data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NewType

SocketId = NewType("SocketId", int)


class Event:
    """Base class for stack events."""

    __slots__ = ()


@dataclass(frozen=True, slots=True)
class SocketConnected(Event):
    """Active open completed; the connection is ESTABLISHED."""

    sid: SocketId


@dataclass(frozen=True, slots=True)
class SocketReadable(Event):
    """The receive buffer went from empty to non-empty."""

    sid: SocketId


@dataclass(frozen=True, slots=True)
class SocketWritable(Event):
    """Send buffer space went from zero to non-zero."""

    sid: SocketId


@dataclass(frozen=True, slots=True)
class SocketPeerClosed(Event):
    """A FIN arrived and the receive buffer has drained: clean EOF."""

    sid: SocketId


@dataclass(frozen=True, slots=True)
class SocketClosed(Event):
    """The socket is fully released. ``sid`` may be reused after this."""

    sid: SocketId
    reason: str


@dataclass(frozen=True, slots=True)
class SocketError(Event):
    """The connection failed: RST, RTO exhaustion, or an ICMP hard error."""

    sid: SocketId
    error: Exception


@dataclass(frozen=True, slots=True)
class UdpReceived(Event):
    """A datagram was queued on a UDP socket."""

    sid: SocketId


@dataclass(frozen=True, slots=True)
class IcmpEchoReply(Event):
    """An echo reply arrived; ``recv_ms`` is the stack clock at receipt."""

    src: str
    ident: int
    seq: int
    recv_ms: int


@dataclass(frozen=True, slots=True)
class PacketDropped(Event):
    """Diagnostics only, off unless packet tracing is enabled."""

    reason: str
    summary: str
