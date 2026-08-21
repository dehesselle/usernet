"""The sans-IO contract between the network stack and the asyncio driver.

This is the seam that keeps the risky code testable and the fast code
replaceable. Everything below it is deterministic and synchronous; everything
above it does I/O. A native backend (smoltcp via PyO3) would satisfy
:class:`NetworkBackend` structurally -- which is why this is a ``Protocol`` and
not an ABC, since a PyO3 extension type cannot cheaply inherit a Python ABC.

Two rules make the whole design work:

1. **Time is a parameter.** ``now`` is milliseconds since an arbitrary
   monotonic epoch, as an ``int`` -- not a float, so tests read cleanly and
   arithmetic stays exact. The stack never calls a clock.
2. **Every mutating call may produce output.** Any method may append to the
   internal outbound-packet queue and the event list, so the driver drains both
   after *every* call. That eliminates the "did I forget to poll" class of bug.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from usernet.net.events import Event, SocketId


@runtime_checkable
class NetworkBackend(Protocol):
    """A userspace network stack driven by raw IP packets and a clock."""

    # --- link side ---------------------------------------------------------

    def handle_input(self, packet: bytes | memoryview, now: int) -> None:
        """Feed one inbound IP packet arriving from the tunnel."""
        ...

    def poll(self, now: int) -> None:
        """Fire every timer due at or before ``now``."""
        ...

    def poll_at(self) -> int | None:
        """Absolute time (ms) of the next deadline, or None if idle.

        The driver waits at most this long before calling :meth:`poll`.
        """
        ...

    def take_output(self) -> list[bytes]:
        """Remove and return IP packets queued for the tunnel."""
        ...

    def take_events(self) -> list[Event]:
        """Remove and return pending events."""
        ...

    # --- TCP, all synchronous and non-blocking -----------------------------

    def tcp_connect(self, dst: tuple[str, int], *, nodelay: bool = True) -> SocketId:
        """Begin an active open. Completion arrives as ``SocketConnected``."""
        ...

    def tcp_send(self, sid: SocketId, data: memoryview) -> int:
        """Copy as much as the send buffer accepts; return the byte count.

        A short return is normal backpressure, not an error: wait for
        ``SocketWritable`` and retry the remainder.
        """
        ...

    def tcp_recv(self, sid: SocketId, max_bytes: int, now: int = 0) -> bytes:
        """Take up to ``max_bytes`` from the receive buffer; ``b""`` if empty.

        Only call this once the consumer is genuinely ready to take the data.
        Draining eagerly into a queue would reopen the receive window without
        the data having gone anywhere, which silently disables flow control.

        Takes ``now`` because reading is precisely what reopens that window,
        and reopening it may need to be announced immediately.
        """
        ...

    def tcp_tx_space(self, sid: SocketId) -> int:
        """Bytes :meth:`tcp_send` would accept right now."""
        ...

    def tcp_rx_available(self, sid: SocketId) -> int:
        """Bytes :meth:`tcp_recv` would return right now."""
        ...

    def tcp_shutdown_write(self, sid: SocketId) -> None:
        """Send FIN once queued data has been acknowledged."""
        ...

    def tcp_abort(self, sid: SocketId) -> None:
        """Send RST and release the socket immediately."""
        ...

    def tcp_close(self, sid: SocketId) -> None:
        """Close gracefully, then release."""
        ...

    # --- UDP ---------------------------------------------------------------

    def udp_open(self, local_port: int | None = None) -> SocketId:
        """Bind a UDP socket, choosing an ephemeral port if none is given."""
        ...

    def udp_send_to(self, sid: SocketId, dst: tuple[str, int], data: bytes) -> None:
        """Queue one datagram."""
        ...

    def udp_recv_from(self, sid: SocketId) -> tuple[tuple[str, int], bytes] | None:
        """Take one queued datagram, or None."""
        ...

    def udp_close(self, sid: SocketId) -> None:
        """Release a UDP socket."""
        ...

    # --- ICMP --------------------------------------------------------------

    def icmp_echo(self, dst: str, ident: int, seq: int, payload: bytes) -> None:
        """Queue an echo request. Replies arrive as ``IcmpEchoReply``."""
        ...
