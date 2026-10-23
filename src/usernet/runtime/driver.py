"""The driver: the only task permitted to touch the stack.

The concurrency invariant that makes this safe without any locking: stack
methods are synchronous and asyncio is single-threaded, so a caller may invoke
several of them and then wake the driver, with no ``await`` in between. **Never
``await`` between two stack calls that must be atomic.**

Backpressure is the part that has to be right. Received bytes stay in the
stack's receive buffer until the application asks for them, and the advertised
window is computed from that backlog. Draining eagerly into an
``asyncio.Queue`` would reopen the window without the data having gone
anywhere, silently converting flow control into unbounded memory growth --
which is why nothing here does that.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import time
from dataclasses import replace
from types import TracebackType

from usernet.aio import first_of
from usernet.errors import ConnectionTimeout, NetworkError, ResolveError
from usernet.link import IpLink
from usernet.net.events import (
    IcmpEchoReply,
    PacketDropped,
    SocketClosed,
    SocketConnected,
    SocketError,
    SocketId,
    SocketPeerClosed,
    SocketReadable,
    SocketWritable,
)
from usernet.net.stack import PyStack, StackConfig
from usernet.net.tcb import DEFAULT_MAX_OOO_SEGMENTS, State, TcbConfig
from usernet.net.tcp import DEFAULT_MSS
from usernet.resolve import Resolver, is_address

log = logging.getLogger("usernet.runtime")

# Packets the stack discarded, under their own name so they can be silenced
# without losing the rest: one line per drop is a lot during a port scan.
drop_log = logging.getLogger("usernet.net")

# Bounds how long the driver may sleep with nothing to do. Doubles as a
# watchdog tick and as the reason an idle loop still notices Ctrl-C on Windows,
# where there is no signal-handler support in the proactor loop.
MAX_IDLE_MS = 500


def monotonic_ms() -> int:
    return int(time.monotonic() * 1000)


def _ooo_cap(buffer: int) -> int:
    """Reassembly entries to allow for a buffer of this size.

    Has to scale with the buffer or it binds first, and then a single loss
    means discarding in-window data that arrived intact -- a stall rather than
    a saving. Sized against the RFC 1122 floor MSS, since a peer may really
    send segments that small.
    """
    return max(DEFAULT_MAX_OOO_SEGMENTS, buffer // DEFAULT_MSS + 64)


class TcpStream:
    """An open connection, presented as async read/write.

    Deliberately not an ``asyncio.Transport``: it is the minimal byte-stream
    shape everything else in the project builds on. Code that wants the
    stdlib's ``StreamReader``/``StreamWriter`` pair gets one from
    :func:`usernet.runtime.transport.wrap_stream`.
    """

    def __init__(self, driver: Driver, sid: SocketId, peer: tuple[str, int]) -> None:
        self._driver = driver
        self._sid = sid
        self.peer = peer

        self.connected = asyncio.Event()
        self.readable = asyncio.Event()
        self.writable = asyncio.Event()
        self.finished = asyncio.Event()
        self.error: NetworkError | None = None
        self.eof = False

        # Payload bytes as the application saw them, for whoever wants to show
        # that a connection is alive. Plain ints: everything runs on one loop.
        self.rx = 0
        self.tx = 0
        self.opened_at = time.monotonic()

    async def read(self, max_bytes: int = 65536) -> bytes:
        """Read once. Returns ``b""`` at end of stream."""
        while True:
            self._driver.raise_if_failed(self)
            data = self._driver.stack.tcp_recv(self._sid, max_bytes, self._driver.now)
            if data:
                self._driver.wake()  # a window update may be waiting to go out
                self.rx += len(data)
                return data
            if self.eof or self.finished.is_set():
                return b""

            self.readable.clear()
            await self._wait(self.readable)

    async def read_all(self, limit: int = 8 * 1024 * 1024) -> bytes:
        """Read until the peer closes, bounded so a runaway cannot exhaust RAM."""
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await self.read(min(65536, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total >= limit:
                break
        return b"".join(chunks)

    async def write(self, data: bytes) -> None:
        """Write everything, waiting for send-buffer space as needed."""
        view = memoryview(data)
        while view:
            self._driver.raise_if_failed(self)
            accepted = self._driver.stack.tcp_send(self._sid, view, self._driver.now)
            self._driver.wake()
            if accepted:
                self.tx += accepted
                view = view[accepted:]
                continue

            self.writable.clear()
            await self._wait(self.writable)

    async def _wait(self, event: asyncio.Event) -> None:
        """Wait for ``event`` or for the connection to end, whichever first."""
        await first_of(event, self.finished)
        self._driver.raise_if_failed(self)

    def close(self) -> None:
        self._driver.stack.tcp_close(self._sid, self._driver.now)
        self._driver.wake()

    def abort(self) -> None:
        self._driver.stack.tcp_abort(self._sid, self._driver.now)
        self._driver.wake()

    async def wait_closed(self) -> None:
        await self.finished.wait()

    async def __aenter__(self) -> TcpStream:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class Driver:
    """Joins the sans-IO stack to an :class:`~usernet.link.IpLink`."""

    def __init__(
        self,
        link: IpLink,
        *,
        mss: int | None = None,
        buffer: int | None = None,
        stack_config: StackConfig | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        self.link = link
        # How names become addresses, for everything that dials through this
        # driver: connect, ping, the HTTP transport, and the SOCKS server
        # unless it is given its own. None means names are refused.
        self.resolver = resolver
        tunnel = link.config

        # Per-socket send and receive buffer. Worth exposing because it sets
        # the throughput ceiling directly: one connection cannot exceed
        # buffer / RTT, so a distant gateway wants a larger one and nothing
        # else moves the number.
        tcb = TcbConfig(mss=mss if mss is not None else tunnel.mtu - 40)
        if buffer is not None:
            tcb = replace(
                tcb,
                rx_buffer=buffer,
                tx_buffer=buffer,
                # Scaled with the buffer, or it binds first and a single loss
                # becomes a stall instead of a retransmission.
                max_ooo_segments=_ooo_cap(buffer),
            )
        self.config = stack_config or StackConfig(
            local_ip=tunnel.address,
            netmask=tunnel.netmask,
            mtu=tunnel.mtu,
            # MSS comes from the tunnel MTU, minus the IP and TCP headers, and
            # is also clamped to the peer's advertised MSS during the
            # handshake -- getting this wrong is the classic silent-hang bug.
            tcb=tcb,
            rng=lambda: secrets.randbits(32),
        )
        self.stack = self._new_stack()

        self.now = monotonic_ms()
        self._streams: dict[SocketId, TcpStream] = {}
        self._echo_waiters: dict[tuple[int, int], asyncio.Future[int]] = {}
        self._wake = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._icmp_ident = secrets.randbits(16)
        self.address_changes = 0

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="usernet-driver")
        self._task.add_done_callback(self._on_done)

    async def aclose(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    def _on_done(self, task: asyncio.Task[None]) -> None:
        if task.cancelled():
            return
        exception = task.exception()
        if exception is not None:
            log.error("driver failed: %r", exception)
            for stream in list(self._streams.values()):
                stream.error = NetworkError(f"driver failed: {exception!r}")
                stream.finished.set()

    def wake(self) -> None:
        self._wake.set()

    # --- the loop ----------------------------------------------------------

    async def _run(self) -> None:
        while True:
            await self._wait_for_work()
            self.now = monotonic_ms()

            # One string comparison per pass, and it is what makes a
            # reconnecting link safe: if the gateway handed us a different
            # address, every socket's local endpoint has ceased to exist.
            if self.link.config.address != self.config.local_ip:
                self._rebind(self.link.config.address)

            for packet in self.link.take_inbound():
                self.stack.handle_input(packet, self.now)

            self.stack.poll(self.now)
            self._flush()

            if self.link.closed.is_set():
                self._fail_all(self.link.close_reason or "tunnel closed")
                return

    async def _wait_for_work(self) -> None:
        deadline = self.stack.poll_at()
        timeout = MAX_IDLE_MS if deadline is None else max(0, deadline - monotonic_ms())
        timeout = min(timeout, MAX_IDLE_MS)

        await first_of(self._wake, self.link.wake, self.link.closed, seconds=timeout / 1000)
        self._wake.clear()

    def _flush(self) -> None:
        """Hand outbound packets to the link and dispatch events."""
        for packet in self.stack.take_output():
            self.link.send(packet)
        for event in self.stack.take_events():
            self._dispatch(event)

    def _dispatch(self, event: object) -> None:
        if isinstance(event, SocketConnected):
            stream = self._streams.get(event.sid)
            if stream is not None:
                stream.connected.set()
                stream.writable.set()
        elif isinstance(event, SocketReadable):
            self._set(event.sid, "readable")
        elif isinstance(event, SocketWritable):
            self._set(event.sid, "writable")
        elif isinstance(event, SocketPeerClosed):
            stream = self._streams.get(event.sid)
            if stream is not None:
                stream.eof = True
                stream.readable.set()
        elif isinstance(event, SocketError):
            stream = self._streams.get(event.sid)
            if stream is not None:
                stream.error = (
                    event.error
                    if isinstance(event.error, NetworkError)
                    else NetworkError(str(event.error))
                )
                self._finish(event.sid)
        elif isinstance(event, SocketClosed):
            self._finish(event.sid)
        elif isinstance(event, IcmpEchoReply):
            waiter = self._echo_waiters.pop((event.ident, event.seq), None)
            if waiter is not None and not waiter.done():
                waiter.set_result(event.recv_ms)
        elif isinstance(event, PacketDropped):
            # A fragment means an assumption broke: we set DF and size from the
            # MTU, so the path is not behaving the way the tunnel says it does.
            level = logging.WARNING if event.reason == "ip-fragment" else logging.DEBUG
            drop_log.log(level, "dropped (%s): %s", event.reason, event.summary)

    def _set(self, sid: SocketId, name: str) -> None:
        stream = self._streams.get(sid)
        if stream is not None:
            getattr(stream, name).set()

    def _finish(self, sid: SocketId) -> None:
        stream = self._streams.pop(sid, None)
        if stream is not None:
            stream.eof = True
            stream.readable.set()
            stream.writable.set()
            stream.finished.set()

    def _rebind(self, address: str) -> None:
        """Adopt a new tunnel address, abandoning everything bound to the old.

        There is no way to carry connections across this. Their four-tuples
        name an address the gateway has taken back, so every segment we sent
        would be discarded and every reply misrouted. Failing them with a
        message that says exactly this is the only honest option -- and far
        better than sockets that quietly stop working.
        """
        previous = self.config.local_ip
        log.warning("tunnel address changed: %s -> %s; resetting the stack", previous, address)
        self.address_changes += 1

        self._fail_all(
            f"the gateway reassigned our address ({previous} -> {address}); "
            f"connections opened under the old one cannot continue"
        )
        self.config = replace(self.config, local_ip=address)
        self.stack = self._new_stack()

    def _new_stack(self) -> PyStack:
        stack = PyStack(self.config)
        # Costs one event per discarded packet and nothing otherwise, and a
        # silent drop is the hardest thing to find in a hang.
        stack.trace_drops = True
        return stack

    def _fail_all(self, reason: str) -> None:
        for sid in list(self._streams):
            stream = self._streams[sid]
            if stream.error is None:
                stream.error = NetworkError(reason)
            self._finish(sid)

    def raise_if_failed(self, stream: TcpStream) -> None:
        if stream.error is not None:
            raise stream.error

    # --- public operations -------------------------------------------------

    async def resolve(self, host: str) -> str:
        """``host`` as an address: unchanged if it is one, else via the resolver.

        Raises :class:`~usernet.errors.ResolveError` for a name this driver
        cannot resolve -- never asks the host's DNS instead.
        """
        if is_address(host):
            return host
        if self.resolver is None:
            raise ResolveError(
                f"cannot resolve {host!r}: this tunnel has no resolver, and names are "
                f"never sent to the host's. Use an address."
            )
        return await self.resolver(host)

    async def connect(
        self,
        host: str,
        port: int,
        *,
        timeout: float = 30.0,  # noqa: ASYNC109 - see the docstring
    ) -> TcpStream:
        """Open a TCP connection through the tunnel.

        The timeout is a parameter rather than something the caller wraps,
        because a failed connect must abort the half-open socket rather than
        leave it retransmitting SYNs into a cancelled task.

        ``host`` may be a name if the driver has a resolver.
        """
        host = await self.resolve(host)
        self.now = monotonic_ms()
        sid = self.stack.tcp_connect((host, port))
        stream = TcpStream(self, sid, (host, port))
        self._streams[sid] = stream

        # Register the stream before the SYN leaves, so a reply arriving in the
        # same driver pass cannot be dispatched to a socket we do not know yet.
        self.stack.start_connect(sid, self.now)
        self.wake()

        try:
            async with asyncio.timeout(timeout):
                await first_of(stream.connected, stream.finished)
        except TimeoutError as exc:
            stream.abort()
            self._streams.pop(sid, None)
            raise ConnectionTimeout(f"connection to {host}:{port} timed out") from exc

        if stream.error is not None:
            raise stream.error
        if not stream.connected.is_set():
            raise ConnectionTimeout(f"connection to {host}:{port} ended during setup")
        assert self.stack.tcp_state(sid) is State.ESTABLISHED
        return stream

    async def ping(
        self,
        host: str,
        sequence: int,
        *,
        timeout: float = 2.0,  # noqa: ASYNC109 - the timeout is the result
    ) -> float | None:
        """One ICMP echo. Returns the round-trip time in ms, or None if lost.

        A lost echo is an ordinary outcome rather than an error, so the
        timeout belongs in the signature: callers want ``None``, not a
        cancellation to catch.
        """
        host = await self.resolve(host)
        key = (self._icmp_ident, sequence)
        future: asyncio.Future[int] = asyncio.get_running_loop().create_future()
        self._echo_waiters[key] = future

        sent_at = monotonic_ms()
        self.stack.icmp_echo(host, self._icmp_ident, sequence, b"usernet" * 4)
        self.wake()

        try:
            async with asyncio.timeout(timeout):
                received = await future
            return float(received - sent_at)
        except TimeoutError:
            return None
        finally:
            self._echo_waiters.pop(key, None)
