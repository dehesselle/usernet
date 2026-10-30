# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""An ``asyncio.Transport`` over a tunnel stream.

This is what makes the stack usable by code that was never written for it.
``asyncssh``, ``asyncpg`` and most of the async ecosystem take a
``(StreamReader, StreamWriter)`` pair, or call ``loop.create_connection``; none
of them know what a :class:`~usernet.runtime.driver.TcpStream` is. Wrapping one in
a real ``asyncio.Transport`` and pairing it with ``StreamReaderProtocol``
produces exactly the pair the stdlib produces, so they need not care.

The interesting part is flow control, and it composes for free in both
directions:

* ``StreamReader`` calls :meth:`StackTransport.pause_reading` when its buffer
  passes the high-water mark. That stops us draining the stack's receive
  buffer, which shrinks the advertised window, which stops the peer sending.
  Backpressure reaches the far end without a single queue in between.
* ``StreamWriter.drain`` waits while :meth:`write` has more buffered than the
  high-water mark, so an application that outruns the tunnel is slowed rather
  than allowed to accumulate.

Deliberately generic over :class:`ByteStream` rather than tied to ``TcpStream``:
a :class:`~usernet.runtime.tls.TlsStream` inside the tunnel is the same shape,
so it gets a reader/writer pair from this same code instead of a second
implementation.
"""

from __future__ import annotations

import asyncio
import logging
from functools import partial
from typing import Any, Protocol, runtime_checkable

log = logging.getLogger("usernet.runtime")

CHUNK = 65536

# asyncio's own defaults for a socket transport. Matching them means code
# tuned against the stdlib behaves the same way here.
HIGH_WATER = 64 * 1024
LOW_WATER = 16 * 1024


@runtime_checkable
class ByteStream(Protocol):
    """The shape everything carrying bytes in this project already has."""

    async def read(self, size: int = CHUNK) -> bytes: ...
    async def write(self, data: bytes) -> None: ...
    def close(self) -> None: ...


class StackTransport(asyncio.Transport):
    """Drive an ``asyncio.Protocol`` from a :class:`ByteStream`."""

    def __init__(
        self,
        stream: ByteStream,
        protocol: asyncio.Protocol,
        *,
        peername: tuple[str, int] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        info: dict[str, Any] = {"peername": peername, "socket": None, "sockname": None}
        info.update(extra or {})
        super().__init__(info)

        self._stream = stream
        self._protocol = protocol
        self._loop = asyncio.get_running_loop()

        self._buffer = bytearray()
        self._high = HIGH_WATER
        self._low = LOW_WATER

        self._closing = False
        self._eof_sent = False
        self._eof_requested = False
        self._lost = False
        self._error: Exception | None = None

        self._reading = asyncio.Event()
        self._reading.set()
        self._writable = asyncio.Event()
        self._write_paused = False

        # Called synchronously rather than through call_soon, unlike asyncio's
        # socket transports: the connection is already established by the time
        # we get here, and doing it now means a StreamWriter built on the next
        # line is safe to use immediately.
        protocol.connection_made(self)

        self._reader_task = self._loop.create_task(self._pump_reads(), name="usernet-transport-rx")
        self._writer_task = self._loop.create_task(self._pump_writes(), name="usernet-transport-tx")

    # --- transport interface -----------------------------------------------

    def get_protocol(self) -> asyncio.BaseProtocol:
        return self._protocol

    def set_protocol(self, protocol: asyncio.BaseProtocol) -> None:
        assert isinstance(protocol, asyncio.Protocol)
        self._protocol = protocol

    def is_closing(self) -> bool:
        return self._closing

    def is_reading(self) -> bool:
        return self._reading.is_set() and not self._closing

    def pause_reading(self) -> None:
        """Stop draining the stack, and therefore close the receive window.

        The whole point of the design: nothing is buffered on our behalf while
        paused, so the pressure reaches the peer rather than our memory.
        """
        self._reading.clear()

    def resume_reading(self) -> None:
        self._reading.set()

    def write(self, data: bytes | bytearray | memoryview) -> None:
        if self._closing or self._eof_requested:
            return
        if not data:
            return
        self._buffer += data
        if not self._write_paused and len(self._buffer) > self._high:
            self._write_paused = True
            self._call_protocol("pause_writing")
        self._writable.set()

    def writelines(self, chunks: Any) -> None:
        self.write(b"".join(chunks))

    def can_write_eof(self) -> bool:
        return True

    def write_eof(self) -> None:
        """Half close: our FIN goes out, the peer may still send."""
        if self._eof_requested or self._closing:
            return
        self._eof_requested = True
        self._writable.set()

    def get_write_buffer_size(self) -> int:
        return len(self._buffer)

    def get_write_buffer_limits(self) -> tuple[int, int]:
        return self._low, self._high

    def set_write_buffer_limits(self, high: int | None = None, low: int | None = None) -> None:
        if high is None:
            high = self._high if low is None else low * 4
        if low is None:
            low = high // 4
        if low > high:
            raise ValueError(f"low water mark {low} exceeds high water mark {high}")
        self._high, self._low = high, low

    def close(self) -> None:
        """Graceful: whatever is buffered still goes out."""
        if self._closing:
            return
        self._closing = True
        self._writable.set()

    def abort(self) -> None:
        """Immediate: buffered data is discarded and the peer gets a reset."""
        if self._lost:
            return
        self._closing = True
        self._buffer.clear()
        reset = getattr(self._stream, "abort", None)
        if callable(reset):
            reset()
        else:
            self._stream.close()
        self._finish(None)

    # --- the pumps ----------------------------------------------------------

    async def _pump_reads(self) -> None:
        held: bytes | None = None
        try:
            while True:
                await self._reading.wait()
                if self._closing:
                    return
                data = held if held is not None else await self._stream.read(CHUNK)
                held = None
                if not data:
                    # A protocol returning True keeps the transport open so it
                    # can still write -- that is what half close means here.
                    if self._protocol.eof_received() is not True:
                        self.close()
                    return
                if not self._reading.is_set():
                    # Paused while that read was in flight. Hold the chunk
                    # rather than pushing it at a protocol that has just asked
                    # us to stop -- delivering anyway is how a StreamReader's
                    # buffer grows past the limit it set. One chunk, bounded.
                    held = data
                    continue
                self._protocol.data_received(data)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._fail(exc)

    async def _pump_writes(self) -> None:
        try:
            while True:
                if not self._buffer:
                    if self._eof_requested and not self._eof_sent:
                        self._eof_sent = True
                        self._stream.close()  # FIN; receiving continues
                    if self._closing:
                        self._finish(self._error)
                        return
                    self._writable.clear()
                    await self._writable.wait()
                    continue

                chunk = bytes(self._buffer)
                del self._buffer[: len(chunk)]
                await self._stream.write(chunk)

                if self._write_paused and len(self._buffer) <= self._low:
                    self._write_paused = False
                    self._call_protocol("resume_writing")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._fail(exc)

    # --- teardown -----------------------------------------------------------

    def _fail(self, error: Exception) -> None:
        self._error = error
        self._closing = True
        self._buffer.clear()
        self._finish(error)

    def _finish(self, error: Exception | None) -> None:
        """Report the connection gone, exactly once."""
        if self._lost:
            return
        self._lost = True
        self._stream.close()
        for task in (self._reader_task, self._writer_task):
            if task is not asyncio.current_task():
                task.cancel()
        # Bound through partial rather than passed as an argument: the
        # protocol's callback is typed for Exception, call_soon for
        # BaseException, and there is no cast that makes both true.
        self._loop.call_soon(partial(self._protocol.connection_lost, error))

    def _call_protocol(self, name: str) -> None:
        """Flow-control callbacks must not take the transport down with them."""
        try:
            getattr(self._protocol, name)()
        except Exception:
            log.exception("protocol.%s() failed", name)


async def wrap_stream(
    stream: ByteStream,
    *,
    peername: tuple[str, int] | None = None,
    limit: int = CHUNK,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Present a :class:`ByteStream` as the stdlib's reader/writer pair."""
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=limit, loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
    transport = StackTransport(stream, protocol, peername=peername)
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    return reader, writer
