# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Blocking stdin/stdout, bridged onto the event loop by two threads.

You cannot select on a pipe under the Windows proactor loop, so ``add_reader``
and ``connect_read_pipe`` are unavailable for stdio there. Dedicated threads
are the portable answer, and using them on every platform keeps one code path
instead of two -- for an interactive session the thread hop costs nothing
measurable, and the alternative is a POSIX path that Windows never exercises.

Both threads are daemons deliberately: a thread blocked in ``os.read`` on a
pipe cannot be cancelled, and a non-daemon one would hang interpreter shutdown
forever.

**The most valuable lines in the whole Windows path are the**
``msvcrt.setmode`` **calls.** Without them the C runtime performs CRLF
translation on these descriptors, quietly corrupting any binary stream. An SSH
session then fails looking like a protocol error rather than a text-mode bug,
which is a genuinely horrible afternoon.

Handover is lock-step in both directions -- the reader thread waits for the
consumer before reading again, and each write is awaited to completion -- so
neither direction accumulates a buffer. That is the same rule the rest of the
project follows: no queue may sit between the network and the application.
"""

from __future__ import annotations

import asyncio
import os
import queue
import sys
import threading

CHUNK = 65536

if sys.platform == "win32":
    import msvcrt


def set_binary(fd: int) -> None:
    """Stop the Windows C runtime translating CRLF on this descriptor."""
    if sys.platform == "win32":
        msvcrt.setmode(fd, os.O_BINARY)


class StdioBridge:
    """Async ``read``/``write`` over two blocking descriptors.

    ``in_fd`` and ``out_fd`` default to stdin and stdout; tests pass pipes.
    """

    def __init__(self, in_fd: int | None = None, out_fd: int | None = None, *, chunk: int = CHUNK):
        self._chunk = chunk
        self._loop = asyncio.get_running_loop()
        self._in_fd = sys.stdin.fileno() if in_fd is None else in_fd
        self._out_fd = sys.stdout.fileno() if out_fd is None else out_fd
        set_binary(self._in_fd)
        set_binary(self._out_fd)

        self._pending: asyncio.Future[bytes] = self._loop.create_future()
        self._resume = threading.Event()
        self._writes: queue.Queue[tuple[bytes, asyncio.Future[None]] | None] = queue.Queue()
        self._eof = False
        self._closed = False

        self._reader = threading.Thread(target=self._read_loop, name="usernet-stdin", daemon=True)
        self._writer = threading.Thread(target=self._write_loop, name="usernet-stdout", daemon=True)
        self._reader.start()
        self._writer.start()

    # --- the async side ----------------------------------------------------

    async def read(self) -> bytes:
        """One chunk from the input descriptor; ``b""`` at end of input."""
        if self._eof:
            return b""
        data = await self._pending
        if not data:
            self._eof = True
            return b""
        # A fresh future must exist before the thread is released, or it would
        # deliver into the one just consumed.
        self._pending = self._loop.create_future()
        self._resume.set()
        return data

    async def write(self, data: bytes) -> None:
        """Write everything, waiting for the descriptor to take it.

        Awaiting completion is what applies backpressure: a consumer that has
        stopped reading stops us reading from the network too.
        """
        if not data:
            return
        future: asyncio.Future[None] = self._loop.create_future()
        self._writes.put((data, future))
        await future

    def close(self) -> None:
        self._closed = True
        self._resume.set()
        self._writes.put(None)

    def join(self, timeout: float = 2.0) -> None:
        """Wait for both threads to finish, as far as that is possible.

        The output thread stops on the sentinel :meth:`close` queues. The input
        thread cannot be made to stop while it is parked in ``os.read`` -- only
        whoever holds the other end of that descriptor can release it by
        closing theirs. That is exactly why these threads are daemons, and why
        this call takes a timeout rather than promising anything.
        """
        self._writer.join(timeout)
        self._reader.join(timeout)

    # --- the thread side ---------------------------------------------------

    def _read_loop(self) -> None:
        while True:
            try:
                data = os.read(self._in_fd, self._chunk)
            except OSError as exc:
                self._loop.call_soon_threadsafe(self._fail_read, exc)
                return
            self._loop.call_soon_threadsafe(self._deliver, data)
            if not data:
                return
            self._resume.wait()
            self._resume.clear()
            if self._closed:
                return

    def _write_loop(self) -> None:
        while True:
            item = self._writes.get()
            if item is None:
                return
            data, future = item
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(self._out_fd, view) :]
            except OSError as exc:
                self._loop.call_soon_threadsafe(self._settle, future, exc)
            else:
                self._loop.call_soon_threadsafe(self._settle, future, None)

    # --- handover, always on the loop thread -------------------------------

    def _deliver(self, data: bytes) -> None:
        if not self._pending.done():
            self._pending.set_result(data)

    def _fail_read(self, error: BaseException) -> None:
        if not self._pending.done():
            self._pending.set_exception(error)

    def _settle(self, future: asyncio.Future[None], error: BaseException | None) -> None:
        if future.done():
            return
        if error is None:
            future.set_result(None)
        else:
            future.set_exception(error)
