# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Two pipes standing in for stdin and stdout, with the test on the far end.

The companion to :class:`~usernet.runtime.stdio.StdioBridge`: anything that
relays a connection over the process's own stdio -- an ssh ``ProxyCommand``, a
``nc``-style subcommand -- needs a way to be the other end of those pipes. That
is the same problem for every such command, so it is solved once here rather
than in each project's test tree.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import threading
from collections.abc import Iterator


class Pipes:
    """Two pipes standing in for stdin and stdout, with the test on the far end.

    Output is drained by a *daemon* thread rather than ``asyncio.to_thread``.
    That is not fussiness: a default-executor worker blocked in ``os.read`` is
    non-daemon, and the event loop joins the executor when it closes -- so a
    single assertion that times out would wedge the whole suite instead of
    failing. The bridge under test avoids that trap the same way.
    """

    def __init__(self) -> None:
        self.stdin_read, self.stdin_write = os.pipe()
        self.stdout_read, self.stdout_write = os.pipe()
        self._output: asyncio.Queue[bytes] | None = None
        self._thread: threading.Thread | None = None

    def send(self, data: bytes) -> None:
        """Write to the bridge's stdin."""
        os.write(self.stdin_write, data)

    def end_input(self) -> None:
        """Close the write end, which is the only thing that frees a reader
        parked in ``os.read``. Idempotent, because teardown repeats it."""
        if self.stdin_write >= 0:
            os.close(self.stdin_write)
            self.stdin_write = -1

    async def receive(self, size: int = 65536) -> bytes:
        """One chunk of whatever the bridge wrote to stdout."""
        return await self._queue().get()

    async def receive_exactly(self, count: int) -> bytes:
        """Accumulate until ``count`` bytes have arrived, however they split."""
        collected = b""
        while len(collected) < count:
            collected += await self._queue().get()
        return collected

    def _queue(self) -> asyncio.Queue[bytes]:
        if self._output is None:
            loop = asyncio.get_running_loop()
            self._output = asyncio.Queue()
            self._thread = threading.Thread(
                target=self._drain_output, args=(loop, self._output), daemon=True
            )
            self._thread.start()
        return self._output

    def _drain_output(self, loop: asyncio.AbstractEventLoop, into: asyncio.Queue[bytes]) -> None:
        while True:
            try:
                data = os.read(self.stdout_read, 65536)
            except OSError:
                return
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(into.put_nowait, data)
            if not data:
                return

    def close(self) -> None:
        # Write ends first: closing a descriptor while a thread is parked
        # reading the other end of it hangs.
        for fd in (self.stdin_write, self.stdout_write, self.stdin_read, self.stdout_read):
            if fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(fd)
        self.stdin_write = -1


@contextlib.contextmanager
def pipes() -> Iterator[Pipes]:
    """``Pipes`` that always get closed, for use as a pytest fixture body."""
    made = Pipes()
    try:
        yield made
    finally:
        made.close()
