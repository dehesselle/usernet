"""The threaded stdio bridge, over real OS pipes.

Real pipes rather than fakes, because the whole reason this class exists is
that pipes cannot be selected on under the Windows proactor loop -- a fake
would test the one thing that was never in doubt.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import threading
from collections.abc import AsyncIterator, Iterator

import pytest
import pytest_asyncio

from usernet.runtime.stdio import StdioBridge


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


@pytest.fixture
def pipes() -> Iterator[Pipes]:
    made = Pipes()
    try:
        yield made
    finally:
        made.close()


@pytest_asyncio.fixture
async def bridge(pipes: Pipes) -> AsyncIterator[StdioBridge]:
    made = StdioBridge(pipes.stdin_read, pipes.stdout_write, chunk=4096)
    try:
        yield made
    finally:
        made.close()
        # Release the reader thread before anyone closes the descriptor it is
        # sitting on: closing a pipe out from under a blocked read hangs.
        pipes.end_input()
        await asyncio.to_thread(made.join, 2.0)


async def test_input_arrives(bridge: StdioBridge, pipes: Pipes) -> None:
    pipes.send(b"hello")
    assert await bridge.read() == b"hello"


async def test_successive_chunks_keep_their_order(bridge: StdioBridge, pipes: Pipes) -> None:
    """The reader thread waits for the consumer, so nothing may be dropped."""
    collected = b""
    for index in range(20):
        pipes.send(bytes([index]) * 100)
        collected += await bridge.read()
    assert collected == b"".join(bytes([index]) * 100 for index in range(20))


async def test_end_of_input_is_reported_once_and_stays(bridge: StdioBridge, pipes: Pipes) -> None:
    pipes.send(b"last")
    assert await bridge.read() == b"last"
    pipes.end_input()

    assert await bridge.read() == b""
    # A second read must not hang waiting for a thread that has already exited.
    assert await asyncio.wait_for(bridge.read(), timeout=2) == b""


async def test_output_reaches_the_descriptor(bridge: StdioBridge, pipes: Pipes) -> None:
    await bridge.write(b"to stdout")
    assert await pipes.receive() == b"to stdout"


async def test_writes_complete_in_order(bridge: StdioBridge, pipes: Pipes) -> None:
    for index in range(10):
        await bridge.write(bytes([index]) * 50)

    received = await pipes.receive_exactly(500)
    assert received == b"".join(bytes([index]) * 50 for index in range(10))


async def test_an_empty_write_is_a_no_op(bridge: StdioBridge) -> None:
    await asyncio.wait_for(bridge.write(b""), timeout=2)


async def test_a_large_write_is_delivered_whole(bridge: StdioBridge, pipes: Pipes) -> None:
    """Bigger than a pipe buffer, so os.write returns short and must loop."""
    payload = bytes(range(256)) * 2000  # 500 KB

    writing = asyncio.ensure_future(bridge.write(payload))
    received = await pipes.receive_exactly(len(payload))
    await writing

    assert received == payload


async def test_binary_data_survives_the_round_trip(bridge: StdioBridge, pipes: Pipes) -> None:
    """CRLF translation on Windows is what this whole class guards against, and
    it would corrupt exactly this."""
    payload = b"\r\n\x1a\x00\r\r\n\n" * 64
    pipes.send(payload)
    assert await bridge.read() == payload

    await bridge.write(payload)
    assert await pipes.receive_exactly(len(payload)) == payload
