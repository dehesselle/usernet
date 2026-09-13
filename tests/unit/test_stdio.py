"""The threaded stdio bridge, over real OS pipes.

Real pipes rather than fakes, because the whole reason this class exists is
that pipes cannot be selected on under the Windows proactor loop -- a fake
would test the one thing that was never in doubt.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator

import pytest
import pytest_asyncio

from usernet.runtime.stdio import StdioBridge
from usernet.testing.pipes import Pipes


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
