# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Many connections, opened and ended every way there is, leave nothing behind.

A proxy runs for days and opens thousands of connections. One socket, timer or
task left over per connection is invisible in every other test and fatal over
that span. So this suite churns through connections ending in each way the
application or the peer can end them, then checks that the stack, the driver
and the event loop are back to where they started.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest
import pytest_asyncio

from usernet.errors import NetworkError
from usernet.net.stack import StackConfig
from usernet.net.tcb import TcbConfig
from usernet.runtime.driver import Driver, TcpStream
from usernet.testing import TcpPeer, VirtualLink
from usernet.testing.peer import http_handler

SERVER_IP = "10.221.188.32"
CLIENT_IP = "172.29.29.5"
BODY = b"churn" * 300  # bigger than one segment
REQUEST = b"GET / HTTP/1.1\r\n\r\n"
TIME_WAIT_MS = 200


@pytest_asyncio.fixture
async def driver() -> AsyncIterator[Driver]:
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(BODY))
    link = VirtualLink(peer, address=CLIENT_IP)
    driver = Driver(
        link,
        stack_config=StackConfig(
            local_ip=CLIENT_IP,
            mtu=link.config.mtu,
            # Short, so the test can wait it out; long enough that the
            # endings below really do find connections in TIME_WAIT.
            tcb=TcbConfig(mss=link.config.mtu - 40, time_wait_ms=TIME_WAIT_MS),
        ),
    )
    driver.start()
    try:
        yield driver
    finally:
        await driver.aclose()


# --- how a connection can end ------------------------------------------------


async def passive_close(stream: TcpStream) -> None:
    """The peer finishes first; we follow. CLOSE_WAIT, LAST_ACK."""
    await stream.write(REQUEST)
    assert (await stream.read_all()).endswith(BODY)
    stream.close()


async def active_close(stream: TcpStream) -> None:
    """We finish first and the peer answers after. FIN_WAIT, TIME_WAIT."""
    await stream.write(REQUEST)
    stream.close()
    assert (await stream.read_all()).endswith(BODY)


async def abort(stream: TcpStream) -> None:
    await stream.write(REQUEST)
    stream.abort()


async def abort_in_time_wait(stream: TcpStream) -> None:
    """An abort that arrives after the connection has already ended cleanly
    -- a relay torn down at shutdown, say -- must still finish the stream."""
    await active_close(stream)
    await asyncio.sleep(0.02)  # let the final ACK go out
    stream.abort()


ENDINGS: list[Callable[[TcpStream], Awaitable[None]]] = [
    passive_close,
    active_close,
    abort,
    abort_in_time_wait,
]


async def run(driver: Driver, index: int) -> TcpStream:
    stream = await driver.connect(SERVER_IP, 80, timeout=10)
    ending = ENDINGS[index % len(ENDINGS)]
    try:
        await ending(stream)
    except NetworkError:
        # An abort reports itself to anything still waiting on the stream.
        assert ending in (abort, abort_in_time_wait)
    return stream


async def drained(driver: Driver) -> None:
    """Everything is gone: streams, sockets, timers."""
    stack = driver.stack
    async with asyncio.timeout(10):
        while driver._streams or stack._tcbs:  # noqa: ASYNC110 - no event says "empty"
            await asyncio.sleep(0.05)
    assert stack._by_tuple == {}
    assert stack._deadlines == {}
    assert stack.poll_at() is None


async def tasks_settle(baseline: int) -> None:
    """The task count returns to ``baseline``.

    Waited for, not read at once: a stream's wait cancels the waiter that
    lost, and that task finishes cancelling an iteration or two later. A
    leaked task never does, so a bounded wait still catches one.
    """
    try:
        async with asyncio.timeout(5):
            while len(asyncio.all_tasks()) > baseline:  # noqa: ASYNC110 - nothing to wait on
                await asyncio.sleep(0.01)
    except TimeoutError:
        pass
    assert len(asyncio.all_tasks()) == baseline, f"tasks left over: {asyncio.all_tasks()}"


# --- the tests ---------------------------------------------------------------


@pytest.mark.slow
@pytest.mark.timeout(120)
async def test_sequential_churn_leaves_nothing_behind(driver: Driver) -> None:
    tasks_before = len(asyncio.all_tasks())

    streams = [await run(driver, index) for index in range(500)]

    await drained(driver)
    assert all(stream.finished.is_set() for stream in streams), "a stream never finished"
    await tasks_settle(tasks_before)


@pytest.mark.slow
@pytest.mark.timeout(120)
async def test_concurrent_churn_leaves_nothing_behind(driver: Driver) -> None:
    tasks_before = len(asyncio.all_tasks())

    streams = await asyncio.gather(*(run(driver, index) for index in range(200)))

    await drained(driver)
    assert all(stream.finished.is_set() for stream in streams), "a stream never finished"
    await tasks_settle(tasks_before)


@pytest.mark.timeout(60)
async def test_a_hundred_concurrent_transfers_arrive_byte_exact(driver: Driver) -> None:
    """Demultiplexing under load: each connection gets its own bytes, whole."""

    async def fetch(index: int) -> bytes:
        stream = await driver.connect(SERVER_IP, 80, timeout=10)
        await stream.write(f"GET /{index} HTTP/1.1\r\nX-Pad: {'p' * index * 20}\r\n\r\n".encode())
        response = await stream.read_all()
        stream.close()
        return response

    responses = await asyncio.gather(*(fetch(index) for index in range(100)))

    assert all(response.endswith(BODY) for response in responses)
    peer = driver.link.peer  # type: ignore[attr-defined]
    requests = sorted(bytes(connection.received) for connection in peer.connections.values())
    expected = sorted(
        f"GET /{index} HTTP/1.1\r\nX-Pad: {'p' * index * 20}\r\n\r\n".encode()
        for index in range(100)
    )
    assert requests == expected
    await drained(driver)
