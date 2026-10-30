# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Minutes of mixed traffic against the kernel, for the nightly run.

The other conformance tests each prove one property in a few seconds. This one
keeps several connections busy at once for as long as it is given -- uploads
and downloads of random sizes, every one checked byte for byte -- and then
checks that the stack is empty again. It finds what only time finds: a timer
that drifts, a counter that wraps, state that leaks one connection at a time.

``USERNET_CONFORMANCE_SOAK=<seconds>`` turns it on. It is off by default
because it is long, not because it is optional. ``USERNET_CONFORMANCE_SOAK_SEED``
chooses the sizes the workers draw, 0 by default; the nightly workflow changes
it on every run, and a failure names the seed to rerun it with.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import random
import time

import pytest

from tests.conformance.conftest import HOST_IP, within
from tests.conformance.test_kernel_tcp import Serve
from usernet.runtime.driver import Driver

SECONDS = float(os.environ.get("USERNET_CONFORMANCE_SOAK", "0"))
SEED = int(os.environ.get("USERNET_CONFORMANCE_SOAK_SEED", "0"))
WORKERS = 8

pytestmark = [
    pytest.mark.linux_only,
    pytest.mark.skipif(
        not SECONDS, reason="long-running: set USERNET_CONFORMANCE_SOAK=<seconds> to run it"
    ),
]


def body(size: int, salt: int) -> bytes:
    unit = hashlib.sha256(salt.to_bytes(8, "big")).digest()
    return (unit * (size // len(unit) + 1))[:size]


async def exchange_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Read ``up down salt``, then that many bytes; answer with their digest
    and ``down`` bytes of our own."""
    up, down, salt = map(int, (await reader.readline()).split())
    received = await reader.readexactly(up)
    writer.write(hashlib.sha256(received).hexdigest().encode() + b"\n")
    writer.write(body(down, salt))
    await writer.drain()
    writer.close()


@pytest.mark.timeout(SECONDS + 300 if SECONDS else 30)
async def test_mixed_traffic_for_a_long_time(driver: Driver, serve: Serve) -> None:
    port = await within(5, "the listener", serve(exchange_handler))
    deadline = time.monotonic() + SECONDS
    sizes = [0, 1, 1000, 64 * 1024, 512 * 1024, 2 * 1024 * 1024]
    done = [0] * WORKERS

    async def worker(index: int) -> None:
        rng = random.Random(SEED * WORKERS + index)
        while time.monotonic() < deadline:
            up, down, salt = rng.choice(sizes), rng.choice(sizes), rng.randrange(2**32)
            outgoing = body(up, salt ^ 0xFFFF)
            stream = await within(15, "a handshake", driver.connect(HOST_IP, port))
            await within(120, "an upload", stream.write(f"{up} {down} {salt}\n".encode()))
            await within(120, "an upload", stream.write(outgoing))
            reply = await within(180, "a download", stream.read_all(limit=down + 100))
            stream.close()

            digest, _, incoming = reply.partition(b"\n")
            context = f"seed {SEED}, worker {index}, exchange {done[index]}: up {up}, down {down}"
            assert digest.decode() == hashlib.sha256(outgoing).hexdigest(), f"upload: {context}"
            assert incoming == body(down, salt), f"download: {context}"
            done[index] += 1

    await asyncio.gather(*(worker(index) for index in range(WORKERS)))

    print(f"{sum(done)} exchanges in {SECONDS:g}s, seed {SEED}")
    async with asyncio.timeout(60):  # TIME_WAIT is 30 s
        while driver.stack._tcbs:  # noqa: ASYNC110 - no event says the stack is empty
            await asyncio.sleep(0.5)
    assert driver.stack.poll_at() is None
