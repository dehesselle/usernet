# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Seeded random transfers through the real driver.

The stateful suite searches the TCB's own state space. This one runs the whole
driver -- asyncio, timers, flow control, the event plumbing -- through
randomly chosen, reproducible combinations of link impairment, MTU, buffer
size, transfer sizes and reading pattern, and asks only that every byte
arrives exactly once.

``USERNET_SOAK_SEEDS`` sets how many seeds run: a handful by default, which is
what every push gets, and hundreds in the nightly workflow.
``USERNET_SOAK_SEED_BASE`` is the first of them, 0 by default; the nightly
workflow moves it on every run, so each night tries seeds no night has tried
before rather than replaying the same ones. A failure names its seed, and
``USERNET_SOAK_SEED=<n>`` replays that one alone.
"""

from __future__ import annotations

import asyncio
import os
import random

import pytest

from usernet.net.stack import StackConfig
from usernet.net.tcb import TcbConfig
from usernet.runtime.driver import Driver
from usernet.testing import TcpPeer, VirtualLink
from usernet.testing.peer import http_handler

SERVER_IP = "10.221.188.32"
CLIENT_IP = "172.29.29.5"


def seeds() -> list[int]:
    if "USERNET_SOAK_SEED" in os.environ:
        return [int(os.environ["USERNET_SOAK_SEED"])]
    base = int(os.environ.get("USERNET_SOAK_SEED_BASE", "0"))
    return list(range(base, base + int(os.environ.get("USERNET_SOAK_SEEDS", "4"))))


def scenario(seed: int) -> dict[str, object]:
    """Everything about one run, drawn from its seed and nothing else."""
    rng = random.Random(seed)
    s: dict[str, object] = {
        # Not above 5%. The fixture peer discards out-of-order data, so every
        # loss makes us send the whole window behind it again, and Karn's rule
        # allows no RTT sample from anything sent twice. Near the end of a
        # transfer, with no new data left to time, nothing stops the RTO
        # backing off, and at 10% a 120 KB request outlasted the test. A
        # kernel keeps out-of-order data; the conformance suite covers it.
        "loss": rng.choice([0.0, 0.0, 0.01, 0.02, 0.05]),
        "duplicate": rng.choice([0.0, 0.0, 0.02, 0.2]),
        "reorder": rng.choice([0.0, 0.0, 0.05, 0.3]),
        "mtu": rng.choice([576, 1383, 1500]),
        "buffer": rng.choice([4096, 16 * 1024, 256 * 1024, 1024 * 1024]),
        "request": rng.choice([0, 100, 5000, 60_000]),
        "response": rng.choice([0, 1, 1400, 100_000, 400_000]),
        "read": rng.choice([None, 1, 1000, 65536]),
        "pause": rng.choice([0.0, 0.0, 0.02]),
        "link_seed": rng.randrange(2**32),
    }
    # Loss falls on our packets only, ACKs and window updates among them, and
    # the fixture peer can neither retransmit nor probe a closed window. Behind
    # a large response one lost update stalls the harness, not the stack -- so
    # loss here is for our retransmission of the request, and the conformance
    # suite owns loss on bulk transfers.
    if s["loss"]:
        s["response"] = min(s["response"], 1400)  # type: ignore[type-var]
    # Loss bounds the request too, at the smallest MTU. With no timestamps,
    # Karn's rule leaves no RTT sample while one recovery follows another, and
    # behind a fixture peer that discards out-of-order data every segment sent
    # past a hole goes out again. So each timeout doubles the RTO and nothing
    # brings it back down. In 536-byte segments, 120 KB of hex reached a 60 s
    # RTO and outlasted the test in 2 of 145 seeds, at 2% loss and at 5%. 40 KB
    # is fewer segments than the largest request takes at the other MTUs,
    # where no seed out of 300 took longer than 9 s.
    if s["loss"] and s["mtu"] == 576:
        s["request"] = min(s["request"], 20_000)  # type: ignore[type-var]
    # Reading a byte at a time is for partial reads, not throughput: through
    # the driver each read is a pass of the event loop, and 400 KB of them
    # takes minutes.
    if s["read"] == 1:
        s["response"] = min(s["response"], 1400)  # type: ignore[type-var]
    return s


def pattern(size: int, salt: int) -> bytes:
    """A body in which a byte out of place cannot go unnoticed."""
    unit = bytes((salt + index * 7) % 251 for index in range(251))
    return (unit * (size // len(unit) + 1))[:size]


@pytest.mark.timeout(120)
@pytest.mark.parametrize("seed", seeds(), ids=lambda seed: f"seed-{seed}")
async def test_a_random_transfer_arrives_byte_exact(seed: int) -> None:
    s = scenario(seed)
    body = pattern(s["response"], seed)  # type: ignore[arg-type]
    padding = pattern(s["request"], seed + 1)  # type: ignore[arg-type]
    request = b"GET /soak HTTP/1.1\r\nX-Pad: " + padding.hex().encode() + b"\r\n\r\n"

    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(body))
    link = VirtualLink(
        peer,
        address=CLIENT_IP,
        mtu=s["mtu"],  # type: ignore[arg-type]
        loss=s["loss"],  # type: ignore[arg-type]
        duplicate=s["duplicate"],  # type: ignore[arg-type]
        reorder=s["reorder"],  # type: ignore[arg-type]
        seed=s["link_seed"],  # type: ignore[arg-type]
    )
    buffer = s["buffer"]
    driver = Driver(
        link,
        stack_config=StackConfig(
            local_ip=CLIENT_IP,
            mtu=link.config.mtu,
            tcb=TcbConfig(
                mss=link.config.mtu - 40,
                rx_buffer=buffer,  # type: ignore[arg-type]
                tx_buffer=buffer,  # type: ignore[arg-type]
            ),
        ),
    )
    driver.start()
    try:
        stream = await driver.connect(SERVER_IP, 80, timeout=20)
        await stream.write(request)
        if s["read"] is None:
            response = await stream.read_all(limit=len(body) + 1000)
        else:
            # A slow reader pauses now and then, which is enough to shut the
            # window; pausing after every read would only test the timer
            # resolution, a byte at a time.
            chunks = bytearray()
            unpaused = 0
            while chunk := await stream.read(s["read"]):  # type: ignore[arg-type]
                chunks += chunk
                unpaused += len(chunk)
                if s["pause"] and unpaused >= 32 * 1024:
                    unpaused = 0
                    await asyncio.sleep(s["pause"])  # type: ignore[arg-type]
            response = bytes(chunks)
        stream.close()
    finally:
        await driver.aclose()

    context = f"seed {seed}: {s}"
    assert response.split(b"\r\n\r\n", 1)[1] == body, f"response damaged; {context}"
    (connection,) = peer.connections.values()
    assert bytes(connection.received) == request, f"request damaged; {context}"
