# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Whole-stack throughput and latency against real Linux TCP.

    python bench/macro.py download [--bytes N] [--idle K] [--profile FILE]
    python bench/macro.py upload   [--bytes N]
    python bench/macro.py echo     [--count N] [--size B] [--idle K]

Linux only, and normally started by ``bench/run.py`` rather than by hand. The
shipping ``Driver`` and ``PyStack`` run unmodified over the conformance
suite's ``TunLink``; ``bench/kernel_server.py`` answers from a separate
process. Prints one JSON object.

On a clean tun link nothing limits throughput except CPU, so the transfer
numbers are the stack's per-byte cost seen from outside. Every transfer is
checked byte for byte, after the clock has stopped.
"""

from __future__ import annotations

import argparse
import asyncio
import cProfile
import hashlib
import io
import json
import os
import pstats
import statistics
import sys
import time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))  # for tests.conformance

from kernel_server import pattern  # bench/ is the script's own directory
from tests.conformance.tun import TunDevice, TunLink

from usernet.link import SimpleLinkConfig
from usernet.runtime.driver import Driver, TcpStream

DEVICE = os.environ.get("USERNET_TUN_DEV", "usernet0")
HOST_IP = os.environ.get("USERNET_TUN_HOST", "10.99.0.1")
STACK_IP = os.environ.get("USERNET_TUN_STACK", "10.99.0.2")
NETMASK = "255.255.255.0"
MIB = 1024 * 1024
SETTLE_S = 0.5


class Clock:
    """Wall and CPU time over the same interval."""

    def __enter__(self) -> Clock:
        self.wall = time.perf_counter()
        self.cpu = time.process_time()
        return self

    def __exit__(self, *exc: object) -> None:
        self.wall = time.perf_counter() - self.wall
        self.cpu = time.process_time() - self.cpu


async def park(driver: Driver, port: int, count: int) -> list[TcpStream]:
    """Open ``count`` connections that then do nothing.

    They cost nothing on the wire but sit in the stack's tables, which is the
    browser-on-SOCKS case: hundreds of sockets, mostly quiet, beside the one
    that matters.
    """
    parked = []
    for _ in range(count):
        stream = await driver.connect(HOST_IP, port, timeout=10)
        await stream.write(b"IDLE\n")
        parked.append(stream)
    return parked


async def download(driver: Driver, port: int, size: int, idle: int) -> dict[str, object]:
    parked = await park(driver, port, idle)
    stream = await driver.connect(HOST_IP, port, timeout=10)
    chunks: list[bytes] = []
    with Clock() as clock:
        await stream.write(b"SRC %d\n" % size)
        while chunk := await stream.read():
            chunks.append(chunk)
    stream.close()
    for stream in parked:
        stream.close()

    received = b"".join(chunks)
    if received != pattern(size):
        raise SystemExit(f"download corrupted: got {len(received)} bytes, wanted {size}")
    return _transfer(size, clock)


async def upload(driver: Driver, port: int, size: int) -> dict[str, object]:
    data = pattern(size)
    expected = hashlib.sha256(data).hexdigest()
    stream = await driver.connect(HOST_IP, port, timeout=10)
    with Clock() as clock:
        await stream.write(b"SNK %d\n" % size)
        await stream.write(data)
        stream.close()  # FIN: the server replies once it has everything
        reply = await stream.read_all()
    count, digest = reply.split()
    if int(count) != size or digest.decode() != expected:
        raise SystemExit(f"upload corrupted: server saw {int(count)} bytes, wanted {size}")
    return _transfer(size, clock)


async def echo(driver: Driver, port: int, count: int, size: int, idle: int) -> dict[str, object]:
    message = bytes(range(256))[:size]
    parked = await park(driver, port, idle)
    stream = await driver.connect(HOST_IP, port, timeout=10)
    await stream.write(b"ECHO\n")
    latencies: list[float] = []
    with Clock() as clock:
        for _ in range(count):
            t0 = time.perf_counter_ns()
            await stream.write(message)
            got = 0
            while got < size:
                chunk = await stream.read()
                if not chunk:
                    raise SystemExit("echo server closed early")
                got += len(chunk)
            latencies.append((time.perf_counter_ns() - t0) / 1000)
    stream.close()
    for stream in parked:
        stream.close()
    latencies.sort()
    return {
        "p50_us": statistics.median(latencies),
        "p99_us": latencies[int(len(latencies) * 0.99)],
        "mean_us": statistics.fmean(latencies),
        "cpu_us_per_op": clock.cpu / count * 1e6,
    }


def _transfer(size: int, clock: Clock) -> dict[str, object]:
    return {
        "mb_per_s": size / MIB / clock.wall,
        "cpu_s_per_mib": clock.cpu / (size / MIB),
        "wall_s": clock.wall,
    }


async def run(args: argparse.Namespace, mtu: int) -> dict[str, object]:
    device = TunDevice(DEVICE)
    link = TunLink(device, SimpleLinkConfig(address=STACK_IP, netmask=NETMASK, mtu=mtu))
    link.start()
    driver = Driver(link)
    driver.start()
    try:
        if args.scenario == "download":
            return await download(driver, args.port, args.bytes, args.idle)
        if args.scenario == "upload":
            return await upload(driver, args.port, args.bytes)
        return await echo(driver, args.port, args.count, args.size, args.idle)
    finally:
        # Let the closes finish on the wire before the process goes. Leaving
        # them half-done strands the kernel's ends in ESTABLISHED, and a
        # later run whose SYN lands on one of those four-tuples gets a bare
        # ACK back instead of a SYN-ACK -- a connect timeout that looks like
        # a stack bug. With 300 idle connections a run, it soon happens.
        await asyncio.sleep(SETTLE_S)
        await driver.aclose()
        await link.aclose()
        device.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("scenario", choices=["download", "upload", "echo"])
    parser.add_argument("--port", type=int, default=5201)
    parser.add_argument("--bytes", type=int, default=64 * MIB)
    parser.add_argument("--idle", type=int, default=0)
    parser.add_argument("--count", type=int, default=2000)
    parser.add_argument("--size", type=int, default=100)
    parser.add_argument("--profile", type=Path, help="write a cProfile summary here")
    args = parser.parse_args()

    profiler = cProfile.Profile() if args.profile else None
    if profiler is not None:
        profiler.enable()
    # The interface's real MTU, so the stack sizes segments as it would there.
    mtu = int(Path(f"/sys/class/net/{DEVICE}/mtu").read_text().strip())
    result = asyncio.run(run(args, mtu))
    if profiler is not None:
        profiler.disable()
        out = io.StringIO()
        pstats.Stats(profiler, stream=out).sort_stats("tottime").print_stats(25)
        args.profile.write_text(out.getvalue())
    print(json.dumps(result))


if __name__ == "__main__":
    main()
