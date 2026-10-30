# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Fixtures for the L3 conformance suite.

Two things matter more here than in the rest of the tree.

*Skips must explain themselves.* A silently skipped conformance suite is worse
than no suite, because it looks green. Every skip names the command that would
have made it run.

*Failures must arrive diagnosed.* These tests run on a machine the author
cannot reach, so the packet trace is printed during teardown of every test.
pytest shows captured output only for failures, which is exactly the policy
wanted: silent when green, a full trace when not.
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from usernet.link import SimpleLinkConfig
from usernet.runtime.driver import Driver

if TYPE_CHECKING:
    from tests.conformance.tun import TunDevice, TunLink

# Importing tun.py needs fcntl, so this package is not collectable elsewhere.
collect_ignore_glob = ["test_*.py"] if sys.platform != "linux" else []

DEVICE = "usernet0"
HOST_IP = "10.99.0.1"  # the kernel's end -- real Linux TCP answers here
STACK_IP = "10.99.0.2"  # ours
NETMASK = "255.255.255.0"

IMPAIRED = bool(os.environ.get("USERNET_TUN_NETEM"))
"""Set when the run is under ``tc qdisc ... netem``.

Some properties are only guaranteed on a clean link. TCP must deliver every
byte either way -- that is the whole point -- but ICMP echo is unreliable by
definition, and packet counts stop meaning anything once loss is deliberate.
Asserting those under netem tests the impairment, not the stack.
"""

SETUP_HINT = (
    "run 'sudo sh tests/conformance/setup.sh' then 'uv run python -m tests.conformance.preflight'"
)

TIMEOUT_HINT = (
    "packets went out and nothing came back. Usual causes, most likely first:\n"
    f"  1. a firewall dropping traffic on {DEVICE} "
    f"(sudo iptables -I INPUT -i {DEVICE} -j ACCEPT)\n"
    f"  2. {DEVICE} is down, or lost its address\n"
    "  3. reverse-path filtering "
    f"(sudo sysctl -w net.ipv4.conf.{DEVICE}.rp_filter=0)\n"
    "The trace below shows exactly how far the exchange got."
)


# --- the device -------------------------------------------------------------


@pytest.fixture(scope="session")
def tun_device() -> Iterator[TunDevice]:
    from tests.conformance.tun import TunDevice, TunSetupError

    try:
        device = TunDevice(DEVICE)
    except TunSetupError as exc:
        pytest.skip(f"{exc}\n{SETUP_HINT}")
    try:
        yield device
    finally:
        device.close()


@pytest.fixture(scope="session")
def tun_mtu() -> int:
    """The interface's real MTU, so the tests follow the machine, not a guess."""
    try:
        return int(Path(f"/sys/class/net/{DEVICE}/mtu").read_text().strip())
    except OSError:
        return 1500


@pytest.fixture
def trace() -> Iterator[Any]:
    from tests.conformance.trace import PacketTrace

    recorder = PacketTrace()
    yield recorder
    # Unconditional: pytest discards captured output for passing tests and
    # prints it for failing ones, which is the behaviour wanted here.
    print(recorder.dump("this test"))


@pytest.fixture
async def link(tun_device: TunDevice, tun_mtu: int, trace: Any) -> AsyncIterator[TunLink]:
    from tests.conformance.tun import TunLink

    config = SimpleLinkConfig(address=STACK_IP, netmask=NETMASK, mtu=tun_mtu)
    tun_link = TunLink(tun_device, config, trace)
    tun_link.start()
    try:
        yield tun_link
    finally:
        await tun_link.aclose()


@pytest.fixture
async def driver(link: TunLink) -> AsyncIterator[Driver]:
    stack_driver = Driver(link)
    stack_driver.start()
    try:
        yield stack_driver
    finally:
        await stack_driver.aclose()


# --- peers on the kernel's side --------------------------------------------

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


@pytest.fixture
async def serve() -> AsyncIterator[Callable[[Handler], Awaitable[int]]]:
    """Start a real kernel-side TCP server; returns the port it landed on.

    An ordinary asyncio server, which means an ordinary kernel socket: the
    thing on the other side of these tests is Linux TCP, not a model of it.
    """
    servers: list[asyncio.Server] = []

    async def start(handler: Handler) -> int:
        server = await asyncio.start_server(handler, HOST_IP, 0)
        servers.append(server)
        return int(server.sockets[0].getsockname()[1])

    try:
        yield start
    finally:
        for server in servers:
            server.close()
        for server in servers:
            # Bounded: from 3.12 wait_closed() also waits for live handlers,
            # and a test that failed mid-transfer may well have left one.
            try:
                async with asyncio.timeout(2):
                    await server.wait_closed()
            except (TimeoutError, OSError):
                pass


@pytest.fixture
async def closed_port() -> int:
    """A port on the kernel's address with nothing listening, so it RSTs."""
    server = await asyncio.start_server(lambda r, w: None, HOST_IP, 0)
    port = int(server.sockets[0].getsockname()[1])
    server.close()
    await server.wait_closed()
    return port


# --- turning hangs into readable failures -----------------------------------


async def within[T](seconds: float, what: str, awaitable: Awaitable[T]) -> T:
    """Await with a deadline that fails the test instead of wedging it.

    pytest-timeout would kill the process, and a killed process prints no
    trace. Failing normally keeps the diagnostics.
    """
    try:
        async with asyncio.timeout(seconds):
            return await awaitable
    except TimeoutError:
        pytest.fail(f"timed out after {seconds:g}s waiting for {what}.\n{TIMEOUT_HINT}")
