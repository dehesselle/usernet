# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""What the SOCKS server does with clients that do not follow the protocol.

Every local process can reach the listener, so whatever one sends must cost it
that one connection and nothing more: a refusal with the right code where the
protocol has one, a closed socket where it does not, and a server that goes on
serving the next client.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

from usernet.runtime.driver import Driver
from usernet.socks import Socks5Server
from usernet.socks.protocol import Reply
from usernet.testing import TcpPeer, VirtualLink
from usernet.testing.peer import http_handler

SERVER_IP = "10.221.188.32"
CLIENT_IP = "172.29.29.5"
GREETING = b"\x05\x01\x00"
CONNECT = b"\x05\x01\x00\x01" + bytes([10, 221, 188, 32]) + (80).to_bytes(2, "big")


@pytest_asyncio.fixture
async def server() -> AsyncIterator[Socks5Server]:
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b"still serving"))
    driver = Driver(VirtualLink(peer, address=CLIENT_IP))
    driver.start()
    socks = Socks5Server(driver, port=0, handshake_timeout=0.5)
    await socks.start()
    try:
        yield socks
    finally:
        await socks.aclose()
        await driver.aclose()


async def exchange(server: Socks5Server, *messages: bytes) -> bytes:
    """Send each message, then read whatever the server says until it closes."""
    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    try:
        for message in messages:
            writer.write(message)
            await writer.drain()
        return await asyncio.wait_for(reader.read(), timeout=5)
    finally:
        writer.close()


async def still_serves(server: Socks5Server) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    try:
        writer.write(GREETING)
        assert await reader.readexactly(2) == b"\x05\x00"
        writer.write(CONNECT)
        reply = await reader.readexactly(10)
        assert reply[1] == Reply.SUCCESS
        writer.write(b"GET / HTTP/1.1\r\n\r\n")
        assert (await reader.read()).endswith(b"still serving")
    finally:
        writer.close()


async def settled(server: Socks5Server) -> None:
    """Wait for the handlers of closed connections to finish."""
    async with asyncio.timeout(5):
        while server.active:  # noqa: ASYNC110 - a counter, with no event to wait on
            await asyncio.sleep(0.01)


@pytest.mark.parametrize(
    ("messages", "reply"),
    [
        ((b"\x04\x01\x00\x50" + bytes(4) + b"\x00",), b""),
        ((b"\x05\x01\x02",), b"\x05\xff"),
        ((GREETING, b"\x05\x02\x00\x01" + bytes(6)), b"\x05\x00\x05\x07"),
        ((GREETING, b"\x05\x03\x00\x01" + bytes(6)), b"\x05\x00\x05\x07"),
        ((GREETING, b"\x05\x01\x00\x04" + bytes(18)), b"\x05\x00\x05\x08"),
        ((GREETING, b"\x05\x01\x00\x07\x00"), b"\x05\x00\x05\x08"),
        ((GREETING, b"\x05\x01\x00\x03\x20short"), b"\x05\x00"),
    ],
    ids=[
        "socks4",
        "no-acceptable-method",
        "bind",
        "udp-associate",
        "ipv6",
        "unknown-address-type",
        "truncated-name",
    ],
)
async def test_a_bad_client_costs_one_connection(
    server: Socks5Server, messages: tuple[bytes, ...], reply: bytes
) -> None:
    received = await exchange(server, *messages)

    # The method reply, then the start of the refusal: the rest is BND.ADDR.
    assert received[: len(reply)] == reply
    await settled(server)
    assert server.rejected == 1
    await still_serves(server)


async def test_a_client_that_says_nothing_is_disconnected(server: Socks5Server) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    try:
        assert await asyncio.wait_for(reader.read(), timeout=5) == b""
    finally:
        writer.close()

    await settled(server)
    assert server.rejected == 1
    await still_serves(server)


async def test_a_client_that_stalls_after_the_greeting_is_disconnected(
    server: Socks5Server,
) -> None:
    """Past the greeting is where a slow client holds a negotiated slot."""
    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    try:
        writer.write(GREETING)
        assert await reader.readexactly(2) == b"\x05\x00"
        writer.write(CONNECT[:3])  # and then nothing
        assert await asyncio.wait_for(reader.read(), timeout=5) == b""
    finally:
        writer.close()

    await settled(server)
    assert server.rejected == 1


async def test_many_bad_clients_at_once_leave_nothing_behind(server: Socks5Server) -> None:
    await asyncio.gather(
        *(exchange(server, b"\x05\x01\x00\x09") for _ in range(50)),
        *(exchange(server, GREETING) for _ in range(50)),
    )

    await settled(server)
    assert server.rejected == 100
    assert server.relays == {}
    await still_serves(server)
