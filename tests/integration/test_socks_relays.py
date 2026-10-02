"""What the SOCKS server exposes about its live relays.

A long-running proxy is easier to trust when it can show what it is carrying:
which destinations are open, and that bytes are still moving through them.
Those are plain counters on the stream and a map on the server; these tests
pin down that they agree with what actually crossed the relay.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable

import pytest_asyncio

from usernet.runtime.driver import Driver
from usernet.socks import Socks5Server
from usernet.testing import TcpPeer, VirtualLink
from usernet.testing.peer import http_handler

SERVER_IP = "10.221.188.32"
CLIENT_IP = "172.29.29.5"
NAME = "inside.example"
BODY = b"x" * 5000
REQUEST = b"GET / HTTP/1.1\r\nHost: inside\r\n\r\n"


async def a_resolver(host: str) -> str:
    assert host == NAME
    return SERVER_IP


@pytest_asyncio.fixture
async def proxy() -> AsyncIterator[Socks5Server]:
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(BODY))
    driver = Driver(VirtualLink(peer, address=CLIENT_IP))
    driver.start()
    server = Socks5Server(driver, host="127.0.0.1", port=0, resolver=a_resolver)
    await server.start()
    try:
        yield server
    finally:
        await server.aclose()
        await driver.aclose()


async def open_relay(port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"
    encoded = NAME.encode()
    writer.write(b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded + (80).to_bytes(2, "big"))
    await writer.drain()
    reply = await reader.readexactly(10)
    assert reply[1] == 0
    return reader, writer


async def until(condition: Callable[[], object]) -> None:
    """Poll: the relay's bookkeeping happens in the server's own task."""
    for _ in range(500):
        if condition():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition never became true")


async def test_a_relay_is_listed_by_the_name_the_client_asked_for(proxy: Socks5Server) -> None:
    _reader, writer = await open_relay(proxy.port)
    try:
        await until(lambda: proxy.relays)
        assert list(proxy.relays.values()) == [f"{NAME}:80"]
    finally:
        writer.close()


async def test_the_counters_match_what_crossed_the_relay(proxy: Socks5Server) -> None:
    reader, writer = await open_relay(proxy.port)
    try:
        await until(lambda: proxy.relays)
        (stream,) = proxy.relays

        writer.write(REQUEST)
        await writer.drain()
        response = b""
        while BODY not in response:
            chunk = await reader.read(65536)
            assert chunk, "the relay ended before the body arrived"
            response += chunk

        assert stream.tx == len(REQUEST)
        assert stream.rx == len(response)
        assert stream.opened_at > 0
    finally:
        writer.close()


async def test_a_finished_relay_leaves_the_map(proxy: Socks5Server) -> None:
    _reader, writer = await open_relay(proxy.port)
    await until(lambda: proxy.relays)
    writer.close()
    await until(lambda: proxy.active == 0)
    assert proxy.relays == {}
