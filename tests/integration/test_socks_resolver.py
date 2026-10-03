"""The SOCKS server's name-resolution seam, end to end over a virtual link.

A SOCKS5 request may carry a hostname instead of an address, and the point of
``socks5h://`` is that the *proxy* resolves it. Which resolver that should be
belongs to the tunnel, not to this package -- so it arrives as a callable, and
the tests below are about what happens at that seam rather than about DNS,
which usernet does not implement and should not.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

from usernet.errors import ResolveError
from usernet.http import httpx_client
from usernet.runtime.driver import Driver
from usernet.socks import Socks5Server
from usernet.socks.protocol import Reply
from usernet.testing import TcpPeer, VirtualLink
from usernet.testing.peer import http_handler

SERVER_IP = "10.221.188.32"
CLIENT_IP = "172.29.29.5"
NAME = "inside.example"


async def a_resolver(host: str) -> str:
    if host == NAME:
        return SERVER_IP
    raise ResolveError(f"{host!r} is not a name this tunnel knows")


@pytest_asyncio.fixture
async def peer() -> AsyncIterator[TcpPeer]:
    yield TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(b"resolved"))


async def serve(peer: TcpPeer, **kwargs: object) -> tuple[Socks5Server, Driver]:
    link = VirtualLink(peer, address=CLIENT_IP)
    driver = Driver(link)
    driver.start()
    proxy = Socks5Server(driver, host="127.0.0.1", port=0, **kwargs)  # type: ignore[arg-type]
    await proxy.start()
    return proxy, driver


async def socks_connect(port: int, target: bytes | str, dest_port: int) -> tuple[int, bytes]:
    """One SOCKS5 CONNECT. Returns the reply code and whatever came back."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        assert await reader.readexactly(2) == b"\x05\x00"

        if isinstance(target, str):
            encoded = target.encode()
            request = b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded
        else:
            request = b"\x05\x01\x00\x01" + target
        writer.write(request + dest_port.to_bytes(2, "big"))
        await writer.drain()

        reply = await reader.readexactly(10)
        if reply[1] != 0:
            return reply[1], b""

        writer.write(b"GET / HTTP/1.1\r\nHost: internal\r\n\r\n")
        await writer.drain()
        return 0, await reader.read(200)
    finally:
        writer.close()


# --- with a resolver --------------------------------------------------------


async def test_a_name_the_resolver_knows_is_connected_to(peer: TcpPeer) -> None:
    proxy, driver = await serve(peer, resolver=a_resolver)
    try:
        code, body = await socks_connect(proxy.port, NAME, 80)
        assert code == Reply.SUCCESS
        assert b"resolved" in body
    finally:
        await proxy.aclose()
        await driver.aclose()


async def test_the_resolvers_own_message_is_what_the_client_is_told(peer: TcpPeer) -> None:
    """The resolver knows which names it serves and this package does not, so
    its wording is what reaches whoever is reading a terminal."""
    proxy, driver = await serve(peer, resolver=a_resolver)
    try:
        code, _ = await socks_connect(proxy.port, "elsewhere.example", 80)
        assert code == Reply.HOST_UNREACHABLE
    finally:
        await proxy.aclose()
        await driver.aclose()


async def test_an_address_still_needs_no_resolver(peer: TcpPeer) -> None:
    proxy, driver = await serve(peer, resolver=a_resolver)
    try:
        code, body = await socks_connect(proxy.port, socket.inet_aton(SERVER_IP), 80)
        assert code == Reply.SUCCESS
        assert b"resolved" in body
    finally:
        await proxy.aclose()
        await driver.aclose()


async def test_a_resolved_address_outside_the_routes_is_refused(peer: TcpPeer) -> None:
    """Routing is checked against what the name resolved *to*. Checking the
    name instead would let any name at all past the split-route policy."""

    async def resolve_elsewhere(_host: str) -> str:
        return "8.8.8.8"

    link = VirtualLink(peer, address=CLIENT_IP, split_include=("10.0.0.0/8",))
    driver = Driver(link)
    driver.start()
    proxy = Socks5Server(driver, host="127.0.0.1", port=0, resolver=resolve_elsewhere)
    await proxy.start()
    try:
        code, _ = await socks_connect(proxy.port, NAME, 80)
        assert code == Reply.NOT_ALLOWED
    finally:
        await proxy.aclose()
        await driver.aclose()


# --- without one ------------------------------------------------------------


async def test_without_a_resolver_a_name_is_refused_with_an_explanation(peer: TcpPeer) -> None:
    """Never the host's own DNS. Resolving there would send tunnel-destined
    traffic to whatever public record happened to match the name."""
    proxy, driver = await serve(peer)
    try:
        code, _ = await socks_connect(proxy.port, NAME, 80)
        assert code == Reply.HOST_UNREACHABLE
    finally:
        await proxy.aclose()
        await driver.aclose()


async def test_a_resolver_that_raises_something_unexpected_does_not_kill_the_proxy(
    peer: TcpPeer,
) -> None:
    """One bad lookup must not take the listener down with it: every other
    client is still using it."""

    async def broken(_host: str) -> str:
        raise RuntimeError("the resolver is on fire")

    proxy, driver = await serve(peer, resolver=broken)
    try:
        with pytest.raises((asyncio.IncompleteReadError, ConnectionError)):
            await socks_connect(proxy.port, NAME, 80)
        # Still serving: an address needs no resolver and must still work.
        code, body = await socks_connect(proxy.port, socket.inet_aton(SERVER_IP), 80)
        assert code == Reply.SUCCESS
        assert b"resolved" in body
    finally:
        await proxy.aclose()
        await driver.aclose()


# --- on the driver ------------------------------------------------------------


async def test_a_drivers_resolver_is_the_proxys_default(peer: TcpPeer) -> None:
    """One resolver per tunnel, not one per consumer."""
    link = VirtualLink(peer, address=CLIENT_IP)
    driver = Driver(link, resolver=a_resolver)
    driver.start()
    proxy = Socks5Server(driver, host="127.0.0.1", port=0)
    await proxy.start()
    try:
        code, body = await socks_connect(proxy.port, NAME, 80)
        assert code == Reply.SUCCESS
        assert b"resolved" in body
    finally:
        await proxy.aclose()
        await driver.aclose()


async def test_the_driver_connects_to_a_name_it_can_resolve(peer: TcpPeer) -> None:
    driver = Driver(VirtualLink(peer, address=CLIENT_IP), resolver=a_resolver)
    driver.start()
    try:
        stream = await driver.connect(NAME, 80, timeout=5.0)
        assert stream.peer == (SERVER_IP, 80)
        stream.abort()
    finally:
        await driver.aclose()


async def test_http_through_the_driver_reaches_a_name(peer: TcpPeer) -> None:
    """The HTTP transport dials through the driver, so it needs nothing of its own."""
    driver = Driver(VirtualLink(peer, address=CLIENT_IP), resolver=a_resolver)
    driver.start()
    try:
        async with httpx_client(driver) as client:
            response = await client.get(f"http://{NAME}/")
        assert response.text == "resolved"
    finally:
        await driver.aclose()


async def test_without_a_resolver_the_driver_refuses_a_name(peer: TcpPeer) -> None:
    driver = Driver(VirtualLink(peer, address=CLIENT_IP))
    driver.start()
    try:
        with pytest.raises(ResolveError, match="no resolver"):
            await driver.connect(NAME, 80, timeout=5.0)
    finally:
        await driver.aclose()


async def test_the_resolvers_refusal_reaches_the_caller(peer: TcpPeer) -> None:
    driver = Driver(VirtualLink(peer, address=CLIENT_IP), resolver=a_resolver)
    driver.start()
    try:
        with pytest.raises(ResolveError, match="not a name this tunnel knows"):
            await driver.connect("elsewhere.example", 80, timeout=5.0)
    finally:
        await driver.aclose()
