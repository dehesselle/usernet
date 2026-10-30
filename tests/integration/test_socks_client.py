# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The SOCKS5 client, against our own server and against proxies that misbehave.

Against our server, the two halves of usernet.socks.protocol meet, and every
refusal the server can give must come back to the client as the error it stood
for. Against a scripted proxy, the client meets the replies our server would
never send.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest
import pytest_asyncio

from usernet.errors import (
    ConnectionTimeout,
    HostUnreachable,
    NetworkError,
    ProtocolParseError,
    ResolveError,
    RouteNotAllowed,
)
from usernet.runtime.driver import Driver
from usernet.socks import Socks5Server
from usernet.socks.client import open_via_socks
from usernet.testing import TcpPeer, VirtualLink
from usernet.testing.peer import http_handler

SERVER_IP = "10.221.188.32"
CLIENT_IP = "172.29.29.5"
EXCLUDED_IP = "10.99.0.7"
NAME = "inside.example"
BODY = b"through the proxy"
REQUEST = b"GET / HTTP/1.1\r\nHost: inside\r\n\r\n"


async def resolver(host: str) -> str:
    if host == NAME:
        return SERVER_IP
    raise ResolveError(f"{host} is not a name this tunnel knows")


@contextlib.asynccontextmanager
async def proxy(**options: object) -> AsyncIterator[int]:
    peer = TcpPeer(ip=SERVER_IP, port=80, handler=http_handler(BODY))
    driver = Driver(VirtualLink(peer, address=CLIENT_IP, split_exclude=("10.99.0.0/16",)))
    driver.start()
    server = Socks5Server(driver, port=0, resolver=resolver, **options)  # type: ignore[arg-type]
    await server.start()
    try:
        yield server.port
    finally:
        await server.aclose()
        await driver.aclose()


@pytest_asyncio.fixture
async def port() -> AsyncIterator[int]:
    async with proxy(connect_timeout=1.0) as bound:
        yield bound


async def fetch(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bytes:
    writer.write(REQUEST)
    await writer.drain()
    try:
        return await reader.read()
    finally:
        writer.close()


# --- against our own server --------------------------------------------------


@pytest.mark.parametrize("host", [SERVER_IP, NAME], ids=["address", "name"])
async def test_a_request_goes_through_the_proxy_and_back(port: int, host: str) -> None:
    response = await fetch(*await open_via_socks("127.0.0.1", port, host, 80))
    assert response.startswith(b"HTTP/1.1 200 OK")
    assert response.endswith(BODY)


async def test_credentials_are_offered_when_the_proxy_wants_them() -> None:
    async with proxy(username="alice", password="s3cret") as bound:
        streams = await open_via_socks(
            "127.0.0.1", bound, SERVER_IP, 80, username="alice", password="s3cret"
        )
        assert (await fetch(*streams)).endswith(BODY)


async def test_wrong_credentials_are_reported_as_rejected() -> None:
    async with proxy(username="alice", password="s3cret") as bound:
        with pytest.raises(NetworkError, match="rejected the credentials"):
            await open_via_socks(
                "127.0.0.1", bound, SERVER_IP, 80, username="alice", password="guess"
            )


async def test_missing_credentials_are_named_as_the_likely_cause() -> None:
    async with proxy(username="alice", password="s3cret") as bound:
        with pytest.raises(NetworkError, match="may require a username and password"):
            await open_via_socks("127.0.0.1", bound, SERVER_IP, 80)


@pytest.mark.parametrize(
    ("host", "port_number", "expected"),
    [
        (EXCLUDED_IP, 80, RouteNotAllowed),
        ("nowhere.example", 80, HostUnreachable),
        (SERVER_IP, 81, ConnectionTimeout),  # nothing answers there
    ],
    ids=["outside-the-routes", "unresolvable", "no-answer"],
)
async def test_a_refusal_comes_back_as_the_error_it_stands_for(
    port: int, host: str, port_number: int, expected: type[NetworkError]
) -> None:
    with pytest.raises(expected):
        await open_via_socks("127.0.0.1", port, host, port_number)


# --- against a proxy that misbehaves -----------------------------------------

Script = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


@contextlib.asynccontextmanager
async def scripted(script: Script) -> AsyncIterator[int]:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await script(reader, writer)
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    try:
        yield int(server.sockets[0].getsockname()[1])
    finally:
        server.close()
        await server.wait_closed()


def answering(*replies: bytes) -> Script:
    """A proxy that reads each client message and answers with the next reply."""

    async def script(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        for reply in replies:
            await reader.read(512)
            writer.write(reply)
            await writer.drain()
        await reader.read()  # until the client gives up

    return script


SUCCESS_IPV4 = b"\x05\x00\x00\x01" + bytes(4) + b"\x00\x00"


@pytest.mark.parametrize(
    "bound",
    [
        b"\x05\x00\x00\x03\x0bproxy.local\x01\xbb",
        b"\x05\x00\x00\x04" + bytes(16) + b"\x01\xbb",
    ],
    ids=["name", "ipv6"],
)
async def test_any_bound_address_type_is_accepted(bound: bytes) -> None:
    """BND.ADDR is informational for CONNECT; a proxy may report any type."""
    async with scripted(answering(b"\x05\x00", bound)) as bound_port:
        _reader, writer = await open_via_socks("127.0.0.1", bound_port, SERVER_IP, 80)
        writer.close()


@pytest.mark.parametrize(
    ("replies", "expected", "match"),
    [
        ((b"HTTP/1.1 400 Bad Request\r\n",), ProtocolParseError, "method reply"),
        ((b"\x05\x01",), ProtocolParseError, "method 1"),
        ((b"\x05\x02",), NetworkError, "none were given"),
        ((b"\x05\x00", b"\x05\x00\x00\x07\x00\x00\x00\x00\x00\x00"), ProtocolParseError, "type 7"),
        ((b"\x05\x00", b"\x05\x05\x00\x01" + bytes(6)), NetworkError, "refused the connection"),
        ((b"\x05\x00", b"\x05\x42\x00\x01" + bytes(6)), NetworkError, "general failure"),
    ],
    ids=[
        "not-socks",
        "unsupported-method",
        "unrequested-credentials",
        "unknown-address-type",
        "refused",
        "unknown-reply-code",
    ],
)
async def test_a_misbehaving_proxy_is_reported_not_trusted(
    replies: tuple[bytes, ...], expected: type[Exception], match: str
) -> None:
    async with scripted(answering(*replies)) as bound_port:
        with pytest.raises(expected, match=match):
            await open_via_socks("127.0.0.1", bound_port, SERVER_IP, 80)
