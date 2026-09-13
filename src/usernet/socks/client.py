"""A SOCKS5 client, for reaching the VPN through a proxy someone else is running.

``usernet nc --via`` uses this so an ``ssh`` session can borrow a tunnel that is
already up, instead of authenticating and building a second one. That matters
more than convenience: gateways enforce concurrent-session limits, and one
login per ssh invocation exhausts them quickly.
"""

from __future__ import annotations

import asyncio

from usernet.errors import NetworkError, ProtocolParseError
from usernet.socks.protocol import (
    AUTH_NONE,
    AUTH_UNACCEPTABLE,
    AUTH_USERPASS,
    REPLY_PREFIX,
    Reply,
    build_greeting,
    build_request,
    build_userpass,
    error_for,
    parse_auth_reply,
    parse_method_reply,
    parse_reply,
    reply_length,
)


async def open_via_socks(
    proxy_host: str,
    proxy_port: int,
    host: str,
    port: int,
    *,
    username: str | None = None,
    password: str | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """CONNECT to ``host:port`` through a SOCKS5 proxy.

    Returns the proxy connection once it is carrying the target's bytes, so
    callers treat it as an ordinary stream from then on.
    """
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    try:
        await _negotiate(reader, writer, username, password)

        writer.write(build_request(host, port))
        await writer.drain()

        prefix = await reader.readexactly(REPLY_PREFIX)
        rest = await reader.readexactly(reply_length(prefix) - REPLY_PREFIX)
        code, _bound_host, _bound_port = parse_reply(prefix + rest)
        if code is not Reply.SUCCESS:
            raise error_for(code, f"{host}:{port}")
    except BaseException:
        writer.close()
        raise
    return reader, writer


async def _negotiate(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    username: str | None,
    password: str | None,
) -> None:
    methods = (AUTH_NONE, AUTH_USERPASS) if username is not None else (AUTH_NONE,)
    writer.write(build_greeting(methods))
    await writer.drain()

    method = parse_method_reply(await reader.readexactly(2))
    if method == AUTH_UNACCEPTABLE:
        raise NetworkError(
            "the proxy accepted none of our authentication methods"
            + ("" if username else "; it may require credentials (--via-auth USER:PASS)")
        )
    if method == AUTH_USERPASS:
        if username is None:
            raise NetworkError("the proxy asked for credentials and none were given")
        writer.write(build_userpass(username, password or ""))
        await writer.drain()
        if not parse_auth_reply(await reader.readexactly(2)):
            raise NetworkError("the proxy rejected the credentials")
    elif method != AUTH_NONE:
        raise ProtocolParseError(f"the proxy chose authentication method {method}, which we do not")
