# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""An httpcore network backend that dials through the tunnel.

httpcore exposes a documented seam -- ``AsyncNetworkBackend`` -- for replacing
how connections are made. Filling it in gets connection pooling, keep-alive,
redirects, HTTP/1.1 framing, and the whole httpx API for the price of three
methods, which is a far better trade than writing an HTTP client.

``httpx.AsyncHTTPTransport`` does not accept a ``network_backend``, so
:class:`PoolTransport` drives an
``httpcore.AsyncConnectionPool`` itself, which *does* take a backend and is
public httpcore API, behind ``httpx.AsyncBaseTransport``, which is httpx's
documented extension point. No private attribute is touched anywhere, and the
seam tests pin the signatures either way.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import time
import typing

import httpcore
import httpx
from httpcore import AsyncNetworkBackend, AsyncNetworkStream

from usernet.errors import NetworkError
from usernet.runtime.driver import Driver, TcpStream
from usernet.runtime.tls import TlsStream, wrap

if typing.TYPE_CHECKING:
    from httpcore._backends.base import SOCKET_OPTION


class TunnelStream(AsyncNetworkStream):
    """One connection through the tunnel, in the shape httpcore expects."""

    def __init__(self, stream: TcpStream, driver: Driver) -> None:
        self._stream = stream
        self._driver = driver

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        # Timeouts are httpx's to enforce around the call; adding our own here
        # would produce two competing deadlines and confusing error messages.
        return await self._stream.read(max_bytes)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._stream.write(buffer)

    async def aclose(self) -> None:
        self._stream.close()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> AsyncNetworkStream:
        tls = await wrap(
            _TransportAdapter(self._stream),
            ssl_context,
            server_hostname=server_hostname,
        )
        return TlsNetworkStream(tls)

    def get_extra_info(self, info: str) -> typing.Any:
        if info == "client_addr":
            return (self._driver.link.config.address, 0)
        if info == "server_addr":
            return self._stream.peer
        return None


class _TransportAdapter:
    """Presents a :class:`TcpStream` as the transport ``TlsStream`` expects."""

    def __init__(self, stream: TcpStream) -> None:
        self._stream = stream

    async def read(self, size: int = 65536) -> bytes:
        return await self._stream.read(size)

    async def write(self, data: bytes) -> None:
        await self._stream.write(data)

    def close(self) -> None:
        self._stream.close()


class TlsNetworkStream(AsyncNetworkStream):
    """A :class:`~usernet.runtime.tls.TlsStream`, in httpcore's shape."""

    def __init__(self, tls: TlsStream) -> None:
        self._tls = tls

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._tls.read(max_bytes)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._tls.write(buffer)

    async def aclose(self) -> None:
        await self._tls.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> AsyncNetworkStream:
        raise NetworkError("TLS is already established on this connection")

    def get_extra_info(self, info: str) -> typing.Any:
        if info == "ssl_object":
            return self._tls
        if info == "server_hostname":
            return None
        return None


class UsernetNetworkBackend(AsyncNetworkBackend):
    """Makes httpx dial through the VPN instead of the operating system."""

    def __init__(self, driver: Driver, *, connect_timeout: float = 30.0) -> None:
        self._driver = driver
        self._connect_timeout = connect_timeout
        self.connections = 0
        self.last_connect_ms = 0.0
        """How long the most recent handshake took. One round trip through the
        tunnel, which is the single most useful number when something feels
        slow -- and httpx has no way to report it."""

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[SOCKET_OPTION] | None = None,
    ) -> AsyncNetworkStream:
        # local_address and socket_options are meaningless here: the source
        # address is whatever the gateway assigned, and there is no OS socket
        # to set options on. Accepting and ignoring them beats refusing.
        started = time.monotonic()
        stream = await self._driver.connect(
            host, port, timeout=timeout if timeout is not None else self._connect_timeout
        )
        self.last_connect_ms = (time.monotonic() - started) * 1000
        self.connections += 1
        return TunnelStream(stream, self._driver)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: typing.Iterable[SOCKET_OPTION] | None = None,
    ) -> AsyncNetworkStream:
        raise NetworkError("a VPN tunnel carries no unix sockets")

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


# Specific before general: ConnectTimeout is a TimeoutException, and a dict
# preserves insertion order, so the first match wins.
_MAPPED_EXCEPTIONS = (
    "ConnectTimeout",
    "ReadTimeout",
    "WriteTimeout",
    "PoolTimeout",
    "TimeoutException",
    "ConnectError",
    "ReadError",
    "WriteError",
    "NetworkError",
    "LocalProtocolError",
    "RemoteProtocolError",
    "ProtocolError",
    "ProxyError",
    "UnsupportedProtocol",
)

EXCEPTION_MAP: dict[type[Exception], type[Exception]] = {
    getattr(httpcore, name): getattr(httpx, name)
    for name in _MAPPED_EXCEPTIONS
    if hasattr(httpcore, name) and hasattr(httpx, name)
}
"""httpcore errors, translated so callers can catch ordinary httpx exceptions.

Built by name rather than written out, so a version that renames one drops it
from the map instead of failing to import.
"""


@contextlib.contextmanager
def _as_httpx_errors() -> typing.Iterator[None]:
    try:
        yield
    except Exception as exc:
        for source, target in EXCEPTION_MAP.items():
            if isinstance(exc, source):
                raise target(str(exc)) from exc
        # Anything else -- notably our own NetworkError subclasses -- passes
        # through untouched. "10.9.8.7 is outside the gateway's split routes"
        # is worth far more to whoever reads it than "ConnectError".
        raise


def build_ssl_context(
    verify: bool | str | ssl.SSLContext = True, *, http2: bool = False
) -> ssl.SSLContext:
    """How to verify the *target's* certificate.

    Nothing to do with the gateway's: reaching an internal API over an internal
    CA is an entirely separate trust decision from trusting the VPN's front
    door, and a flag governing one must never quietly govern the other.
    """
    if isinstance(verify, ssl.SSLContext):
        context = verify
    elif verify is False:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context = ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)
    context.set_alpn_protocols(["h2", "http/1.1"] if http2 else ["http/1.1"])
    return context


class PoolTransport(httpx.AsyncBaseTransport):
    """An httpx transport over an httpcore pool with a backend you supply.

    Split out from :class:`TunnelTransport` because "where do the bytes come
    from" is the only thing a caller ever wants to change, and everything else
    -- HTTP/2 flow control, streaming response bodies, the error translation --
    is httpcore's and worth not reimplementing. ``pyts`` uses this to run
    HTTP/2 inside a Noise session, which is not a tunnel and has no driver.

    The alternative is reaching into ``client._transport._pool`` to swap the
    backend after the fact, which works until httpx renames something.
    """

    def __init__(
        self,
        backend: AsyncNetworkBackend,
        *,
        ssl_context: ssl.SSLContext | None = None,
        http1: bool = True,
        http2: bool = False,
        **pool_options: typing.Any,
    ) -> None:
        self.backend = backend
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            network_backend=backend,
            http1=http1,
            http2=http2,
            **pool_options,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        assert isinstance(request.stream, httpx.AsyncByteStream)
        wrapped = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        with _as_httpx_errors():
            response = await self._pool.handle_async_request(wrapped)

        assert isinstance(response.stream, typing.AsyncIterable)
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_ResponseStream(response.stream),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


class TunnelTransport(PoolTransport):
    """An httpx transport whose connections all run through the tunnel.

    ``verify`` belongs here rather than on the client. ``httpx.AsyncClient``
    only applies its own ``verify`` to the transport *it* builds, so passing
    one alongside a custom transport silently does nothing -- which would make
    a caller's "skip verification" or "trust this CA" look like it worked
    while changing nothing at all.
    """

    def __init__(
        self,
        driver: Driver,
        *,
        verify: bool | str | ssl.SSLContext = True,
        connect_timeout: float = 30.0,
        http2: bool = False,
        **pool_options: typing.Any,
    ) -> None:
        backend = UsernetNetworkBackend(driver, connect_timeout=connect_timeout)
        super().__init__(
            backend,
            ssl_context=build_ssl_context(verify, http2=http2),
            http1=True,
            http2=http2,
            **pool_options,
        )
        self._backend = backend

    @property
    def last_connect_ms(self) -> float:
        """How long the most recent handshake took. See ``UsernetNetworkBackend``."""
        return self._backend.last_connect_ms


class _ResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: typing.AsyncIterable[bytes]) -> None:
        self._stream = stream

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        with _as_httpx_errors():
            async for part in self._stream:
                yield part

    async def aclose(self) -> None:
        if hasattr(self._stream, "aclose"):
            await self._stream.aclose()


def httpx_transport(driver: Driver, **kwargs: typing.Any) -> TunnelTransport:
    """An httpx transport whose connections run through the tunnel."""
    return TunnelTransport(driver, **kwargs)


def httpx_client(driver: Driver, **kwargs: typing.Any) -> httpx.AsyncClient:
    """An ``httpx.AsyncClient`` that reaches only inside the VPN.

    ``verify`` and friends apply to the *target's* certificate, which has
    nothing to do with the gateway's -- those two trust decisions are separate
    and must stay that way.
    """
    transport = kwargs.pop("transport", None) or httpx_transport(driver)
    return httpx.AsyncClient(transport=transport, **kwargs)
