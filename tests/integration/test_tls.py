"""The MemoryBIO TLS wrapper, against a real TLS server.

Real OpenSSL on both sides over a loopback socket. A fake would prove nothing:
the whole risk in this module is driving ``SSLObject`` correctly -- flushing
the outgoing BIO after every call, and reading more when it asks -- and only a
genuine peer exercises that.

The transport here is an asyncio stream pair rather than a tunnel stream. The
two are interchangeable by construction (``TlsStream`` takes anything with
read/write/close), and using loopback keeps these tests about TLS instead of
about TCP.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from pathlib import Path

import pytest
import trustme

from usernet.runtime.tls import TlsError, TlsStream, wrap


class StreamTransport:
    """An asyncio stream pair in the shape ``TlsStream`` consumes."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer

    async def read(self, size: int = 65536) -> bytes:
        return await self._reader.read(size)

    async def write(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    def close(self) -> None:
        self._writer.close()


class TlsServer:
    """A TLS echo server that answers a request with a scripted response."""

    def __init__(self, certs: Path, response: bytes = b"hello over tls", expect: int = 1) -> None:
        self._certs = certs
        self._response = response
        self._expect = expect
        """Bytes to gather before replying. One read is not one message: a
        payload spanning several TLS records arrives in several pieces."""
        self.received: list[bytes] = []
        self._server: asyncio.Server | None = None
        self.ca_path = certs / "ca.pem"

    async def start(self, *, hostname: str = "localhost") -> None:
        ca = trustme.CA()
        cert = ca.issue_cert(hostname)
        ca.cert_pem.write_to_path(self.ca_path)
        chain = self._certs / "server.pem"
        cert.private_key_and_cert_chain_pem.write_to_path(chain)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(chain)
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=context)

    @property
    def port(self) -> int:
        assert self._server is not None
        return int(self._server.sockets[0].getsockname()[1])

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            data = b""
            while len(data) < self._expect:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                data += chunk
            if data:
                self.received.append(data)
                writer.write(self._response)
                await writer.drain()
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()

    async def aclose(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()


@pytest.fixture
def certs(tmp_path: Path) -> Path:
    return tmp_path


async def connect_to(server: TlsServer, context: ssl.SSLContext, server_hostname: str) -> TlsStream:
    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    return await wrap(StreamTransport(reader, writer), context, server_hostname=server_hostname)


def trusting(server: TlsServer) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(server.ca_path))


# --- the handshake ----------------------------------------------------------


async def test_a_request_and_response_cross_a_tls_session(certs: Path) -> None:
    server = TlsServer(certs)
    await server.start()
    try:
        tls = await connect_to(server, context=trusting(server), server_hostname="localhost")
        await tls.write(b"a request")
        assert await tls.read() == b"hello over tls"
        await tls.aclose()
    finally:
        await server.aclose()

    assert server.received == [b"a request"]


async def test_the_session_reports_what_was_negotiated(certs: Path) -> None:
    server = TlsServer(certs)
    await server.start()
    try:
        tls = await connect_to(server, context=trusting(server), server_hostname="localhost")
        assert tls.version is not None and tls.version.startswith("TLS")
        assert tls.cipher is not None
        assert tls.peer_certificate is not None
        await tls.aclose()
    finally:
        await server.aclose()


async def test_an_untrusted_certificate_is_refused(certs: Path) -> None:
    """The default must be to refuse: this is the whole point of verification."""
    server = TlsServer(certs)
    await server.start()
    try:
        with pytest.raises(TlsError, match="certificate verification failed"):
            await connect_to(
                server, context=ssl.create_default_context(), server_hostname="localhost"
            )
    finally:
        await server.aclose()


async def test_a_hostname_mismatch_is_refused(certs: Path) -> None:
    server = TlsServer(certs)
    await server.start()
    try:
        with pytest.raises(TlsError, match="certificate verification failed"):
            await connect_to(server, context=trusting(server), server_hostname="not-the-right-name")
    finally:
        await server.aclose()


async def test_verification_can_be_switched_off(certs: Path) -> None:
    """`usernet get --insecure` depends on this working, and only this."""
    server = TlsServer(certs)
    await server.start()
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        tls = await connect_to(server, context=context, server_hostname="anything")
        await tls.write(b"unverified")
        assert await tls.read() == b"hello over tls"
        await tls.aclose()
    finally:
        await server.aclose()


# --- transfer ---------------------------------------------------------------


async def test_a_payload_larger_than_one_tls_record_round_trips(certs: Path) -> None:
    """TLS records cap at 16 KiB, so this must be split and rejoined."""
    payload = bytes(range(256)) * 400  # 100 KB
    server = TlsServer(certs, response=payload, expect=len(payload))
    await server.start()
    try:
        tls = await connect_to(server, context=trusting(server), server_hostname="localhost")
        await tls.write(payload)

        received = b""
        while len(received) < len(payload):
            chunk = await tls.read()
            if not chunk:
                break
            received += chunk
        await tls.aclose()
    finally:
        await server.aclose()

    assert received == payload
    assert b"".join(server.received) == payload


async def test_an_empty_write_does_nothing(certs: Path) -> None:
    server = TlsServer(certs)
    await server.start()
    try:
        tls = await connect_to(server, context=trusting(server), server_hostname="localhost")
        await tls.write(b"")
        await tls.write(b"then something")
        assert await tls.read() == b"hello over tls"
        await tls.aclose()
    finally:
        await server.aclose()

    assert server.received == [b"then something"]


async def test_a_closed_session_reads_as_end_of_stream(certs: Path) -> None:
    server = TlsServer(certs)
    await server.start()
    try:
        tls = await connect_to(server, context=trusting(server), server_hostname="localhost")
        await tls.write(b"one shot")
        assert await tls.read() == b"hello over tls"
        # The server closes after replying, so the next read is the close.
        assert await tls.read() == b""
        assert await tls.read() == b""  # and it stays closed
        await tls.aclose()
    finally:
        await server.aclose()


async def test_closing_twice_is_harmless(certs: Path) -> None:
    server = TlsServer(certs)
    await server.start()
    try:
        tls = await connect_to(server, context=trusting(server), server_hostname="localhost")
        await tls.aclose()
        await tls.aclose()
    finally:
        await server.aclose()


async def test_a_server_that_is_not_speaking_tls_fails_clearly(certs: Path) -> None:
    """A plain-text port is an easy mistake; the error has to name the cause."""

    async def plain(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read(100)
        writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await writer.drain()
        writer.close()

    plain_server = await asyncio.start_server(plain, "127.0.0.1", 0)
    port = int(plain_server.sockets[0].getsockname()[1])
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        with pytest.raises(TlsError, match="handshake"):
            await wrap(
                StreamTransport(reader, writer),
                ssl.create_default_context(),
                server_hostname="localhost",
            )
    finally:
        plain_server.close()
