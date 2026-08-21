"""TLS over a stream we own, via ``ssl.MemoryBIO``.

The REST case is HTTPS, so TLS has to run *inside* the tunnel, over a
connection our own TCP stack is carrying.

``loop.start_tls()`` is not an option: it needs a real asyncio transport
implementing the private ``_start_tls_compatible`` protocol, and its behaviour
has shifted between Python versions. Driving ``ssl.SSLObject`` against two
``MemoryBIO`` buffers by hand is a hundred lines, works identically everywhere,
and can be tested without a network.

The whole thing is one rule applied repeatedly: after *any* call into the
``SSLObject``, whatever landed in the outgoing BIO must be written to the
transport, and ``SSLWantReadError`` means "read more from the transport and try
again". Forgetting the flush is the classic MemoryBIO deadlock -- the handshake
simply stops, with both sides waiting for the other.
"""

from __future__ import annotations

import contextlib
import ssl
from typing import Any, Protocol

from usernet.errors import NetworkError

CHUNK = 65536


class TlsError(NetworkError):
    """A TLS failure, reported as a network error rather than an ssl one."""


class Transport(Protocol):
    """What :class:`TlsStream` needs underneath: bytes in, bytes out.

    A Protocol so a tunnel stream, an asyncio stream pair, or a test double
    all satisfy it without inheriting anything.
    """

    async def read(self, size: int = CHUNK) -> bytes: ...
    async def write(self, data: bytes) -> None: ...
    def close(self) -> None: ...


class TlsStream:
    """A TLS session over any byte transport, presented as read/write.

    Not a context manager and not an ``asyncio.Transport``: it is deliberately
    the same shape as everything else that carries bytes in this project, so
    it can wrap a tunnel stream and be wrapped by httpx in turn.
    """

    def __init__(
        self,
        transport: Transport,
        context: ssl.SSLContext,
        *,
        server_hostname: str | None = None,
    ) -> None:
        self._transport = transport
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._object = context.wrap_bio(
            self._incoming,
            self._outgoing,
            server_side=False,
            server_hostname=server_hostname,
        )
        self._eof = False
        self._closed = False

    # --- handshake ---------------------------------------------------------

    async def handshake(self) -> None:
        """Complete the TLS handshake. Must be awaited before any transfer."""
        while True:
            try:
                self._object.do_handshake()
            except ssl.SSLWantReadError:
                await self._flush()
                if not await self._feed():
                    raise TlsError("the peer closed during the TLS handshake") from None
                continue
            except ssl.SSLCertVerificationError as exc:
                raise TlsError(
                    f"certificate verification failed: {exc.verify_message or exc}"
                ) from exc
            except ssl.SSLError as exc:
                raise TlsError(f"TLS handshake failed: {exc}") from exc
            await self._flush()
            return

    @property
    def peer_certificate(self) -> Any:
        cert = self._object.getpeercert()
        return cert if cert else None

    def selected_alpn_protocol(self) -> str | None:
        return self._object.selected_alpn_protocol()

    @property
    def version(self) -> str | None:
        return self._object.version()

    @property
    def cipher(self) -> tuple[str, str, int] | None:
        return self._object.cipher()

    # --- transfer ----------------------------------------------------------

    async def read(self, size: int = CHUNK) -> bytes:
        """Decrypted application data; ``b""`` once the peer has closed."""
        while True:
            try:
                data: bytes = self._object.read(size)
            except ssl.SSLWantReadError:
                if self._eof:
                    # A truncated stream: the peer vanished without a proper
                    # close_notify. Report end of data rather than raise --
                    # far too many servers do this to treat it as an error.
                    return b""
                await self._feed()
                continue
            except ssl.SSLZeroReturnError:
                return b""  # a clean close_notify
            except ssl.SSLError as exc:
                raise TlsError(f"TLS read failed: {exc}") from exc
            return data

    async def write(self, data: bytes) -> None:
        if not data:
            return
        view = memoryview(data)
        while view:
            try:
                written = self._object.write(view)
            except ssl.SSLWantReadError:
                # A renegotiation the peer started; feed it and retry.
                await self._flush()
                if not await self._feed():
                    raise TlsError("the peer closed during a TLS write") from None
                continue
            except ssl.SSLError as exc:
                raise TlsError(f"TLS write failed: {exc}") from exc
            view = view[written:]
            await self._flush()

    async def unwrap(self) -> None:
        """Send ``close_notify``, so the peer can tell this from truncation."""
        if self._closed:
            return
        self._closed = True
        # Best effort throughout: the transport is closing regardless, and a
        # peer that has already gone will make either step fail.
        with contextlib.suppress(ssl.SSLError, OSError):
            self._object.unwrap()
        with contextlib.suppress(OSError, NetworkError):
            await self._flush()

    def close(self) -> None:
        self._closed = True
        self._transport.close()

    async def aclose(self) -> None:
        await self.unwrap()
        self.close()

    # --- the two directions of the BIO pair --------------------------------

    async def _flush(self) -> None:
        """Write everything the SSL object produced. Never skip this."""
        pending = self._outgoing.read()
        if pending:
            await self._transport.write(pending)

    async def _feed(self) -> bool:
        """Read from the transport into the SSL object; False at end of stream."""
        data = await self._transport.read(CHUNK)
        if not data:
            self._eof = True
            self._incoming.write_eof()
            return False
        self._incoming.write(data)
        return True


async def wrap(
    transport: Transport,
    context: ssl.SSLContext,
    *,
    server_hostname: str | None = None,
) -> TlsStream:
    """Wrap ``transport`` in TLS and complete the handshake."""
    stream = TlsStream(transport, context, server_hostname=server_hostname)
    await stream.handshake()
    return stream
