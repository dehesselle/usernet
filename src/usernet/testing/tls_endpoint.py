# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""A TLS-terminating HTTP responder, driven byte by byte.

Lets the virtual peer answer ``https://`` through the tunnel, which is what
turns "the TLS wrapper works" and "httpx works over the tunnel" into "an HTTPS
request works over the tunnel". Composition is exactly where the glue bugs
live, so the composition is what gets asserted.

Server-side ``MemoryBIO``, for the same reason the client uses one: there is no
socket here, only bytes arriving from a TCP state machine.
"""

from __future__ import annotations

import ssl
from pathlib import Path

CHUNK = 65536


class TlsHttpEndpoint:
    """Feed it ciphertext, get ciphertext back."""

    def __init__(self, chain: Path, body: bytes, status: str = "200 OK") -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(chain)

        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._object = context.wrap_bio(self._incoming, self._outgoing, server_side=True)
        self._handshaken = False

        self._body = body
        self._status = status
        self.requests: list[bytes] = []
        self._buffer = b""

    def __call__(self, data: bytes) -> bytes:
        """One round: ciphertext in, ciphertext out."""
        if data:
            self._incoming.write(data)

        if not self._handshaken:
            try:
                self._object.do_handshake()
                self._handshaken = True
            except ssl.SSLWantReadError:
                return self._outgoing.read()
            except ssl.SSLError:
                return self._outgoing.read()

        while True:
            try:
                plaintext = self._object.read(CHUNK)
            except (ssl.SSLWantReadError, ssl.SSLZeroReturnError, ssl.SSLError):
                break
            if not plaintext:
                break
            self._buffer += plaintext
            # Requests are answered as they complete, so keep-alive works and
            # a second request on the same connection is served too.
            while b"\r\n\r\n" in self._buffer:
                head, _, self._buffer = self._buffer.partition(b"\r\n\r\n")
                self.requests.append(head)
                self._object.write(self._response())

        return self._outgoing.read()

    def _response(self) -> bytes:
        head = (
            f"HTTP/1.1 {self._status}\r\n"
            f"Content-Length: {len(self._body)}\r\n"
            f"Content-Type: text/plain\r\n\r\n"
        )
        return head.encode() + self._body
