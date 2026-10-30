# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The far end of the path-MTU test: take an upload, say what arrived.

pmtu.sh runs this inside its own network namespace under the system Python, so
it uses the standard library only. Each connection is read to EOF and answered
with one line, the byte count and the SHA-256 of what came in.
"""

from __future__ import annotations

import hashlib
import socketserver
import sys


class Upload(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        digest = hashlib.sha256()
        total = 0
        while chunk := self.request.recv(65536):
            digest.update(chunk)
            total += len(chunk)
        self.wfile.write(f"{total} {digest.hexdigest()}\n".encode())


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    Server((sys.argv[1], int(sys.argv[2])), Upload).serve_forever()
