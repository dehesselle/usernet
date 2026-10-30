# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The kernel's end of the macro benchmarks: an ordinary socket server.

Runs as its own process, pinned to its own core, for the same reason the
conformance suite exists at all -- the peer should be real Linux TCP -- and
for one more: sharing a process would put the peer on our GIL, and the
numbers would then measure the two of them taking turns.

Each connection opens with one command line:

``SRC <n>``   send ``n`` bytes of :func:`pattern`, then close
``SNK <n>``   read to EOF, reply ``<count> <sha256>``, close
``ECHO``      echo everything back until EOF
``IDLE``      hold the connection open, silently, until EOF

Imports nothing from usernet, so any Python runs it.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import socket

CHUNK = 256 * 1024
BLOCK = bytes(range(256)) * 4096  # 1 MiB


def pattern(n: int) -> memoryview:
    """``n`` deterministic bytes, which the client checks after timing stops."""
    repeats = n // len(BLOCK) + 1
    return memoryview(BLOCK * repeats)[:n]


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    sock = writer.get_extra_info("socket")
    if sock is not None:
        # Request/response latency should be ours, not Nagle's.
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        command = (await reader.readline()).split()
        if not command:
            return
        verb = command[0]
        if verb == b"SRC":
            data = pattern(int(command[1]))
            for offset in range(0, len(data), CHUNK):
                writer.write(data[offset : offset + CHUNK])
                await writer.drain()
        elif verb == b"SNK":
            digest = hashlib.sha256()
            count = 0
            while chunk := await reader.read(1024 * 1024):
                digest.update(chunk)
                count += len(chunk)
            writer.write(f"{count} {digest.hexdigest()}\n".encode())
            await writer.drain()
        elif verb == b"ECHO":
            while chunk := await reader.read(65536):
                writer.write(chunk)
                await writer.drain()
        elif verb == b"IDLE":
            while await reader.read(65536):
                pass
    except (ConnectionError, OSError):
        pass  # a client that died mid-run is the client's problem to report
    finally:
        writer.close()


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="10.99.0.1")
    parser.add_argument("--port", type=int, default=5201)
    parser.add_argument("--ports", type=int, default=1, help="listen on this many, from --port")
    args = parser.parse_args()

    ports = range(args.port, args.port + args.ports)
    servers = [await asyncio.start_server(handle, args.host, p, backlog=1024) for p in ports]
    print(f"listening on {args.host}:{ports.start}-{ports.stop - 1}", flush=True)
    await asyncio.gather(*(server.serve_forever() for server in servers))


if __name__ == "__main__":
    asyncio.run(main())
