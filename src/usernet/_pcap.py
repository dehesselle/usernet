"""Minimal pcap writer for tunnel IP traffic.

Roughly forty lines that make every later problem observable in Wireshark
instead of guessed at from logs. ``LINKTYPE_RAW`` means the payload is a bare
IP packet with no link-layer header, which is exactly what the tunnel carries.
"""

from __future__ import annotations

import struct
import time
from pathlib import Path
from types import TracebackType

LINKTYPE_RAW = 101
SNAPLEN = 262144

_GLOBAL_HEADER = struct.Struct("<IHHiIII")
_PACKET_HEADER = struct.Struct("<IIII")


class PcapWriter:
    """Appends raw IP packets to a pcap file, in both directions.

    ``LINKTYPE_RAW`` has no link-layer header and therefore no direction field,
    which needs none: the tunnel address appears as the source of everything we
    send and the destination of everything we receive, so Wireshark reads the
    conversation correctly from the IP headers alone.

    Not thread-safe and not asynchronous. Both callers are tasks on the one
    event loop, so calls cannot interleave, and writes are small and buffered.
    """

    def __init__(self, path: str | Path) -> None:
        # Deliberately not a context manager at this level: the writer owns the
        # file for the whole life of the tunnel. Callers close it, or use this
        # class itself as a context manager.
        self._file = Path(path).open("wb")  # noqa: SIM115
        self._file.write(_GLOBAL_HEADER.pack(0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, LINKTYPE_RAW))

    def write(self, packet: bytes | memoryview, timestamp: float | None = None) -> None:
        moment = time.time() if timestamp is None else timestamp
        length = len(packet)
        self._file.write(
            _PACKET_HEADER.pack(
                int(moment),
                int((moment % 1) * 1_000_000),
                min(length, SNAPLEN),
                length,
            )
        )
        self._file.write(bytes(packet[:SNAPLEN]))

    def flush(self) -> None:
        self._file.flush()

    def close(self) -> None:
        if not self._file.closed:
            self._file.close()

    def __enter__(self) -> PcapWriter:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
