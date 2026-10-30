# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Reading back what :class:`~usernet.pcap.PcapWriter` wrote.

The writer exists so that a later "it hangs" investigation has a capture to
open. That makes the file format worth asserting directly rather than trusting:
a malformed pcap does not fail loudly, it just makes Wireshark refuse the file
or, worse, show nonsense.

Anything that captures its own traffic wants the same reader in its tests, so
it lives here rather than in one project's test tree.
"""

from __future__ import annotations

import struct
from pathlib import Path

from usernet.pcap import LINKTYPE_RAW, SNAPLEN

GLOBAL_HEADER = struct.Struct("<IHHiIII")
PACKET_HEADER = struct.Struct("<IIII")

Record = tuple[int, int, int, int, bytes]
"""seconds, microseconds, captured length, original length, payload."""


def records(path: Path) -> list[Record]:
    """Re-read a pcap the way Wireshark would: header, then length-prefixed records."""
    data = path.read_bytes()
    magic, major, minor, _zone, _sigfigs, snaplen, network = GLOBAL_HEADER.unpack_from(data)
    assert magic == 0xA1B2C3D4, "wrong byte order or not a pcap at all"
    assert (major, minor) == (2, 4)
    assert snaplen == SNAPLEN
    assert network == LINKTYPE_RAW

    out: list[Record] = []
    offset = GLOBAL_HEADER.size
    while offset < len(data):
        seconds, micros, captured, original = PACKET_HEADER.unpack_from(data, offset)
        offset += PACKET_HEADER.size
        out.append((seconds, micros, captured, original, data[offset : offset + captured]))
        offset += captured
    return out
