"""The pcap writer's file format.

A malformed pcap does not fail loudly: Wireshark simply refuses to open it, or
worse, opens it and shows nonsense. Since this file is the tool every later
"it hangs" investigation depends on, the bytes are worth asserting directly.
"""

from __future__ import annotations

import struct
from pathlib import Path

from usernet._pcap import LINKTYPE_RAW, SNAPLEN, PcapWriter

GLOBAL_HEADER = struct.Struct("<IHHiIII")
PACKET_HEADER = struct.Struct("<IIII")


def records(path: Path) -> list[tuple[int, int, int, int, bytes]]:
    """Re-read a pcap the way Wireshark would: header, then length-prefixed records."""
    data = path.read_bytes()
    magic, major, minor, _zone, _sigfigs, snaplen, network = GLOBAL_HEADER.unpack_from(data)
    assert magic == 0xA1B2C3D4, "wrong byte order or not a pcap at all"
    assert (major, minor) == (2, 4)
    assert snaplen == SNAPLEN
    assert network == LINKTYPE_RAW

    out = []
    offset = GLOBAL_HEADER.size
    while offset < len(data):
        seconds, micros, captured, original = PACKET_HEADER.unpack_from(data, offset)
        offset += PACKET_HEADER.size
        out.append((seconds, micros, captured, original, data[offset : offset + captured]))
        offset += captured
    return out


def test_an_empty_capture_is_just_the_global_header(tmp_path: Path) -> None:
    path = tmp_path / "empty.pcap"
    PcapWriter(path).close()

    assert path.stat().st_size == GLOBAL_HEADER.size == 24
    assert records(path) == []


def test_packets_are_written_back_to_back(tmp_path: Path) -> None:
    path = tmp_path / "two.pcap"
    with PcapWriter(path) as writer:
        writer.write(b"\x45\x00first", timestamp=1.5)
        writer.write(b"\x45\x00second", timestamp=2.25)

    written = records(path)
    assert [record[4] for record in written] == [b"\x45\x00first", b"\x45\x00second"]
    assert [(record[0], record[1]) for record in written] == [(1, 500_000), (2, 250_000)]


def test_the_original_length_survives_truncation(tmp_path: Path) -> None:
    """Wireshark shows a truncated packet honestly only if told the real size."""
    path = tmp_path / "big.pcap"
    with PcapWriter(path) as writer:
        writer.write(b"x" * (SNAPLEN + 100))

    (_seconds, _micros, captured, original, payload) = records(path)[0]
    assert captured == SNAPLEN
    assert original == SNAPLEN + 100
    assert len(payload) == SNAPLEN


def test_a_memoryview_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "view.pcap"
    with PcapWriter(path) as writer:
        writer.write(memoryview(b"\x45\x00payload"))

    assert records(path)[0][4] == b"\x45\x00payload"


def test_closing_twice_is_harmless(tmp_path: Path) -> None:
    writer = PcapWriter(tmp_path / "closed.pcap")
    writer.close()
    writer.close()
