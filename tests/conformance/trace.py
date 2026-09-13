"""A readable packet trace, printed when a conformance test fails.

These tests run on a machine the author cannot reach, so a failure has to
arrive already diagnosed. A bare ``assert b"" == b"hello"`` says nothing about
which side stopped talking; the last hundred packets say everything.

Sequence numbers are shown relative to the first value seen in each direction,
as Wireshark does, because absolute ISNs are random and comparing two ten-digit
numbers by eye is how subtle off-by-ones get missed.
"""

from __future__ import annotations

import struct
import time
from collections import deque

from usernet.errors import ProtocolParseError
from usernet.net.icmp import parse_icmp
from usernet.net.ipv4 import PROTO_ICMP, PROTO_TCP, PROTO_UDP, parse_ipv4
from usernet.net.tcp import Flag, parse_tcp

# Short flag letters, in the order a reader expects to see them.
FLAG_LETTERS: tuple[tuple[Flag, str], ...] = (
    (Flag.SYN, "S"),
    (Flag.ACK, "A"),
    (Flag.FIN, "F"),
    (Flag.RST, "R"),
    (Flag.PSH, "P"),
    (Flag.URG, "U"),
    (Flag.ECE, "E"),
    (Flag.CWR, "C"),
)

ICMP_TYPES = {0: "echo-reply", 3: "unreachable", 8: "echo-request", 11: "ttl-exceeded"}

Flow = tuple[str, int, str, int]


class PacketTrace:
    """A bounded record of everything that crossed the tun device."""

    def __init__(self, limit: int = 400) -> None:
        self._lines: deque[str] = deque(maxlen=limit)
        self.packets: deque[tuple[bool, bytes]] = deque(maxlen=limit)
        """The raw packets behind the lines, so a test can assert on the wire
        rather than on our own idea of what we put there."""
        self._first: dict[Flow, int] = {}
        self._started = time.monotonic()
        self.sent = 0
        self.received = 0
        self.largest_sent = 0

    def record(self, outbound: bool, packet: bytes) -> None:
        if outbound:
            self.sent += 1
            self.largest_sent = max(self.largest_sent, len(packet))
        else:
            self.received += 1
        arrow = "->" if outbound else "<-"
        elapsed = time.monotonic() - self._started
        self.packets.append((outbound, bytes(packet)))
        self._lines.append(f"{elapsed:8.4f} {arrow} {self._describe(packet)}")

    def _describe(self, packet: bytes) -> str:
        try:
            header, payload = parse_ipv4(packet)
        except ProtocolParseError as exc:
            return f"unparseable ({len(packet)} bytes): {exc}"

        if header.protocol == PROTO_TCP:
            return self._describe_tcp(header.source, header.destination, payload, len(packet))
        if header.protocol == PROTO_ICMP:
            try:
                message = parse_icmp(payload)
            except ProtocolParseError:
                return f"icmp {header.source} > {header.destination} (unparseable)"
            kind = ICMP_TYPES.get(message.type, f"type {message.type}")
            return (
                f"icmp {header.source} > {header.destination} "
                f"{kind} id={message.ident} seq={message.sequence}"
            )
        if header.protocol == PROTO_UDP and len(payload) >= 4:
            source_port, destination_port = struct.unpack_from("!HH", payload)
            return (
                f"udp  {header.source}:{source_port} > "
                f"{header.destination}:{destination_port} ({len(packet)} bytes)"
            )
        return f"ip   {header.source} > {header.destination} proto={header.protocol}"

    def _describe_tcp(self, source: str, destination: str, payload: bytes, total: int) -> str:
        try:
            segment = parse_tcp(payload)
        except ProtocolParseError as exc:
            return f"tcp  {source} > {destination} (unparseable: {exc})"

        forward: Flow = (source, segment.source_port, destination, segment.destination_port)
        reverse: Flow = (destination, segment.destination_port, source, segment.source_port)
        self._first.setdefault(forward, segment.seq)

        flags = "".join(letter for flag, letter in FLAG_LETTERS if segment.flags & flag) or "-"
        seq = self._relative(forward, segment.seq)
        # The ACK field lives in the *peer's* sequence space, so it is only
        # meaningful against the ISN recorded for the reverse direction.
        ack = self._relative(reverse, segment.ack) if segment.flags & Flag.ACK else "-"

        options = ""
        if segment.mss is not None:
            options += f" mss={segment.mss}"
        if segment.window_scale is not None:
            options += f" ws={segment.window_scale}"
        if segment.sack_permitted:
            options += " sackOK"

        return (
            f"tcp  {source}:{segment.source_port} > "
            f"{destination}:{segment.destination_port} "
            f"[{flags:<3}] seq={seq} ack={ack} win={segment.window} "
            f"len={len(segment.payload)}{options} ({total}B)"
        )

    def _relative(self, flow: Flow, value: int) -> str:
        base = self._first.get(flow)
        if base is None:
            # No SYN seen for this direction, so there is nothing to be
            # relative to; the star marks the number as absolute.
            return f"*{value}"
        return str((value - base) & 0xFFFFFFFF)

    def lines(self) -> list[str]:
        """The formatted packet lines alone, without the surrounding report."""
        return list(self._lines)

    def dump(self, title: str) -> str:
        header = (
            f"\n--- packet trace: {title} "
            f"({self.sent} sent, {self.received} received, "
            f"largest sent {self.largest_sent}B) ---\n"
            "seq/ack are relative to the first packet seen in each direction; "
            "* marks an absolute value\n"
        )
        return header + "\n".join(self._lines) + "\n--- end of trace ---"
