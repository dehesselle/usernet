# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Per-packet CPU cost of the stack, as pyperf micro-benchmarks.

    uv run --with pyperf python bench/micro.py -o micro.json
    uv run --with pyperf python -m pyperf compare_to base.json micro.json --table

Only the public API is used -- the codec functions, ``PyStack`` and nothing
below it -- so the same file measures any revision, including ones whose
internals have been rearranged. That is the point: an A/B comparison is only
fair if both sides run identical benchmark code.

The stack benchmarks prebuild every inbound packet before the clock starts,
so what is timed is the stack's work and not the cost of faking a peer.
"""

from __future__ import annotations

import time

import pyperf

from usernet.net.checksum import checksum
from usernet.net.ipv4 import PROTO_TCP, build_ipv4, parse_ipv4
from usernet.net.stack import PyStack, StackConfig
from usernet.net.tcp import Flag, build_tcp, parse_tcp, seq_add

LOCAL_IP = "10.99.0.2"
REMOTE_IP = "10.99.0.1"
REMOTE_PORT = 5201
PEER_ISN = 0x10000000

# Production's tunnel MTU, so segments have production's size.
MTU = 1406
MSS = MTU - 40
PEER_WSCALE = 7
PAYLOAD = bytes(range(256)) * (MSS // 256 + 1)


def _packet(
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    *,
    mss: int | None = None,
    window_scale: int | None = None,
) -> bytes:
    """An IPv4/TCP packet from the remote end to us."""
    segment = build_tcp(
        source_ip=REMOTE_IP,
        destination_ip=LOCAL_IP,
        source_port=sport,
        destination_port=dport,
        seq=seq,
        ack=ack,
        flags=flags,
        window=0xFFFF,
        payload=payload,
        mss=mss,
        window_scale=window_scale,
    )
    return build_ipv4(source=REMOTE_IP, destination=LOCAL_IP, protocol=PROTO_TCP, payload=segment)


class Established:
    """A stack with one connection through its handshake, driven by hand."""

    def __init__(self) -> None:
        self.stack = PyStack(StackConfig(local_ip=LOCAL_IP, mtu=MTU, rng=lambda: 0x01020304))
        self.now = 1_000
        self.sid = self.stack.tcp_connect((REMOTE_IP, REMOTE_PORT))
        self.stack.start_connect(self.sid, self.now)
        (syn,) = self.stack.take_output()
        _, view = parse_ipv4(syn)
        segment = parse_tcp(view)
        self.local_port = segment.source_port
        self.snd = seq_add(segment.seq, 1)  # our next sequence number
        self.rcv = seq_add(PEER_ISN, 1)  # theirs

        self.stack.handle_input(
            _packet(
                REMOTE_PORT,
                self.local_port,
                PEER_ISN,
                self.snd,
                Flag.SYN | Flag.ACK,
                mss=MSS,
                window_scale=PEER_WSCALE,
            ),
            self.now,
        )
        self.stack.take_output()
        self.stack.take_events()

    def ack(self, ack: int) -> bytes:
        return _packet(REMOTE_PORT, self.local_port, self.rcv, ack, Flag.ACK)

    def data(self, seq: int) -> bytes:
        return _packet(
            REMOTE_PORT, self.local_port, seq, self.snd, Flag.ACK | Flag.PSH, PAYLOAD[:MSS]
        )


# --- codec -----------------------------------------------------------------


def bench_checksum(loops: int, data: bytes) -> float:
    t0 = time.perf_counter()
    for _ in range(loops):
        checksum(data)
    return time.perf_counter() - t0


def bench_build(loops: int, payload: bytes, flags: int) -> float:
    t0 = time.perf_counter()
    for _ in range(loops):
        segment = build_tcp(
            source_ip=LOCAL_IP,
            destination_ip=REMOTE_IP,
            source_port=50000,
            destination_port=REMOTE_PORT,
            seq=12345,
            ack=67890,
            flags=flags,
            window=0xFFFF,
            payload=payload,
        )
        build_ipv4(source=LOCAL_IP, destination=REMOTE_IP, protocol=PROTO_TCP, payload=segment)
    return time.perf_counter() - t0


def bench_parse(loops: int) -> float:
    packet = _packet(REMOTE_PORT, 50000, 1, 1, Flag.ACK | Flag.PSH, PAYLOAD[:MSS])
    t0 = time.perf_counter()
    for _ in range(loops):
        _, view = parse_ipv4(packet)
        parse_tcp(view)
    return time.perf_counter() - t0


# --- stack -----------------------------------------------------------------


def bench_stack_tx(loops: int) -> float:
    """One full-sized data segment out, and the peer's ACK for it back in."""
    conn = Established()
    acks = [conn.ack(seq_add(conn.snd, (i + 1) * MSS)) for i in range(loops)]
    stack, sid, now = conn.stack, conn.sid, conn.now
    data = memoryview(PAYLOAD)[:MSS]

    t0 = time.perf_counter()
    for packet in acks:
        stack.tcp_send(sid, data, now)
        stack.handle_input(packet, now)
        stack.take_output()
        stack.take_events()
    return time.perf_counter() - t0


def bench_stack_rx(loops: int) -> float:
    """One full-sized data segment in, read by the application, ACK out."""
    conn = Established()
    segments = [conn.data(seq_add(conn.rcv, i * MSS)) for i in range(loops)]
    stack, sid, now = conn.stack, conn.sid, conn.now

    t0 = time.perf_counter()
    for packet in segments:
        stack.handle_input(packet, now)
        stack.tcp_recv(sid, 65536, now)
        stack.take_output()
        stack.take_events()
    return time.perf_counter() - t0


def bench_poll(loops: int, sockets: int) -> float:
    """One driver pass's timer work with ``sockets`` connects outstanding.

    Nothing is due -- the SYN timer is a second out -- so this is the pure
    cost of finding that out.
    """
    stack = PyStack(StackConfig(local_ip=LOCAL_IP, mtu=MTU, max_sockets=sockets + 1))
    for port in range(sockets):
        sid = stack.tcp_connect((REMOTE_IP, 1000 + port))
        stack.start_connect(sid, 0)
    stack.take_output()
    now = 500

    t0 = time.perf_counter()
    for _ in range(loops):
        stack.poll(now)
        stack.poll_at()
    return time.perf_counter() - t0


def main() -> None:
    runner = pyperf.Runner()
    runner.metadata["description"] = "usernet per-packet CPU cost"

    for size in (40, 576, 1363, 65535):
        data = (bytes(range(256)) * (size // 256 + 1))[:size]
        runner.bench_time_func(f"checksum_{size}", bench_checksum, data)
    runner.bench_time_func("build_data", bench_build, PAYLOAD[:MSS], Flag.ACK | Flag.PSH)
    runner.bench_time_func("build_ack", bench_build, b"", Flag.ACK)
    runner.bench_time_func("parse_data", bench_parse)
    runner.bench_time_func("stack_tx_segment", bench_stack_tx)
    runner.bench_time_func("stack_rx_segment", bench_stack_rx)
    for sockets in (1, 50, 200, 500):
        runner.bench_time_func(f"poll_{sockets}_sockets", bench_poll, sockets)


if __name__ == "__main__":
    main()
