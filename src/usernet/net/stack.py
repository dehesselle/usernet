# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The userspace stack: packet demultiplexing, socket table, and timers.

Implements :class:`~usernet.net.backend.NetworkBackend`. Everything here is
synchronous and deterministic -- ``now`` arrives as a parameter and no clock is
ever read -- which is what lets the whole thing be driven from tests without a
network.
"""

from __future__ import annotations

import heapq
from collections.abc import Callable
from dataclasses import dataclass, field

from usernet.errors import (
    ConnectionRefused,
    HostUnreachable,
    NetworkError,
    ProtocolParseError,
)
from usernet.net import icmp
from usernet.net.events import (
    Event,
    IcmpEchoReply,
    PacketDropped,
    SocketClosed,
    SocketConnected,
    SocketError,
    SocketId,
    SocketPeerClosed,
    SocketReadable,
    SocketWritable,
    UdpReceived,
)
from usernet.net.ipv4 import (
    PROTO_ICMP,
    PROTO_TCP,
    PROTO_UDP,
    build_ipv4,
    parse_ipv4,
    verify_header_checksum,
)
from usernet.net.tcb import State, Tcb, TcbConfig
from usernet.net.tcp import build_tcp_ipv4, parse_tcp, verify_tcp_checksum
from usernet.net.udp import build_udp, parse_udp, verify_udp_checksum

DEFAULT_MTU = 1406
IP_HEADER_LEN = 20
TCP_HEADER_LEN = 20

EPHEMERAL_LOW = 49152
EPHEMERAL_HIGH = 65535


@dataclass(frozen=True, slots=True)
class StackConfig:
    """Tunables for one stack instance."""

    local_ip: str
    netmask: str = "255.255.255.255"
    mtu: int = DEFAULT_MTU

    max_sockets: int = 512
    verify_checksums: bool = True
    """Drop received packets whose checksums fail, at every layer: the IP
    header, and the TCP, UDP or ICMP checksum over the data itself. RFC 1122
    makes the transport checks a MUST -- the tunnel's crypto protects only the
    leg to the gateway, and nothing else end to end checks the rest -- so
    this stays on outside tests."""

    tcb: TcbConfig = field(default_factory=TcbConfig)

    # Injected so tests can pin ISNs and port choices; production supplies a
    # `secrets`-backed callable from the driver.
    rng: Callable[[], int] = field(default=lambda: 0, repr=False, compare=False)

    @property
    def mss(self) -> int:
        """MSS derived from the tunnel MTU, before the peer's clamp."""
        return self.mtu - IP_HEADER_LEN - TCP_HEADER_LEN


@dataclass(slots=True)
class _UdpSocket:
    local_port: int
    datagrams: list[tuple[tuple[str, int], bytes]] = field(default_factory=list)


class PyStack:
    """Pure-Python :class:`~usernet.net.backend.NetworkBackend` implementation."""

    def __init__(self, config: StackConfig) -> None:
        self.config = config
        self._out: list[bytes] = []
        self._events: list[Event] = []

        self._tcbs: dict[SocketId, Tcb] = {}
        self._udp: dict[SocketId, _UdpSocket] = {}
        self._by_tuple: dict[tuple[int, str, int], SocketId] = {}
        self._udp_by_port: dict[int, SocketId] = {}

        # Timers: a heap of (deadline, sid), so a driver pass costs what is
        # due rather than what is open. Entries are never removed in place;
        # _deadlines holds each socket's one current deadline, and a heap
        # entry that disagrees with it is stale and skipped when it surfaces.
        self._timers: list[tuple[int, SocketId]] = []
        self._deadlines: dict[SocketId, int] = {}

        self._next_sid = 1
        # Started at a random point in the range, not at the bottom of it.
        # A stack that always opens on 49152 collides with its own previous
        # process: run something short-lived twice -- an ssh ProxyCommand is
        # the obvious case -- and the second run's SYN lands on a four-tuple
        # the peer still has open. The peer answers per RFC 793 with a bare
        # ACK carrying the *old* connection's sequence numbers rather than a
        # SYN-ACK, so the connect times out with the wire full of traffic and
        # nothing to say why. RFC 6056 asks for this for stronger reasons; the
        # cheap collision is the one that actually bites.
        self._next_port = EPHEMERAL_LOW + config.rng() % (EPHEMERAL_HIGH - EPHEMERAL_LOW + 1)
        self._ip_id = 0
        self._icmp_ident = 0

        self.trace_drops = False

    # --- link side ---------------------------------------------------------

    def handle_input(self, packet: bytes | memoryview, now: int) -> None:
        try:
            header, payload = parse_ipv4(packet)
        except ProtocolParseError as exc:
            self._drop("malformed-ip", str(exc))
            return

        if self.config.verify_checksums and not verify_header_checksum(packet):
            self._drop("bad-ip-checksum", f"from {header.source}")
            return

        if header.is_fragment:
            # We set DF on everything and size from the tunnel MTU, so this
            # should be impossible. Loud, because it means an assumption broke.
            self._drop("ip-fragment", f"from {header.source}, offset {header.fragment_offset}")
            return

        if header.destination != self.config.local_ip:
            self._drop("not-for-us", f"{header.source} > {header.destination}")
            return

        if header.protocol == PROTO_TCP:
            self._on_tcp(header.source, payload, now)
        elif header.protocol == PROTO_ICMP:
            self._on_icmp(header.source, payload, now)
        elif header.protocol == PROTO_UDP:
            self._on_udp(header.source, payload)
        else:
            self._drop("unsupported-protocol", f"protocol {header.protocol}")

    def poll(self, now: int) -> None:
        # Collect first, then tick: each socket fires at most once per call,
        # as it did when every socket was ticked. A deadline that on_tick
        # left in the past then shows up as another driver pass, rather
        # than as a loop that never leaves this method.
        due: list[SocketId] = []
        while self._timers and self._timers[0][0] <= now:
            deadline, sid = heapq.heappop(self._timers)
            if self._deadlines.get(sid) == deadline:
                del self._deadlines[sid]
                due.append(sid)
        for sid in due:
            tcb = self._tcbs.get(sid)
            if tcb is not None:
                tcb.on_tick(now)
                self._harvest(sid, tcb)

    def poll_at(self) -> int | None:
        timers = self._timers
        while timers and self._deadlines.get(timers[0][1]) != timers[0][0]:
            heapq.heappop(timers)
        return timers[0][0] if timers else None

    def take_output(self) -> list[bytes]:
        out = self._out
        self._out = []
        return out

    def take_events(self) -> list[Event]:
        events = self._events
        self._events = []
        return events

    # --- TCP ---------------------------------------------------------------

    def tcp_connect(self, dst: tuple[str, int], *, nodelay: bool = True) -> SocketId:
        if len(self._tcbs) >= self.config.max_sockets:
            raise NetworkError(f"socket limit of {self.config.max_sockets} reached")

        remote_ip, remote_port = dst
        local_port = self._allocate_port(remote_ip, remote_port)
        sid = SocketId(self._next_sid)
        self._next_sid += 1

        config = self.config.tcb
        tcb = Tcb(
            local_ip=self.config.local_ip,
            local_port=local_port,
            remote_ip=remote_ip,
            remote_port=remote_port,
            isn=self.config.rng() & 0xFFFFFFFF,
            config=config,
        )
        self._tcbs[sid] = tcb
        self._by_tuple[(local_port, remote_ip, remote_port)] = sid
        return sid

    def start_connect(self, sid: SocketId, now: int) -> None:
        """Emit the SYN. Separate from :meth:`tcp_connect` so the caller can
        register interest in the socket before anything reaches the wire."""
        tcb = self._tcbs[sid]
        tcb.connect(now)
        self._harvest(sid, tcb)

    def tcp_send(self, sid: SocketId, data: memoryview, now: int = 0) -> int:
        tcb = self._tcbs.get(sid)
        if tcb is None:
            return 0
        accepted = tcb.send(data, now)
        self._harvest(sid, tcb)
        return accepted

    def tcp_recv(self, sid: SocketId, max_bytes: int, now: int = 0) -> bytes:
        tcb = self._tcbs.get(sid)
        if tcb is None:
            return b""
        data = tcb.recv(max_bytes, now)
        # Reading is what reopens the receive window, and a reopened window is
        # announced with an ACK -- so this call can put a segment on the wire.
        self._harvest(sid, tcb)
        return data

    def tcp_tx_space(self, sid: SocketId) -> int:
        tcb = self._tcbs.get(sid)
        return tcb.tx_space if tcb is not None else 0

    def tcp_rx_available(self, sid: SocketId) -> int:
        tcb = self._tcbs.get(sid)
        return tcb.rx_available if tcb is not None else 0

    def tcp_state(self, sid: SocketId) -> State | None:
        tcb = self._tcbs.get(sid)
        return tcb.state if tcb is not None else None

    def tcp_shutdown_write(self, sid: SocketId, now: int = 0) -> None:
        tcb = self._tcbs.get(sid)
        if tcb is not None:
            tcb.close(now)
            self._harvest(sid, tcb)

    def tcp_abort(self, sid: SocketId, now: int = 0) -> None:
        tcb = self._tcbs.get(sid)
        if tcb is not None:
            tcb.abort(now)
            self._harvest(sid, tcb)

    def tcp_close(self, sid: SocketId, now: int = 0) -> None:
        self.tcp_shutdown_write(sid, now)

    def _on_tcp(self, source: str, payload: memoryview, now: int) -> None:
        # Checked before parsing, so damage is reported as what it is rather
        # than as a malformed header. local_ip is the destination: anything
        # addressed elsewhere was dropped as not-for-us already.
        if self.config.verify_checksums and not verify_tcp_checksum(
            source, self.config.local_ip, payload
        ):
            self._drop("bad-tcp-checksum", f"from {source}")
            return
        try:
            segment = parse_tcp(payload)
        except ProtocolParseError as exc:
            self._drop("malformed-tcp", str(exc))
            return

        key = (segment.destination_port, source, segment.source_port)
        sid = self._by_tuple.get(key)
        if sid is None:
            # Nothing is listening. A real stack would RST; staying silent is
            # safer for a client-only stack and reveals nothing to a scanner.
            self._drop("no-socket", f"{source}:{segment.source_port} -> {key[0]}")
            return

        tcb = self._tcbs.get(sid)
        if tcb is None:
            return
        tcb.on_segment(segment, now)
        self._harvest(sid, tcb)

    def _harvest(self, sid: SocketId, tcb: Tcb) -> None:
        """Collect what a TCB call produced: segments, events, next deadline.

        Every call into a TCB ends here -- the backend's "every mutating call
        may produce output" rule -- and a deadline can only move during such
        a call. That is what lets the timer heap trust a deadline it was
        handed here until the next harvest says otherwise.
        """
        for segment in tcb.pending_segments:
            self._out.append(
                build_tcp_ipv4(
                    source_ip=tcb.local_ip,
                    destination_ip=tcb.remote_ip,
                    source_port=segment.source_port,
                    destination_port=segment.destination_port,
                    seq=segment.seq,
                    ack=segment.ack,
                    flags=segment.flags,
                    window=segment.window,
                    payload=segment.payload,
                    mss=segment.mss,
                    window_scale=segment.window_scale,
                    identification=self._next_ip_id(),
                )
            )
        tcb.pending_segments.clear()

        for name, detail in tcb.pending_events:
            self._events.append(self._translate(sid, name, detail))
        tcb.pending_events.clear()

        if tcb.state is State.CLOSED:
            self._release(sid, tcb)
            return

        deadline = tcb.next_deadline()
        if deadline is None:
            self._deadlines.pop(sid, None)
        elif self._deadlines.get(sid) != deadline:
            self._deadlines[sid] = deadline
            heapq.heappush(self._timers, (deadline, sid))
            # Stale entries are dropped only as they surface, so a deadline
            # that keeps moving later -- the RTO, restarted by every ACK --
            # would grow the heap without bound. Rebuild it from the live set.
            if len(self._timers) > 4 * len(self._deadlines) + 64:
                self._timers = [(d, s) for s, d in self._deadlines.items()]
                heapq.heapify(self._timers)

    def _translate(self, sid: SocketId, name: str, detail: object) -> Event:
        if name == "connected":
            return SocketConnected(sid)
        if name == "readable":
            return SocketReadable(sid)
        if name == "writable":
            return SocketWritable(sid)
        if name == "peer_closed":
            return SocketPeerClosed(sid)
        if name == "error":
            assert isinstance(detail, Exception)
            return SocketError(sid, detail)
        return SocketClosed(sid, str(detail))

    def _release(self, sid: SocketId, tcb: Tcb) -> None:
        self._tcbs.pop(sid, None)
        self._deadlines.pop(sid, None)
        self._by_tuple.pop((tcb.local_port, tcb.remote_ip, tcb.remote_port), None)

    def _allocate_port(self, remote_ip: str, remote_port: int) -> int:
        """Round-robin ephemeral port, skipping four-tuples still in use."""
        for _ in range(EPHEMERAL_HIGH - EPHEMERAL_LOW + 1):
            port = self._next_port
            self._next_port += 1
            if self._next_port > EPHEMERAL_HIGH:
                self._next_port = EPHEMERAL_LOW
            if (port, remote_ip, remote_port) not in self._by_tuple:
                return port
        raise NetworkError("no ephemeral port available")

    # --- ICMP --------------------------------------------------------------

    def icmp_echo(self, dst: str, ident: int, seq: int, payload: bytes = b"") -> None:
        self._out.append(self._wrap(dst, PROTO_ICMP, icmp.build_echo_request(ident, seq, payload)))

    def _on_icmp(self, source: str, payload: memoryview, now: int) -> None:
        if self.config.verify_checksums and not icmp.verify_checksum(payload):
            self._drop("bad-icmp-checksum", f"from {source}")
            return
        try:
            message = icmp.parse_icmp(payload)
        except ProtocolParseError as exc:
            self._drop("malformed-icmp", str(exc))
            return

        if message.type == icmp.ECHO_REPLY:
            self._events.append(IcmpEchoReply(source, message.ident, message.sequence, now))
        elif message.type == icmp.ECHO_REQUEST:
            # Being pingable from inside the VPN is invaluable when debugging
            # with someone on the other end.
            reply = icmp.build_echo_reply(message.ident, message.sequence, message.payload)
            self._out.append(self._wrap(source, PROTO_ICMP, reply))
        elif message.type == icmp.DEST_UNREACHABLE:
            self._on_icmp_error(message, now)
        else:
            self._drop("icmp-ignored", f"type {message.type} from {source}")

    def _on_icmp_error(self, message: icmp.IcmpMessage, now: int) -> None:
        quoted = icmp.quoted_headers(message)
        if quoted is None:
            return
        _source, destination, source_port, destination_port = quoted

        sid = self._by_tuple.get((source_port, destination, destination_port))
        if sid is None:
            return
        tcb = self._tcbs.get(sid)
        if tcb is None:
            return

        mtu = message.next_hop_mtu
        if mtu is not None:
            # Path MTU shrank. Clamp and let retransmission carry the data;
            # aborting here would turn a recoverable mismatch into a dead
            # connection, which is the silent-hang failure mode.
            tcb.peer_mss = max(536, min(tcb.peer_mss, mtu - IP_HEADER_LEN - TCP_HEADER_LEN))
            self._drop("pmtu-clamp", f"mss now {tcb.peer_mss}")
            return

        if message.is_hard_error and tcb.state is State.SYN_SENT:
            # Turns a 15-second connect timeout into an instant, correct error.
            error: NetworkError = (
                ConnectionRefused(f"{tcb.remote_ip}:{tcb.remote_port} refused")
                if message.code == 3
                else HostUnreachable(f"{tcb.remote_ip} unreachable (icmp code {message.code})")
            )
            # Reported through abort() rather than after it: abort() alone
            # reports a reset, and the driver keeps a stream's first error,
            # so a refused connect surfaced as ConnectionReset.
            tcb.abort(now, error=error)
            self._harvest(sid, tcb)

    # --- UDP ---------------------------------------------------------------

    def udp_open(self, local_port: int | None = None) -> SocketId:
        port = local_port if local_port is not None else self._allocate_udp_port()
        sid = SocketId(self._next_sid)
        self._next_sid += 1
        self._udp[sid] = _UdpSocket(local_port=port)
        self._udp_by_port[port] = sid
        return sid

    def udp_send_to(self, sid: SocketId, dst: tuple[str, int], data: bytes) -> None:
        socket = self._udp.get(sid)
        if socket is None:
            return
        datagram = build_udp(
            source_ip=self.config.local_ip,
            destination_ip=dst[0],
            source_port=socket.local_port,
            destination_port=dst[1],
            payload=data,
        )
        self._out.append(self._wrap(dst[0], PROTO_UDP, datagram))

    def udp_recv_from(self, sid: SocketId) -> tuple[tuple[str, int], bytes] | None:
        socket = self._udp.get(sid)
        if socket is None or not socket.datagrams:
            return None
        return socket.datagrams.pop(0)

    def udp_close(self, sid: SocketId) -> None:
        socket = self._udp.pop(sid, None)
        if socket is not None:
            self._udp_by_port.pop(socket.local_port, None)

    def _allocate_udp_port(self) -> int:
        for _ in range(EPHEMERAL_HIGH - EPHEMERAL_LOW + 1):
            port = self._next_port
            self._next_port += 1
            if self._next_port > EPHEMERAL_HIGH:
                self._next_port = EPHEMERAL_LOW
            if port not in self._udp_by_port:
                return port
        raise NetworkError("no ephemeral port available")

    def _on_udp(self, source: str, payload: memoryview) -> None:
        if self.config.verify_checksums and not verify_udp_checksum(
            source, self.config.local_ip, payload
        ):
            self._drop("bad-udp-checksum", f"from {source}")
            return
        try:
            datagram = parse_udp(payload)
        except ProtocolParseError as exc:
            self._drop("malformed-udp", str(exc))
            return

        sid = self._udp_by_port.get(datagram.destination_port)
        if sid is None:
            self._drop("no-udp-socket", f"port {datagram.destination_port}")
            return
        self._udp[sid].datagrams.append(((source, datagram.source_port), datagram.payload))
        self._events.append(UdpReceived(sid))

    # --- helpers -----------------------------------------------------------

    def _wrap(self, destination: str, protocol: int, payload: bytes) -> bytes:
        return build_ipv4(
            source=self.config.local_ip,
            destination=destination,
            protocol=protocol,
            payload=payload,
            identification=self._next_ip_id(),
        )

    def _next_ip_id(self) -> int:
        self._ip_id = (self._ip_id + 1) & 0xFFFF
        return self._ip_id

    def _drop(self, reason: str, summary: str) -> None:
        if self.trace_drops:
            self._events.append(PacketDropped(reason, summary))
