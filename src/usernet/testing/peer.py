# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""A minimal server-side TCP implementation, for tests only.

The shipping stack is client-only and deliberately has no ``LISTEN`` or
``SYN_RECEIVED`` state -- it never accepts a connection, so it should never
carry the code to do so. This peer supplies the other half so the real state
machine can be exercised end to end.

It is intentionally simple: in-order data only, immediate ACKs, no congestion
control. It is a test fixture, not a second implementation to be trusted.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from usernet.net.ipv4 import PROTO_TCP, build_ipv4, parse_ipv4
from usernet.net.tcp import Flag, build_tcp, parse_tcp, seq_add

Handler = Callable[[bytes], bytes | None]
"""Given everything received so far, return a response, or None for "need more"."""

StreamHandler = Callable[[bytes], bytes]
"""Given the bytes that just arrived, return bytes to send back.

The incremental alternative to :data:`Handler`, for endpoints that cannot be
expressed as one request and one response -- TLS being the obvious case, since
its handshake is several rounds before any application data exists.
"""


@dataclass
class Connection:
    local_port: int
    remote_ip: str
    remote_port: int
    snd_nxt: int
    rcv_nxt: int
    established: bool = False
    received: bytearray = field(default_factory=bytearray)
    responded: bool = False
    fin_sent: bool = False
    fin_pending: bool = False
    peer_fin: bool = False

    snd_una: int = 0
    peer_window: int = 65535
    peer_wscale: int = 0
    """The client's window shift, learned from its SYN.

    Ignoring it would silently cap the client's advertised window at 64 KiB and
    quietly hide any window-scaling bug on its side.
    """
    stream: StreamHandler | None = None
    """Per-connection incremental handler, when the peer was given a factory."""
    pending: bytearray = field(default_factory=bytearray)
    """Response bytes not yet sent, because the client's window is full.

    A peer that ignored the advertised window would overrun the receive buffer
    and -- since this fixture has no retransmission -- stall forever. Honouring
    it is what makes the harness exercise real flow control.
    """


@dataclass
class TcpPeer:
    """Answers connections addressed to ``ip`` on ``port``."""

    ip: str
    port: int
    handler: Handler
    stream_factory: Callable[[], StreamHandler] | None = None
    """Set instead of relying on ``handler`` for incremental endpoints. Called
    once per connection, so each gets its own state."""
    isn: int = 900_000
    mss: int = 1400
    window: int = 65535
    window_scale: int | None = 0
    """Shift offered in the SYN-ACK; ``None`` refuses scaling entirely."""

    connections: dict[tuple[str, int], Connection] = field(default_factory=dict)
    resets: int = 0

    def handle(self, packet: bytes) -> list[bytes]:
        """Process one inbound IP packet; return packets to send back."""
        header, payload = parse_ipv4(packet)
        if header.protocol != PROTO_TCP:
            return []

        segment = parse_tcp(payload)
        if segment.destination_port != self.port:
            return []

        key = (header.source, segment.source_port)
        out: list[bytes] = []

        if segment.has(Flag.RST):
            self.resets += 1
            self.connections.pop(key, None)
            return []

        if segment.has(Flag.SYN) and not segment.has(Flag.ACK):
            connection = Connection(
                local_port=self.port,
                remote_ip=header.source,
                remote_port=segment.source_port,
                snd_nxt=self.isn,
                rcv_nxt=seq_add(segment.seq, 1),
            )
            if self.stream_factory is not None:
                connection.stream = self.stream_factory()
            connection.peer_window = segment.window  # a SYN's window is unscaled
            if self.window_scale is not None and segment.window_scale is not None:
                connection.peer_wscale = segment.window_scale
            self.connections[key] = connection
            out.append(
                self._segment(
                    connection, Flag.SYN | Flag.ACK, mss=min(self.mss, segment.mss or self.mss)
                )
            )
            connection.snd_nxt = seq_add(connection.snd_nxt, 1)
            return out

        # Indexed rather than ``.get()`` so the name keeps the type it was given
        # in the SYN branch above; a segment for a connection we never opened is
        # simply dropped, which is what a closed port does.
        if key not in self.connections:
            return []
        connection = self.connections[key]

        if segment.has(Flag.ACK):
            if not connection.established:
                connection.established = True
                connection.snd_una = segment.ack
            elif segment.ack != connection.snd_una:
                connection.snd_una = segment.ack
            connection.peer_window = segment.window << connection.peer_wscale

        if segment.payload and segment.seq == connection.rcv_nxt:
            connection.received += segment.payload
            connection.rcv_nxt = seq_add(connection.rcv_nxt, len(segment.payload))
            out.append(self._segment(connection, Flag.ACK))

            if connection.stream is not None:
                # Incremental: the endpoint decides when, and whether, to
                # answer -- and never closes on our behalf, since keep-alive
                # is the whole point of speaking HTTP over TLS.
                connection.pending += connection.stream(segment.payload)
            elif not connection.responded:
                response = self.handler(bytes(connection.received))
                if response is not None:
                    connection.responded = True
                    connection.pending += response
                    connection.fin_pending = True

        elif segment.payload:
            # Out of order: re-ACK what we actually want next.
            out.append(self._segment(connection, Flag.ACK))

        if segment.has(Flag.FIN) and not connection.peer_fin:
            connection.peer_fin = True
            connection.rcv_nxt = seq_add(connection.rcv_nxt, 1)
            out.append(self._segment(connection, Flag.ACK))
            connection.fin_pending = True

        out.extend(self._drain(connection))
        return out

    def _drain(self, connection: Connection) -> list[bytes]:
        """Send as much of the pending response as the client's window allows."""
        packets: list[bytes] = []
        while connection.pending:
            in_flight = (connection.snd_nxt - connection.snd_una) & 0xFFFFFFFF
            usable = connection.peer_window - in_flight
            if usable <= 0:
                break
            size = min(self.mss, usable, len(connection.pending))
            chunk = bytes(connection.pending[:size])
            del connection.pending[:size]
            packets.append(self._segment(connection, Flag.ACK | Flag.PSH, payload=chunk))
            connection.snd_nxt = seq_add(connection.snd_nxt, size)

        if connection.fin_pending and not connection.pending and not connection.fin_sent:
            packets.append(self._segment(connection, Flag.FIN | Flag.ACK))
            connection.snd_nxt = seq_add(connection.snd_nxt, 1)
            connection.fin_sent = True
        return packets

    def _segment(
        self,
        connection: Connection,
        flags: int,
        *,
        payload: bytes = b"",
        mss: int | None = None,
    ) -> bytes:
        segment = build_tcp(
            source_ip=self.ip,
            destination_ip=connection.remote_ip,
            source_port=self.port,
            destination_port=connection.remote_port,
            seq=connection.snd_nxt,
            ack=connection.rcv_nxt,
            flags=flags,
            window=self.window,
            payload=payload,
            mss=mss,
            window_scale=self.window_scale if mss is not None else None,
        )
        return build_ipv4(
            source=self.ip,
            destination=connection.remote_ip,
            protocol=PROTO_TCP,
            payload=segment,
        )


def http_handler(body: bytes, status: str = "200 OK") -> Handler:
    """A handler that answers once the request headers are complete."""

    def handle(received: bytes) -> bytes | None:
        if b"\r\n\r\n" not in received:
            return None
        return (
            f"HTTP/1.1 {status}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Content-Type: text/plain\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + body

    return handle
