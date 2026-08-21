"""The TCP state machine, client side only.

Covers active open; in-order and out-of-order data with reassembly; cumulative
ACK; RFC 6298 retransmission with Jacobson/Karels smoothing and Karn's
ambiguity rule; RFC 5681 slow start and congestion avoidance with RFC 6582
NewReno fast retransmit and fast recovery; RFC 7323 window scaling; zero-window
persist probing; delayed ACK; and a full close in both directions.

Deliberately absent, and unlikely to arrive:

* SACK and timestamps -- both are parsed for length and skipped (see
  ``tcp.py``), so an unexpected option can never desynchronise the option walk,
  but neither is advertised.

  SACK was left out on the assumption that it only pays off on links losing
  several segments per window; the deciding evidence turned out to come from
  the other end. The production gateway's peers offer no ``SACK_PERM`` at all,
  so the option would never be negotiated on the path that matters however
  well it were implemented. Under 2% loss both ways against a Linux kernel,
  NewReno recovers a 2 MiB transfer in ~15 s, and the measured limit on a real
  tunnel is the receive window rather than loss recovery. SACK stays out.
* ``LISTEN`` and ``SYN_RECEIVED``. Nothing here ever accepts a connection, so
  the shipping code never grows that attack surface. A passive-open TCB exists
  in the test tree only, to give the harness a peer.
* Nagle. The consumers are interactive SSH and request/response HTTP, and the
  driver already batches application writes.

Sans-IO throughout: ``now`` is milliseconds as an int, and the only outputs are
segments to send and events to report.
"""

from __future__ import annotations

from bisect import insort
from dataclasses import dataclass, field
from enum import Enum, auto

from usernet.errors import ConnectionRefused, ConnectionReset, ConnectionTimeout, NetworkError
from usernet.net.tcp import (
    DEFAULT_MSS,
    MAX_WINDOW,
    MAX_WINDOW_SCALE,
    Flag,
    TcpSegment,
    build_tcp,
    seq_add,
    seq_diff,
    seq_geq,
    seq_gt,
    seq_leq,
    seq_lt,
)

# "No threshold yet": stay in slow start until the first loss says otherwise.
INFINITE_SSTHRESH = 0x7FFFFFFF

# See TcbConfig.max_ooo_segments. Named here so the driver can scale it with a
# custom buffer without reaching into the dataclass for its default.
DEFAULT_MAX_OOO_SEGMENTS = 4096


class State(Enum):
    CLOSED = auto()
    SYN_SENT = auto()
    ESTABLISHED = auto()
    FIN_WAIT_1 = auto()
    FIN_WAIT_2 = auto()
    CLOSING = auto()
    TIME_WAIT = auto()
    CLOSE_WAIT = auto()
    LAST_ACK = auto()

    @property
    def is_closed(self) -> bool:
        return self is State.CLOSED

    @property
    def can_send(self) -> bool:
        return self in (State.ESTABLISHED, State.CLOSE_WAIT)


@dataclass(slots=True)
class TcbConfig:
    """Per-connection tunables, injected so tests can shrink them."""

    mss: int = 1343  # tunnel MTU 1383 - 20 IP - 20 TCP

    # One connection cannot go faster than buffer / RTT, whatever the code
    # does, so on a distant gateway this number *is* the throughput. Measured
    # against a real kernel at 150 ms: 256 KiB gave 0.8 MB/s and 1 MiB gave
    # 3.6 MB/s, which is why the default is no longer 256 KiB.
    #
    # It is a cap, not an allocation -- the buffers are bytearrays that grow
    # on demand -- so idle connections cost nothing and the price is only paid
    # by a reader that falls behind. Beyond 1 MiB the returns fade for what
    # this tool is for (REST calls and SSH) while the worst case,
    # max_sockets x rx_buffer, grows into gigabytes.
    #
    # Only usable because window scaling is negotiated; without it the 16-bit
    # field would cap the advertisement at 64 KiB regardless.
    rx_buffer: int = 1024 * 1024
    tx_buffer: int = 1024 * 1024

    rto_initial_ms: int = 1000
    rto_min_ms: int = 250
    rto_max_ms: int = 60_000
    max_retransmits: int = 8
    syn_retransmits: int = 4
    connect_timeout_ms: int = 15_000
    time_wait_ms: int = 30_000

    # 40 ms, not the traditional 200: asyncio sleeps round to ~15.6 ms on
    # Windows, so anything shorter is noise, and anything longer is felt.
    delayed_ack_ms: int = 40

    initial_cwnd_segments: int = 10  # IW10, RFC 6928
    window_scaling: bool = True

    # Memory is already bounded in *bytes*: _trim clips every segment to the
    # window we advertised, and recv_window subtracts what is held out of
    # order. This cap exists only so that a peer sending one byte per segment
    # cannot make the list itself the cost.
    #
    # It must stay comfortably above rx_buffer/mss, and therefore has to be
    # raised whenever rx_buffer is -- test_the_segment_cap_stays_clear_of_the
    # _byte_bound enforces that, sized against the RFC 1122 floor MSS of 536
    # rather than a typical one, since a peer really may send segments that
    # small.
    #
    # At 64 it bound first, and the effect was not a saving but a stall: a
    # 256 KiB window holds ~180 full segments, so after a single loss we
    # discarded ~190 KB that had arrived intact and made the peer send it
    # again -- repeatedly, since the next window did the same. Found by the L3
    # conformance suite under 2% loss, where a 2 MiB transfer went from 15 s to
    # over 120 s. Seen again at a 4 MiB buffer, which is what the invariant
    # test now exists to prevent.
    max_ooo_segments: int = DEFAULT_MAX_OOO_SEGMENTS


def initial_window_scale(buffer_size: int) -> int:
    """The smallest shift that lets ``buffer_size`` fit the 16-bit field.

    Smallest, not largest: every extra shift coarsens the window's granularity,
    and a window rounded down by 8 KiB rather than 8 bytes stalls transfers for
    no gain.
    """
    shift = 0
    while (buffer_size >> shift) > MAX_WINDOW and shift < MAX_WINDOW_SCALE:
        shift += 1
    return shift


@dataclass(slots=True)
class Tcb:
    """One TCP connection.

    Drive it with :meth:`on_segment` and :meth:`on_tick`, then drain
    :attr:`pending_segments` and :attr:`pending_events`.
    """

    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    config: TcbConfig = field(default_factory=TcbConfig)
    isn: int = 0

    state: State = State.CLOSED

    # Send sequence space (RFC 9293 3.3.1)
    snd_una: int = 0
    snd_nxt: int = 0
    snd_max: int = 0
    """Highest sequence ever sent. A timeout rewinds ``snd_nxt``, so it is this
    -- not ``snd_nxt`` -- that says whether an ACK covers data we really sent."""
    snd_wnd: int = 0
    snd_wl1: int = 0  # seq of the segment that last updated snd_wnd
    snd_wl2: int = 0  # ack of the segment that last updated snd_wnd

    # Receive sequence space
    rcv_nxt: int = 0

    peer_mss: int = DEFAULT_MSS

    # Window scaling (RFC 7323). Both stay 0 unless *both* SYNs carry the
    # option, which is what the RFC requires and what makes the fallback safe.
    snd_wscale: int = 0
    rcv_wscale: int = 0
    offered_wscale: int = 0

    # Congestion control (RFC 5681 / 6582)
    cwnd: int = 0
    ssthresh: int = INFINITE_SSTHRESH
    dup_acks: int = 0
    recover: int = 0
    in_recovery: bool = False

    send_buffer: bytearray = field(default_factory=bytearray)
    """Everything from ``send_base`` onwards: unacknowledged *and* unsent.

    Bytes stay here until the peer acknowledges them, which is what makes
    retransmission a matter of rewinding ``snd_nxt`` rather than replaying a
    list of segments. A queue of already-formed segments can only ever be
    replayed one entry at a time, and after a timeout that costs a whole RTO
    per segment -- a transfer that technically completes and practically does
    not.
    """
    send_base: int = 0
    """Sequence number of ``send_buffer[0]``; equals ``snd_una`` once the SYN
    has been acknowledged."""

    recv_buffer: bytearray = field(default_factory=bytearray)

    # RFC 6298 retransmission timer
    srtt_ms: float = 0.0
    rttvar_ms: float = 0.0
    rto_ms: int = 1000
    retransmit_count: int = 0
    retransmit_deadline: int | None = None

    # One segment per window is timed, per RFC 6298 3.1.
    rtt_seq_end: int | None = None
    rtt_sent_at: int = 0
    _rtt_blocked_through: int | None = None
    """Karn again: after a timeout everything up to here is being sent for the
    second time, so no sample may be taken until we are past it."""

    persist_ms: int = 0
    persist_deadline: int | None = None
    persist_count: int = 0
    ack_deadline: int | None = None
    time_wait_deadline: int | None = None
    connect_deadline: int | None = None

    close_requested: bool = False
    fin_sent_seq: int | None = None
    peer_fin_seen: bool = False

    _ooo: list[tuple[int, bytes]] = field(default_factory=list)
    """Segments received ahead of ``rcv_nxt``, sorted by distance from it."""
    _ooo_bytes: int = 0
    ooo_dropped: int = 0
    """In-window segments refused because the reassembly queue was full.

    Should stay zero. Anything else means we discarded data that arrived
    intact and asked the peer to send it again.
    """
    _peer_fin_seq: int | None = None
    _segments_since_ack: int = 0
    _write_blocked: bool = False

    pending_segments: list[bytes] = field(default_factory=list)
    pending_events: list[tuple[str, object]] = field(default_factory=list)
    """``(name, detail)`` pairs the stack translates into typed events. Kept as
    plain tuples so ``usernet.net.tcb`` need not import the event classes."""
    error: NetworkError | None = None

    # --- public API --------------------------------------------------------

    def connect(self, now: int) -> None:
        """Begin an active open."""
        if self.state is not State.CLOSED:
            raise RuntimeError(f"connect() in state {self.state.name}")

        self.snd_una = self.isn
        self.snd_nxt = self.isn
        self.snd_max = self.isn
        self.send_base = seq_add(self.isn, 1)
        self.rto_ms = self.config.rto_initial_ms
        self.connect_deadline = now + self.config.connect_timeout_ms
        self.state = State.SYN_SENT
        self.offered_wscale = (
            initial_window_scale(self.config.rx_buffer) if self.config.window_scaling else 0
        )
        # RFC 6298 permits the handshake itself to supply the first RTT sample,
        # and taking it means the very first data segment already has a sane
        # timer rather than the 1 s default.
        self.rtt_seq_end = seq_add(self.isn, 1)
        self.rtt_sent_at = now
        self._emit(Flag.SYN, now, syn_options=True)

    def send(self, data: bytes | memoryview, now: int) -> int:
        """Queue application data; returns how many bytes were accepted."""
        if not self.state.can_send or self.close_requested:
            return 0
        accepted = min(self.tx_space, len(data))
        if accepted < len(data):
            self._write_blocked = True
        if accepted > 0:
            self.send_buffer += bytes(data[:accepted])
            self._pump(now)
        return accepted

    def recv(self, max_bytes: int, now: int = 0) -> bytes:
        """Take received data out of the receive buffer.

        ``now`` is needed because handing data to the application is what
        reopens the receive window, and a reopened window has to be announced.
        """
        if not self.recv_buffer:
            return b""
        before = self.recv_window
        take = min(max_bytes, len(self.recv_buffer))
        data = bytes(self.recv_buffer[:take])
        del self.recv_buffer[:take]
        self._announce_window(before, now)
        return data

    @property
    def rx_available(self) -> int:
        return len(self.recv_buffer)

    @property
    def tx_space(self) -> int:
        """Free transmit space.

        The buffer holds unacknowledged bytes as well as unsent ones, so this
        is a true bound on the memory one socket can hold.
        """
        return max(0, self.config.tx_buffer - len(self.send_buffer))

    @property
    def unsent(self) -> int:
        """Buffered bytes not yet put on the wire."""
        return max(0, len(self.send_buffer) - seq_diff(self.snd_nxt, self.send_base))

    @property
    def recv_window(self) -> int:
        """Advertised window: whatever is still free in the receive buffer.

        Computed at ACK time from the *unread* backlog, which is what makes
        flow control real. Draining into an unbounded queue elsewhere would
        keep this permanently wide open.

        Out-of-order bytes are deliberately *not* subtracted. They already sit
        inside ``[rcv_nxt, rcv_nxt + window)``, so charging for them again
        halves the window the moment a hole opens -- exactly when it needs to
        stay open, since the peer can only keep sending, and only continued
        sending produces the duplicate ACKs that trigger fast retransmit. The
        memory bound still holds: the peer may have at most ``window`` bytes in
        that range, so ``len(recv_buffer) + _ooo_bytes`` cannot exceed
        ``rx_buffer`` even if every one of them arrives out of order.
        """
        return max(0, self.config.rx_buffer - len(self.recv_buffer))

    @property
    def advertised_window(self) -> int:
        """:attr:`recv_window` as it appears in the 16-bit field, post-scaling."""
        return min(self.recv_window >> self.rcv_wscale, MAX_WINDOW)

    @property
    def flight_size(self) -> int:
        """Bytes sent but not yet acknowledged."""
        return max(0, seq_diff(self.snd_nxt, self.snd_una))

    def close(self, now: int) -> None:
        """Begin a graceful close; the FIN follows any queued data."""
        if self.close_requested or self.state.is_closed:
            return
        self.close_requested = True
        self._pump(now)

    def abort(self, now: int, reason: str = "aborted") -> None:
        """Send RST and drop the connection immediately."""
        if self.state in (State.CLOSED, State.TIME_WAIT):
            self.state = State.CLOSED
            return
        self._emit(Flag.RST | Flag.ACK, now)
        self._fail(ConnectionReset(reason))

    # --- inbound -----------------------------------------------------------

    def on_segment(self, segment: TcpSegment, now: int) -> None:
        """Process one inbound segment."""
        if self.state.is_closed:
            return

        # Any segment at all proves the peer is still there, which is the only
        # thing the persist probe counter is really asking about.
        self.persist_count = 0

        if segment.has(Flag.RST):
            self._on_reset(segment)
            return

        if self.state is State.SYN_SENT:
            self._on_syn_sent(segment, now)
            return

        if segment.has(Flag.SYN):
            # RFC 5961 4.2: a SYN in a synchronized state gets a challenge ACK
            # -- <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK> -- and no further
            # processing. Written as an attack mitigation, but the case that
            # matters here is ordinary loss: if our handshake ACK is dropped,
            # the peer keeps retransmitting its SYN-ACK, and this reply is the
            # only thing that completes the connection. Without it the peer
            # backs off and gives up while we sit in ESTABLISHED believing all
            # is well. Not rate limited: the response is one segment per SYN,
            # so there is nothing to amplify.
            self._emit(Flag.ACK, now)
            return

        # Anything arriving now must acknowledge data we actually sent.
        if segment.has(Flag.ACK):
            if seq_gt(segment.ack, self.snd_max):
                return  # acknowledges something unsent: ignore
            self._on_ack(segment, now)
            self._update_send_window(segment)

        if segment.segment_length > 0 or segment.has(Flag.FIN):
            self._on_data(segment, now)

        self._pump(now)
        self._flush_ack(now)
        self._check_close_completion(now)

    def _on_syn_sent(self, segment: TcpSegment, now: int) -> None:
        if not segment.has(Flag.SYN):
            return
        if segment.has(Flag.ACK) and segment.ack != seq_add(self.isn, 1):
            return  # not our handshake

        self.rcv_nxt = seq_add(segment.seq, 1)
        # The window on a SYN is never scaled -- the shift is only in force
        # once both SYNs have been exchanged.
        self.snd_wnd = segment.window
        self.snd_wl1 = segment.seq
        self.snd_wl2 = segment.ack
        # Clamp to the peer's advertised MSS: sending larger is the classic
        # silent-hang bug, where the handshake works and bulk data never does.
        if segment.mss:
            self.peer_mss = max(DEFAULT_MSS, min(segment.mss, self.config.mss))
        else:
            self.peer_mss = min(DEFAULT_MSS, self.config.mss)

        # Scaling takes effect only if the peer echoed the option.
        if segment.window_scale is not None and self.config.window_scaling:
            self.snd_wscale = segment.window_scale
            self.rcv_wscale = self.offered_wscale

        if segment.has(Flag.ACK):
            self._ack_through(segment.ack, now)
            self.state = State.ESTABLISHED
            self.connect_deadline = None
            self.cwnd = self.config.initial_cwnd_segments * self.peer_mss
            self.ssthresh = INFINITE_SSTHRESH
            self.recover = self.snd_nxt
            self._emit(Flag.ACK, now)
            self.pending_events.append(("connected", None))
            self._pump(now)
        # Simultaneous open (SYN without ACK) is out of scope; ignoring it
        # leaves the connect timeout to report the failure.

    def _on_reset(self, segment: TcpSegment) -> None:
        if self.state is State.SYN_SENT:
            self._fail(ConnectionRefused(f"{self.remote_ip}:{self.remote_port} refused"))
            return
        # Only accept an in-window RST, per RFC 5961, so a blind off-path
        # guess cannot tear down the connection.
        if seq_geq(segment.seq, self.rcv_nxt) and seq_lt(
            segment.seq, seq_add(self.rcv_nxt, max(1, self.recv_window))
        ):
            self._fail(ConnectionReset("connection reset by peer"))

    # --- acknowledgement and congestion control ----------------------------

    def _on_ack(self, segment: TcpSegment, now: int) -> None:
        if seq_leq(segment.ack, self.snd_una):
            if self._is_duplicate_ack(segment):
                self._on_duplicate_ack(now)
            return

        self.dup_acks = 0
        acked = seq_diff(segment.ack, self.snd_una)
        self._ack_through(segment.ack, now)
        self._on_ack_congestion(segment.ack, acked, now)

    def _is_duplicate_ack(self, segment: TcpSegment) -> bool:
        """RFC 5681 2: same ACK, no data, no window change, data outstanding."""
        return (
            segment.ack == self.snd_una
            and not segment.payload
            and not segment.has(Flag.SYN | Flag.FIN)
            and (segment.window << self.snd_wscale) == self.snd_wnd
            and self.flight_size > 0
        )

    def _on_duplicate_ack(self, now: int) -> None:
        self.dup_acks += 1

        if self.in_recovery:
            # Each duplicate means one more segment left the network, so the
            # pipe has room for one more even though snd_una has not moved.
            self.cwnd += self.peer_mss
            self._pump(now)
            return

        if self.dup_acks == 3 and seq_gt(self.snd_nxt, self.recover):
            self._enter_fast_recovery(now)

    def _enter_fast_recovery(self, now: int) -> None:
        """Three duplicates mean a segment was lost, not merely delayed.

        Retransmitting now rather than waiting out the RTO is the difference
        between a usable and an unusably slow connection on a lossy link.
        """
        self.ssthresh = max(self.flight_size // 2, 2 * self.peer_mss)
        self.cwnd = self.ssthresh + 3 * self.peer_mss
        self.recover = self.snd_nxt
        self.in_recovery = True
        self._retransmit_leftmost(now)
        self.retransmit_deadline = now + self.rto_ms

    def _on_ack_congestion(self, ack: int, acked: int, now: int) -> None:
        if self.in_recovery:
            if seq_geq(ack, self.recover):
                # Full ACK: everything outstanding when the loss was detected
                # is now acknowledged, so the episode is over.
                self.in_recovery = False
                self.dup_acks = 0
                self.cwnd = self.ssthresh
            else:
                # Partial ACK: a second segment in the same window was lost.
                # Retransmit it immediately instead of waiting for another
                # three duplicates -- that wait is what NewReno exists to fix.
                self.cwnd = max(self.peer_mss, self.cwnd - acked + self.peer_mss)
                self._retransmit_leftmost(now)
                self.retransmit_deadline = now + self.rto_ms
            return

        if self.cwnd < self.ssthresh:
            self.cwnd += min(acked, self.peer_mss)  # slow start
        else:
            # Congestion avoidance: roughly one MSS per round trip.
            self.cwnd += max(1, self.peer_mss * self.peer_mss // self.cwnd)

    def _ack_through(self, ack: int, now: int) -> None:
        """Retire acknowledged bytes and update the RTT estimate."""
        newly = seq_diff(ack, self.snd_una)
        if newly <= 0:
            return
        self.snd_una = ack

        consumed = seq_diff(ack, self.send_base)
        if consumed > 0:
            del self.send_buffer[: min(consumed, len(self.send_buffer))]
            self.send_base = ack

        if self._rtt_blocked_through is not None and seq_geq(ack, self._rtt_blocked_through):
            self._rtt_blocked_through = None
        if self.rtt_seq_end is not None and seq_geq(ack, self.rtt_seq_end):
            self._update_rtt(now - self.rtt_sent_at)
            self.rtt_seq_end = None

        self.retransmit_count = 0
        # RFC 6298 5.2/5.3: stop the timer when nothing is outstanding,
        # otherwise restart it for what still is.
        self.retransmit_deadline = now + self.rto_ms if self.flight_size > 0 else None

        if self._write_blocked and self.tx_space > 0:
            self._write_blocked = False
            self.pending_events.append(("writable", None))

    def _update_send_window(self, segment: TcpSegment) -> None:
        """RFC 9293 3.10.7.4, so a reordered segment cannot shrink the window.

        Without the ``snd_wl1``/``snd_wl2`` guard an old segment arriving late
        reinstates a stale window, and the connection either stalls or
        overruns the peer.
        """
        if seq_lt(self.snd_wl1, segment.seq) or (
            self.snd_wl1 == segment.seq and seq_leq(self.snd_wl2, segment.ack)
        ):
            self.snd_wnd = segment.window << self.snd_wscale
            self.snd_wl1 = segment.seq
            self.snd_wl2 = segment.ack

    # --- receive path ------------------------------------------------------

    def _on_data(self, segment: TcpSegment, now: int) -> None:
        payload = segment.payload
        seq = segment.seq
        had_gap = bool(self._ooo)

        if segment.has(Flag.FIN) and self._peer_fin_seq is None:
            fin_at = seq_add(seq, len(payload))
            if seq_geq(fin_at, self.rcv_nxt):
                self._peer_fin_seq = fin_at

        out_of_order = False
        duplicate = False
        accepted = False
        if payload:
            seq, trimmed = self._trim(seq, payload)
            duplicate = not trimmed
            payload = trimmed
        if payload:
            if seq == self.rcv_nxt:
                self._accept(payload)
                self._drain_ooo()
                accepted = True
            else:
                self._hold(seq, payload)
                out_of_order = True

        if self._consume_peer_fin(now):
            return

        # RFC 5681 4.2 lists the cases that must not wait on the timer. Each is
        # one where the peer is either blocked or about to retransmit, and a
        # delayed ACK would cost a round trip or a whole RTO.
        fin_pending = self._peer_fin_seq is not None and not self.peer_fin_seen
        immediate = (
            out_of_order  # a gap: keep the peer's duplicate-ACK count climbing
            or duplicate  # it resent, so it believes our last ACK was lost
            or bool(self._ooo)
            or fin_pending
            or (accepted and had_gap)  # a hole just closed; say so at once
            or self.recv_window == 0  # the peer must learn the window shut
        )
        if immediate:
            self._schedule_ack(now, immediate=True)
        elif accepted:
            self._segments_since_ack += 1
            # Acknowledge at least every second full-sized segment.
            self._schedule_ack(now, immediate=self._segments_since_ack >= 2)

    def _trim(self, seq: int, payload: bytes) -> tuple[int, bytes]:
        """Clip a payload to the part that is both new and inside the window."""
        if seq_lt(seq, self.rcv_nxt):
            skip = seq_diff(self.rcv_nxt, seq)
            if skip >= len(payload):
                return self.rcv_nxt, b""
            payload = payload[skip:]
            seq = self.rcv_nxt

        room = self.recv_window - seq_diff(seq, self.rcv_nxt)
        if room <= 0:
            return seq, b""
        return seq, payload[:room]

    def _accept(self, payload: bytes) -> None:
        self.recv_buffer += payload
        self.rcv_nxt = seq_add(self.rcv_nxt, len(payload))
        self.pending_events.append(("readable", None))

    def _has_room_for(self, extra: int) -> bool:
        """Whether ``extra`` more bytes fit inside the buffer we advertised.

        The memory bound, stated directly rather than inferred from sequence
        space. Non-overlapping segments can never reach it -- the window
        already limits those -- but a peer may send *overlapping* ones, whose
        bytes add up faster than the range they cover, and no amount of
        sequence arithmetic notices. Every path that grows the queue asks here.
        """
        return len(self.recv_buffer) + self._ooo_bytes + extra <= self.config.rx_buffer

    def _hold(self, seq: int, payload: bytes) -> None:
        """Queue a segment that arrived ahead of the gap."""
        for index, (held_seq, held) in enumerate(self._ooo):
            if held_seq != seq:
                continue
            if len(held) >= len(payload):
                return  # already have it
            # A longer resend of the same segment replaces the shorter copy,
            # rather than being appended and double-counted against the window.
            # Still charged for: repeatedly upgrading short segments to long
            # ones is otherwise a way to grow the queue without ever appending.
            growth = len(payload) - len(held)
            if not self._has_room_for(growth):
                self.ooo_dropped += 1
                return
            self._ooo_bytes += growth
            self._ooo[index] = (seq, payload)
            return
        if not self._has_room_for(len(payload)):
            self.ooo_dropped += 1
            return
        if len(self._ooo) >= self.config.max_ooo_segments:
            # Past the bound we fall back to the peer's retransmission, which
            # costs an RTO. Counted, because reaching it at all means the cap
            # is binding before the byte bound does -- which is a stall, and
            # was one. See TcbConfig.max_ooo_segments.
            self.ooo_dropped += 1
            return
        # Insert in place rather than re-sorting: the queue now holds a whole
        # window, and a sort per arriving segment would be the next thing to go
        # wrong. Every entry is ahead of rcv_nxt and the key shifts by the same
        # amount as it advances, so the ordering stays valid.
        insort(self._ooo, (seq, payload), key=lambda item: seq_diff(item[0], self.rcv_nxt))
        self._ooo_bytes += len(payload)

    def _drain_ooo(self) -> None:
        """Deliver whatever the newly arrived data made contiguous."""
        progressed = True
        while progressed and self._ooo:
            progressed = False
            for index, (seq, payload) in enumerate(self._ooo):
                if seq_gt(seq, self.rcv_nxt):
                    break  # sorted, so nothing further is contiguous either
                del self._ooo[index]
                self._ooo_bytes -= len(payload)
                progressed = True
                skip = seq_diff(self.rcv_nxt, seq)
                if skip < len(payload):
                    self._accept(payload[skip:])
                break

    def _consume_peer_fin(self, now: int) -> bool:
        """Act on the peer's FIN once every byte before it has been delivered."""
        if self.peer_fin_seen or self._peer_fin_seq is None:
            return False
        if self.rcv_nxt != self._peer_fin_seq:
            return False

        self.peer_fin_seen = True
        self.rcv_nxt = seq_add(self.rcv_nxt, 1)
        self.pending_events.append(("peer_closed", None))
        if self.state is State.ESTABLISHED:
            self.state = State.CLOSE_WAIT
        elif self.state is State.FIN_WAIT_1:
            self.state = State.CLOSING
        elif self.state is State.FIN_WAIT_2:
            self._enter_time_wait(now)
        self._schedule_ack(now, immediate=True)
        return True

    def _announce_window(self, before: int, now: int) -> None:
        """Tell the peer promptly that a closed or cramped window reopened.

        A peer in persist mode otherwise waits out a whole probe interval
        before discovering it may send again, which adds an RTO to every
        recovery from a full buffer.
        """
        if self.state.is_closed or self.state is State.TIME_WAIT:
            return
        opened = self.recv_window - before
        # RFC 1122 4.2.3.3: the smallest increase worth telling the sender
        # about is min(MSS, buffer/2) -- below one segment it cannot act on the
        # news anyway. This was max(2*MSS, buffer/2), which inverts the rule
        # and, worse, scales the wrong way: the larger the receive buffer, the
        # rarer the updates, so raising the buffer to cover a high-latency link
        # made throughput worse rather than better.
        threshold = min(self.peer_mss, self.config.rx_buffer // 2)
        if before == 0 or opened >= threshold:
            self._schedule_ack(now, immediate=True)
            self._flush_ack(now)

    # --- ACK scheduling ----------------------------------------------------

    def _schedule_ack(self, now: int, *, immediate: bool) -> None:
        deadline = now if immediate else now + self.config.delayed_ack_ms
        if self.ack_deadline is None or deadline < self.ack_deadline:
            self.ack_deadline = deadline

    def _flush_ack(self, now: int) -> None:
        """Emit an owed ACK if it is due and nothing else has carried it."""
        if self.ack_deadline is None or now < self.ack_deadline:
            return
        if self.state.is_closed:
            self.ack_deadline = None
            return
        self._emit(Flag.ACK, now)

    # --- timers ------------------------------------------------------------

    def on_tick(self, now: int) -> None:
        """Fire whatever is due."""
        if self.state.is_closed:
            return

        if self.connect_deadline is not None and now >= self.connect_deadline:
            self._fail(
                ConnectionTimeout(f"connect to {self.remote_ip}:{self.remote_port} timed out")
            )
            return

        if self.time_wait_deadline is not None and now >= self.time_wait_deadline:
            self.state = State.CLOSED
            self.pending_events.append(("closed", "time-wait expired"))
            return

        # Persist and retransmission are mutually exclusive: a zero window
        # means the peer is not asking for anything back, so backing off a
        # retransmission timer against it would only waste the probe.
        if self.persist_deadline is not None:
            if now >= self.persist_deadline:
                self._probe(now)
        elif self.retransmit_deadline is not None and now >= self.retransmit_deadline:
            self._retransmit(now)

        self._flush_ack(now)

    def next_deadline(self) -> int | None:
        candidates = [
            deadline
            for deadline in (
                self.retransmit_deadline if self.persist_deadline is None else None,
                self.persist_deadline,
                self.ack_deadline,
                self.time_wait_deadline,
                self.connect_deadline,
            )
            if deadline is not None
        ]
        return min(candidates) if candidates else None

    def _retransmit(self, now: int) -> None:
        limit = (
            self.config.syn_retransmits
            if self.state is State.SYN_SENT
            else (self.config.max_retransmits)
        )
        if self.retransmit_count >= limit:
            self._fail(
                ConnectionTimeout(
                    f"{self.remote_ip}:{self.remote_port} stopped responding "
                    f"after {self.retransmit_count} retransmissions"
                )
            )
            return

        self.retransmit_count += 1
        # Exponential backoff, capped. The RTO stays backed off until a fresh
        # (non-retransmitted) sample replaces it.
        self.rto_ms = min(self.rto_ms * 2, self.config.rto_max_ms)

        if self.state is State.SYN_SENT:
            self.rtt_seq_end = None
            self._transmit(self.isn, Flag.SYN, b"", syn_options=True)
        else:
            # RFC 5681 3.1: a timeout means the pipe drained. Start over from
            # one segment; anything gentler risks sustaining the congestion.
            self.ssthresh = max(self.flight_size // 2, 2 * self.peer_mss)
            self.cwnd = self.peer_mss
            self.in_recovery = False
            self.dup_acks = 0
            # Rewind and let _pump send again from the left edge. Resending
            # only the leftmost segment and then waiting for the next timeout
            # costs an RTO *per segment* -- a transfer that technically
            # completes and practically hangs.
            self._rtt_blocked_through = self.snd_nxt
            self.rtt_seq_end = None
            self.snd_nxt = self.snd_una
            self.recover = self.snd_una
            self._pump(now)

        self.retransmit_deadline = now + self.rto_ms

    def _retransmit_leftmost(self, now: int) -> None:
        """Resend one segment from the left edge, leaving ``snd_nxt`` alone.

        This is the fast-retransmit shape: the pipe is believed to be intact
        apart from the one hole, so everything already in flight stays there.
        """
        # Karn: once a segment has been sent twice, an ACK for it says nothing
        # about which copy arrived, so the timing sample is worthless.
        self.rtt_seq_end = None
        if not self.send_buffer:
            return
        size = min(self.peer_mss, len(self.send_buffer))
        self._transmit(self.snd_una, Flag.ACK | Flag.PSH, bytes(self.send_buffer[:size]))
        if seq_lt(self.snd_nxt, seq_add(self.snd_una, size)):
            self.snd_nxt = seq_add(self.snd_una, size)

    def _probe(self, now: int) -> None:
        """Zero-window probe.

        The window update that reopens a closed window is a bare ACK, and a
        bare ACK is not retransmitted by anyone. Losing it would deadlock the
        connection forever, so the sender is the side that must keep asking.
        """
        self.persist_count += 1
        if self.persist_count > self.config.max_retransmits:
            # RFC 1122 4.2.2.17 forbids giving up merely because the window
            # stays shut -- but this is a peer that has answered nothing at
            # all, and a connection hung with no error is the worst outcome.
            self._fail(
                ConnectionTimeout(
                    f"{self.remote_ip}:{self.remote_port} stopped answering window probes"
                )
            )
            return

        if self.send_buffer:
            # Always the byte at the left edge. It stays in the buffer, so the
            # peer discarding it -- which is what a zero window means -- costs
            # nothing, and every probe offers the same byte again.
            self._transmit(self.snd_una, Flag.ACK | Flag.PSH, bytes(self.send_buffer[:1]))
            if seq_leq(self.snd_nxt, self.snd_una):
                self.snd_nxt = seq_add(self.snd_una, 1)
        else:
            self._emit(Flag.ACK, now)

        backed_off = max(self.persist_ms * 2, self.config.rto_min_ms)
        self.persist_ms = min(backed_off, self.config.rto_max_ms)
        self.persist_deadline = now + self.persist_ms

    def _exit_persist(self, now: int) -> None:
        self.persist_deadline = None
        self.persist_ms = 0
        self.persist_count = 0
        # Probes were sent past a closed window and therefore discarded, so
        # resume from the left edge rather than from wherever probing reached.
        self.snd_nxt = self.snd_una
        if self.flight_size > 0:
            self.retransmit_deadline = now + self.rto_ms

    def _arm_persist(self, now: int) -> None:
        wants_to_send = self.unsent > 0 and self.state.can_send
        if self.snd_wnd == 0 and wants_to_send:
            if self.persist_deadline is None:
                self.persist_ms = max(self.rto_ms, self.config.rto_min_ms)
                self.persist_deadline = now + self.persist_ms
        elif self.persist_deadline is not None and not wants_to_send:
            self.persist_deadline = None
            self.persist_ms = 0
            self.persist_count = 0

    def _update_rtt(self, sample_ms: int) -> None:
        """RFC 6298 with Jacobson/Karels smoothing."""
        sample = float(max(1, sample_ms))
        if self.srtt_ms == 0.0:
            self.srtt_ms = sample
            self.rttvar_ms = sample / 2
        else:
            self.rttvar_ms = 0.75 * self.rttvar_ms + 0.25 * abs(self.srtt_ms - sample)
            self.srtt_ms = 0.875 * self.srtt_ms + 0.125 * sample
        computed = int(self.srtt_ms + 4 * self.rttvar_ms)
        self.rto_ms = max(self.config.rto_min_ms, min(computed, self.config.rto_max_ms))

    # --- outbound ----------------------------------------------------------

    def _pump(self, now: int) -> None:
        """Send whatever the windows and buffer allow."""
        if self.state not in (
            State.ESTABLISHED,
            State.CLOSE_WAIT,
            State.FIN_WAIT_1,
            State.CLOSING,
            State.LAST_ACK,
        ):
            return

        if self.persist_deadline is not None and self.snd_wnd > 0:
            self._exit_persist(now)

        # The send window is the smaller of what the peer will accept and what
        # the network has shown it will carry.
        window = min(self.snd_wnd, self.cwnd)
        while True:
            offset = seq_diff(self.snd_nxt, self.send_base)
            remaining = len(self.send_buffer) - offset
            usable = window - self.flight_size
            if remaining <= 0 or usable <= 0:
                break
            size = min(self.peer_mss, usable, remaining)
            chunk = bytes(self.send_buffer[offset : offset + size])
            self._transmit(self.snd_nxt, Flag.ACK | Flag.PSH, chunk)
            if self.rtt_seq_end is None and self._past_retransmitted(self.snd_nxt):
                self.rtt_seq_end = seq_add(self.snd_nxt, size)
                self.rtt_sent_at = now
            self.snd_nxt = seq_add(self.snd_nxt, size)
            self._arm_rto(now)

        self._arm_persist(now)

        # The FIN follows the last data byte in sequence. Rewinding snd_nxt on
        # a timeout naturally brings us back here, so this doubles as the FIN's
        # retransmission without a special case.
        data_end = seq_add(self.send_base, len(self.send_buffer))
        if self.close_requested and self.snd_nxt == data_end:
            if self.fin_sent_seq is None:
                self.fin_sent_seq = self.snd_nxt
                if self.state is State.ESTABLISHED:
                    self.state = State.FIN_WAIT_1
                elif self.state is State.CLOSE_WAIT:
                    self.state = State.LAST_ACK
            self._transmit(self.snd_nxt, Flag.FIN | Flag.ACK, b"")
            self.snd_nxt = seq_add(self.snd_nxt, 1)
            self._arm_rto(now)

    def _past_retransmitted(self, seq: int) -> bool:
        return self._rtt_blocked_through is None or seq_geq(seq, self._rtt_blocked_through)

    def _arm_rto(self, now: int) -> None:
        """RFC 6298 5.1: start the timer if it is not already running."""
        if self.retransmit_deadline is None and self.persist_deadline is None:
            self.retransmit_deadline = now + self.rto_ms

    def _check_close_completion(self, now: int) -> None:
        """Advance the closing states once our FIN has been acknowledged."""
        if self.fin_sent_seq is None:
            return
        fin_acked = seq_gt(self.snd_una, self.fin_sent_seq)
        if not fin_acked:
            return

        if self.state is State.FIN_WAIT_1:
            self.state = State.FIN_WAIT_2 if not self.peer_fin_seen else State.TIME_WAIT
            if self.state is State.TIME_WAIT:
                self._enter_time_wait(now)
        elif self.state is State.CLOSING:
            self._enter_time_wait(now)
        elif self.state is State.LAST_ACK:
            self.state = State.CLOSED
            self.pending_events.append(("closed", "closed"))

    def _enter_time_wait(self, now: int) -> None:
        self.state = State.TIME_WAIT
        self.retransmit_deadline = None
        self.persist_deadline = None
        self.time_wait_deadline = now + self.config.time_wait_ms

    def _emit(self, flags: Flag, now: int, *, syn_options: bool = False) -> None:
        """Send a control segment. Data and FIN go out through :meth:`_pump`."""
        seq = self.snd_nxt
        self._transmit(seq, flags, b"", syn_options=syn_options)
        if flags & Flag.SYN:
            self.snd_nxt = seq_add(seq, 1)
            self._arm_rto(now)

    def _transmit(
        self,
        seq: int,
        flags: Flag,
        payload: bytes,
        *,
        syn_options: bool = False,
    ) -> None:
        if not flags & Flag.RST:
            end = seq_add(seq, len(payload) + (1 if flags & (Flag.SYN | Flag.FIN) else 0))
            if seq_gt(end, self.snd_max):
                self.snd_max = end

        self.pending_segments.append(
            build_tcp(
                source_ip=self.local_ip,
                destination_ip=self.remote_ip,
                source_port=self.local_port,
                destination_port=self.remote_port,
                seq=seq,
                ack=self.rcv_nxt if flags & Flag.ACK or self.state is not State.SYN_SENT else 0,
                flags=flags,
                window=self._window_field(flags),
                payload=payload,
                mss=self.config.mss if syn_options else None,
                window_scale=(
                    self.offered_wscale if syn_options and self.config.window_scaling else None
                ),
            )
        )
        if flags & Flag.ACK:
            # Whatever else this segment was for, it carried the ACK.
            self.ack_deadline = None
            self._segments_since_ack = 0

    def _window_field(self, flags: Flag) -> int:
        # RFC 7323: the SYN's own window is unscaled, because the shift is only
        # agreed once both SYNs have crossed.
        if flags & Flag.SYN:
            return min(self.recv_window, MAX_WINDOW)
        return self.advertised_window

    def _fail(self, error: NetworkError) -> None:
        self.error = error
        self.state = State.CLOSED
        self.retransmit_deadline = None
        self.persist_deadline = None
        self.connect_deadline = None
        self.ack_deadline = None
        self.pending_events.append(("error", error))
