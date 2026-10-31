# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The TCP state machine against a network that does anything it likes.

test_tcb.py walks one scenario per test. Here Hypothesis chooses the scenario:
application calls, the peer's segments, a network that reorders, duplicates
and drops them, hostile segments from off the path, and the clock, all
interleaved at will. After every step the TCB is held to what must be true
whatever happened:

* what the application reads is a prefix of what the peer sent, and what is
  buffered or held out of order is the peer's bytes at the right offsets;
* what goes on the wire is a slice of what the application wrote, inside the
  window the peer offered;
* we never acknowledge bytes the peer has not sent, and never shrink the
  window we offered;
* memory stays within the configured buffers;
* nothing is outstanding without a timer that will recover it;
* the timers stay within their configured bounds, and a connection gives up
  only after its whole retransmission budget has passed without progress;
* the state only moves forward, and a closed connection stays silent.

The peer is a model, not a TCP. It is sane -- its sequence numbers and
acknowledgements only move forward, as any real sender's do -- and otherwise
chooses at random. Real peers' good manners are the conformance suite's
business. This suite exists for everything a well-behaved kernel never sends.
"""

from __future__ import annotations

import os

import pytest
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    initialize,
    invariant,
    precondition,
    rule,
)

from usernet.errors import ConnectionRefused, ConnectionReset, ConnectionTimeout, NetworkError
from usernet.net.tcb import State, Tcb, TcbConfig
from usernet.net.tcp import (
    MAX_WINDOW,
    MAX_WINDOW_SCALE,
    SEQ_MASK,
    Flag,
    TcpSegment,
    seq_add,
    seq_diff,
    seq_geq,
    seq_gt,
)

LOCAL_IP = "172.29.29.5"
REMOTE_IP = "10.221.188.32"
LOCAL_PORT = 51000
REMOTE_PORT = 80

# A passing run takes seconds. A failing one is shrunk, which can take far
# longer, and the global 30 s timeout would kill it before it prints the
# reproduction -- leaving a CI failure that cannot be replayed. The nightly
# profile searches for much longer still, and a marker here would override
# the hour its workflow allows on the command line.
NIGHTLY = os.environ.get("HYPOTHESIS_PROFILE") == "nightly"
pytestmark = pytest.mark.timeout(3600 if NIGHTLY else 600)

SYNCHRONIZED = frozenset(State) - {State.CLOSED, State.SYN_SENT}

# One step of the state diagram. A single call may take several -- a segment
# that carries the peer's FIN and acknowledges ours moves FIN_WAIT_1 through
# CLOSING to TIME_WAIT -- so what is checked is reachability, not adjacency.
NEXT = {
    State.CLOSED: {State.SYN_SENT},
    State.SYN_SENT: {State.ESTABLISHED, State.CLOSED},
    State.ESTABLISHED: {State.FIN_WAIT_1, State.CLOSE_WAIT, State.CLOSED},
    State.FIN_WAIT_1: {State.FIN_WAIT_2, State.CLOSING, State.TIME_WAIT, State.CLOSED},
    State.FIN_WAIT_2: {State.TIME_WAIT, State.CLOSED},
    State.CLOSING: {State.TIME_WAIT, State.CLOSED},
    State.CLOSE_WAIT: {State.LAST_ACK, State.CLOSED},
    State.LAST_ACK: {State.CLOSED},
    State.TIME_WAIT: {State.CLOSED},
}


def reachable(source: State, target: State) -> bool:
    seen = {source}
    frontier = [source]
    while frontier:
        for state in NEXT[frontier.pop()]:
            if state not in seen:
                seen.add(state)
                frontier.append(state)
    return target in seen


# Hashed rather than counted, so that a slice delivered at the wrong offset
# cannot coincidentally match; periodic, with a prime period, so a slice is a
# slice of a table rather than a loop in Python. The invariants compare whole
# receive buffers after every step, and that loop was most of the run time.
_PERIOD = 65521
_STREAM = bytes(((o * 2654435761) >> 13) & 0xFF for o in range(_PERIOD))


def peer_bytes(offset: int, length: int) -> bytes:
    """The peer's stream: a fixed byte for every offset."""
    start = offset % _PERIOD
    repeated = _STREAM * ((start + length) // _PERIOD + 1)
    return repeated[start : start + length]


# Anywhere in sequence space, and often just short of the wrap, where a raw
# comparison instead of seq_lt would go wrong.
sequence_numbers = st.one_of(
    st.integers(0, SEQ_MASK),
    st.integers(SEQ_MASK - 4000, SEQ_MASK),
)
windows = st.one_of(st.integers(0, MAX_WINDOW), st.sampled_from([0, 1, MAX_WINDOW]))
delays = st.one_of(st.integers(0, 3000), st.sampled_from([40, 250, 1000, 15_000, 60_000]))
peer_mss = st.one_of(st.none(), st.integers(0, 0xFFFF))
peer_window_scale = st.one_of(st.none(), st.integers(0, MAX_WINDOW_SCALE))
# (rto_min_ms, rto_initial_ms, rto_max_ms). With the defaults, holding the RTO
# at its cap takes seven timeouts with progress between them, a sequence a run
# of 100 steps almost never finds. A low cap gets there in a few, and a fixed
# RTO starts there, which also makes the retransmission budget exact.
rto_bounds = st.sampled_from(
    [(250, 1000, 60_000), (250, 1000, 60_000), (250, 250, 2000), (250, 250, 250), (1, 1, 1)]
)


class TcbAgainstAnything(RuleBasedStateMachine):
    # --- set-up --------------------------------------------------------

    @initialize(
        isn=sequence_numbers,
        peer_isn=sequence_numbers,
        # The 536-byte floor is what a peer may always send, so a smaller
        # local MSS is not a configuration the TCB can honour.
        mss=st.integers(536, 1460),
        rx_buffer=st.one_of(st.integers(1, 5000), st.integers(65_536, 300_000)),
        tx_buffer=st.integers(1, 5000),
        max_ooo=st.integers(1, 64),
        scaling=st.booleans(),
        rto=rto_bounds,
        max_retransmits=st.sampled_from([8, 8, 2]),
        # Mostly connected from the start: a run spent in SYN_SENT is a run
        # that tests almost nothing, and the clock or a refusal ends most of
        # them there if left to chance.
        handshake=st.sampled_from([True, True, True, True, False]),
        syn_ack_mss=peer_mss,
        syn_ack_window=windows,
        syn_ack_window_scale=peer_window_scale,
    )
    def connect(
        self,
        isn: int,
        peer_isn: int,
        mss: int,
        rx_buffer: int,
        tx_buffer: int,
        max_ooo: int,
        scaling: bool,
        rto: tuple[int, int, int],
        max_retransmits: int,
        handshake: bool,
        syn_ack_mss: int | None,
        syn_ack_window: int,
        syn_ack_window_scale: int | None,
    ) -> None:
        self.now = 0
        self.isn = isn
        self.peer_isn = peer_isn
        self.tcb = Tcb(
            local_ip=LOCAL_IP,
            local_port=LOCAL_PORT,
            remote_ip=REMOTE_IP,
            remote_port=REMOTE_PORT,
            isn=isn,
            config=TcbConfig(
                mss=mss,
                rx_buffer=rx_buffer,
                tx_buffer=tx_buffer,
                max_ooo_segments=max_ooo,
                window_scaling=scaling,
                rto_min_ms=rto[0],
                rto_initial_ms=rto[1],
                rto_max_ms=rto[2],
                max_retransmits=max_retransmits,
            ),
        )
        self.state = State.CLOSED
        self.una = self.tcb.snd_una
        self.progressed_at = self.now
        """When an ACK last moved snd_una: the retransmission budget's start."""
        self.heard_at = self.now
        """When any segment last arrived: the persist budget's start."""
        self.probing = False

        # Our side, as the application sees it.
        self.written = bytearray()
        self.read = bytearray()
        self.app_closed = False

        # The peer. Offsets count from the first byte after each ISN.
        self.syn_ack_sent = False
        self.peer_sent = 0
        """Every peer byte below this has been sent at least once."""
        self.peer_fin: int | None = None
        self.peer_ack = 0
        self.peer_edge = 0
        """The furthest right edge the peer has offered, in our offsets."""
        self.network: list[TcpSegment] = []

        # What we told the peer.
        self.our_ack = 0
        self.our_edge: int | None = None

        self.connected = False
        self.ended = False

        self.tcb.connect(self.now)
        self.settle()
        if handshake:
            self.peer_accepts(syn_ack_mss, syn_ack_window, syn_ack_window_scale)
            self.deliver(0, duplicate=False)

    # --- the peer ------------------------------------------------------

    def receive(self, segment: TcpSegment) -> None:
        self.heard_at = self.now
        self.tcb.on_segment(segment, self.now)

    def our_offset(self, seq: int) -> int:
        return seq_diff(seq, seq_add(self.isn, 1))

    def peer_seq(self, offset: int) -> int:
        return seq_add(self.peer_isn, 1 + offset)

    def peer_segment(
        self, *, offset: int, flags: int, payload: bytes = b"", window: int
    ) -> TcpSegment:
        """A segment as the peer would send it now, carrying its current ACK."""
        edge = self.peer_ack + (window << self.tcb.snd_wscale)
        self.peer_edge = max(self.peer_edge, edge)
        return TcpSegment(
            source_port=REMOTE_PORT,
            destination_port=LOCAL_PORT,
            seq=self.peer_seq(offset),
            ack=seq_add(self.isn, 1 + self.peer_ack),
            flags=flags | Flag.ACK,
            window=window,
            payload=payload,
        )

    @precondition(lambda self: not self.syn_ack_sent)
    @rule(mss=peer_mss, window=windows, window_scale=peer_window_scale)
    def peer_accepts(self, mss: int | None, window: int, window_scale: int | None) -> None:
        """The SYN-ACK goes into the network like anything else, so it can be
        duplicated -- the case the challenge ACK exists for -- or lost."""
        self.syn_ack_sent = True
        self.peer_edge = window  # a SYN's window is never scaled
        self.network.append(
            TcpSegment(
                source_port=REMOTE_PORT,
                destination_port=LOCAL_PORT,
                seq=self.peer_isn,
                ack=seq_add(self.isn, 1),
                flags=Flag.SYN | Flag.ACK,
                window=window,
                payload=b"",
                mss=mss,
                window_scale=window_scale,
            )
        )

    def transmit(self, segment: TcpSegment, at_once: bool) -> None:
        """Into the network, or straight through it: most segments in real
        life arrive in order, and a run that queues everything spends its
        steps delivering rather than getting anywhere."""
        if at_once:
            self.receive(segment)
            self.settle()
        else:
            self.network.append(segment)

    @precondition(lambda self: self.connected)
    @rule(
        # Usually everything sent so far, as a peer keeping up would.
        advance=st.one_of(st.just(2**31), st.integers(0, 20_000)),
        window=windows,
        at_once=st.booleans(),
    )
    def peer_acknowledges(self, advance: int, window: int, at_once: bool) -> None:
        """Acknowledge some of what we sent. Never more than we sent, never
        less than before: the peer's view only moves forward."""
        sent = self.our_offset(self.tcb.snd_max)
        self.peer_ack = max(self.peer_ack, min(self.peer_ack + advance, sent))
        next_offset = self.peer_sent + (1 if self.peer_fin is not None else 0)
        self.transmit(self.peer_segment(offset=next_offset, flags=0, window=window), at_once)

    @precondition(lambda self: self.connected)
    @rule(
        back=st.integers(0, 6000),
        length=st.integers(0, 3000),
        window=windows,
        at_once=st.booleans(),
    )
    def peer_sends(self, back: int, length: int, window: int, at_once: bool) -> None:
        """New data, or a resend of anything already sent -- overlapping,
        partial, or wholly duplicate. The bytes for an offset never change."""
        start = max(0, self.peer_sent - back)
        end = start + length
        if self.peer_fin is not None:
            end = min(end, self.peer_fin)
            start = min(start, end)
        self.peer_sent = max(self.peer_sent, end)
        fin = Flag.FIN if self.peer_fin is not None and end == self.peer_fin else 0
        segment = self.peer_segment(
            offset=start,
            flags=Flag.PSH | fin,
            payload=peer_bytes(start, end - start),
            window=window,
        )
        self.transmit(segment, at_once)

    @precondition(lambda self: self.connected)
    @rule(
        pieces=st.lists(
            st.tuples(st.integers(0, 4000), st.integers(1, 2000)), min_size=2, max_size=8
        ),
        window=windows,
    )
    def peer_bursts(self, pieces: list[tuple[int, int]], window: int) -> None:
        """New data in overlapping pieces, arriving in any order, with the
        piece that starts it held back in the network.

        Reassembly is where the subtle bugs live, and building its states one
        segment at a time is too deep a search: a gap, then several held
        segments overlapping each other, then whatever fills the gap.
        """
        base = self.peer_sent
        for start, length in pieces:
            first = base + start
            end = first + length
            if self.peer_fin is not None:
                end = min(end, self.peer_fin)
                first = min(first, end)
            self.peer_sent = max(self.peer_sent, end)
            segment = self.peer_segment(
                offset=first,
                flags=Flag.PSH,
                payload=peer_bytes(first, end - first),
                window=window,
            )
            # Anything covering the first new byte waits, so a gap is certain.
            self.transmit(segment, at_once=first > base)

    @precondition(lambda self: self.connected and self.peer_fin is None)
    @rule(window=windows, at_once=st.booleans())
    def peer_closes(self, window: int, at_once: bool) -> None:
        self.peer_fin = self.peer_sent
        segment = self.peer_segment(offset=self.peer_fin, flags=Flag.FIN, window=window)
        self.transmit(segment, at_once)

    # --- the network ---------------------------------------------------

    @precondition(lambda self: self.network)
    @rule(pick=st.integers(0, 1000), duplicate=st.booleans())
    def deliver(self, pick: int, duplicate: bool) -> None:
        """Any segment in flight, in any order; optionally leaving a copy."""
        index = pick % len(self.network)
        segment = self.network[index] if duplicate else self.network.pop(index)
        self.receive(segment)
        self.settle()

    @precondition(lambda self: self.network)
    @rule(pick=st.integers(0, 1000))
    def lose(self, pick: int) -> None:
        self.network.pop(pick % len(self.network))

    # --- off the path --------------------------------------------------

    # Mostly a miss. Every hit ends the run, and left to itself Hypothesis
    # favours a distance of zero, which is the one sure hit.
    @rule(hit=st.sampled_from([False] * 31 + [True]), with_ack=st.booleans(), data=st.data())
    def blind_reset(self, hit: bool, with_ack: bool, data: st.DataObject) -> None:
        """RFC 5961: only a RST at exactly RCV.NXT may end a synchronized
        connection, elsewhere in the window it earns a challenge ACK, and in
        SYN_SENT only one acknowledging our SYN counts (RFC 9293 3.10.7.3)."""
        tcb = self.tcb
        window = max(1, tcb.recv_window)
        if hit:
            distance = data.draw(st.integers(0, window - 1), label="distance")
        else:
            distance = data.draw(
                st.one_of(st.integers(-(2**31), -1), st.integers(window, 2**31 - 1)),
                label="distance",
            )
        seq = seq_add(tcb.rcv_nxt, distance)
        before = tcb.state
        challenged = False
        if before is State.SYN_SENT:
            ack = seq_add(self.isn, 1 if hit else 1 + distance)
            expected = with_ack and hit
            error_type: type[NetworkError] = ConnectionRefused
        else:
            ack = seq_add(self.isn, 1 + self.peer_ack)
            expected = hit and distance == 0
            challenged = hit and distance != 0
            error_type = ConnectionReset
        sent_before = len(tcb.pending_segments)
        self.receive(
            TcpSegment(
                source_port=REMOTE_PORT,
                destination_port=LOCAL_PORT,
                seq=seq,
                ack=ack,
                flags=Flag.RST | (Flag.ACK if with_ack else 0),
                window=0,
                payload=b"",
            )
        )
        if before.is_closed:
            expected = challenged = False
        if expected:
            assert tcb.state is State.CLOSED, f"an acceptable RST left us in {tcb.state.name}"
            assert isinstance(tcb.error, error_type)
        else:
            assert tcb.state is before, f"a blind RST moved {before.name} to {tcb.state.name}"
        replies = tcb.pending_segments[sent_before:]
        if challenged:
            assert [(s.flags, s.ack) for s in replies] == [(Flag.ACK, tcb.rcv_nxt)]
        elif not expected:
            assert replies == [], "a RST outside the window was answered"
        self.settle()

    @precondition(lambda self: self.tcb.state in SYNCHRONIZED)
    @rule(seq=sequence_numbers, with_ack=st.booleans())
    def stray_syn(self, seq: int, with_ack: bool) -> None:
        """RFC 5961 4.2: a SYN in a synchronized state gets one challenge ACK
        and changes nothing else."""
        tcb = self.tcb
        before = (tcb.state, tcb.snd_nxt, tcb.rcv_nxt)
        self.receive(
            TcpSegment(
                source_port=REMOTE_PORT,
                destination_port=LOCAL_PORT,
                seq=seq,
                ack=seq_add(self.isn, 1 + self.peer_ack),
                flags=Flag.SYN | (Flag.ACK if with_ack else 0),
                window=MAX_WINDOW,
                payload=b"",
            )
        )
        assert (tcb.state, tcb.snd_nxt, tcb.rcv_nxt) == before
        (challenge,) = tcb.pending_segments
        assert challenge.flags == Flag.ACK
        assert challenge.seq == tcb.snd_nxt
        assert challenge.ack == tcb.rcv_nxt
        self.settle()

    @precondition(lambda self: self.tcb.state in SYNCHRONIZED)
    @rule(beyond=st.integers(1, 2**31 - 1), length=st.integers(0, 100))
    def ack_of_unsent_data(self, beyond: int, length: int) -> None:
        """Acknowledging bytes we never sent is not something a peer can do;
        the segment is ignored entirely, data and all."""
        tcb = self.tcb
        before = (tcb.state, tcb.snd_una, tcb.rcv_nxt, tcb.snd_wnd)
        self.receive(
            TcpSegment(
                source_port=REMOTE_PORT,
                destination_port=LOCAL_PORT,
                seq=tcb.rcv_nxt,
                ack=seq_add(tcb.snd_max, beyond),
                flags=Flag.ACK,
                window=MAX_WINDOW,
                payload=b"\xee" * length,
            )
        )
        assert (tcb.state, tcb.snd_una, tcb.rcv_nxt, tcb.snd_wnd) == before
        assert not tcb.pending_segments
        self.settle()

    # --- the application -----------------------------------------------

    # Only the length is drawn. Every check compares against what was written,
    # so the content need not be random -- and random kilobytes, recorded for
    # every write of every example, took the nightly search past 3 GB.
    @rule(length=st.integers(1, 4000))
    def app_writes(self, length: int) -> None:
        data = peer_bytes(len(self.written) + _PERIOD // 2, length)
        tcb = self.tcb
        open_for_writing = tcb.state.can_send and not tcb.close_requested
        space = tcb.tx_space
        accepted = tcb.send(data, self.now)
        if open_for_writing:
            assert accepted == min(len(data), space)
        else:
            assert accepted == 0
        self.written += data[:accepted]
        self.settle()

    @rule(size=st.integers(1, 6000))
    def app_reads(self, size: int) -> None:
        chunk = self.tcb.recv(size, self.now)
        assert len(chunk) <= size
        assert chunk == peer_bytes(len(self.read), len(chunk)), "read the wrong bytes"
        self.read += chunk
        self.settle()

    # Mostly nothing at all. Hypothesis leans towards this rule -- it sorts
    # first -- and a close or abort early in a run leaves every later step
    # with nothing to do. Measured: most runs never wrote a byte.
    @rule(action=st.sampled_from(["wait"] * 24 + ["close"] * 6 + ["abort"]))
    def app_closes(self, action: str) -> None:
        if action == "abort":
            self.tcb.abort(self.now)
        elif action == "close":
            if not self.tcb.state.is_closed:
                self.app_closed = True
            self.tcb.close(self.now)
        self.settle()

    # --- the clock -----------------------------------------------------

    @rule(milliseconds=delays)
    def time_passes(self, milliseconds: int) -> None:
        self.now += milliseconds
        self.tcb.on_tick(self.now)
        self.settle()

    @precondition(lambda self: self.tcb.next_deadline() is not None)
    @rule()
    def next_timer_fires(self) -> None:
        deadline = self.tcb.next_deadline()
        assert deadline is not None
        self.now = max(self.now, deadline)
        self.tcb.on_tick(self.now)
        self.settle()

    # --- checking what came out ----------------------------------------

    def settle(self) -> None:
        """Drain and check everything the last call produced."""
        tcb = self.tcb
        segments = list(tcb.pending_segments)
        events = list(tcb.pending_events)
        tcb.pending_segments.clear()
        tcb.pending_events.clear()

        if self.ended:
            assert not segments, f"a closed connection sent {segments}"
            assert not events, f"a closed connection reported {events}"

        for segment in segments:
            self.check_segment(segment)
        for name, detail in events:
            self.check_event(name, detail)

        assert reachable(self.state, tcb.state), f"{self.state.name} -> {tcb.state.name}"
        # The stack releases a socket the moment it is CLOSED; without an
        # event, whoever holds it waits forever.
        if tcb.state is State.CLOSED and self.state is not State.CLOSED:
            assert self.ended, f"{self.state.name} -> CLOSED without saying so"
        self.state = tcb.state
        if tcb.snd_una != self.una:
            self.una = tcb.snd_una
            self.progressed_at = self.now
        self.probing = tcb.persist_deadline is not None

    def check_segment(self, segment: TcpSegment) -> None:
        tcb = self.tcb
        assert (segment.source_port, segment.destination_port) == (LOCAL_PORT, REMOTE_PORT)
        assert 0 <= segment.window <= MAX_WINDOW

        if segment.has(Flag.SYN):
            assert segment.seq == self.isn
            assert not segment.payload
            assert not segment.has(Flag.ACK)
            assert segment.mss == tcb.config.mss
            return
        if segment.has(Flag.RST):
            return

        start = self.our_offset(segment.seq)
        end = start + len(segment.payload)
        # A segment sent after our FIN sits one past the last byte.
        assert 0 <= start <= len(self.written) + (1 if self.app_closed else 0), (
            f"sent from offset {start}, outside the stream"
        )
        if segment.payload:
            assert end <= len(self.written), "sent bytes the application never wrote"
            assert segment.payload == self.written[start:end], "sent the wrong bytes"
            assert len(segment.payload) <= tcb.peer_mss, "sent more than the peer's MSS"
            # One byte past the edge is a zero-window probe; anything more is
            # an overrun the peer will discard.
            assert end <= self.peer_edge + 1, (
                f"sent through offset {end}, but the peer never offered past {self.peer_edge}"
            )
        if segment.has(Flag.FIN):
            assert self.app_closed, "sent a FIN nobody asked for"
            assert end == len(self.written), "the FIN is not after the last byte"

        if not segment.has(Flag.ACK):
            return
        ack = seq_diff(segment.ack, self.peer_seq(0))
        limit = self.peer_sent + (1 if self.peer_fin is not None else 0)
        assert 0 <= ack <= limit, f"acknowledged offset {ack}; the peer sent up to {limit}"
        assert ack >= self.our_ack, "our acknowledgement went backwards"
        self.our_ack = ack

        # RFC 9293 3.8.6.2.2: the right edge must not move left. Scaling
        # rounds the window down, which may cost up to one unit of the shift.
        edge = ack + (segment.window << tcb.rcv_wscale)
        if self.our_edge is not None:
            slack = (1 << tcb.rcv_wscale) - 1
            assert edge >= self.our_edge - slack, (
                f"the window's right edge moved left from {self.our_edge} to {edge}"
            )
        self.our_edge = edge if self.our_edge is None else max(edge, self.our_edge)

    def check_event(self, name: str, detail: object) -> None:
        tcb = self.tcb
        assert not self.ended
        if name == "connected":
            assert not self.connected
            assert self.state is State.SYN_SENT
            self.connected = True
        elif name == "readable":
            assert tcb.rx_available > 0
        elif name == "writable":
            assert tcb.tx_space > 0
        elif name == "peer_closed":
            assert self.peer_fin is not None, "reported a FIN the peer never sent"
            assert len(self.read) + tcb.rx_available == self.peer_fin, (
                "reported end of stream before every byte had arrived"
            )
        elif name == "error":
            assert isinstance(detail, NetworkError)
            assert tcb.state is State.CLOSED
            if isinstance(detail, ConnectionTimeout) and self.state in SYNCHRONIZED:
                self.check_the_timeout_was_earned()
            self.ended = True
        elif name == "closed":
            assert tcb.state is State.CLOSED
            self.ended = True
        else:
            raise AssertionError(f"unknown event {name!r}")

    def check_the_timeout_was_earned(self) -> None:
        """Giving up takes max_retransmits resends or probes and one more
        expiry, none sooner than rto_min_ms.

        The retransmission budget restarts with every ACK that moves snd_una,
        so a peer acknowledging a byte per timeout keeps the connection alive
        however far the RTO has backed off. The persist budget restarts with
        any segment at all: RFC 1122 4.2.2.17 lets a connection give up on a
        peer that stopped answering its probes, never on one that answers them
        with the window still shut.
        """
        config = self.tcb.config
        if self.probing:
            since, what = self.heard_at, "the last segment"
        else:
            since, what = self.progressed_at, "progress"
        quiet = self.now - since
        budget = (config.max_retransmits + 1) * config.rto_min_ms
        assert quiet >= budget, (
            f"gave up {quiet} ms after {what}; the budget is at least {budget} ms"
        )

    # --- what holds between steps --------------------------------------

    @invariant()
    def sequence_space_is_ordered(self) -> None:
        tcb = self.tcb
        assert seq_geq(tcb.snd_nxt, tcb.snd_una)
        assert seq_geq(tcb.snd_max, tcb.snd_nxt)
        if tcb.state in SYNCHRONIZED:
            assert tcb.send_base == tcb.snd_una

    @invariant()
    def memory_is_bounded(self) -> None:
        tcb = self.tcb
        config = tcb.config
        assert len(tcb.send_buffer) <= config.tx_buffer
        assert len(tcb.recv_buffer) + tcb._ooo_bytes <= config.rx_buffer
        assert len(tcb._ooo) <= config.max_ooo_segments
        assert tcb._ooo_bytes == sum(len(payload) for _, payload in tcb._ooo)

    @invariant()
    def buffers_hold_the_right_bytes(self) -> None:
        tcb = self.tcb
        if not self.connected:
            return
        received = len(self.read)
        assert bytes(tcb.recv_buffer) == peer_bytes(received, len(tcb.recv_buffer))
        delivered = received + len(tcb.recv_buffer)
        previous: int | None = None
        for seq, payload in tcb._ooo:
            offset = seq_diff(seq, self.peer_seq(0))
            assert offset > delivered, "a held segment is not ahead of the gap"
            assert payload == peer_bytes(offset, len(payload)), "held the wrong bytes"
            assert previous is None or offset >= previous, "the reassembly queue is unsorted"
            previous = offset

        unacked = self.our_offset(tcb.send_base)
        if tcb.state in SYNCHRONIZED and unacked <= len(self.written):
            tail = self.written[unacked : unacked + len(tcb.send_buffer)]
            assert bytes(tcb.send_buffer) == bytes(tail), "the send buffer drifted"

    @invariant()
    def timers_stay_within_bounds(self) -> None:
        tcb = self.tcb
        config = tcb.config
        assert config.rto_min_ms <= tcb.rto_ms <= config.rto_max_ms
        assert tcb.persist_ms <= config.rto_max_ms

    @invariant()
    def nothing_is_outstanding_without_a_timer(self) -> None:
        """A connection with work to do and no deadline hangs forever."""
        tcb = self.tcb
        if tcb.state.is_closed:
            return
        owes_data = tcb.flight_size > 0 or tcb.unsent > 0
        owes_fin = tcb.close_requested and (
            tcb.fin_sent_seq is None or not seq_gt(tcb.snd_una, tcb.fin_sent_seq)
        )
        if owes_data or owes_fin or tcb.state in (State.SYN_SENT, State.TIME_WAIT):
            assert tcb.next_deadline() is not None, (
                f"{tcb.state.name} with work outstanding and no timer: "
                f"flight={tcb.flight_size} unsent={tcb.unsent} fin={tcb.fin_sent_seq}"
            )


TestTcbAgainstAnything = TcbAgainstAnything.TestCase
# Deeper than the profile's default: each run costs milliseconds, and a large
# share of Hypothesis's examples are near-minimal runs that end before any
# data has moved.
TestTcbAgainstAnything.settings = settings(
    settings.default,
    max_examples=max(400, settings.default.max_examples),
    stateful_step_count=max(100, settings.default.stateful_step_count),
)
