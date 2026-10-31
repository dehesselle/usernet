# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The TCP state machine, driven deterministically.

The clock is an integer advanced by hand, so every timing assertion is exact
and nothing depends on wall time. A test here that sleeps, or that passes only
sometimes, is a bug in the test.
"""

from __future__ import annotations

import pytest

from usernet.errors import ConnectionRefused, ConnectionReset, ConnectionTimeout
from usernet.net.ipv4 import PROTO_TCP
from usernet.net.tcb import State, Tcb, TcbConfig, initial_window_scale
from usernet.net.tcp import (
    DEFAULT_MSS,
    MAX_WINDOW_SCALE,
    Flag,
    TcpSegment,
    seq_add,
)

LOCAL_IP = "172.29.29.5"
REMOTE_IP = "10.221.188.32"
LOCAL_PORT = 51000
REMOTE_PORT = 80
ISN = 1000
PEER_ISN = 500_000


class Harness:
    """One TCB, a frozen clock, and helpers to speak to it as the peer."""

    def __init__(self, **config: object) -> None:
        self.now = 0
        self.tcb = Tcb(
            local_ip=LOCAL_IP,
            local_port=LOCAL_PORT,
            remote_ip=REMOTE_IP,
            remote_port=REMOTE_PORT,
            isn=ISN,
            config=TcbConfig(**config),  # type: ignore[arg-type]
        )

    # --- driving -------------------------------------------------------

    def advance(self, milliseconds: int) -> None:
        self.now += milliseconds
        self.tcb.on_tick(self.now)

    def let_ack_fire(self) -> None:
        """Advance just past the delayed-ACK timer."""
        self.advance(self.tcb.config.delayed_ack_ms)

    def sent(self) -> list[TcpSegment]:
        """Drain and parse everything the TCB wants to send."""
        segments = list(self.tcb.pending_segments)
        self.tcb.pending_segments.clear()
        return segments

    def one(self) -> TcpSegment:
        segments = self.sent()
        assert len(segments) == 1, f"expected exactly one segment, got {len(segments)}"
        return segments[0]

    def events(self) -> list[object]:
        drained = list(self.tcb.pending_events)
        self.tcb.pending_events.clear()
        return drained

    def event_names(self) -> list[str]:
        return [name for name, _ in self.events()]  # type: ignore[misc]

    def peer(
        self,
        *,
        seq: int,
        ack: int,
        flags: int,
        payload: bytes = b"",
        window: int = 65535,
        mss: int | None = None,
        window_scale: int | None = None,
    ) -> None:
        self.tcb.on_segment(
            TcpSegment(
                source_port=REMOTE_PORT,
                destination_port=LOCAL_PORT,
                seq=seq,
                ack=ack,
                flags=flags,
                window=window,
                payload=payload,
                mss=mss,
                window_scale=window_scale,
            ),
            self.now,
        )

    # --- shortcuts -----------------------------------------------------

    def establish(
        self,
        *,
        peer_mss: int | None = 1460,
        rtt_ms: int = 0,
        window: int = 65535,
        window_scale: int | None = None,
    ) -> None:
        """Complete a handshake, optionally taking ``rtt_ms`` to do it.

        The handshake itself yields the connection's first RTT sample, so
        ``rtt_ms`` seeds the estimator deliberately rather than leaving tests
        to trip over an implicit near-zero sample.
        """
        self.tcb.connect(self.now)
        self.sent()
        self.now += rtt_ms
        self.peer(
            seq=PEER_ISN,
            ack=seq_add(ISN, 1),
            flags=Flag.SYN | Flag.ACK,
            mss=peer_mss,
            window=window,
            window_scale=window_scale,
        )
        self.sent()
        self.events()
        assert self.tcb.state is State.ESTABLISHED


@pytest.fixture
def h() -> Harness:
    return Harness()


# --- handshake -------------------------------------------------------------


def test_connect_sends_syn_with_mss(h: Harness) -> None:
    h.tcb.connect(h.now)
    syn = h.one()

    assert syn.flags == Flag.SYN
    assert syn.seq == ISN
    assert syn.source_port == LOCAL_PORT
    assert syn.destination_port == REMOTE_PORT
    assert syn.mss == h.tcb.config.mss
    assert h.tcb.state is State.SYN_SENT


def test_syn_ack_completes_the_handshake(h: Harness) -> None:
    h.tcb.connect(h.now)
    h.sent()
    h.peer(seq=PEER_ISN, ack=seq_add(ISN, 1), flags=Flag.SYN | Flag.ACK, mss=1460)

    ack = h.one()
    assert ack.flags & Flag.ACK
    assert ack.seq == seq_add(ISN, 1)
    assert ack.ack == seq_add(PEER_ISN, 1)
    assert h.tcb.state is State.ESTABLISHED
    assert h.event_names() == ["connected"]


def test_our_mss_is_clamped_to_the_peers(h: Harness) -> None:
    """Sending above the peer's MSS is the classic silent-hang bug."""
    h.establish(peer_mss=536)
    assert h.tcb.peer_mss == 536


def test_peer_mss_larger_than_ours_does_not_raise_ours(h: Harness) -> None:
    h.establish(peer_mss=9000)
    assert h.tcb.peer_mss == h.tcb.config.mss


def test_missing_mss_option_falls_back_to_the_rfc_floor(h: Harness) -> None:
    h.establish(peer_mss=None)
    assert h.tcb.peer_mss == DEFAULT_MSS


@pytest.mark.parametrize("peer_mss", [1460, 300, None])
def test_our_mss_below_the_rfc_floor_is_never_raised_to_it(peer_mss: int | None) -> None:
    """Ours comes from the tunnel's MTU. The floor guards against a peer
    asking for tiny segments; applied to ours, it sent packets the tunnel
    could not carry."""
    h = Harness(mss=400)
    h.establish(peer_mss=peer_mss)
    assert h.tcb.peer_mss == 400


def test_syn_ack_for_a_different_handshake_is_ignored(h: Harness) -> None:
    h.tcb.connect(h.now)
    h.sent()
    h.peer(seq=PEER_ISN, ack=99999, flags=Flag.SYN | Flag.ACK)

    assert h.tcb.state is State.SYN_SENT
    assert h.sent() == []


def test_rst_during_connect_is_connection_refused(h: Harness) -> None:
    h.tcb.connect(h.now)
    h.sent()
    h.peer(seq=0, ack=seq_add(ISN, 1), flags=Flag.RST | Flag.ACK)

    assert h.tcb.state is State.CLOSED
    assert isinstance(h.tcb.error, ConnectionRefused)


@pytest.mark.parametrize(
    ("flags", "ack"),
    [(Flag.RST, 0), (Flag.RST | Flag.ACK, ISN), (Flag.RST | Flag.ACK, ISN + 2)],
    ids=["without-ack", "ack-below-syn", "ack-beyond-syn"],
)
def test_a_reset_not_acknowledging_our_syn_is_ignored(h: Harness, flags: int, ack: int) -> None:
    """RFC 9293 3.10.7.3. Only the ACK ties a RST to our SYN; without it,
    anyone who guesses the four-tuple could fail the connect."""
    h.tcb.connect(h.now)
    h.sent()
    h.peer(seq=0, ack=ack, flags=flags)

    assert h.tcb.state is State.SYN_SENT
    assert h.tcb.error is None


def test_syn_is_retransmitted_with_backoff_then_gives_up(h: Harness) -> None:
    h = Harness(rto_initial_ms=1000, syn_retransmits=3, connect_timeout_ms=999_999)
    h.tcb.connect(h.now)
    h.sent()

    for expected_delay in (1000, 2000, 4000):
        h.advance(expected_delay)
        assert h.one().flags == Flag.SYN

    h.advance(8000)
    assert h.tcb.state is State.CLOSED
    assert isinstance(h.tcb.error, ConnectionTimeout)


def test_connect_timeout_fires_independently_of_retransmits(h: Harness) -> None:
    h = Harness(connect_timeout_ms=5000, rto_initial_ms=100_000)
    h.tcb.connect(h.now)
    h.sent()

    h.advance(5000)
    assert h.tcb.state is State.CLOSED
    assert isinstance(h.tcb.error, ConnectionTimeout)


# --- data transfer ---------------------------------------------------------


def test_send_produces_a_data_segment(h: Harness) -> None:
    h.establish()
    assert h.tcb.send(b"GET / HTTP/1.1\r\n\r\n", h.now) == 18

    segment = h.one()
    assert segment.payload == b"GET / HTTP/1.1\r\n\r\n"
    assert segment.flags & Flag.PSH
    assert segment.flags & Flag.ACK
    assert segment.seq == seq_add(ISN, 1)


def test_send_is_split_at_the_peer_mss(h: Harness) -> None:
    h.establish(peer_mss=536)
    h.tcb.send(b"x" * 1200, h.now)

    segments = h.sent()
    assert [len(s.payload) for s in segments] == [536, 536, 128]
    assert b"".join(s.payload for s in segments) == b"x" * 1200
    # Sequence numbers must be contiguous across the split.
    assert segments[1].seq == seq_add(segments[0].seq, 536)


def test_send_respects_the_peer_window(h: Harness) -> None:
    h.tcb.connect(h.now)
    h.sent()
    h.peer(seq=PEER_ISN, ack=seq_add(ISN, 1), flags=Flag.SYN | Flag.ACK, mss=1460, window=100)
    h.sent()

    h.tcb.send(b"y" * 500, h.now)
    segments = h.sent()

    assert sum(len(s.payload) for s in segments) == 100
    assert h.tcb.unsent == 400  # the rest stays queued
    assert len(h.tcb.send_buffer) == 500  # and all of it is retained for resend


def test_window_reopening_releases_queued_data(h: Harness) -> None:
    h.tcb.connect(h.now)
    h.sent()
    h.peer(seq=PEER_ISN, ack=seq_add(ISN, 1), flags=Flag.SYN | Flag.ACK, mss=1460, window=100)
    h.sent()
    h.tcb.send(b"y" * 500, h.now)
    h.sent()

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 101), flags=Flag.ACK, window=400)
    assert sum(len(s.payload) for s in h.sent()) == 400


def test_send_is_bounded_by_the_transmit_buffer(h: Harness) -> None:
    h = Harness(tx_buffer=100)
    h.establish(peer_mss=1460)
    # Window is wide open, so everything accepted is sent immediately.
    assert h.tcb.send(b"z" * 500, h.now) == 100


def test_receiving_data_buffers_it_and_acks(h: Harness) -> None:
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"hello")
    h.let_ack_fire()

    ack = h.one()
    assert ack.ack == seq_add(PEER_ISN, 6)
    assert h.tcb.recv(100) == b"hello"
    assert "readable" in h.event_names()


def test_recv_takes_only_what_is_asked_for(h: Harness) -> None:
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"abcdef")

    assert h.tcb.recv(2) == b"ab"
    assert h.tcb.recv(2) == b"cd"
    assert h.tcb.recv(100) == b"ef"
    assert h.tcb.recv(100) == b""


def test_out_of_order_segment_is_held_and_reacked(h: Harness) -> None:
    """Held, not delivered: the ACK keeps asking for the byte before the gap."""
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 100), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"future")

    ack = h.one()
    assert ack.ack == seq_add(PEER_ISN, 1)  # still asking for the gap
    assert h.tcb.recv(100) == b""


def test_advertised_window_shrinks_as_the_buffer_fills(h: Harness) -> None:
    """Flow control is only real if the window reflects unread bytes."""
    h = Harness(rx_buffer=1000)
    h.establish()

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"a" * 400)
    h.let_ack_fire()
    assert h.one().window == 600

    h.tcb.recv(400, h.now)
    h.sent()
    h.peer(seq=seq_add(PEER_ISN, 401), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"b" * 10)
    h.let_ack_fire()
    assert h.one().window == 990


def test_data_beyond_the_receive_buffer_is_not_accepted(h: Harness) -> None:
    h = Harness(rx_buffer=100)
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"c" * 250)

    assert len(h.tcb.recv_buffer) == 100
    assert h.one().window == 0


# --- retransmission --------------------------------------------------------


def test_unacked_data_is_retransmitted(h: Harness) -> None:
    h = Harness(rto_initial_ms=1000)
    h.establish()
    h.tcb.send(b"payload", h.now)
    first = h.one()

    h.advance(1000)
    again = h.one()
    assert again.payload == first.payload
    assert again.seq == first.seq


def test_acked_data_is_not_retransmitted(h: Harness) -> None:
    h = Harness(rto_initial_ms=1000)
    h.establish()
    h.tcb.send(b"payload", h.now)
    h.sent()

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 8), flags=Flag.ACK)
    h.sent()

    h.advance(5000)
    assert h.sent() == []


def test_retransmission_backs_off_exponentially(h: Harness) -> None:
    h = Harness(rto_initial_ms=1000, max_retransmits=5)
    h.establish()
    h.tcb.send(b"data", h.now)
    h.sent()

    for delay in (1000, 2000, 4000):
        h.advance(delay)
        assert len(h.sent()) == 1


def test_giving_up_reports_a_timeout(h: Harness) -> None:
    h = Harness(rto_initial_ms=1000, max_retransmits=2)
    h.establish()
    h.tcb.send(b"data", h.now)
    h.sent()

    h.advance(1000)
    h.advance(2000)
    h.advance(4000)

    assert h.tcb.state is State.CLOSED
    assert isinstance(h.tcb.error, ConnectionTimeout)


def test_the_handshake_provides_the_first_rtt_sample(h: Harness) -> None:
    """RFC 6298: the SYN exchange is a legitimate first measurement."""
    h = Harness(rto_min_ms=1)
    h.establish(rtt_ms=100)

    # First sample: srtt=100, rttvar=50, rto=srtt+4*rttvar=300.
    assert h.tcb.srtt_ms == 100
    assert h.tcb.rttvar_ms == 50
    assert h.tcb.rto_ms == 300


def test_later_samples_are_smoothed_into_the_estimate(h: Harness) -> None:
    h = Harness(rto_min_ms=1)
    h.establish(rtt_ms=100)
    h.tcb.send(b"data", h.now)
    h.sent()

    h.now += 200
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 5), flags=Flag.ACK)

    # srtt = 0.875*100 + 0.125*200 = 112.5, moving toward the new sample.
    assert h.tcb.srtt_ms == pytest.approx(112.5)
    assert 100 < h.tcb.rto_ms < 400


def test_karn_ignores_the_rtt_of_a_retransmitted_segment(h: Harness) -> None:
    """We cannot tell which copy was acknowledged, so the sample is unusable."""
    h = Harness(rto_initial_ms=1000, rto_min_ms=1)
    h.establish(rtt_ms=100)
    before = h.tcb.srtt_ms
    h.tcb.send(b"data", h.now)
    h.sent()

    h.advance(1000)  # retransmit
    h.sent()
    h.now += 10
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 5), flags=Flag.ACK)

    assert h.tcb.srtt_ms == before  # the ambiguous sample was discarded


def test_rto_is_clamped_to_the_minimum(h: Harness) -> None:
    """A fast LAN RTT would otherwise compute an RTO below Windows' timer
    granularity, turning every minor delay into a spurious retransmission."""
    h = Harness(rto_min_ms=250)
    h.establish(rtt_ms=1)
    assert h.tcb.rto_ms == 250


def test_a_long_recovery_still_yields_a_sample() -> None:
    """After a second timeout, the first resend past the rewound snd_nxt is
    timed. Without that, a receiver that discards out-of-order data left a
    whole recovery without a sample, and the RTO doubled throughout."""
    h = Harness(rto_initial_ms=1000, rto_min_ms=1)
    h.establish(peer_mss=536, rtt_ms=100)
    h.tcb.send(b"z" * 2144, h.now)
    h.sent()
    h.advance(h.tcb.rto_ms)
    h.advance(h.tcb.rto_ms)
    h.sent()
    backed_off = h.tcb.rto_ms

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 537), flags=Flag.ACK)
    assert h.sent()[0].seq == seq_add(ISN, 537), "the second segment goes out again"
    h.now += 50
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1073), flags=Flag.ACK)

    assert h.tcb.srtt_ms == pytest.approx(0.875 * 100 + 0.125 * 50)
    assert h.tcb.rto_ms < backed_off


def test_an_ack_that_covers_a_resent_hole_is_no_sample() -> None:
    """The segment timed in this window was resent by fast retransmit, so its
    ACK may be for either copy; timing resumes with the next new data."""
    h = Harness(rto_min_ms=1, rto_initial_ms=100_000)
    h.establish(peer_mss=536, rtt_ms=100)
    h.tcb.send(b"z" * 2144, h.now)
    h.sent()
    for _ in range(3):
        h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK)
    assert h.one().seq == seq_add(ISN, 1)

    h.now += 1000
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 2145), flags=Flag.ACK)
    assert h.tcb.srtt_ms == 100

    # Past the hole, samples resume with the next data.
    h.tcb.send(b"z" * 536, h.now)
    h.sent()
    h.now += 200
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 2681), flags=Flag.ACK)
    assert h.tcb.srtt_ms == pytest.approx(112.5)


def test_a_backed_off_timer_collapses_with_the_first_clean_sample() -> None:
    """RFC 6298 5.5 holds the backed-off RTO only until data sent once is
    acknowledged; that sample brings it back to what the path needs."""
    h = Harness(rto_initial_ms=1000, rto_min_ms=1)
    h.establish(peer_mss=536, rtt_ms=100)
    h.tcb.send(b"z" * 536, h.now)
    h.sent()
    h.advance(h.tcb.rto_ms)
    h.advance(h.tcb.rto_ms)
    h.sent()
    backed_off = h.tcb.rto_ms
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 537), flags=Flag.ACK)
    assert h.tcb.rto_ms == backed_off

    h.tcb.send(b"z" * 536, h.now)
    h.sent()
    h.now += 100
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1073), flags=Flag.ACK)
    assert h.tcb.rto_ms < backed_off // 2


def test_progress_outlasts_a_backoff_held_at_the_cap() -> None:
    """Behind a receiver that discards out-of-order data, every segment past a
    loss goes out twice, so each ACK here is for a second transmission and
    Karn's rule allows no sample. The RTO doubles to its cap and stays there.
    But each ACK that moves snd_una restarts the retransmission budget: a
    connection still making progress must not fail however many timeouts it
    takes. The driver soak reached this only in seeds too slow for its
    timeout, so it is pinned here instead."""
    h = Harness(rto_min_ms=1, rto_max_ms=5000, max_retransmits=3)
    h.establish(peer_mss=536, rtt_ms=100)
    data = bytes(range(256)) * 64
    h.tcb.send(data, h.now)
    h.sent()  # the first flight, lost

    delivered = b""
    rtos = []
    for timeout in range(1, 9):
        h.advance(h.tcb.rto_ms)
        assert h.tcb.error is None, f"gave up at timeout {timeout}"
        rtos.append(h.tcb.rto_ms)
        (resent,) = h.sent()
        delivered += resent.payload
        h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1 + len(delivered)), flags=Flag.ACK)
        h.sent()  # the next flight, lost again

    assert rtos == [600, 1200, 2400, 4800, 5000, 5000, 5000, 5000]
    assert h.tcb.state is State.ESTABLISHED
    assert h.tcb.srtt_ms == 100
    assert delivered == data[: len(delivered)]

    # The second segment of the last flight went out once, so its ACK is a
    # sample at last, and the RTO comes back to what the path needs.
    h.now += 100
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1 + len(delivered) + 1072), flags=Flag.ACK)
    assert h.tcb.rto_ms < 1000


# --- closing ---------------------------------------------------------------


def test_active_close_walks_fin_wait_to_time_wait(h: Harness) -> None:
    h.establish()
    h.tcb.close(h.now)

    fin = h.one()
    assert fin.flags & Flag.FIN
    assert h.tcb.state is State.FIN_WAIT_1

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 2), flags=Flag.ACK)
    h.sent()
    assert h.tcb.state is State.FIN_WAIT_2

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 2), flags=Flag.FIN | Flag.ACK)
    h.sent()
    assert h.tcb.state is State.TIME_WAIT


def test_an_acknowledged_fin_is_not_sent_again(h: Harness) -> None:
    h.establish()
    h.tcb.close(h.now)
    h.sent()

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 2), flags=Flag.ACK)
    assert h.sent() == []
    assert h.tcb.next_deadline() is None, "a timer is running with nothing outstanding"


def test_a_half_closed_connection_outlives_the_retransmission_budget(h: Harness) -> None:
    """We have closed and the peer is still sending -- a request followed by a
    long download. Nothing of ours is outstanding, so no timer may run down,
    however long the download takes."""
    h.establish()
    h.tcb.close(h.now)
    h.sent()
    seq = seq_add(PEER_ISN, 1)
    h.peer(seq=seq, ack=seq_add(ISN, 2), flags=Flag.ACK)

    for _ in range(600):
        h.advance(1000)
        h.peer(seq=seq, ack=seq_add(ISN, 2), flags=Flag.ACK | Flag.PSH, payload=b"x")
        seq = seq_add(seq, 1)
        h.tcb.recv(1, h.now)

    assert h.tcb.state is State.FIN_WAIT_2
    assert h.tcb.error is None


def test_time_wait_expires_into_closed(h: Harness) -> None:
    h = Harness(time_wait_ms=30_000)
    h.establish()
    h.tcb.close(h.now)
    h.sent()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 2), flags=Flag.FIN | Flag.ACK)
    h.sent()

    h.advance(29_999)
    assert h.tcb.state is State.TIME_WAIT
    h.advance(1)
    assert h.tcb.state is State.CLOSED


def test_passive_close_walks_close_wait_to_last_ack(h: Harness) -> None:
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.FIN | Flag.ACK)
    h.sent()

    assert h.tcb.state is State.CLOSE_WAIT
    assert "peer_closed" in h.event_names()

    h.tcb.close(h.now)
    assert h.one().flags & Flag.FIN
    assert h.tcb.state is State.LAST_ACK

    h.peer(seq=seq_add(PEER_ISN, 2), ack=seq_add(ISN, 2), flags=Flag.ACK)
    assert h.tcb.state is State.CLOSED


def test_simultaneous_close_goes_through_closing(h: Harness) -> None:
    h.establish()
    h.tcb.close(h.now)
    h.sent()

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.FIN | Flag.ACK)
    h.sent()
    assert h.tcb.state is State.CLOSING

    h.peer(seq=seq_add(PEER_ISN, 2), ack=seq_add(ISN, 2), flags=Flag.ACK)
    assert h.tcb.state is State.TIME_WAIT


def test_queued_data_is_flushed_before_the_fin(h: Harness) -> None:
    h.establish(peer_mss=536)
    h.tcb.send(b"q" * 1000, h.now)
    h.sent()
    h.tcb.close(h.now)

    # Everything was already sent, so only the FIN remains.
    assert h.one().flags & Flag.FIN


def test_close_before_the_window_allows_sending_defers_the_fin(h: Harness) -> None:
    h.tcb.connect(h.now)
    h.sent()
    h.peer(seq=PEER_ISN, ack=seq_add(ISN, 1), flags=Flag.SYN | Flag.ACK, mss=1460, window=10)
    h.sent()

    h.tcb.send(b"w" * 100, h.now)
    h.sent()
    h.tcb.close(h.now)
    assert not any(s.flags & Flag.FIN for s in h.sent())

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 11), flags=Flag.ACK, window=1000)
    assert any(s.flags & Flag.FIN for s in h.sent())


def test_send_after_close_is_refused(h: Harness) -> None:
    h.establish()
    h.tcb.close(h.now)
    assert h.tcb.send(b"too late", h.now) == 0


# --- resets ----------------------------------------------------------------


def test_a_reset_at_rcv_nxt_tears_down_the_connection(h: Harness) -> None:
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.RST)

    assert h.tcb.state is State.CLOSED
    assert isinstance(h.tcb.error, ConnectionReset)


def test_a_reset_elsewhere_in_the_window_is_challenged(h: Harness) -> None:
    """RFC 5961 3.2: anywhere in the window gives a blind attacker a window's
    worth of chances; only RCV.NXT exactly is a reset."""
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 100), ack=seq_add(ISN, 1), flags=Flag.RST)

    challenge = h.one()
    assert challenge.flags == Flag.ACK
    assert challenge.seq == seq_add(ISN, 1)
    assert challenge.ack == seq_add(PEER_ISN, 1)
    assert h.tcb.state is State.ESTABLISHED
    assert h.tcb.error is None


def test_a_peer_answering_the_challenge_resets_the_connection(h: Harness) -> None:
    """A genuine peer whose RST overtook data we never received: it answers
    the challenge ACK with a RST at the sequence number that ACK names."""
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 100), ack=seq_add(ISN, 1), flags=Flag.RST)
    challenge = h.one()

    h.peer(seq=challenge.ack, ack=0, flags=Flag.RST)

    assert h.tcb.state is State.CLOSED
    assert isinstance(h.tcb.error, ConnectionReset)


def test_out_of_window_reset_is_ignored(h: Harness) -> None:
    """RFC 5961: a blind off-path guess must not kill the connection."""
    h.establish()
    # Past the window, derived rather than hardcoded: the window follows
    # rx_buffer, and a fixed offset silently lands *inside* it the moment the
    # buffer grows -- turning this into a test that the RST is accepted.
    beyond = h.tcb.config.rx_buffer + 10_000
    h.peer(seq=seq_add(PEER_ISN, beyond), ack=seq_add(ISN, 1), flags=Flag.RST)

    assert h.tcb.state is State.ESTABLISHED
    assert h.tcb.error is None


def test_a_retransmitted_syn_ack_is_answered_with_a_challenge_ack(h: Harness) -> None:
    """Found by the L3 suite under 2% loss, and invisible to every self-test.

    If our handshake ACK is dropped the peer keeps retransmitting its SYN-ACK.
    Nothing else in the state machine reacts to it -- a bare SYN carries no
    payload, so the delayed-ACK policy sees neither new data nor a duplicate --
    and the connection is established for us and not for the peer, until the
    peer gives up. RFC 5961 4.2 requires the reply that fixes it.
    """
    h.establish()
    h.peer(seq=PEER_ISN, ack=seq_add(ISN, 1), flags=Flag.SYN | Flag.ACK)

    reply = h.one()
    assert reply.flags & Flag.ACK
    assert not reply.flags & Flag.SYN
    assert reply.seq == seq_add(ISN, 1), "SEQ=SND.NXT, so the peer can validate it"
    assert reply.ack == seq_add(PEER_ISN, 1), "ACK=RCV.NXT, completing the handshake"
    assert h.tcb.state is State.ESTABLISHED


def test_a_challenge_ack_does_not_disturb_the_sequence_space(h: Harness) -> None:
    """It is a reply, not new data: consuming sequence space here would make
    every subsequent ACK look wrong to the peer."""
    h.establish()
    h.tcb.send(b"payload", h.now)
    h.sent()
    before = (h.tcb.snd_nxt, h.tcb.snd_una, h.tcb.snd_max, h.tcb.rcv_nxt)

    h.peer(seq=PEER_ISN, ack=seq_add(ISN, 1), flags=Flag.SYN | Flag.ACK)
    h.one()

    assert (h.tcb.snd_nxt, h.tcb.snd_una, h.tcb.snd_max, h.tcb.rcv_nxt) == before


def test_a_bare_syn_in_established_does_not_reset_us(h: Harness) -> None:
    """The other half of RFC 5961 4.2, and the reason it exists: a blind
    off-path SYN must cost the connection nothing."""
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 500_000), ack=0, flags=Flag.SYN)

    assert h.tcb.state is State.ESTABLISHED
    assert h.tcb.error is None
    assert h.one().flags & Flag.ACK


def test_abort_sends_a_reset(h: Harness) -> None:
    h.establish()
    h.tcb.abort(h.now, "user abort")

    assert h.one().flags & Flag.RST
    assert h.tcb.state is State.CLOSED


def test_an_abort_in_time_wait_is_reported_without_a_reset(h: Harness) -> None:
    """The connection already ended cleanly, so there is nothing to reset --
    but whoever holds the socket is still owed word that it is gone."""
    h.establish()
    h.tcb.close(h.now)
    h.sent()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 2), flags=Flag.FIN | Flag.ACK)
    h.sent()
    h.events()
    assert h.tcb.state is State.TIME_WAIT

    h.tcb.abort(h.now)

    assert h.sent() == []
    assert h.tcb.state is State.CLOSED
    assert h.event_names() == ["closed"]
    assert h.tcb.next_deadline() is None


# --- correctness of what goes on the wire ----------------------------------


def test_acknowledging_unsent_data_is_ignored(h: Harness) -> None:
    h.establish()
    before = h.tcb.snd_una
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 5000), flags=Flag.ACK)
    assert h.tcb.snd_una == before


def test_protocol_number_is_tcp() -> None:
    assert PROTO_TCP == 6


# --- window scaling --------------------------------------------------------


def test_the_smallest_sufficient_shift_is_chosen() -> None:
    """Every extra shift coarsens the window; take only what is needed."""
    assert initial_window_scale(64 * 1024) == 1
    assert initial_window_scale(65535) == 0
    assert initial_window_scale(256 * 1024) == 3
    assert initial_window_scale(1 << 40) == MAX_WINDOW_SCALE


def test_syn_offers_a_window_scale_matching_the_buffer(h: Harness) -> None:
    h = Harness(rx_buffer=256 * 1024)
    h.tcb.connect(h.now)
    syn = h.one()

    assert syn.window_scale == 3
    # The SYN's own window is unscaled, so it can say no more than 65535.
    assert syn.window == 0xFFFF


def test_scaling_is_only_used_if_the_peer_agrees(h: Harness) -> None:
    """RFC 7323: one side offering is not enough, and guessing would overrun."""
    h = Harness(rx_buffer=256 * 1024)
    h.establish(window_scale=None)

    assert h.tcb.rcv_wscale == 0
    assert h.tcb.snd_wscale == 0
    assert h.tcb.advertised_window == 0xFFFF  # capped, not scaled


def test_agreed_scaling_advertises_the_whole_buffer(h: Harness) -> None:
    h = Harness(rx_buffer=256 * 1024)
    h.establish(window_scale=0)

    assert h.tcb.rcv_wscale == 3
    assert h.tcb.advertised_window == 256 * 1024 >> 3
    assert h.tcb.advertised_window << h.tcb.rcv_wscale == 256 * 1024


def test_the_peers_window_is_scaled_by_its_shift(h: Harness) -> None:
    h.establish(window_scale=7, window=100)
    # The SYN-ACK's own window is unscaled...
    assert h.tcb.snd_wnd == 100

    # ...but everything after it is not.
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, window=1000)
    assert h.tcb.snd_wnd == 1000 << 7


def test_scaling_can_be_switched_off_entirely() -> None:
    h = Harness(window_scaling=False)
    h.tcb.connect(h.now)
    assert h.one().window_scale is None


def test_a_reordered_segment_cannot_reinstate_a_stale_window(h: Harness) -> None:
    """RFC 9293 3.10.7.4. Without the guard the connection stalls or overruns."""
    h.establish(window=1000)
    h.peer(seq=seq_add(PEER_ISN, 5), ack=seq_add(ISN, 1), flags=Flag.ACK, window=8000)
    assert h.tcb.snd_wnd == 8000

    # An older segment arriving late must not drag the window back down.
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, window=10)
    assert h.tcb.snd_wnd == 8000


# --- delayed ACK -----------------------------------------------------------


def test_a_single_segment_is_acked_on_the_timer(h: Harness) -> None:
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"one")

    assert h.sent() == []
    h.advance(h.tcb.config.delayed_ack_ms - 1)
    assert h.sent() == []
    h.advance(1)
    assert h.one().ack == seq_add(PEER_ISN, 4)


def test_the_second_segment_forces_an_immediate_ack(h: Harness) -> None:
    """RFC 5681: never leave more than two segments unacknowledged."""
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"one")
    h.sent()
    h.peer(seq=seq_add(PEER_ISN, 4), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"two")

    assert h.one().ack == seq_add(PEER_ISN, 7)
    # ...and the timer is spent, so nothing fires afterwards.
    h.let_ack_fire()
    assert h.sent() == []


def test_outbound_data_carries_the_delayed_ack(h: Harness) -> None:
    """A reply is an acknowledgement; sending a bare one too is pure waste."""
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"request")
    assert h.sent() == []

    h.tcb.send(b"response", h.now)
    reply = h.one()
    assert reply.payload == b"response"
    assert reply.ack == seq_add(PEER_ISN, 8)

    h.let_ack_fire()
    assert h.sent() == []


def test_an_out_of_order_segment_is_acked_at_once(h: Harness) -> None:
    """Duplicate ACKs only drive the peer's fast retransmit if they are prompt."""
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 100), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"gap")

    assert h.one().ack == seq_add(PEER_ISN, 1)


def test_a_fin_is_acked_at_once(h: Harness) -> None:
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.FIN | Flag.ACK)

    assert h.one().ack == seq_add(PEER_ISN, 2)


def test_a_filled_receive_buffer_is_acked_at_once() -> None:
    """The peer must learn the window shut before it sends into the void."""
    h = Harness(rx_buffer=100)
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"c" * 100)

    assert h.one().window == 0


# --- out-of-order reassembly -----------------------------------------------


def test_a_gap_is_filled_and_delivered_in_order(h: Harness) -> None:
    h.establish()
    base = seq_add(PEER_ISN, 1)
    h.peer(seq=seq_add(base, 5), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"world")
    h.sent()
    assert h.tcb.recv(100) == b""

    h.peer(seq=base, ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"hello")

    assert h.tcb.recv(100) == b"helloworld"
    assert h.one().ack == seq_add(base, 10)


def test_several_gaps_are_reassembled(h: Harness) -> None:
    h.establish()
    base = seq_add(PEER_ISN, 1)
    for offset in (9, 3, 6):
        h.peer(seq=seq_add(base, offset), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"xyz")
    h.sent()
    assert h.tcb.recv(100) == b""

    h.peer(seq=base, ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"abc")
    assert h.tcb.recv(100) == b"abcxyzxyzxyz"


def test_an_overlapping_retransmission_is_trimmed(h: Harness) -> None:
    """A peer that resends more than we are missing must not duplicate bytes."""
    h.establish()
    base = seq_add(PEER_ISN, 1)
    h.peer(seq=base, ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"abcdef")
    h.sent()

    h.peer(seq=base, ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"abcdefghi")
    assert h.tcb.recv(100) == b"abcdefghi"


def test_a_wholly_duplicate_segment_is_acked_but_not_delivered(h: Harness) -> None:
    h.establish()
    base = seq_add(PEER_ISN, 1)
    h.peer(seq=base, ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"once")
    h.let_ack_fire()
    h.sent()

    h.peer(seq=base, ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"once")

    assert h.tcb.recv(100) == b"once"
    # Immediately, not on the timer: it resent because it thinks we went quiet.
    assert h.one().ack == seq_add(base, 4)


def test_a_gap_does_not_shrink_the_advertised_window() -> None:
    """Held bytes sit inside ``[rcv_nxt, rcv_nxt + window)`` already, so
    charging for them again halves the window exactly when a hole opens --
    which is when it must stay open, because only continued sending produces
    the duplicate ACKs that trigger fast retransmit. Subtracting them cost a
    2 MiB transfer over 120 s under 2% loss, against 15 s without.
    """
    h = Harness(rx_buffer=1000)
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 501), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"h" * 400)

    assert h.one().window == 1000


def test_a_whole_window_of_out_of_order_segments_is_held() -> None:
    """The regression that mattered: at 64 segments the cap bound long before
    the byte bound, so after one loss we discarded ~190 KB that had arrived
    intact and demanded it again -- every window, indefinitely."""
    h = Harness()
    h.establish(peer_mss=1460)
    base = seq_add(PEER_ISN, 1)
    # Enough segments to fill whatever the configured window is, so this keeps
    # testing what it says when rx_buffer changes.
    segments = h.tcb.config.rx_buffer // 1460
    for index in range(1, segments + 1):  # segment 0 is the hole
        h.peer(
            seq=seq_add(base, index * 1460),
            ack=seq_add(ISN, 1),
            flags=Flag.ACK,
            payload=b"y" * 1460,
        )
    h.sent()

    assert h.tcb.ooo_dropped == 0, "in-window data that arrived intact was discarded"
    assert h.tcb._ooo_bytes > h.tcb.config.rx_buffer - 2 * 1460, "the window was not filled"


def test_the_segment_cap_stays_clear_of_the_byte_bound() -> None:
    """The cap is protection against a peer sending one byte at a time, not the
    memory bound. If it can bind first for legitimate traffic it is a stall."""
    config = TcbConfig()
    assert config.max_ooo_segments > config.rx_buffer // DEFAULT_MSS


def test_overlapping_segments_cannot_exceed_the_receive_buffer() -> None:
    """Sequence space does not bound memory on its own: overlapping segments
    add up faster than the range they cover, and the window arithmetic cannot
    see it. Hence an explicit byte bound in _hold."""
    h = Harness(rx_buffer=4000)
    h.establish()
    base = seq_add(PEER_ISN, 1)
    for index in range(1, 400):
        # Every segment overlaps its neighbours, so the bytes far exceed the
        # 4000-byte span they occupy.
        h.peer(
            seq=seq_add(base, index * 10),
            ack=seq_add(ISN, 1),
            flags=Flag.ACK,
            payload=b"z" * 500,
        )
    h.sent()

    assert len(h.tcb.recv_buffer) + h.tcb._ooo_bytes <= h.tcb.config.rx_buffer
    assert h.tcb.ooo_dropped > 0, "the bound never engaged, so nothing was proven"


def test_in_order_data_cannot_carry_overlapping_held_segments_past_the_buffer() -> None:
    """Two held segments overlapping by two bytes, then in-order data filling
    the window up to them. Each step fits on its own; the overlap, counted
    twice, is what would carry the total over. Found by the stateful suite."""
    h = Harness(rx_buffer=576)
    h.establish()
    base = seq_add(PEER_ISN, 1)
    for offset, length in ((574, 2), (482, 94), (0, 481)):
        h.peer(
            seq=seq_add(base, offset),
            ack=seq_add(ISN, 1),
            flags=Flag.ACK,
            payload=b"o" * length,
        )

    assert len(h.tcb.recv_buffer) == 481
    assert len(h.tcb.recv_buffer) + h.tcb._ooo_bytes <= h.tcb.config.rx_buffer


def test_upgrading_held_segments_cannot_exceed_the_receive_buffer() -> None:
    """A longer resend replaces a shorter copy in place, which grows the queue
    without appending to it -- so it has to be charged for like any other
    growth, or it is a way around the bound rather than an exception to it."""
    h = Harness(rx_buffer=2000)
    h.establish()
    base = seq_add(PEER_ISN, 1)
    # Stake out many small held segments, then resend each one much longer.
    for index in range(1, 40):
        h.peer(seq=seq_add(base, index * 50), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"s")
    for index in range(1, 40):
        h.peer(
            seq=seq_add(base, index * 50), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"L" * 50
        )
    h.sent()

    assert len(h.tcb.recv_buffer) + h.tcb._ooo_bytes <= h.tcb.config.rx_buffer


def test_the_reassembly_queue_is_bounded_by_segment_count_too() -> None:
    """Past the bound we fall back to retransmission rather than pin memory."""
    h = Harness(max_ooo_segments=4)
    h.establish()
    base = seq_add(PEER_ISN, 1)
    for index in range(1, 12):
        offset = index * 10
        h.peer(seq=seq_add(base, offset), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"y" * 10)
    h.sent()

    assert h.tcb._ooo_bytes == 40
    assert h.tcb.ooo_dropped == 7

    # The gap still fills, and only the segments we kept are delivered.
    h.peer(seq=base, ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"x" * 10)
    assert h.tcb.recv(1000) == b"x" * 10 + b"y" * 40


def test_a_fin_behind_a_gap_waits_for_the_gap(h: Harness) -> None:
    """Acting on the FIN early would silently truncate the stream."""
    h.establish()
    base = seq_add(PEER_ISN, 1)
    h.peer(seq=seq_add(base, 4), ack=seq_add(ISN, 1), flags=Flag.FIN | Flag.ACK, payload=b"tail")
    h.sent()

    assert h.tcb.state is State.ESTABLISHED
    assert not h.tcb.peer_fin_seen

    h.peer(seq=base, ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"head")

    assert h.tcb.state is State.CLOSE_WAIT
    assert h.tcb.recv(100) == b"headtail"
    assert h.one().ack == seq_add(base, 9)


# --- congestion control ----------------------------------------------------


def test_the_first_burst_is_limited_to_the_initial_window(h: Harness) -> None:
    """IW10 (RFC 6928): ten segments before the first ACK, and no more."""
    h.establish(peer_mss=536)
    assert h.tcb.cwnd == 10 * 536

    h.tcb.send(b"z" * 20_000, h.now)
    segments = h.sent()

    assert len(segments) == 10
    assert sum(len(s.payload) for s in segments) == 5360


def test_slow_start_opens_the_window_by_one_segment_per_ack(h: Harness) -> None:
    h.establish(peer_mss=536)
    h.tcb.send(b"z" * 20_000, h.now)
    h.sent()

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 537), flags=Flag.ACK)
    assert h.tcb.cwnd == 10 * 536 + 536


def test_congestion_avoidance_opens_it_by_one_segment_per_round_trip(h: Harness) -> None:
    h.establish(peer_mss=536)
    h.tcb.send(b"z" * 20_000, h.now)
    h.sent()
    # Past the threshold, growth becomes linear rather than exponential.
    h.tcb.ssthresh = 2000
    h.tcb.cwnd = 5360

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 537), flags=Flag.ACK)
    assert h.tcb.cwnd == 5360 + 536 * 536 // 5360


def test_three_duplicate_acks_retransmit_without_waiting_for_the_timer(h: Harness) -> None:
    """The whole point of fast retransmit: recovery in an RTT, not an RTO."""
    h = Harness(rto_initial_ms=100_000)
    h.establish(peer_mss=536)
    h.tcb.send(b"z" * 2144, h.now)
    first = h.sent()[0]

    for _ in range(3):
        h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK)

    resent = h.one()
    assert resent.seq == first.seq
    assert resent.payload == first.payload
    assert h.tcb.in_recovery


def test_two_duplicate_acks_are_not_enough(h: Harness) -> None:
    """Two can be plain reordering, and retransmitting on them would thrash."""
    h = Harness(rto_initial_ms=100_000)
    h.establish(peer_mss=536)
    h.tcb.send(b"z" * 2144, h.now)
    h.sent()

    for _ in range(2):
        h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK)

    assert h.sent() == []
    assert not h.tcb.in_recovery


def test_entering_recovery_halves_the_threshold(h: Harness) -> None:
    h = Harness(rto_initial_ms=100_000)
    h.establish(peer_mss=536)
    h.tcb.send(b"z" * 2144, h.now)
    h.sent()

    for _ in range(3):
        h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK)

    assert h.tcb.ssthresh == 2144 // 2
    assert h.tcb.cwnd == 2144 // 2 + 3 * 536  # inflated by what has left the net


def test_further_duplicates_inflate_the_window(h: Harness) -> None:
    h = Harness(rto_initial_ms=100_000)
    h.establish(peer_mss=536)
    h.tcb.send(b"z" * 2144, h.now)
    h.sent()

    for _ in range(3):
        h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK)
    inflated = h.tcb.cwnd
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK)

    assert h.tcb.cwnd == inflated + 536


def test_a_full_ack_ends_recovery_at_the_threshold(h: Harness) -> None:
    h = Harness(rto_initial_ms=100_000)
    h.establish(peer_mss=536)
    h.tcb.send(b"z" * 2144, h.now)
    h.sent()
    for _ in range(3):
        h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK)
    h.sent()

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 2145), flags=Flag.ACK)

    assert not h.tcb.in_recovery
    assert h.tcb.cwnd == h.tcb.ssthresh


def test_a_partial_ack_retransmits_the_next_hole_immediately(h: Harness) -> None:
    """NewReno's reason to exist: a second loss must not cost another RTO."""
    h = Harness(rto_initial_ms=100_000)
    h.establish(peer_mss=536)
    h.tcb.send(b"z" * 2144, h.now)
    sent = h.sent()
    for _ in range(3):
        h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK)
    h.sent()

    # Only the first hole was filled; the rest of the window is still missing.
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 537), flags=Flag.ACK)

    assert h.tcb.in_recovery
    assert h.one().seq == sent[1].seq


def test_a_timeout_collapses_the_window_to_one_segment(h: Harness) -> None:
    """RFC 5681: a timeout means the pipe drained, so start over."""
    h = Harness(rto_initial_ms=1000)
    h.establish(peer_mss=536)
    h.tcb.send(b"z" * 2144, h.now)
    h.sent()

    h.advance(1000)

    assert h.tcb.cwnd == 536
    assert h.tcb.ssthresh == 2144 // 2
    assert not h.tcb.in_recovery


def test_a_timeout_resumes_the_window_rather_than_one_segment_per_rto() -> None:
    """The bug this guards against still completes transfers -- eventually.

    Retransmitting only the leftmost segment and then waiting for the next
    timeout costs a full RTO per segment, so a lossy 30 KB request takes
    minutes instead of milliseconds. Recovery has to resume from the left edge
    and then keep going as slow start reopens the window.
    """
    h = Harness(rto_initial_ms=1000, rto_min_ms=1)
    h.establish(peer_mss=536, rtt_ms=10)
    h.tcb.send(b"z" * 5360, h.now)  # ten segments, all of which go missing
    h.sent()

    h.advance(1000)
    assert len(h.sent()) == 1  # collapsed to one segment, as RFC 5681 requires

    # The acknowledgement of that one segment must put the next ones on the
    # wire immediately, without waiting out another timeout.
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 537), flags=Flag.ACK)
    assert len(h.sent()) == 2

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1609), flags=Flag.ACK)
    assert len(h.sent()) == 3


def test_an_ack_for_data_sent_before_a_timeout_is_still_accepted() -> None:
    """A timeout rewinds snd_nxt, so validating an ACK against it would throw
    away a perfectly good delayed acknowledgement and stall the transfer."""
    h = Harness(rto_initial_ms=1000)
    h.establish(peer_mss=536)
    h.tcb.send(b"z" * 2144, h.now)
    h.sent()

    h.advance(1000)
    h.sent()
    assert h.tcb.snd_nxt == seq_add(ISN, 537)  # rewound to one segment out

    # The original burst did arrive after all; its acknowledgement was slow.
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 2145), flags=Flag.ACK)

    assert h.tcb.snd_una == seq_add(ISN, 2145)
    assert h.tcb.state is State.ESTABLISHED
    assert h.tcb.unsent == 0
    # And snd_nxt moves with it, rather than walking up to it by resending
    # what was just acknowledged.
    assert h.tcb.snd_nxt == h.tcb.snd_una
    assert h.sent() == []
    assert h.tcb.next_deadline() is None


def test_an_unacknowledged_fin_is_retransmitted() -> None:
    """A lost FIN otherwise leaves both sides waiting on each other forever."""
    h = Harness(rto_initial_ms=1000)
    h.establish()
    h.tcb.close(h.now)
    first = h.one()
    assert first.flags & Flag.FIN

    h.advance(1000)
    again = h.one()

    assert again.flags & Flag.FIN
    assert again.seq == first.seq


def test_data_and_fin_are_both_replayed_after_a_timeout() -> None:
    h = Harness(rto_initial_ms=1000)
    h.establish(peer_mss=536)
    h.tcb.send(b"z" * 400, h.now)
    h.tcb.close(h.now)
    first = h.sent()
    assert [s.flags & Flag.FIN == Flag.FIN for s in first] == [False, True]

    h.advance(1000)
    replayed = h.sent()

    # The 400 bytes fit in the one segment the collapsed window allows, so the
    # FIN follows them in the same pass, exactly as it did the first time.
    assert [s.seq for s in replayed] == [s.seq for s in first]
    assert replayed[0].payload == b"z" * 400
    assert replayed[1].flags & Flag.FIN


def test_a_window_full_of_data_does_not_trigger_fast_retransmit(h: Harness) -> None:
    """An ACK that advances, or carries data, is not a duplicate."""
    h = Harness(rto_initial_ms=100_000)
    h.establish(peer_mss=536)
    h.tcb.send(b"z" * 2144, h.now)
    h.sent()

    for index in range(3):
        h.peer(
            seq=seq_add(PEER_ISN, 1 + index),
            ack=seq_add(ISN, 1),
            flags=Flag.ACK,
            payload=b"d",
        )

    assert not h.tcb.in_recovery
    assert h.tcb.dup_acks == 0


# --- zero window and persist ------------------------------------------------


def test_a_closed_window_starts_the_persist_timer() -> None:
    h = Harness(rto_min_ms=250)
    h.establish(window=0)
    h.tcb.send(b"blocked", h.now)

    assert h.sent() == []
    assert h.tcb.persist_deadline == 250


def test_the_persist_probe_sends_one_byte() -> None:
    h = Harness(rto_min_ms=250)
    h.establish(window=0)
    h.tcb.send(b"blocked", h.now)
    h.sent()

    h.advance(250)
    probe = h.one()

    assert probe.payload == b"b"
    assert probe.seq == seq_add(ISN, 1)


def test_the_probe_repeats_the_same_byte_with_backoff() -> None:
    """A byte sent past a closed window is discarded, so a fresh one would be
    stranded; the probe has to keep offering the same one."""
    h = Harness(rto_min_ms=250)
    h.establish(window=0)
    h.tcb.send(b"blocked", h.now)
    h.sent()

    h.advance(250)
    assert h.one().payload == b"b"
    h.advance(499)
    assert h.sent() == []
    h.advance(1)
    assert h.one().payload == b"b"


def test_a_probe_carrying_the_last_byte_stays_covered_by_a_timer() -> None:
    """The peer answers the probe with its window still shut. Nothing is
    unsent any more -- the byte is in flight -- but it has not been accepted,
    so something must keep offering it."""
    h = Harness(rto_min_ms=250)
    h.establish(window=0)
    h.tcb.send(b"k", h.now)
    h.advance(250)
    assert h.one().payload == b"k"

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, window=0)
    assert h.tcb.next_deadline() is not None, "nothing will ever resend the byte"

    resent = []
    for _ in range(3):
        deadline = h.tcb.next_deadline()
        assert deadline is not None
        h.advance(deadline - h.now)
        resent += [s.payload for s in h.sent()]
    assert b"k" in resent


def test_data_queued_before_close_is_probed_for_in_closing() -> None:
    """Both sides have closed; our last byte and FIN were sent but the byte
    was lost, and the peer's window has shut. The application can no longer
    write, yet that byte still has to go out, so persist must cover it.
    Found by the stateful suite at nightly depth."""
    h = Harness(rto_min_ms=250)
    h.establish(window=0)
    h.tcb.send(b"ab", h.now)
    h.tcb.close(h.now)
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, window=2)
    assert any(s.has(Flag.FIN) for s in h.sent())  # b"ab" and the FIN went out

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.FIN | Flag.ACK, window=0)
    assert h.tcb.state is State.CLOSING
    h.advance(250)  # the RTO rewinds, but the window is shut
    h.sent()
    h.peer(seq=seq_add(PEER_ISN, 2), ack=seq_add(ISN, 2), flags=Flag.ACK, window=0)

    assert h.tcb.unsent == 1
    assert h.tcb.next_deadline() is not None, "nothing will ever send the last byte"
    resent = []
    for _ in range(3):
        deadline = h.tcb.next_deadline()
        assert deadline is not None
        h.advance(deadline - h.now)
        resent += [s.payload for s in h.sent()]
    assert b"b" in resent


def test_a_reopened_window_cancels_persist_and_resends() -> None:
    h = Harness(rto_min_ms=250)
    h.establish(window=0)
    h.tcb.send(b"blocked", h.now)
    h.advance(250)
    h.sent()

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, window=1000)

    assert h.tcb.persist_deadline is None
    # The probe byte was dropped by the peer, so it leads the rest of the data.
    assert b"".join(s.payload for s in h.sent()) == b"blocked"


def test_a_peer_that_never_answers_probes_eventually_fails() -> None:
    """A connection hung with no error is worse than one that reports why."""
    h = Harness(rto_min_ms=250, max_retransmits=3)
    h.establish(window=0)
    h.tcb.send(b"blocked", h.now)
    h.sent()

    probes = 0
    while h.tcb.persist_deadline is not None:
        h.advance(h.tcb.persist_deadline - h.now)
        probes += len(h.sent())

    assert probes == 3  # max_retransmits, then it gives up
    assert h.tcb.state is State.CLOSED
    assert isinstance(h.tcb.error, ConnectionTimeout)


def test_a_peer_that_answers_probes_keeps_the_connection() -> None:
    """RFC 1122 4.2.2.17: the window may stay shut for as long as the peer
    likes, and a peer answering every probe is still there. Only silence
    spends the budget."""
    h = Harness(rto_min_ms=250, max_retransmits=3)
    h.establish(window=0)
    h.tcb.send(b"blocked", h.now)
    h.sent()

    for probe in range(1, 11):
        deadline = h.tcb.persist_deadline
        assert deadline is not None, f"stopped probing after {probe - 1} probes"
        h.advance(deadline - h.now)
        assert h.one().payload == b"b"
        h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, window=0)
        h.sent()

    assert h.tcb.state is State.ESTABLISHED
    assert h.tcb.error is None


def test_reading_reopens_a_closed_window_immediately() -> None:
    """A peer in persist would otherwise wait out a whole probe interval."""
    h = Harness(rx_buffer=100)
    h.establish()
    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 1), flags=Flag.ACK, payload=b"c" * 100)
    assert h.one().window == 0

    h.tcb.recv(100, h.now)

    assert h.one().window == 100


# --- transmit accounting ----------------------------------------------------


def test_unacknowledged_bytes_count_against_the_transmit_buffer() -> None:
    """They are still held for retransmission, so ignoring them bounds nothing."""
    h = Harness(tx_buffer=1000)
    h.establish(peer_mss=536)

    assert h.tcb.send(b"z" * 1000, h.now) == 1000
    h.sent()
    assert h.tcb.tx_space == 0  # all of it is in flight, none of it is free
    assert h.tcb.send(b"more", h.now) == 0


def test_acknowledgement_reports_the_socket_writable_again() -> None:
    h = Harness(tx_buffer=1000)
    h.establish(peer_mss=536)
    h.tcb.send(b"z" * 1200, h.now)
    h.sent()
    h.events()

    h.peer(seq=seq_add(PEER_ISN, 1), ack=seq_add(ISN, 601), flags=Flag.ACK)

    assert "writable" in h.event_names()
    assert h.tcb.tx_space == 600


# --- ephemeral ports --------------------------------------------------------


def test_two_stacks_do_not_open_on_the_same_ephemeral_port() -> None:
    """A stack that always starts at 49152 collides with its own previous
    process. Run something short-lived twice -- an ssh ProxyCommand is the
    obvious case -- and the second run's SYN lands on a four-tuple the peer
    still has open, which it answers with a bare ACK carrying the *old*
    connection's sequence numbers rather than a SYN-ACK. The connect then times
    out with the wire full of traffic and nothing anywhere to say why.
    """
    from usernet.net.stack import EPHEMERAL_HIGH, EPHEMERAL_LOW, PyStack, StackConfig

    seeds = iter(range(1, 200))
    ports = set()
    for _ in range(16):
        seed = next(seeds) * 7919  # anything that is not a run of consecutives
        stack = PyStack(StackConfig(local_ip="100.64.0.1", rng=lambda seed=seed: seed))  # type: ignore[misc]
        sid = stack.tcp_connect(("100.64.0.2", 22))
        ports.add(stack._tcbs[sid].local_port)

    assert len(ports) > 8, f"only {len(ports)} distinct ports from 16 stacks"
    assert all(EPHEMERAL_LOW <= port <= EPHEMERAL_HIGH for port in ports)


def test_a_pinned_rng_still_gives_a_reproducible_port() -> None:
    """The randomness is injected, so a failing run reproduces exactly."""
    from usernet.net.stack import PyStack, StackConfig

    def first_port() -> int:
        stack = PyStack(StackConfig(local_ip="100.64.0.1", rng=lambda: 12345))
        sid = stack.tcp_connect(("100.64.0.2", 22))
        return stack._tcbs[sid].local_port

    assert first_port() == first_port()
