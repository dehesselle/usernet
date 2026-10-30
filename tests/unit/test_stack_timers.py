# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The stack's timer heap, checked against the scan it replaced.

``poll_at`` used to take the minimum of every TCB's ``next_deadline`` and
``poll`` used to tick every TCB. The heap must be indistinguishable from
that: the same next deadline after any sequence of operations, and nothing
due left unfired after a poll. The scan survives here as the oracle.
"""

from __future__ import annotations

import random

from usernet.net.events import SocketId
from usernet.net.ipv4 import PROTO_TCP, build_ipv4
from usernet.net.stack import PyStack, StackConfig
from usernet.net.tcb import State, Tcb
from usernet.net.tcp import Flag, build_tcp, seq_add

LOCAL_IP = "10.0.0.2"
REMOTE_IP = "10.0.0.1"
PEER_ISN = 5000


def scan(stack: PyStack) -> int | None:
    deadlines = [d for tcb in stack._tcbs.values() if (d := tcb.next_deadline()) is not None]
    return min(deadlines) if deadlines else None


def from_peer(tcb: Tcb, flags: int, seq: int, ack: int, payload: bytes = b"") -> bytes:
    segment = build_tcp(
        source_ip=REMOTE_IP,
        destination_ip=LOCAL_IP,
        source_port=tcb.remote_port,
        destination_port=tcb.local_port,
        seq=seq,
        ack=ack,
        flags=flags,
        window=0xFFFF,
        payload=payload,
        mss=1300 if flags & Flag.SYN else None,
    )
    return build_ipv4(source=REMOTE_IP, destination=LOCAL_IP, protocol=PROTO_TCP, payload=segment)


def test_the_heap_agrees_with_a_full_scan() -> None:
    """Random traffic across hundreds of sockets in every common state.

    Deadlines have to move in both directions *outside* ``poll`` as well as
    inside it: data sent restarts the retransmission timer, an ACK for
    everything clears it, data received arms the delayed ACK. A heap that
    only noticed deadlines set by ``poll`` itself would pass a test made of
    connects and timeouts alone.
    """
    rng = random.Random(1071)
    config = StackConfig(local_ip=LOCAL_IP, max_sockets=500, rng=lambda: rng.getrandbits(32))
    stack = PyStack(config)
    sids: list[SocketId] = []
    now = 0

    def pick(*states: State) -> tuple[SocketId, Tcb] | None:
        candidates = [(s, t) for s in sids if (t := stack._tcbs.get(s)) and t.state in states]
        return rng.choice(candidates) if candidates else None

    for _ in range(5000):
        action = rng.random()
        if action < 0.15 and len(stack._tcbs) < 500:
            sid = stack.tcp_connect((REMOTE_IP, rng.randrange(1, 65536)))
            stack.start_connect(sid, now)
            sids.append(sid)
        elif action < 0.3 and (chosen := pick(State.SYN_SENT)):
            sid, tcb = chosen
            synack = from_peer(tcb, Flag.SYN | Flag.ACK, PEER_ISN, seq_add(tcb.isn, 1))
            stack.handle_input(synack, now)
        elif action < 0.45 and (chosen := pick(State.ESTABLISHED)):
            stack.tcp_send(chosen[0], memoryview(b"x" * rng.randrange(1, 3000)), now)
        elif action < 0.55 and (chosen := pick(State.ESTABLISHED, State.FIN_WAIT_1)):
            _, tcb = chosen
            stack.handle_input(from_peer(tcb, Flag.ACK, tcb.rcv_nxt, tcb.snd_nxt), now)
        elif action < 0.65 and (chosen := pick(State.ESTABLISHED)):
            _, tcb = chosen
            data = from_peer(tcb, Flag.ACK | Flag.PSH, tcb.rcv_nxt, tcb.snd_una, b"y" * 100)
            stack.handle_input(data, now)
        elif action < 0.7 and (chosen := pick(State.SYN_SENT, State.ESTABLISHED)):
            stack.tcp_abort(chosen[0], now)
        elif action < 0.75 and (chosen := pick(State.ESTABLISHED)):
            stack.tcp_close(chosen[0], now)
        else:
            # Mostly small steps, now and then a jump past the connect and
            # retransmission limits, so sockets fail and leave the table.
            if rng.random() < 0.05:
                now += rng.choice([1, 10, 100, 1000, 20_000])
            else:
                now += rng.randrange(60)
            stack.poll(now)
            for tcb in stack._tcbs.values():
                deadline = tcb.next_deadline()
                assert deadline is None or deadline > now, "a due timer was not fired"

        stack.take_output()
        stack.take_events()
        assert stack.poll_at() == scan(stack)


def test_the_heap_stays_bounded_while_a_deadline_keeps_moving() -> None:
    """A deadline pushed later on every call leaves a stale entry each time
    -- the RTO, restarted by every ACK, does exactly this. The rebuild has to
    keep those from accumulating."""
    stack = PyStack(StackConfig(local_ip=LOCAL_IP))
    sid = stack.tcp_connect((REMOTE_IP, 80))
    stack.start_connect(sid, 0)
    tcb = stack._tcbs[sid]
    tcb.connect_deadline = None

    for now in range(1, 10_000):
        tcb.retransmit_deadline = now + 1000  # as if each call restarted it
        stack.tcp_send(sid, memoryview(b""), now)  # any call that harvests
        assert stack.poll_at() == now + 1000

    assert len(stack._timers) <= 4 * len(stack._deadlines) + 64
