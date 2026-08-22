"""An in-memory :class:`~usernet.link.IpLink` carrying IP packets to a peer.

Stands in for the CSTP tunnel, so the stack and driver can be exercised with
no TLS, no gateway, and no network -- while still going through exactly the
same interface the real tunnel presents.
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
from collections.abc import Callable

from usernet.errors import ProtocolParseError
from usernet.link import SimpleLinkConfig
from usernet.testing.peer import TcpPeer


class VirtualLink:
    """Connects a driver to a :class:`TcpPeer`.

    Loss, duplication, and reordering are seeded so a failing run reproduces
    exactly; anything else would make an intermittent bug impossible to chase.
    """

    def __init__(
        self,
        peer: TcpPeer,
        *,
        address: str = "172.29.29.5",
        mtu: int = 1383,
        loss: float = 0.0,
        duplicate: float = 0.0,
        reorder: float = 0.0,
        seed: int = 0,
        on_send: Callable[[bytes], None] | None = None,
        split_include: tuple[str, ...] = (),
        split_exclude: tuple[str, ...] = (),
    ) -> None:
        self.peer = peer
        # Taken as CIDR strings rather than IPv4Network objects: a test reads
        # better with "10.0.0.0/8" in it, and this is the only place in the
        # package where the conversion has to happen anyway.
        self._config = SimpleLinkConfig(
            address=address,
            netmask="255.255.0.0",
            mtu=mtu,
            split_include=tuple(ipaddress.IPv4Network(n) for n in split_include),
            split_exclude=tuple(ipaddress.IPv4Network(n) for n in split_exclude),
        )
        self._inbound: list[bytes] = []
        self._wake = asyncio.Event()
        self._closed = asyncio.Event()
        self._close_reason = ""

        self.loss = loss
        self.duplicate = duplicate
        self.reorder = reorder
        self._random = random.Random(seed)
        self._on_send = on_send
        self._held: bytes | None = None

        self.sent_count = 0
        self.dropped_count = 0
        self.reordered_count = 0

    # --- IpLink ------------------------------------------------------------

    @property
    def config(self) -> SimpleLinkConfig:
        return self._config

    @property
    def wake(self) -> asyncio.Event:
        return self._wake

    @property
    def closed(self) -> asyncio.Event:
        return self._closed

    @property
    def close_reason(self) -> str:
        return self._close_reason

    def send(self, packet: bytes) -> None:
        self.sent_count += 1
        if self._on_send is not None:
            self._on_send(packet)

        # Loss is applied to the client -> peer direction only. The fixture
        # peer has no retransmission timer, so dropping *its* replies would
        # stall forever -- a limitation of the harness, not of the stack. This
        # still exercises our own retransmission, which is the point.
        if self.loss and self._random.random() < self.loss:
            self.dropped_count += 1
            return

        self._deliver(packet)
        if self.duplicate and self._random.random() < self.duplicate:
            self._deliver(packet)

    def _deliver(self, packet: bytes) -> None:
        try:
            replies = self.peer.handle(packet)
        except ProtocolParseError:
            return  # a corrupt packet is dropped, exactly as a real peer would

        for reply in replies:
            self._arrive(reply)
        if self._inbound or self._held is not None:
            self._wake.set()

    def _arrive(self, packet: bytes) -> None:
        """Queue one inbound packet, optionally letting a later one overtake it.

        Reordering is applied on the peer -> client direction because that is
        the one that reaches the stack's reassembly queue. Holding a single
        packet back is enough: it produces a real gap followed by a real fill,
        which is the case that either reassembles or costs an RTO.
        """
        if self.reorder and self._held is None and self._random.random() < self.reorder:
            self._held = packet
            self.reordered_count += 1
            return

        self._inbound.append(packet)
        if self._held is not None:
            self._inbound.append(self._held)
            self._held = None

    def take_inbound(self) -> list[bytes]:
        packets = self._inbound
        if self._held is not None:
            # Release it rather than carry it: a packet held forever is loss,
            # and loss in this direction stalls a peer that cannot retransmit.
            packets.append(self._held)
            self._held = None
        self._inbound = []
        self._wake.clear()
        return packets

    async def aclose(self) -> None:
        self.close("closed by test")

    def close(self, reason: str) -> None:
        self._close_reason = reason
        self._closed.set()
        self._wake.set()
