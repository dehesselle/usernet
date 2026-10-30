# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Path-MTU discovery, with the kernel as the router that says no.

pmtu.sh puts a narrow hop between the kernel and a far namespace. Our first
full-sized segments cannot cross it, the kernel answers with "fragmentation
needed", and everything after must fit -- or the upload hangs, which is how a
path-MTU bug looks in real life: a handshake that works and a transfer that
never finishes.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from tests.conformance.conftest import within
from tests.conformance.test_kernel_tcp import payload
from tests.conformance.trace import PacketTrace
from usernet.net import icmp
from usernet.net.ipv4 import PROTO_ICMP, parse_ipv4
from usernet.runtime.driver import Driver

FAR_IP = "10.98.0.2"
FAR_PORT = 9000
HOP_MTU = int(os.environ.get("USERNET_PMTU_HOP", "1000"))

pytestmark = [
    pytest.mark.linux_only,
    pytest.mark.skipif(
        not Path("/run/netns/usernet-far").exists(),
        reason="no far namespace: run 'sudo sh tests/conformance/pmtu.sh' first",
    ),
]


@pytest.mark.timeout(120)
async def test_a_narrow_hop_is_discovered_and_the_upload_completes(
    driver: Driver, trace: PacketTrace
) -> None:
    # Small enough that the ICMP is still in the trace afterwards -- it keeps
    # its last few hundred packets -- and well past the initial window.
    body = payload(32 * 1024)

    stream = await within(10, f"the handshake with {FAR_IP}", driver.connect(FAR_IP, FAR_PORT))
    await within(60, "the upload", stream.write(body))
    stream.close()
    reply = await within(30, "the far end's report", stream.read_all())

    assert reply == f"{len(body)} {hashlib.sha256(body).hexdigest()}\n".encode()

    # It worked because we listened, not by luck: the kernel did object, and
    # nothing we sent afterwards was too big for the hop.
    objected_at = None
    for index, (outbound, packet) in enumerate(trace.packets):
        if packet[0] >> 4 != 4:
            continue  # the kernel's own IPv6 chatter on the device
        header, message = parse_ipv4(packet)
        if outbound or header.protocol != PROTO_ICMP:
            continue
        parsed = icmp.parse_icmp(message)
        if parsed.next_hop_mtu is not None:
            assert parsed.next_hop_mtu == HOP_MTU
            objected_at = index
            break
    assert objected_at is not None, (
        "no fragmentation-needed arrived, so nothing was proven: "
        f"is the hop narrower than the tun device's MTU of {driver.link.config.mtu}?"
    )
    # The digest already proves every byte crossed the hop. Segments built in
    # the same driver pass as the ICMP was read may still be recorded after it,
    # so what is checked is that the clamp held, not where it began.
    later = [len(packet) for outbound, packet in list(trace.packets)[objected_at:] if outbound]
    assert later, "nothing was sent after the kernel objected"
    assert max(later[-10:]) <= HOP_MTU, f"still sending {max(later[-10:])}-byte packets"
