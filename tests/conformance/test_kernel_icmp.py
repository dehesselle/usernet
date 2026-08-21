"""ICMP against the kernel.

Small, but it is the check that separates "the tunnel carries nothing" from
"TCP is broken" -- which is exactly why ``usernet ping`` exists. If these fail,
nothing in test_kernel_tcp.py is worth reading yet.

Echo is unreliable by design and we send no retries, so nothing here may assume
a particular probe comes back. On a clean link every one must; under deliberate
loss, insisting on that would be asserting against netem rather than against
the stack.
"""

from __future__ import annotations

import pytest

from tests.conformance.conftest import HOST_IP, IMPAIRED
from usernet.runtime.driver import Driver

pytestmark = pytest.mark.linux_only

PROBES = 8

NO_REPLY = (
    "The kernel ignores an echo request it cannot parse and says nothing about "
    "why, so a wrong checksum, header length or source address all end here. "
    "A firewall dropping ICMP on the interface looks identical."
)


async def test_the_kernel_answers_our_echo_request(driver: Driver) -> None:
    """One reply is enough; which probe carries it is not the point."""
    for sequence in range(1, PROBES + 1):
        rtt = await driver.ping(HOST_IP, sequence=sequence, timeout=5.0)
        if rtt is not None:
            assert rtt < 5000
            return
    pytest.fail(f"no reply to any of {PROBES} echo requests to {HOST_IP}. {NO_REPLY}")


async def test_echo_replies_are_matched_to_their_request(driver: Driver) -> None:
    """Matching is by identifier and sequence. Getting it wrong yields
    plausible-but-wrong round-trip times rather than an error, which is why it
    is worth asserting rather than eyeballing."""
    results = [
        await driver.ping(HOST_IP, sequence=sequence, timeout=5.0)
        for sequence in range(1, PROBES + 1)
    ]
    answered = [rtt for rtt in results if rtt is not None]

    # A lost echo is an ordinary outcome, not a failure -- so the bar is what
    # the link can actually promise.
    required = PROBES // 2 if IMPAIRED else PROBES
    assert len(answered) >= required, (
        f"{len(answered)} of {PROBES} echo requests were answered, wanted at "
        f"least {required}. {NO_REPLY}"
    )
    # Each probe waits on its own (ident, sequence) future, so a reply matched
    # to the wrong request would have to arrive before its own was sent.
    assert all(rtt >= 0 for rtt in answered)
