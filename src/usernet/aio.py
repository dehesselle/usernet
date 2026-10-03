"""Small asyncio helpers shared across layers.

Lives at the top level because both ``cstp`` and ``runtime`` need it, and
having the lower layer import from the higher one to get it would invert the
dependency the whole design rests on.
"""

from __future__ import annotations

import asyncio


async def first_of(*events: asyncio.Event, seconds: float | None = None) -> None:
    """Wait until any of ``events`` is set, cancelling the rest."""
    if any(event.is_set() for event in events):
        # Nothing to wait for, so skip the waiter tasks: three of them, and two
        # extra loop iterations before asyncio.wait notices, on every driver
        # pass under load. Still yield once, so that a caller looping on an
        # event that is always set cannot starve the rest of the loop.
        await asyncio.sleep(0)
        return
    waiters = [asyncio.ensure_future(event.wait()) for event in events]
    try:
        await asyncio.wait(waiters, timeout=seconds, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for waiter in waiters:
            waiter.cancel()
