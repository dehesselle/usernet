"""Small asyncio helpers shared across layers.

Lives at the top level because both ``cstp`` and ``runtime`` need it, and
having the lower layer import from the higher one to get it would invert the
dependency the whole design rests on.
"""

from __future__ import annotations

import asyncio


async def first_of(*events: asyncio.Event, seconds: float | None = None) -> None:
    """Wait until any of ``events`` is set, cancelling the rest."""
    waiters = [asyncio.ensure_future(event.wait()) for event in events]
    try:
        await asyncio.wait(waiters, timeout=seconds, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for waiter in waiters:
            waiter.cancel()
