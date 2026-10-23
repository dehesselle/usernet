"""Small asyncio helpers shared across layers.

Lives at the top level rather than in ``runtime`` because a tunnel's link
implementation may need it too, and a link importing from the layer that
drives it would invert the dependency the whole design rests on.
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
