"""The shared asyncio helpers."""

from __future__ import annotations

import asyncio

from usernet.aio import first_of


async def test_first_of_returns_when_any_event_is_set() -> None:
    a, b = asyncio.Event(), asyncio.Event()
    asyncio.get_running_loop().call_later(0.01, b.set)
    await asyncio.wait_for(first_of(a, b), 1)
    assert b.is_set() and not a.is_set()


async def test_first_of_times_out_quietly() -> None:
    await first_of(asyncio.Event(), seconds=0.01)


async def test_first_of_creates_no_tasks_for_an_event_already_set() -> None:
    """The driver's hot path: under load its wake event is nearly always set
    already, and three waiter tasks per pass were pure overhead."""
    event = asyncio.Event()
    event.set()
    before = len(asyncio.all_tasks())
    created = []
    loop = asyncio.get_running_loop()
    factory = loop.get_task_factory()
    loop.set_task_factory(
        lambda lp, coro, **kw: created.append(coro) or asyncio.Task(coro, loop=lp, **kw)
    )
    try:
        await first_of(event, asyncio.Event())
    finally:
        loop.set_task_factory(factory)
    assert not created
    assert len(asyncio.all_tasks()) == before


async def test_first_of_still_yields_when_an_event_is_already_set() -> None:
    """Otherwise a loop over an always-set event would starve every other
    task on the loop."""
    event = asyncio.Event()
    event.set()
    ran = False

    async def other() -> None:
        nonlocal ran
        ran = True

    task = asyncio.create_task(other())
    await first_of(event)
    assert ran
    await task
