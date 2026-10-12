"""One call per key at a time: callers that arrive meanwhile share its result or failure."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Hashable


async def single_flight[T](
    pending: dict[Hashable, asyncio.Future[T]],
    key: Hashable,
    start: Callable[[], Awaitable[T]],
) -> T:
    """`start()` once for every caller of `key` until it ends; then it is forgotten,
    so a failure is shared by the waiting callers and the next caller tries again."""
    flight = pending.get(key)
    if flight is None:
        flight = pending[key] = asyncio.ensure_future(start())
        flight.add_done_callback(lambda _: pending.pop(key, None))
    # A caller that stops waiting never cancels the call the others wait for.
    return await asyncio.shield(flight)
