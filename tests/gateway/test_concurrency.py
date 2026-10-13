from __future__ import annotations

import asyncio

import pytest

from shim.gateway.concurrency import (
    ConcurrencyRefused,
    ConcurrencyTarget,
    InMemoryConcurrencyLimiter,
)

_TARGET = ConcurrencyTarget("tenant", "openai", None, None)


def _limiter(limit: int | None = 1_000) -> InMemoryConcurrencyLimiter:
    return InMemoryConcurrencyLimiter(lambda _target: limit)


@pytest.mark.asyncio
async def test_work_within_the_limit_is_admitted_at_once() -> None:
    limiter = _limiter()

    first = await limiter.acquire(_TARGET, 600, "normal", 0)
    second = await limiter.acquire(_TARGET, 400, "normal", 0)

    assert (first.waited_ms, second.waited_ms) == (0, 0)
    with pytest.raises(ConcurrencyRefused) as refused:
        await limiter.acquire(_TARGET, 1, "normal", 0)
    assert (refused.value.retry_after_seconds, refused.value.never_fits) == (5, False)


@pytest.mark.asyncio
async def test_a_waiter_is_admitted_when_room_is_released() -> None:
    limiter = _limiter()
    held = await limiter.acquire(_TARGET, 900, "normal", 0)

    waiting = asyncio.create_task(limiter.acquire(_TARGET, 500, "normal", 5_000))
    await asyncio.sleep(0.05)
    assert not waiting.done()
    await held.release()
    lease = await asyncio.wait_for(waiting, 1)

    assert lease.waited_ms > 0


@pytest.mark.asyncio
async def test_a_waiter_is_refused_after_its_wait() -> None:
    limiter = _limiter()
    await limiter.acquire(_TARGET, 900, "normal", 0)

    with pytest.raises(ConcurrencyRefused):
        await limiter.acquire(_TARGET, 500, "normal", 50)


@pytest.mark.asyncio
async def test_waiters_are_admitted_in_arrival_order() -> None:
    limiter = _limiter()
    held = await limiter.acquire(_TARGET, 1_000, "normal", 0)
    admitted: list[str] = []

    async def wait(name: str, tokens: int):
        lease = await limiter.acquire(_TARGET, tokens, "normal", 5_000)
        admitted.append(name)
        return lease

    big = asyncio.create_task(wait("big", 900))
    await asyncio.sleep(0.01)
    small = asyncio.create_task(wait("small", 50))
    await asyncio.sleep(0.05)
    assert admitted == []
    await held.release()
    await asyncio.wait_for(asyncio.gather(big, small), 1)

    assert admitted == ["big", "small"]


@pytest.mark.asyncio
async def test_a_release_wakes_only_the_waiters_of_its_target(monkeypatch) -> None:
    limiter = _limiter()
    other = ConcurrencyTarget("tenant", "openai", "https://b.test", "b")
    held = await limiter.acquire(_TARGET, 900, "normal", 0)
    await limiter.acquire(other, 900, "normal", 0)
    checked: list[ConcurrencyTarget] = []
    fits = limiter._fits

    def counted(target, tokens, limit):
        checked.append(target)
        return fits(target, tokens, limit)

    monkeypatch.setattr(limiter, "_fits", counted)
    waiting = asyncio.create_task(limiter.acquire(other, 500, "normal", 5_000))
    await asyncio.sleep(0.05)
    checked.clear()

    await held.release()
    await asyncio.sleep(0.05)

    assert checked == [] and not waiting.done()
    waiting.cancel()


@pytest.mark.asyncio
async def test_an_oversized_request_runs_only_on_an_idle_target() -> None:
    limiter = _limiter()

    alone = await limiter.acquire(_TARGET, 5_000, "normal", 0)
    with pytest.raises(ConcurrencyRefused):
        await limiter.acquire(_TARGET, 5_000, "normal", 0)
    await alone.release()

    assert (await limiter.acquire(_TARGET, 5_000, "normal", 0)).waited_ms == 0


@pytest.mark.asyncio
async def test_low_priority_never_waits() -> None:
    limiter = _limiter()
    await limiter.acquire(_TARGET, 900, "normal", 0)

    with pytest.raises(ConcurrencyRefused):
        await asyncio.wait_for(limiter.acquire(_TARGET, 500, "low", 5_000), 0.5)


@pytest.mark.asyncio
async def test_release_is_idempotent_and_frees_the_target() -> None:
    limiter = _limiter()
    lease = await limiter.acquire(_TARGET, 900, "normal", 0)

    await lease.release()
    await lease.release()

    assert limiter._used == {}
    assert (await limiter.acquire(_TARGET, 1_000, "normal", 0)).waited_ms == 0


@pytest.mark.asyncio
async def test_no_limit_is_a_lease_that_does_nothing() -> None:
    lease = await _limiter(None).acquire(_TARGET, 10**9, "normal", 0)

    await lease.renew()
    await lease.release()
    assert lease.waited_ms == 0


@pytest.mark.asyncio
async def test_the_tracked_targets_are_bounded(monkeypatch) -> None:
    import shim.gateway.concurrency as concurrency

    monkeypatch.setattr(concurrency, "MAX_TRACKED_TARGETS", 2)
    limiter = _limiter()
    for name in ("a", "b"):
        await limiter.acquire(
            ConcurrencyTarget(name, "openai", None, None), 1, "normal", 0
        )

    with pytest.raises(ConcurrencyRefused):
        await limiter.acquire(
            ConcurrencyTarget("c", "openai", None, None), 1, "normal", 0
        )


def test_a_retry_after_is_bounded() -> None:
    for seconds in (0, 3_601):
        with pytest.raises(ValueError):
            ConcurrencyRefused(seconds)
