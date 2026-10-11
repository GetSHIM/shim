import hashlib

import pytest

from shim.gateway.admission import InMemoryLoopDetector, InMemoryRateLimiter


@pytest.mark.asyncio
async def test_in_memory_rate_limiter_uses_bounded_fixed_windows() -> None:
    now = [100.0]
    limiter = InMemoryRateLimiter(max_entries=2, clock=lambda: now[0])

    assert await limiter.allow("first", limit=2, window_seconds=60, amount=2)
    assert not await limiter.allow("first", limit=2, window_seconds=60)

    now[0] = 160.0
    assert await limiter.allow("first", limit=2, window_seconds=60)
    assert await limiter.allow("second", limit=2, window_seconds=60)
    assert await limiter.allow("third", limit=2, window_seconds=60)
    assert tuple(limiter._counters.windows) == ("second", "third")


@pytest.mark.asyncio
async def test_in_memory_loop_detector_stores_only_bounded_prompt_digests() -> None:
    now = [100.0]
    detector = InMemoryLoopDetector(max_entries=2, clock=lambda: now[0])
    prompt = "sensitive repeated prompt"

    results = [
        await detector.check_exact_repeat(
            "tenant-1",
            prompt,
            limit=2,
            window_seconds=30,
        )
        for _ in range(3)
    ]

    assert [(result.status, result.chain_length) for result in results] == [
        ("SAFE", 1),
        ("WARNING", 2),
        ("BLOCKED", 3),
    ]
    stored_key = next(iter(detector._counters.windows))
    assert stored_key == ("tenant-1", hashlib.sha256(prompt.encode()).hexdigest())
    assert prompt not in repr(detector._counters.windows)

    now[0] = 130.0
    result = await detector.check_exact_repeat(
        "tenant-1",
        prompt,
        limit=2,
        window_seconds=30,
    )
    assert (result.status, result.chain_length) == ("SAFE", 1)
    for candidate in ("second prompt", "third prompt"):
        await detector.check_exact_repeat(
            "tenant-1",
            candidate,
            limit=2,
            window_seconds=30,
        )
    assert len(detector._counters.windows) == 2


@pytest.mark.asyncio
async def test_in_memory_admission_rejects_invalid_bounds() -> None:
    with pytest.raises(ValueError, match="positive"):
        InMemoryRateLimiter(max_entries=0)
    with pytest.raises(ValueError, match="cannot be empty"):
        await InMemoryRateLimiter().allow(" ", limit=1, window_seconds=1)
    with pytest.raises(ValueError, match="tenant identity"):
        await InMemoryLoopDetector().check_exact_repeat(
            " ",
            "prompt",
            limit=2,
            window_seconds=1,
        )


def test_expiry_index_handles_mixed_windows_and_bounds_evicted_entries():
    from shim.gateway.admission import _FixedWindowCounters

    now = 0.0
    counters = _FixedWindowCounters(max_entries=3, clock=lambda: now)
    counters.increment("long", amount=1, window_seconds=100)
    counters.increment("short", amount=1, window_seconds=1)
    counters.increment("medium", amount=1, window_seconds=20)
    now = 1.0
    counters.increment("new", amount=1, window_seconds=10)
    assert list(counters.windows) == ["long", "medium", "new"]
    for index in range(100):
        counters.increment(index % 5, amount=1, window_seconds=10)
        assert len(counters.windows) <= 3
        assert len(counters._expirations) <= 6
    now = 12.0
    assert counters.increment("fresh", amount=1, window_seconds=1) == 1
    assert list(counters.windows) == ["fresh"]


@pytest.mark.asyncio
async def test_in_memory_rate_limiter_refuses_without_consuming() -> None:
    limiter = InMemoryRateLimiter(clock=lambda: 100.0)

    assert await limiter.allow("key", limit=10, window_seconds=60, amount=6)
    assert not await limiter.allow("key", limit=10, window_seconds=60, amount=5)
    assert await limiter.allow("key", limit=10, window_seconds=60, amount=4)
    assert not await limiter.allow("key", limit=10, window_seconds=60, amount=1)
    assert not await limiter.allow("fresh", limit=10, window_seconds=60, amount=11)
    assert "fresh" not in limiter._counters.windows
    assert await limiter.allow("fresh", limit=10, window_seconds=60, amount=10)


@pytest.mark.asyncio
async def test_the_loop_detector_counts_a_turn_key_beside_the_prompt() -> None:
    from shim.gateway.admission import LoopDetectionResult

    detector = InMemoryLoopDetector()

    plain = await detector.check_exact_repeat("org", "a", limit=8, window_seconds=60)
    turns = [
        await detector.check_exact_repeat(
            "org", f"prompt {i}", limit=8, window_seconds=60, turn_key="turn-1"
        )
        for i in range(3)
    ]
    other = await detector.check_exact_repeat(
        "org", "b", limit=8, window_seconds=60, turn_key="turn-2"
    )

    assert plain == LoopDetectionResult("SAFE", 1, 0)
    assert [result.turn_repeats for result in turns] == [1, 2, 3]
    assert [result.chain_length for result in turns] == [1, 1, 1]
    assert other.turn_repeats == 1


@pytest.mark.asyncio
async def test_the_task_counter_caps_calls_exactly_and_cost_after_it_lands() -> None:
    from shim.gateway.admission import InMemoryTaskCounter

    now = [0.0]
    counter = InMemoryTaskCounter(max_entries=2, clock=lambda: now[0])
    admit = lambda key="t": counter.admit_call(  # noqa: E731
        "org", key, max_calls=2, max_cost_micro_usd=500, window_seconds=60
    )

    first, second, third = [await admit() for _ in range(3)]
    assert [(a.calls, a.allowed) for a in (first, second, third)] == [
        (1, True),
        (2, True),
        (2, False),
    ]
    await counter.add_cost("org", "c", micro_usd=499, window_seconds=60)
    assert (await admit("c")).allowed is True
    await counter.add_cost("org", "c", micro_usd=1, window_seconds=60)
    refused = await admit("c")
    assert (refused.allowed, refused.cost_micro_usd) == (False, 500)
    now[0] = 61.0
    assert (await admit()).calls == 1, "a new window starts after expiry"


@pytest.mark.asyncio
async def test_throwaway_task_ids_never_reset_a_task_still_calling() -> None:
    from shim.gateway.admission import InMemoryTaskCounter

    now = [0.0]
    counter = InMemoryTaskCounter(max_entries=2, clock=lambda: now[0])

    async def admit(key: str, window_seconds: int = 60):
        return await counter.admit_call(
            "org",
            key,
            max_calls=10,
            max_cost_micro_usd=None,
            window_seconds=window_seconds,
        )

    await admit("live")
    await admit("short", window_seconds=5)
    now[0] = 6.0
    await admit("throwaway-1")  # the expired task goes, not the older live one
    await admit("live")
    await admit("throwaway-2")  # the least recently used, throwaway-1, goes

    assert (await admit("live")).calls == 3


@pytest.mark.asyncio
async def test_the_inflight_registry_has_one_owner_per_tenant_and_digest() -> None:
    from shim.gateway.admission import InFlightRegistry

    registry = InFlightRegistry()

    assert registry.enter("t1", "d", "r1", "k", True) is None
    leader = registry.enter("t1", "d", "r2", "k", True)
    assert leader is not None and leader.request_id == "r1"
    assert registry.enter("t2", "d", "r3", "k", True) is None, "tenants are apart"
    registry.leave("t1", "d", "r2")
    registry.publish("t1", "d", "r2", "not the owner's")
    assert registry.enter("t1", "d", "r4", "k", True) is leader
    assert leader.outcome is not None and not leader.outcome.done()
    registry.publish("t1", "d", "r1", "answer")
    registry.leave("t1", "d", "r1")
    assert leader.outcome.result() == "answer", "leaving keeps a published answer"
    assert registry.enter("t1", "d", "r5", "k", False) is None
    assert registry.entries[("t1", "d")].outcome is None, "only a shareable one waits"
    registry.leave("t2", "d", "r3")
    assert tuple(registry.entries) == (("t1", "d"),)


@pytest.mark.asyncio
async def test_the_inflight_registry_is_bounded_and_expires_a_lost_leader() -> None:
    from shim.gateway.admission import InFlightRegistry

    now = [0.0]
    registry = InFlightRegistry(max_entries=2, expiry_seconds=900, clock=lambda: now[0])
    registry.enter("t", "a", "r1", "k", True)
    oldest = registry.entries[("t", "a")]
    now[0] = 10.0
    registry.enter("t", "b", "r2", "k", True)
    newer = registry.entries[("t", "b")]
    registry.enter("t", "c", "r3", "k", True)

    assert tuple(registry.entries) == (("t", "b"), ("t", "c"))
    assert oldest.outcome is not None and oldest.outcome.result() is None
    now[0] = 910.0
    assert registry.enter("t", "b", "r4", "k", True) is None, "r2 expired"
    assert newer.outcome is not None and newer.outcome.result() is None
    registry.leave("t", "b", "r2")
    assert registry.entries[("t", "b")].request_id == "r4"
