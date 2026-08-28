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
