from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from shim_enterprise.billing.quota import BurstRateLimiter


@pytest.mark.asyncio
async def test_burst_window_passes_the_limit_to_the_atomic_script() -> None:
    redis = SimpleNamespace(eval=AsyncMock(return_value=1))
    limiter = BurstRateLimiter(SimpleNamespace(redis=redis))

    allowed = await limiter.allow("tenant:key", limit=3, window_seconds=60, amount=2)

    assert allowed is True
    arguments = redis.eval.await_args.args
    assert arguments[1:] == (1, "burst:tenant:key", 2, 60, 3)


@pytest.mark.asyncio
async def test_burst_window_reads_a_refusal_from_the_script() -> None:
    redis = SimpleNamespace(eval=AsyncMock(return_value=0))
    limiter = BurstRateLimiter(SimpleNamespace(redis=redis))

    assert await limiter.allow("key", limit=10, window_seconds=60) is False


@pytest.mark.asyncio
async def test_burst_window_fails_open_when_the_script_fails() -> None:
    redis = SimpleNamespace(eval=AsyncMock(side_effect=ConnectionError("down")))
    limiter = BurstRateLimiter(SimpleNamespace(redis=redis))

    assert await limiter.allow("key", limit=10, window_seconds=60) is True


@pytest.mark.asyncio
async def test_burst_window_fails_open_when_redis_is_unavailable() -> None:
    limiter = BurstRateLimiter(SimpleNamespace(redis=None))

    assert await limiter.allow("key", limit=10, window_seconds=60) is True


@pytest.mark.asyncio
async def test_invalid_counter_amount_is_rejected() -> None:
    limiter = BurstRateLimiter(SimpleNamespace(redis=None))

    with pytest.raises(ValueError, match="must be positive"):
        await limiter.allow("key", limit=10, window_seconds=60, amount=0)
