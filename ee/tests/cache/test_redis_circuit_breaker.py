from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from shim_enterprise.cache.circuit_breaker import RedisCircuitBreaker


@pytest.mark.asyncio
async def test_open_circuit_is_excluded_until_recovery_window() -> None:
    redis = SimpleNamespace(
        mget=AsyncMock(return_value=["5", "open", "200"]),
        set=AsyncMock(),
    )
    breaker = RedisCircuitBreaker(
        "openai",
        cache=SimpleNamespace(redis=redis),
        clock=lambda: 100,
    )

    assert await breaker.is_available() is False
    assert await breaker.acquire_call() is False
    redis.set.assert_not_awaited()


@pytest.mark.asyncio
async def test_elapsed_open_circuit_allows_one_probe() -> None:
    redis = SimpleNamespace(
        mget=AsyncMock(return_value=["5", "open", "90"]),
        set=AsyncMock(return_value=True),
    )
    breaker = RedisCircuitBreaker(
        "anthropic",
        cache=SimpleNamespace(redis=redis),
        clock=lambda: 100,
    )

    assert await breaker.is_available() is True
    assert await breaker.acquire_call() is True
    redis.set.assert_awaited_once_with(
        "circuit:anthropic:probe",
        "1",
        nx=True,
        ex=60,
    )


@pytest.mark.asyncio
async def test_success_clears_all_provider_circuit_state() -> None:
    redis = SimpleNamespace(delete=AsyncMock())
    breaker = RedisCircuitBreaker("google", cache=SimpleNamespace(redis=redis))

    await breaker.record_success()

    redis.delete.assert_awaited_once_with(
        "circuit:google:failures",
        "circuit:google:state",
        "circuit:google:open_until",
        "circuit:google:probe",
    )


@pytest.mark.asyncio
async def test_release_probe_preserves_circuit_health_state() -> None:
    redis = SimpleNamespace(delete=AsyncMock())
    breaker = RedisCircuitBreaker("google", cache=SimpleNamespace(redis=redis))

    await breaker.release_probe()

    redis.delete.assert_awaited_once_with("circuit:google:probe")


@pytest.mark.asyncio
async def test_failure_uses_atomic_bounded_state_update() -> None:
    redis = SimpleNamespace(eval=AsyncMock())
    breaker = RedisCircuitBreaker(
        "ollama",
        failure_threshold=3,
        recovery_seconds=20,
        cache=SimpleNamespace(redis=redis),
        clock=lambda: 100,
    )

    await breaker.record_failure()

    arguments = redis.eval.await_args.args
    assert arguments[1:6] == (
        4,
        "circuit:ollama:failures",
        "circuit:ollama:state",
        "circuit:ollama:open_until",
        "circuit:ollama:probe",
    )
    assert arguments[-3:] == (40, 3, 120)


@pytest.mark.asyncio
async def test_missing_redis_fails_open_without_state_mutation() -> None:
    breaker = RedisCircuitBreaker("openai", cache=None)

    assert await breaker.is_available() is True
    assert await breaker.acquire_call() is True
    await breaker.record_failure()
    await breaker.record_success()
