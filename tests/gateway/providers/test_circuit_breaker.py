from __future__ import annotations

import pytest

from shim.core.circuit_breaker import InMemoryCircuitBreaker
from shim.gateway.pipeline.provider_execution import record_provider_error


@pytest.mark.asyncio
async def test_in_memory_circuit_expires_failures_and_allows_one_probe() -> None:
    now = 100.0
    breaker = InMemoryCircuitBreaker(
        failure_threshold=2,
        recovery_seconds=10,
        clock=lambda: now,
    )

    await breaker.record_failure()
    now = 121.0
    await breaker.record_failure()
    assert await breaker.acquire_call() is True

    await breaker.record_failure()
    assert await breaker.acquire_call() is False

    now = 131.0
    assert await breaker.acquire_call() is True
    assert await breaker.acquire_call() is False

    await breaker.release_probe()
    assert await breaker.acquire_call() is True

    await breaker.record_success()
    assert await breaker.acquire_call() is True


class _SdkError(Exception):
    pass


@pytest.mark.asyncio
async def test_rate_limits_never_open_the_circuit_but_outages_do() -> None:
    breaker = InMemoryCircuitBreaker(failure_threshold=5)

    for _ in range(5):
        assert await breaker.acquire_call() is True
        await record_provider_error(breaker, _SdkError(), 429, _SdkError)
    assert await breaker.acquire_call() is True

    for _ in range(5):
        await record_provider_error(breaker, _SdkError(), 503, _SdkError)
    assert await breaker.acquire_call() is False
