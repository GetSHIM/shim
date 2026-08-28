from __future__ import annotations

import pytest

from shim.core.circuit_breaker import InMemoryCircuitBreaker


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
