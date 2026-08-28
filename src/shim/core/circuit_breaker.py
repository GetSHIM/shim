"""Community-safe circuit state for upstream provider calls."""

from __future__ import annotations

from collections.abc import Callable
import time
from typing import Protocol


class CircuitBreaker(Protocol):
    """State operations required by provider execution."""

    async def acquire_call(self) -> bool: ...

    async def release_probe(self) -> None: ...

    async def record_success(self) -> None: ...

    async def record_failure(self) -> None: ...


class InMemoryCircuitBreaker:
    """Process-local circuit with the same recovery window as Redis."""

    def __init__(
        self,
        *,
        failure_threshold: int = 5,
        recovery_seconds: int = 60,
        clock: Callable[[], float] = time.time,
    ) -> None:
        validate_circuit_limits(failure_threshold, recovery_seconds)
        self.failure_threshold = failure_threshold
        self.recovery_seconds = recovery_seconds
        self.clock = clock
        self._failures = 0
        self._open_until = 0.0
        self._expires_at = 0.0
        self._probe_acquired = False

    async def acquire_call(self) -> bool:
        now = self.clock()
        self._expire(now)
        if not self._open_until:
            return True
        if now < self._open_until or self._probe_acquired:
            return False
        self._probe_acquired = True
        return True

    async def record_success(self) -> None:
        self._reset()

    async def release_probe(self) -> None:
        self._probe_acquired = False

    async def record_failure(self) -> None:
        now = self.clock()
        self._expire(now)
        self._failures += 1
        self._expires_at = now + self.recovery_seconds * 2
        if self._failures >= self.failure_threshold:
            self._open_until = now + self.recovery_seconds
        self._probe_acquired = False

    def _expire(self, now: float) -> None:
        if self._expires_at and now >= self._expires_at:
            self._reset()

    def _reset(self) -> None:
        self._failures = 0
        self._open_until = 0.0
        self._expires_at = 0.0
        self._probe_acquired = False


def validate_circuit_limits(failure_threshold: int, recovery_seconds: int) -> None:
    if failure_threshold < 1 or recovery_seconds < 1:
        raise ValueError("circuit limits must be positive")
