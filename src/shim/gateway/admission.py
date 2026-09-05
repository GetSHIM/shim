"""Local admission controls with bounded process memory."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Hashable
from dataclasses import dataclass
import hashlib
import heapq
from itertools import count
import time
from typing import Literal, Protocol


@dataclass(frozen=True, slots=True)
class LoopDetectionResult:
    status: Literal["SAFE", "WARNING", "BLOCKED"]
    chain_length: int


class LoopDetector(Protocol):
    async def check_exact_repeat(
        self,
        organization_id: str,
        prompt: str,
        *,
        limit: int,
        window_seconds: int,
    ) -> LoopDetectionResult: ...


class _FixedWindowCounters:
    def __init__(
        self,
        *,
        max_entries: int,
        clock: Callable[[], float],
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self.max_entries = max_entries
        self.clock = clock
        self.windows: OrderedDict[Hashable, tuple[int, float]] = OrderedDict()
        self._expirations: list[tuple[float, int, Hashable]] = []
        self._sequence = count()

    def increment(self, key: Hashable, *, amount: int, window_seconds: int) -> int:
        now = self.clock()
        current = self.windows.get(key)
        if current is not None and current[1] <= now:
            del self.windows[key]
            current = None
        if current is None:
            if len(self.windows) >= self.max_entries:
                self._discard_expired(now)
            while len(self.windows) >= self.max_entries:
                self.windows.popitem(last=False)
            count = amount
            expires_at = now + window_seconds
            self.windows[key] = (count, expires_at)
            heapq.heappush(self._expirations, (expires_at, next(self._sequence), key))
            if len(self._expirations) > 2 * self.max_entries:
                self._expirations = [
                    (expiry, next(self._sequence), item)
                    for item, (_, expiry) in self.windows.items()
                ]
                heapq.heapify(self._expirations)
            return count
        count = current[0] + amount
        self.windows[key] = (count, current[1])
        return count

    def _discard_expired(self, now: float) -> None:
        while self._expirations and self._expirations[0][0] <= now:
            expires_at, _, key = heapq.heappop(self._expirations)
            current = self.windows.get(key)
            if current is not None and current[1] == expires_at:
                del self.windows[key]


class InMemoryRateLimiter:
    """Apply bounded, per-process fixed-window admission."""

    def __init__(
        self,
        *,
        max_entries: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._counters = _FixedWindowCounters(
            max_entries=max_entries,
            clock=clock,
        )

    async def allow(
        self,
        key: str,
        *,
        limit: int,
        window_seconds: int,
        amount: int = 1,
    ) -> bool:
        _validate_rate_window(key, limit, window_seconds, amount)
        count = self._counters.increment(
            key,
            amount=amount,
            window_seconds=window_seconds,
        )
        return count <= limit


class InMemoryLoopDetector:
    """Count only prompt digests in bounded, per-process windows."""

    def __init__(
        self,
        *,
        max_entries: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._counters = _FixedWindowCounters(
            max_entries=max_entries,
            clock=clock,
        )

    async def check_exact_repeat(
        self,
        organization_id: str,
        prompt: str,
        *,
        limit: int,
        window_seconds: int,
    ) -> LoopDetectionResult:
        _validate_repeat_window(organization_id, limit, window_seconds)
        if not prompt:
            return LoopDetectionResult("SAFE", 0)
        digest = hashlib.sha256(prompt.encode()).hexdigest()
        count = self._counters.increment(
            (organization_id, digest),
            amount=1,
            window_seconds=window_seconds,
        )
        status = "BLOCKED" if count > limit else "WARNING" if count == limit else "SAFE"
        return LoopDetectionResult(status, count)


def _validate_rate_window(
    key: str,
    limit: int,
    window_seconds: int,
    amount: int,
) -> None:
    if not key.strip():
        raise ValueError("rate-limit key cannot be empty")
    if limit < 1 or window_seconds < 1 or amount < 1:
        raise ValueError("rate-limit bounds must be positive")


def _validate_repeat_window(
    organization_id: str,
    limit: int,
    window_seconds: int,
) -> None:
    if not organization_id.strip():
        raise ValueError("repeat window requires a tenant identity")
    if limit < 2 or window_seconds < 1:
        raise ValueError("repeat window bounds are invalid")
