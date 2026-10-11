"""Local admission controls with bounded process memory."""

from __future__ import annotations

import asyncio
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
    # Times the latest tool call of this turn key was seen in the window.
    turn_repeats: int = 0


class LoopDetector(Protocol):
    async def check_exact_repeat(
        self,
        organization_id: str,
        prompt: str,
        *,
        limit: int,
        window_seconds: int,
        turn_key: str | None = None,
    ) -> LoopDetectionResult: ...


@dataclass(frozen=True, slots=True)
class TaskAdmission:
    calls: int
    cost_micro_usd: int
    allowed: bool
    unavailable: bool = False


class TaskCounter(Protocol):
    async def admit_call(
        self,
        tenant_id: str,
        task_key: str,
        *,
        max_calls: int | None,
        max_cost_micro_usd: int | None,
        window_seconds: int,
    ) -> TaskAdmission: ...

    async def add_cost(
        self, tenant_id: str, task_key: str, *, micro_usd: int, window_seconds: int
    ) -> None: ...


@dataclass(slots=True)
class InFlightEntry:
    request_id: str
    api_key_id: str
    shareable: bool
    expires_at: float
    # A shareable entry's answer, or None once it ends without one.
    outcome: asyncio.Future[object] | None = None

    def close(self, value: object = None) -> None:
        if self.outcome is not None and not self.outcome.done():
            self.outcome.set_result(value)


class InFlightRegistry:
    """Identical requests in flight in this process; nothing is kept once one ends."""

    def __init__(
        self,
        *,
        max_entries: int = 10_000,
        expiry_seconds: float = 900,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_entries = max_entries
        self.expiry_seconds = expiry_seconds
        self.clock = clock
        # Insertion order is expiry order: every entry lives expiry_seconds.
        self.entries: OrderedDict[tuple[str, str], InFlightEntry] = OrderedDict()

    def enter(
        self,
        tenant_id: str,
        digest: str,
        request_id: str,
        api_key_id: str,
        shareable: bool,
    ) -> InFlightEntry | None:
        """The earlier identical request still in flight, else None and this one registers."""
        now = self.clock()
        while self.entries and next(iter(self.entries.values())).expires_at <= now:
            self.entries.popitem(last=False)[1].close()
        key = (tenant_id, digest)
        earlier = self.entries.get(key)
        if earlier is not None:
            return earlier
        while len(self.entries) >= self.max_entries:
            self.entries.popitem(last=False)[1].close()
        self.entries[key] = InFlightEntry(
            request_id,
            api_key_id,
            shareable,
            now + self.expiry_seconds,
            asyncio.get_running_loop().create_future() if shareable else None,
        )
        return None

    def publish(
        self, tenant_id: str, digest: str, request_id: str, answer: object
    ) -> None:
        entry = self.entries.get((tenant_id, digest))
        if entry is not None and entry.request_id == request_id:
            entry.close(answer)

    def leave(self, tenant_id: str, digest: str, request_id: str) -> None:
        entry = self.entries.get((tenant_id, digest))
        if entry is not None and entry.request_id == request_id:
            del self.entries[(tenant_id, digest)]
            entry.close()


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

    def add_within(
        self, key: Hashable, *, amount: int, limit: int, window_seconds: int
    ) -> bool:
        current = self.windows.get(key)
        if current is not None and current[1] > self.clock():
            if current[0] + amount > limit:
                return False
        elif amount > limit:
            return False
        self.increment(key, amount=amount, window_seconds=window_seconds)
        return True

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
        return self._counters.add_within(
            key,
            amount=amount,
            limit=limit,
            window_seconds=window_seconds,
        )


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
        turn_key: str | None = None,
    ) -> LoopDetectionResult:
        _validate_repeat_window(organization_id, limit, window_seconds)
        turns = (
            self._counters.increment(
                (organization_id, "turn", turn_key),
                amount=1,
                window_seconds=window_seconds,
            )
            if turn_key
            else 0
        )
        if not prompt:
            return LoopDetectionResult("SAFE", 0, turns)
        digest = hashlib.sha256(prompt.encode()).hexdigest()
        count = self._counters.increment(
            (organization_id, digest),
            amount=1,
            window_seconds=window_seconds,
        )
        status = "BLOCKED" if count > limit else "WARNING" if count == limit else "SAFE"
        return LoopDetectionResult(status, count, turns)


class InMemoryTaskCounter:
    """Calls and settled cost per task in bounded, per-process windows from the first call."""

    def __init__(
        self,
        *,
        max_entries: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self.max_entries = max_entries
        self.clock = clock
        # (tenant, task key) -> [calls, cost in micro-dollars, expiry]
        self.tasks: OrderedDict[tuple[str, str], list[float]] = OrderedDict()

    def _entry(self, key: tuple[str, str], window_seconds: int) -> list[float]:
        now = self.clock()
        entry = self.tasks.get(key)
        if entry is not None and entry[2] > now:
            return entry
        self.tasks.pop(key, None)
        # ponytail: evicts oldest first; an expiry heap if task counts grow large.
        while len(self.tasks) >= self.max_entries:
            self.tasks.popitem(last=False)
        self.tasks[key] = entry = [0, 0, now + window_seconds]
        return entry

    async def admit_call(
        self,
        tenant_id: str,
        task_key: str,
        *,
        max_calls: int | None,
        max_cost_micro_usd: int | None,
        window_seconds: int,
    ) -> TaskAdmission:
        entry = self._entry((tenant_id, task_key), window_seconds)
        calls, cost = int(entry[0]), int(entry[1])
        if (max_calls is not None and calls + 1 > max_calls) or (
            max_cost_micro_usd is not None and cost >= max_cost_micro_usd
        ):
            return TaskAdmission(calls, cost, allowed=False)
        entry[0] = calls + 1
        return TaskAdmission(calls + 1, cost, allowed=True)

    async def add_cost(
        self, tenant_id: str, task_key: str, *, micro_usd: int, window_seconds: int
    ) -> None:
        self._entry((tenant_id, task_key), window_seconds)[1] += micro_usd


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
