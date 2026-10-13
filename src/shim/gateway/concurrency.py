"""How much work a target runs at once: the admission port and a one-process adapter."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from time import perf_counter
from typing import TYPE_CHECKING, Literal, Protocol

from shim.observability.metrics import CONCURRENCY_ADMISSIONS_TOTAL

if TYPE_CHECKING:
    from shim.gateway.kernel.result import AdmissionState, PreparedInference

Priority = Literal["high", "normal", "low"]
# Targets the in-memory adapter tracks at once; work for another one is refused.
MAX_TRACKED_TARGETS = 10_000
REFUSED_RETRY_AFTER_SECONDS = 5


@dataclass(frozen=True)
class ConcurrencyTarget:
    tenant_id: str
    provider: str
    # None: the catalog route.
    base_url: str | None
    deployment_id: str | None


class Lease(Protocol):
    # Milliseconds the request waited for room; 0 when admitted at once.
    waited_ms: int

    async def renew(self) -> None: ...

    async def release(self) -> None: ...


class ConcurrencyRefused(Exception):
    def __init__(self, retry_after_seconds: int, *, never_fits: bool = False) -> None:
        if not 1 <= retry_after_seconds <= 3_600:
            raise ValueError("retry_after_seconds is 1 to 3,600")
        super().__init__("concurrency limit reached")
        self.retry_after_seconds = retry_after_seconds
        self.never_fits = never_fits


class ConcurrencyLimiter(Protocol):
    async def acquire(
        self, target: ConcurrencyTarget, tokens: int, priority: Priority, wait_ms: int
    ) -> Lease: ...


def work_tokens(admission: AdmissionState) -> int:
    """A request's size for the limiter: the approximate input unit TPM uses, plus
    the output admission resolved."""
    return -(-admission.estimated_input_tokens // 4) + admission.maximum_output_tokens


def concurrency_target(prepared: PreparedInference) -> ConcurrencyTarget:
    target = prepared.target
    return ConcurrencyTarget(
        tenant_id=str(prepared.tenant_id),
        provider=str(prepared.provider),
        base_url=target.base_url if target else None,
        deployment_id=target.deployment_id if target else None,
    )


class _NoLease:
    waited_ms = 0

    async def renew(self) -> None:
        return None

    async def release(self) -> None:
        return None


class _MemoryLease:
    def __init__(
        self,
        limiter: InMemoryConcurrencyLimiter,
        target: ConcurrencyTarget,
        tokens: int,
        waited_ms: int,
    ) -> None:
        self._limiter = limiter
        self._target = target
        self._tokens = tokens
        self.waited_ms = waited_ms
        self._released = False

    async def renew(self) -> None:
        return None

    async def release(self) -> None:
        if self._released:
            return
        self._released = True
        await self._limiter._release(self._target, self._tokens)


class InMemoryConcurrencyLimiter:
    """Tokens in flight per target, in this process only: replicas do not share it."""

    def __init__(self, limits: Callable[[ConcurrencyTarget], int | None]) -> None:
        self._limits = limits
        self._condition = asyncio.Condition()
        # target -> (tokens in flight, leases held)
        self._used: dict[ConcurrencyTarget, tuple[int, int]] = {}
        self._waiting: dict[ConcurrencyTarget, deque[object]] = {}

    def _fits(self, target: ConcurrencyTarget, tokens: int, limit: int) -> bool:
        used, held = self._used.get(target, (0, 0))
        # A request larger than the whole limit still runs on an idle target.
        return held == 0 or used + tokens <= limit

    async def acquire(
        self, target: ConcurrencyTarget, tokens: int, priority: Priority, wait_ms: int
    ) -> Lease:
        limit = self._limits(target)
        if limit is None:
            return _NoLease()
        started = perf_counter()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait_ms / 1_000
        async with self._condition:
            if target not in self._used and len(self._used) >= MAX_TRACKED_TARGETS:
                CONCURRENCY_ADMISSIONS_TOTAL.labels(outcome="refused").inc()
                raise ConcurrencyRefused(REFUSED_RETRY_AFTER_SECONDS)
            waited = False
            ticket = object()
            queue = self._waiting.setdefault(target, deque())
            queue.append(ticket)
            try:
                # Arrival order: only the first waiter of a target may take its room.
                while not (queue[0] is ticket and self._fits(target, tokens, limit)):
                    remaining = deadline - loop.time()
                    if priority == "low" or remaining <= 0:
                        CONCURRENCY_ADMISSIONS_TOTAL.labels(outcome="refused").inc()
                        raise ConcurrencyRefused(REFUSED_RETRY_AFTER_SECONDS)
                    waited = True
                    try:
                        await asyncio.wait_for(self._condition.wait(), remaining)
                    except TimeoutError:
                        continue
                used, held = self._used.get(target, (0, 0))
                self._used[target] = (used + tokens, held + 1)
            finally:
                queue.remove(ticket)
                if not queue:
                    del self._waiting[target]
                self._condition.notify_all()
        waited_ms = round((perf_counter() - started) * 1_000) if waited else 0
        CONCURRENCY_ADMISSIONS_TOTAL.labels(
            outcome="after_wait" if waited else "immediate"
        ).inc()
        return _MemoryLease(self, target, tokens, waited_ms)

    async def _release(self, target: ConcurrencyTarget, tokens: int) -> None:
        async with self._condition:
            used, held = self._used[target]
            if held == 1:
                del self._used[target]
            else:
                self._used[target] = (used - tokens, held - 1)
            self._condition.notify_all()
