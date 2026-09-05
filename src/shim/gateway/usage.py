"""Public usage lifecycle and local terminal-event adapter."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from decimal import Decimal
from queue import Full, Queue, ShutDown
from threading import Thread
from typing import Literal, Protocol, TextIO, TypeAlias

from shim.billing.pricing import DEFAULT_PRICE_BOOK, compute_cost_usd
from shim.gateway.kernel.result import AdmissionState, PreparedInference
from shim.gateway.streaming.finalization import StreamFinalization
from shim.observability.metrics import LOCAL_USAGE_DROPPED_TOTAL


logger = logging.getLogger(__name__)


UsageFailureReason: TypeAlias = Literal[
    "admission_aborted",
    "provider_rejected_without_usage",
    "request_aborted",
]


class UsageLimitExceeded(RuntimeError):
    """An authoritative usage policy denied admission."""


class UsageLifecycle(Protocol):
    async def admit(
        self,
        prepared: PreparedInference,
        admission: AdmissionState,
    ) -> None: ...

    async def record_privacy(self, prepared: PreparedInference) -> None: ...

    async def reserve_provider_spend(
        self,
        prepared: PreparedInference,
        *,
        ephemeral_byok: bool,
    ) -> None: ...

    async def mark_provider_started(self, prepared: PreparedInference) -> None: ...

    async def mark_stream_started(self, prepared: PreparedInference) -> None: ...

    async def heartbeat_stream(self, prepared: PreparedInference) -> None: ...

    async def finalize(
        self,
        prepared: PreparedInference,
        terminal: StreamFinalization,
    ) -> None: ...

    async def fail(
        self,
        prepared: PreparedInference,
        *,
        reason: UsageFailureReason,
    ) -> None: ...


class LocalUsageLifecycle:
    """Queue redacted JSONL events; drop newest on overflow or sink failure."""

    def __init__(self, stream: TextIO, *, capacity: int = 1024) -> None:
        if capacity < 1:
            raise ValueError("event queue capacity must be positive")
        self._stream = stream
        self._queue: Queue[str] = Queue(maxsize=capacity)
        self._writer: Thread | None = None
        self.dropped_events = 0
        self.write_failures = 0

    async def aclose(self, timeout_seconds: float = 5.0) -> None:
        self._queue.shutdown()
        if self._writer is not None:
            await asyncio.to_thread(self._writer.join, timeout_seconds)

    def _write_events(self) -> None:
        while True:
            try:
                line = self._queue.get()
            except ShutDown:
                return
            try:
                self._stream.write(f"{line}\n")
                self._stream.flush()
            except Exception as exc:
                self.write_failures += 1
                LOCAL_USAGE_DROPPED_TOTAL.labels(reason="sink_failure").inc()
                logger.warning("Local usage event dropped type=%s", type(exc).__name__)
            finally:
                self._queue.task_done()

    async def admit(
        self,
        prepared: PreparedInference,
        admission: AdmissionState,
    ) -> None:
        pass

    async def record_privacy(self, prepared: PreparedInference) -> None:
        pass

    async def reserve_provider_spend(
        self,
        prepared: PreparedInference,
        *,
        ephemeral_byok: bool,
    ) -> None:
        pass

    async def mark_provider_started(self, prepared: PreparedInference) -> None:
        pass

    async def mark_stream_started(self, prepared: PreparedInference) -> None:
        pass

    async def heartbeat_stream(self, prepared: PreparedInference) -> None:
        pass

    async def finalize(
        self,
        prepared: PreparedInference,
        terminal: StreamFinalization,
    ) -> None:
        usage = terminal.usage
        self._write(
            prepared,
            outcome=terminal.terminal_status,
            completed_at=terminal.completed_at,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            cost_usd=(
                usage.settlement_cost_usd
                if DEFAULT_PRICE_BOOK.supports(
                    usage.provider_model,
                    str(prepared.provider),
                )
                else None
            ),
            model=usage.provider_model,
            estimated=usage.estimated,
        )

    async def fail(
        self,
        prepared: PreparedInference,
        *,
        reason: UsageFailureReason,
    ) -> None:
        admission = prepared.admission
        prompt_tokens = admission.estimated_input_tokens if admission is not None else 0
        supported = DEFAULT_PRICE_BOOK.supports(
            prepared.model,
            str(prepared.provider),
        )
        self._write(
            prepared,
            outcome=reason,
            completed_at=datetime.now(timezone.utc),
            prompt_tokens=prompt_tokens,
            completion_tokens=0,
            cost_usd=(
                compute_cost_usd(
                    prepared.model,
                    prompt_tokens,
                    0,
                    str(prepared.provider),
                )
                if supported
                else None
            ),
            model=prepared.model,
            estimated=True,
        )

    def _write(
        self,
        prepared: PreparedInference,
        *,
        outcome: str,
        completed_at: datetime,
        prompt_tokens: int,
        completion_tokens: int,
        cost_usd: Decimal | None,
        model: str,
        estimated: bool,
    ) -> None:
        event = {
            "version": 1,
            "request_id": str(prepared.request_id),
            "provider": str(prepared.provider),
            "model": model,
            "outcome": outcome,
            "latency_ms": max(
                0,
                round(
                    (completed_at - prepared.context.started_at).total_seconds() * 1_000
                ),
            ),
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "estimated_cost_usd": str(cost_usd) if cost_usd is not None else None,
            "estimated": estimated,
            "privacy_counts": (
                dict(prepared.privacy.pii_entities)
                if prepared.privacy is not None
                else {}
            ),
        }
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        try:
            self._queue.put_nowait(line)
        except (Full, ShutDown):
            # Drop newest telemetry; authoritative enterprise accounting is separate.
            self.dropped_events += 1
            LOCAL_USAGE_DROPPED_TOTAL.labels(reason="queue_unavailable").inc()
            return
        if self._writer is None:
            self._writer = Thread(target=self._write_events, daemon=True)
            self._writer.start()
