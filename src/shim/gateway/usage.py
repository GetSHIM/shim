"""Public usage lifecycle and local terminal-event adapter."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal
from threading import Lock
from typing import Literal, Protocol, TextIO, TypeAlias

from shim.billing.pricing import DEFAULT_PRICE_BOOK, compute_cost_usd
from shim.gateway.kernel.result import AdmissionState, PreparedInference
from shim.gateway.streaming.finalization import StreamFinalization


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
    """Write one redacted JSONL event for each terminal local request."""

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream
        self._write_lock = Lock()

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
        with self._write_lock:
            self._stream.write(f"{line}\n")
            self._stream.flush()
