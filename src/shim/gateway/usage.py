"""Public usage lifecycle and local terminal-event adapter."""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
from decimal import Decimal
from queue import Full, Queue, ShutDown
from threading import Thread
from collections.abc import Mapping
from typing import Any, Literal, Protocol, TextIO, TypeAlias

from shim.billing.pricing import DEFAULT_PRICE_BOOK, CacheSplit, compute_cost_usd
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


class UsageAuditPersistenceError(RuntimeError):
    """Required audit evidence could not be committed before a response."""


class UsageLifecycle(Protocol):
    async def reject(self, prepared: PreparedInference) -> None: ...

    async def admit(
        self,
        prepared: PreparedInference,
        admission: AdmissionState,
    ) -> None: ...

    async def record_privacy(self, prepared: PreparedInference) -> None: ...

    async def record_response_privacy(
        self, prepared: PreparedInference, result: Mapping[str, Any]
    ) -> None: ...

    async def record_token_count(
        self, prepared: PreparedInference, input_tokens: int | None
    ) -> None: ...

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

    def __init__(
        self,
        stream: TextIO,
        *,
        capacity: int = 1024,
        system_prompt_hash_key: bytes | None = None,
    ) -> None:
        if capacity < 1:
            raise ValueError("event queue capacity must be positive")
        self._system_prompt_hash_key = system_prompt_hash_key
        # Hashed at admission, before privacy rewrites the payload.
        # ponytail: one entry per admitted request until its event is written; bound it if an
        # admitted request can ever end without one.
        self._prompt_hashes: dict[str, str | None] = {}
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
        if self._system_prompt_hash_key is not None:
            self._prompt_hashes[str(prepared.request_id)] = system_prompt_hash(
                prepared, self._system_prompt_hash_key
            )

    async def reject(self, prepared: PreparedInference) -> None:
        self._write(
            prepared,
            outcome="rejected",
            prompt_tokens=0,
            completion_tokens=0,
            cost_usd=Decimal("0"),
            model=prepared.model
            if DEFAULT_PRICE_BOOK.supports(prepared.model, str(prepared.provider))
            else "unsupported",
            estimated=False,
            shim_latency_ms=prepared.timing.shim_latency_ms,
        )

    async def record_privacy(self, prepared: PreparedInference) -> None:
        pass

    async def record_response_privacy(
        self, prepared: PreparedInference, result: Mapping[str, Any]
    ) -> None:
        self._emit(
            {
                "version": 4,
                "event": "response_privacy",
                "request_id": str(prepared.request_id),
                **result,
            }
        )

    async def record_token_count(
        self, prepared: PreparedInference, input_tokens: int | None
    ) -> None:
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
            provider_finish_reasons=usage.provider_finish_reasons,
            ttft_ms=usage.ttft_ms,
            completion_outcome=usage.completion_outcome,
            shim_latency_ms=terminal.shim_latency_ms,
            cache_split=usage.cache_split,
        )

    async def fail(
        self,
        prepared: PreparedInference,
        *,
        reason: UsageFailureReason,
    ) -> None:
        if any(verdict.outcome == "deny" for verdict in prepared.policy_verdicts):
            await self.reject(prepared)
            return
        admission = prepared.admission
        prompt_tokens = admission.estimated_input_tokens if admission is not None else 0
        supported = DEFAULT_PRICE_BOOK.supports(
            prepared.model,
            str(prepared.provider),
        )
        self._write(
            prepared,
            outcome=reason,
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
            shim_latency_ms=prepared.timing.shim_latency_ms,
        )

    def _write(
        self,
        prepared: PreparedInference,
        *,
        outcome: str,
        prompt_tokens: int,
        completion_tokens: int,
        cost_usd: Decimal | None,
        model: str,
        estimated: bool,
        shim_latency_ms: int,
        provider_finish_reasons: dict[str, str] | None = None,
        ttft_ms: float | None = None,
        completion_outcome: str | None = None,
        cache_split: CacheSplit | None = None,
    ) -> None:
        admission = prepared.admission
        privacy = prepared.privacy
        event = {
            "version": 4,
            "event": "request",
            "request_id": str(prepared.request_id),
            "provider": str(prepared.provider),
            "model": model,
            "outcome": outcome,
            "shim_latency_ms": shim_latency_ms,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "estimated_cost_usd": str(cost_usd) if cost_usd is not None else None,
            "estimated": estimated,
            "cache_read_tokens": None if cache_split is None else cache_split[0],
            "cache_write_tokens": None
            if cache_split is None
            else cache_split[1] + cache_split[2],
            "provider_finish_reasons": provider_finish_reasons,
            "completion_outcome": completion_outcome,
            "ttft_ms": ttft_ms,
            "repeat_chain_length": (
                admission.repeat_chain_length if admission is not None else None
            ),
            "cost_center": admission.cost_center if admission is not None else None,
            "tags": list(admission.tags) if admission is not None else [],
            "system_prompt_hash": self._prompt_hashes.pop(
                str(prepared.request_id), None
            ),
            "deployment_kind": prepared.deployment_kind,
            "privacy_counts": dict(privacy.pii_entities) if privacy else {},
            "monitored_entities": dict(privacy.monitored_entities) if privacy else {},
            "blocked_entities": dict(privacy.blocked_entities) if privacy else {},
            "bulk_disclosure": dict(privacy.bulk_disclosure)
            if privacy and privacy.bulk_disclosure
            else None,
            "warnings": list(prepared.warnings),
            "policy_verdicts": [
                verdict.model_dump(mode="json") for verdict in prepared.policy_verdicts
            ],
        }
        self._emit(event)

    def _emit(self, event: Mapping[str, Any]) -> None:
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


def system_prompt_hash(prepared: PreparedInference, key: bytes) -> str | None:
    """Hash only explicitly supplied system content, before privacy transformation."""

    payload = prepared.payload
    material: dict[str, Any] = {}
    field = {
        "chat": None,
        "responses": "instructions",
        "messages": "system",
        "count_tokens": "system",
        "generate_content": "systemInstruction",
    }[prepared.protocol]
    if field is not None and payload.get(field) is not None:
        material[field] = payload[field]
    if prepared.protocol in {"chat", "responses"}:
        messages = payload.get("messages" if prepared.protocol == "chat" else "input")
        if isinstance(messages, list):
            instructions = [
                {"role": item["role"], "content": item["content"]}
                for item in messages
                if isinstance(item, dict)
                and item.get("role") in ("system", "developer")
                and item.get("content") is not None
            ]
            if instructions:
                material["messages"] = instructions
    if not material:
        return None
    canonical = json.dumps(
        [
            "shim.system_prompt.v1",
            str(prepared.tenant_id),
            prepared.protocol,
            {
                "deployment_id": prepared.target.deployment_id
                if prepared.target
                else None,
                "deployment_kind": prepared.deployment_kind,
            },
            material,
        ],
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "hmac-sha256:v1:" + hmac.digest(key, canonical, "sha256").hex()
