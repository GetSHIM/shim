"""Native provider response settlement."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
import logging
from datetime import datetime, timezone
from time import perf_counter
from typing import TYPE_CHECKING, Any

from fastapi.responses import JSONResponse, StreamingResponse
from opentelemetry import trace
from starlette.background import BackgroundTask

from shim.billing.pricing import DEFAULT_PRICE_BOOK, CacheSplit, compute_cost_usd
from shim.gateway.kernel.result import PreparedInference, UNSPECIFIED_PROVIDER_MODEL
from shim.gateway.pipeline.admission import candidate_count
from shim.gateway.pipeline.privacy import scan_response
from shim.gateway.pipeline.provider_execution import ProviderNonStream, ProviderStream
from shim.gateway.streaming import (
    StreamFinalization,
    StreamMeter,
    StreamSession,
    StreamTerminalStatus,
)
from shim.gateway.streaming.meter import (
    StreamUsageSnapshot,
    answer_characters,
    answer_markers,
    answer_texts,
    cache_split,
    completion_outcome,
    native_finish_reasons,
    settled_outcome,
)
from shim.gateway.usage import UsageLifecycle
from shim.observability.metrics import (
    COMPLETION_OUTCOMES_TOTAL,
    PROVIDER_LATENCY_MS,
    PROVIDER_REQUESTS_TOTAL,
    bounded_label,
)
from shim.observability.tracing import safe_attributes
from shim.privacy.classification import content_ref
from shim.privacy.pii_scrubber import MAX_ANALYZABLE_TEXT_LENGTH, PIIScrubberService

if TYPE_CHECKING:
    from shim.gateway.kernel.stage import TraceValue

logger = logging.getLogger(__name__)


class _ManagedStreamingResponse(StreamingResponse):
    def __init__(self, session: StreamSession, **kwargs: Any) -> None:
        self._session = session
        super().__init__(session, **kwargs)

    async def stream_response(self, send) -> None:
        try:
            await super().stream_response(send)
        finally:
            await self._session.aclose()


class ResponsePostprocessor:
    def __init__(
        self,
        usage: UsageLifecycle,
        *,
        heartbeat_interval_seconds: float,
        output_hash_salt: str | None,
    ) -> None:
        self._finalization_tasks: set[asyncio.Task[Any]] = set()
        self.usage = usage
        self.heartbeat_interval_seconds = heartbeat_interval_seconds
        self.output_hash_salt = output_hash_salt

    async def drain(self, timeout_seconds: float = 5.0) -> None:
        if self._finalization_tasks:
            _, pending = await asyncio.wait(
                tuple(self._finalization_tasks), timeout=timeout_seconds
            )
            for task in pending:
                task.cancel()

    def _start_response_scan(
        self, prepared: PreparedInference, text: str
    ) -> asyncio.Task[None]:
        task = asyncio.create_task(self._scan_response(prepared, text))
        self._finalization_tasks.add(task)
        task.add_done_callback(self._finalization_tasks.discard)
        return task

    async def _scan_response(self, prepared: PreparedInference, text: str) -> None:
        try:
            result = await asyncio.to_thread(
                scan_response, text, prepared, PIIScrubberService()
            )
        except Exception as exc:
            logger.warning("Response privacy scan failed type=%s", type(exc).__name__)
            result = {"response_entities": None, "error": True}
        try:
            await self.usage.record_response_privacy(prepared, result)
        except Exception as exc:
            logger.error("Response privacy record failed type=%s", type(exc).__name__)

    async def finalize(
        self,
        prepared: PreparedInference,
        response: ProviderNonStream | ProviderStream,
        *,
        stream_session: StreamSession | None,
    ) -> JSONResponse | StreamingResponse:
        if isinstance(response, ProviderStream):
            assert stream_session is not None
            stream_session.meter.started_at_monotonic = response.started_at_monotonic
            stream_session.bind(
                response.events,
                close=response.close,
                prefetched_events=response.prefetched_events,
            )
            prepared.timing.pause()
            return _ManagedStreamingResponse(
                stream_session,
                media_type="text/event-stream",
                headers=_gateway_headers(prepared, response.request_id),
            )

        if prepared.admission is None:
            raise ValueError("admission state is required")
        usage = _usage(response.payload, provider=str(prepared.provider))
        prompt_actual = usage.get("prompt")
        completion_actual = usage.get("completion")
        prompt_tokens = (
            prepared.admission.estimated_input_tokens
            if prompt_actual is None
            else prompt_actual
        )
        completion_tokens = (
            prepared.admission.maximum_output_tokens
            if completion_actual is None
            else completion_actual
        )
        fully_actual = prompt_actual is not None and completion_actual is not None
        raw_usage = response.payload.get(
            "usageMetadata" if str(prepared.provider) == "google" else "usage"
        )
        split = (
            cache_split(raw_usage, str(prepared.provider))
            if fully_actual and isinstance(raw_usage, Mapping)
            else None
        )
        provider = str(prepared.provider)
        lifecycle_status = _lifecycle_status(
            response.payload,
            provider=provider,
            expected_candidates=candidate_count(prepared),
        )
        response_model = response.payload.get("model")
        settlement_model = (
            response_model
            if prepared.model == UNSPECIFIED_PROVIDER_MODEL
            and lifecycle_status == "completed"
            and isinstance(response_model, str)
            and DEFAULT_PRICE_BOOK.supports(response_model, provider)
            else prepared.pricing_model
        )
        settlement_cost = compute_cost_usd(
            settlement_model,
            prompt_tokens,
            completion_tokens,
            provider=provider,
            unpriced=prepared.unpriced,
            cache=split,
            price=prepared.deployment_price,
        )
        if response.latency_ms is not None:
            labels = {
                "provider": bounded_label("provider", prepared.provider),
                "model": bounded_label("model", prepared.model),
            }
            PROVIDER_REQUESTS_TOTAL.labels(
                **labels,
                status=(
                    "success" if lifecycle_status == "completed" else "provider_error"
                ),
            ).inc()
            PROVIDER_LATENCY_MS.labels(**labels).observe(response.latency_ms)
        warn_after_answer(prepared, prompt_actual, split)
        gateway_response = JSONResponse(
            content=response.payload,
            headers=_gateway_headers(prepared, response.request_id),
        )
        completed_at = datetime.now(timezone.utc)
        finish_reasons = native_finish_reasons(response.payload, provider=provider)
        refusal, tool_call = answer_markers(response.payload)
        outcome = completion_outcome(
            finish_reasons,
            output_characters=answer_characters(response.payload),
            refusal=refusal,
            tool_call=tool_call,
        )
        terminal = StreamFinalization(
            terminal_status=lifecycle_status,
            usage=StreamUsageSnapshot(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                settlement_cost_usd=settlement_cost,
                provider_model=settlement_model,
                pricing_metadata=DEFAULT_PRICE_BOOK.resolved_price_metadata(
                    settlement_model,
                    provider,
                    input_tokens=prompt_tokens,
                    output_tokens=completion_tokens,
                    unpriced=prepared.unpriced,
                    cache=split,
                    price=prepared.deployment_price,
                ),
                estimated=not fully_actual,
                cache_split=split,
                provider_finish_reasons=finish_reasons,
                completion_outcome=settled_outcome(
                    outcome, completed=lifecycle_status == "completed"
                ),
                output_hash=(
                    content_ref(
                        self.output_hash_salt, bytes(gateway_response.body).decode()
                    )
                    if self.output_hash_salt is not None
                    else None
                ),
            ),
            completed_at=completed_at,
            error_code=(
                "PROVIDER_RESPONSE_FAILED" if lifecycle_status != "completed" else None
            ),
            error_message=(
                "The provider returned a terminal failure."
                if lifecycle_status != "completed"
                else None
            ),
            shim_latency_ms=prepared.timing.shim_latency_ms,
        )
        gateway_response.headers["X-Shim-Latency-Ms"] = str(terminal.shim_latency_ms)
        record_settled_usage(prepared, terminal.usage)
        await self.usage.finalize(prepared, terminal)
        if prepared.response_scan == "count":
            text = "\n".join(answer_texts(response.payload, tool_arguments=True))

            async def scan_after_send() -> None:
                await self._start_response_scan(prepared, text)

            # Starlette runs this after the body is sent.
            gateway_response.background = BackgroundTask(scan_after_send)
        return gateway_response

    def create_stream_session(
        self,
        prepared: PreparedInference,
    ) -> StreamSession:
        if prepared.admission is None:
            raise ValueError("admission state is required")
        provider_started_at = perf_counter()
        scan = prepared.response_scan == "count"
        meter = StreamMeter(
            provider=str(prepared.provider),
            requested_model=prepared.pricing_model,
            unpriced=prepared.unpriced,
            price=prepared.deployment_price,
            prompt_tokens_estimated=prepared.admission.estimated_input_tokens,
            expected_candidates=candidate_count(prepared),
            output_hash_salt=self.output_hash_salt,
            answer_text_limit=MAX_ANALYZABLE_TEXT_LENGTH + 1 if scan else 0,
        )

        async def record_stream_start() -> None:
            await self.usage.mark_stream_started(prepared)

        async def record_stream_heartbeat() -> None:
            await self.usage.heartbeat_stream(prepared)

        async def finalize_stream(terminal: StreamFinalization) -> None:
            warn_after_answer(
                prepared,
                None if terminal.usage.estimated else terminal.usage.prompt_tokens,
                terminal.usage.cache_split,
            )
            record_settled_usage(prepared, terminal.usage)
            await self.usage.finalize(prepared, terminal)
            if scan:
                # Detached: the stream body ends only after this finalizer returns.
                self._start_response_scan(prepared, "".join(meter.answer_text))

        def observe_terminal(terminal_status: str) -> None:
            status = {
                "completed": "success",
                "client_disconnected": "client_error",
                "cancelled": "client_error",
                "internal_error": "server_error",
            }.get(terminal_status, "provider_error")
            PROVIDER_REQUESTS_TOTAL.labels(
                provider=bounded_label("provider", prepared.provider),
                model=bounded_label("model", prepared.model),
                status=status,
            ).inc()
            PROVIDER_LATENCY_MS.labels(
                provider=bounded_label("provider", prepared.provider),
                model=bounded_label("model", prepared.model),
            ).observe((perf_counter() - provider_started_at) * 1000)

        return StreamSession(
            meter=meter,
            finalizer=finalize_stream,
            stream_start_recorder=record_stream_start,
            stream_heartbeat_recorder=record_stream_heartbeat,
            heartbeat_interval_seconds=self.heartbeat_interval_seconds,
            terminal_observer=observe_terminal,
            finalization_tasks=self._finalization_tasks,
            timing=prepared.timing,
        )


def warn_after_answer(
    prepared: PreparedInference, prompt_tokens: int | None, split: CacheSplit | None
) -> None:
    """Warn from the provider's usage; ``prompt_tokens`` is None when it was estimated."""

    if prompt_tokens is not None and prepared.target is None:
        threshold = DEFAULT_PRICE_BOOK.resolve(
            prepared.pricing_model, str(prepared.provider)
        ).large_context_threshold
        if threshold is not None and prompt_tokens > threshold:
            prepared.warn("LARGE_CONTEXT_PRICE")
    # Anthropic returns no error for a cache_control it did not apply.
    if (
        prepared.provider == "anthropic"
        and split == (0, 0, 0)
        and _has_cache_control(prepared.payload)
    ):
        prepared.warn("CACHE_NOT_APPLIED")


def _has_cache_control(payload: Mapping[str, object]) -> bool:
    """Top-level, system, tool and message-content breakpoints; not a tool schema's keys."""

    def blocks(value: object) -> list[object]:
        return value if isinstance(value, list) else []

    candidates = [
        payload,
        *blocks(payload.get("system")),
        *blocks(payload.get("tools")),
        *(
            block
            for message in blocks(payload.get("messages"))
            if isinstance(message, Mapping)
            for block in blocks(message.get("content"))
        ),
    ]
    return any(
        isinstance(block, Mapping) and "cache_control" in block for block in candidates
    )


def record_settled_usage(
    prepared: PreparedInference, usage: StreamUsageSnapshot
) -> None:
    if usage.completion_outcome is not None:
        COMPLETION_OUTCOMES_TOTAL.labels(
            provider=bounded_label("provider", prepared.provider),
            outcome=bounded_label("outcome", usage.completion_outcome),
        ).inc()
    span = trace.get_current_span()
    if not span.is_recording():
        return
    provider = str(prepared.provider)
    priced = DEFAULT_PRICE_BOOK.supports(usage.provider_model, provider)
    finish_reasons = sorted(set((usage.provider_finish_reasons or {}).values()))
    span.set_attributes(
        safe_attributes(
            {
                "gen_ai.request.model": usage.provider_model if priced else "unpriced",
                "gen_ai.usage.input_tokens": usage.prompt_tokens,
                "gen_ai.usage.output_tokens": usage.completion_tokens,
                "gen_ai.response.finish_reasons": ",".join(finish_reasons) or None,
                "shim.cost_usd": (
                    str(usage.settlement_cost_usd)
                    if priced and usage.settlement_cost_usd is not None
                    else None
                ),
                "shim.usage_estimated": usage.estimated,
            }
        )
    )


class PostprocessStage:
    name = "postprocess"

    def __init__(
        self,
        postprocessor: ResponsePostprocessor,
        prepared: PreparedInference,
        *,
        stream_session: StreamSession | None,
    ) -> None:
        self.postprocessor = postprocessor
        self.prepared = prepared
        self.stream_session = stream_session

    async def run(
        self,
        value: ProviderNonStream | ProviderStream,
    ) -> JSONResponse | StreamingResponse:
        return await self.postprocessor.finalize(
            self.prepared,
            value,
            stream_session=self.stream_session,
        )

    def trace_metadata(
        self,
        output: JSONResponse | StreamingResponse,
    ) -> Mapping[str, TraceValue]:
        return {
            "status_code": output.status_code,
            "streaming": isinstance(output, StreamingResponse),
        }


def _usage(
    payload: Mapping[str, Any],
    *,
    provider: str,
) -> dict[str, int | None]:
    usage = payload.get("usageMetadata" if provider == "google" else "usage")
    if not isinstance(usage, Mapping):
        return {"prompt": None, "completion": None}
    if provider == "google":
        prompt = _sum_counts(
            _token_count(usage.get("promptTokenCount")),
            _token_count(usage.get("toolUsePromptTokenCount")),
        )
        completion = _sum_counts(
            _token_count(usage.get("candidatesTokenCount")),
            _token_count(usage.get("thoughtsTokenCount")),
        )
        total = _token_count(usage.get("totalTokenCount"))
        if prompt is None and completion is not None and total is not None:
            prompt = total - completion if total >= completion else None
        if completion is None and prompt is not None and total is not None:
            completion = total - prompt if total >= prompt else None
        return {"prompt": prompt, "completion": completion}
    prompt = _token_count(usage.get("prompt_tokens", usage.get("input_tokens")))
    if provider == "anthropic":
        prompt = _sum_counts(
            prompt,
            _token_count(usage.get("cache_creation_input_tokens")),
            _token_count(usage.get("cache_read_input_tokens")),
        )
    return {
        "prompt": prompt,
        "completion": _token_count(
            usage.get("completion_tokens", usage.get("output_tokens"))
        ),
    }


def _lifecycle_status(
    payload: Mapping[str, Any],
    *,
    provider: str,
    expected_candidates: int,
) -> StreamTerminalStatus:
    prompt_feedback = payload.get("promptFeedback")
    if (
        provider == "google"
        and isinstance(prompt_feedback, Mapping)
        and prompt_feedback.get("blockReason")
    ):
        return "provider_error"
    if provider == "google":
        candidates = payload.get("candidates")
        if not isinstance(candidates, list):
            return "provider_error"
        finished: set[int] = set()
        for position, candidate in enumerate(candidates):
            if not isinstance(candidate, Mapping) or not candidate.get("finishReason"):
                continue
            index = candidate.get("index", position)
            if isinstance(index, int) and not isinstance(index, bool):
                finished.add(index)
        if len(finished) < expected_candidates:
            return "provider_error"
    if payload.get("type") == "error" or isinstance(payload.get("error"), Mapping):
        return "provider_error"
    status = str(payload.get("status", "completed")).casefold()
    if status in {"error", "failed"}:
        return "provider_error"
    return "cancelled" if status == "cancelled" else "completed"


def _token_count(value: Any) -> int | None:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        else None
    )


def _sum_counts(*values: int | None) -> int | None:
    present = [value for value in values if value is not None]
    return sum(present) if present else None


def _gateway_headers(
    prepared: PreparedInference,
    upstream_request_id: str | None,
) -> dict[str, str]:
    headers = {"X-Shim-Request-Id": str(prepared.request_id)}
    if prepared.warnings:
        headers["X-Shim-Warnings"] = ",".join(prepared.warnings)
    if upstream_request_id:
        header = {
            "anthropic": "request-id",
            "google": "x-goog-request-id",
        }.get(str(prepared.provider), "x-request-id")
        headers[header] = upstream_request_id
    return headers
