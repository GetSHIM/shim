"""Native provider response settlement."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from time import perf_counter
from typing import TYPE_CHECKING, Any

from fastapi.responses import JSONResponse, StreamingResponse

from shim.billing.pricing import DEFAULT_PRICE_BOOK, compute_cost_usd
from shim.gateway.kernel.result import PreparedInference, UNSPECIFIED_PROVIDER_MODEL
from shim.gateway.pipeline.provider_execution import ProviderNonStream, ProviderStream
from shim.gateway.streaming import (
    StreamFinalization,
    StreamMeter,
    StreamSession,
    StreamTerminalStatus,
)
from shim.gateway.streaming.meter import StreamUsageSnapshot
from shim.gateway.usage import UsageLifecycle
from shim.observability.metrics import (
    PROVIDER_LATENCY_MS,
    PROVIDER_REQUESTS_TOTAL,
    bounded_label,
)
from shim.privacy.classification import content_ref

if TYPE_CHECKING:
    from shim.gateway.kernel.stage import TraceValue


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
        self.usage = usage
        self.heartbeat_interval_seconds = heartbeat_interval_seconds
        self.output_hash_salt = output_hash_salt

    async def finalize(
        self,
        prepared: PreparedInference,
        response: ProviderNonStream | ProviderStream,
        *,
        stream_session: StreamSession | None,
    ) -> JSONResponse | StreamingResponse:
        if isinstance(response, ProviderStream):
            assert stream_session is not None
            stream_session.bind(
                response.events,
                close=response.close,
                prefetched_events=response.prefetched_events,
            )
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
        provider = str(prepared.provider)
        lifecycle_status = _lifecycle_status(
            response.payload,
            provider=provider,
            expected_candidates=_expected_candidates(prepared),
        )
        response_model = response.payload.get("model")
        settlement_model = (
            response_model
            if prepared.model == UNSPECIFIED_PROVIDER_MODEL
            and lifecycle_status == "completed"
            and isinstance(response_model, str)
            and DEFAULT_PRICE_BOOK.supports(response_model, provider)
            else prepared.model
        )
        settlement_cost = compute_cost_usd(
            settlement_model,
            prompt_tokens,
            completion_tokens,
            provider=provider,
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
        body = json.dumps(
            response.payload,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        gateway_response = JSONResponse(
            content=response.payload,
            headers=_gateway_headers(prepared, response.request_id),
        )
        completed_at = datetime.now(timezone.utc)
        await self.usage.finalize(
            prepared,
            StreamFinalization(
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
                    ),
                    estimated=not fully_actual,
                    output_hash=(
                        content_ref(self.output_hash_salt, body)
                        if self.output_hash_salt is not None
                        else None
                    ),
                ),
                completed_at=completed_at,
                error_code=(
                    "PROVIDER_RESPONSE_FAILED"
                    if lifecycle_status != "completed"
                    else None
                ),
                error_message=(
                    "The provider returned a terminal failure."
                    if lifecycle_status != "completed"
                    else None
                ),
            ),
        )
        return gateway_response

    def create_stream_session(
        self,
        prepared: PreparedInference,
    ) -> StreamSession:
        if prepared.admission is None:
            raise ValueError("admission state is required")
        provider_started_at = perf_counter()

        async def record_stream_start() -> None:
            await self.usage.mark_stream_started(prepared)

        async def record_stream_heartbeat() -> None:
            await self.usage.heartbeat_stream(prepared)

        async def finalize_stream(terminal: StreamFinalization) -> None:
            await self.usage.finalize(prepared, terminal)

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
            meter=StreamMeter(
                provider=str(prepared.provider),
                requested_model=prepared.model,
                prompt_tokens_estimated=prepared.admission.estimated_input_tokens,
                expected_candidates=_expected_candidates(prepared),
                output_hash_salt=self.output_hash_salt,
            ),
            finalizer=finalize_stream,
            stream_start_recorder=record_stream_start,
            stream_heartbeat_recorder=record_stream_heartbeat,
            heartbeat_interval_seconds=self.heartbeat_interval_seconds,
            terminal_observer=observe_terminal,
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


def _expected_candidates(prepared: PreparedInference) -> int:
    if prepared.provider == "openai" and prepared.protocol == "chat":
        count = prepared.payload.get("n", 1)
    elif prepared.provider == "google":
        config = prepared.payload.get("generationConfig")
        count = config.get("candidateCount", 1) if isinstance(config, Mapping) else 1
    else:
        count = 1
    return (
        count
        if isinstance(count, int) and not isinstance(count, bool) and count > 0
        else 1
    )


def _gateway_headers(
    prepared: PreparedInference,
    upstream_request_id: str | None,
) -> dict[str, str]:
    headers = {"X-Shim-Request-Id": str(prepared.request_id)}
    if upstream_request_id:
        header = {
            "anthropic": "request-id",
            "google": "x-goog-request-id",
        }.get(str(prepared.provider), "x-request-id")
        headers[header] = upstream_request_id
    return headers
