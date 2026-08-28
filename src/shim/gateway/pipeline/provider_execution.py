"""Shared provider execution results and accounting stage."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from email.utils import parsedate_to_datetime
from inspect import signature
from time import perf_counter
from typing import Any

from shim.gateway.kernel.result import PreparedInference
from shim.gateway.kernel.stage import TraceValue
from shim.gateway.usage import UsageLifecycle
from shim.observability.metrics import (
    PROVIDER_LATENCY_MS,
    PROVIDER_REQUESTS_TOTAL,
    bounded_label,
)


@dataclass(slots=True)
class ProviderCallError(RuntimeError):
    status_code: int
    error_code: str
    retryable: bool
    provider: str
    request_id: str | None = None
    retry_after: str | None = None

    def __str__(self) -> str:
        return self.error_code


@dataclass(frozen=True, slots=True)
class ProviderNonStream:
    payload: dict[str, Any]
    request_id: str | None
    latency_ms: float | None = None


@dataclass(frozen=True, slots=True)
class ProviderStream:
    events: AsyncIterator[bytes]
    request_id: str | None
    close: Callable[[], Awaitable[None]]
    prefetched_events: tuple[bytes, ...] = ()


class ProviderExecutionStage:
    name = "provider_execution"

    def __init__(
        self,
        invocation,
        execution: Any,
        usage: UsageLifecycle,
    ) -> None:
        self.invocation = invocation
        self.execution = execution
        self.usage = usage

    async def run(self, value: PreparedInference) -> ProviderNonStream | ProviderStream:
        async def mark_started() -> None:
            await self.usage.mark_provider_started(value)

        started_at = perf_counter()
        try:
            output = await self.execution.execute(
                invocation=self.invocation,
                prepared=value,
                provider_start_callback=mark_started,
            )
        except ProviderCallError:
            _observe_provider(value, "provider_error", started_at)
            raise
        if isinstance(output, ProviderNonStream):
            return replace(output, latency_ms=(perf_counter() - started_at) * 1_000)
        return output

    def trace_metadata(
        self,
        output: ProviderNonStream | ProviderStream,
    ) -> Mapping[str, TraceValue]:
        return {
            "provider": str(self.invocation.provider),
            "streaming": isinstance(output, ProviderStream),
        }


_SDK_TRANSPORT_PARAMETERS = {
    "extra_body",
    "extra_headers",
    "extra_query",
    "timeout",
}


def sdk_create_kwargs(
    create: Callable[..., Any],
    payload: Mapping[str, Any],
    *,
    reserved: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Keep SDK-known body fields typed and pass future fields through unchanged."""

    parameters = signature(create).parameters.keys() - _SDK_TRANSPORT_PARAMETERS
    parameters -= reserved
    kwargs = {key: value for key, value in payload.items() if key in parameters}
    extra_body = {key: value for key, value in payload.items() if key not in parameters}
    if extra_body:
        kwargs["extra_body"] = extra_body
    return kwargs


def select_headers(
    headers: Mapping[str, str],
    allowed: Mapping[str, str],
) -> dict[str, str]:
    return {
        allowed[key.casefold()]: value
        for key, value in headers.items()
        if key.casefold() in allowed
    }


def retry_after_header(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", {})
    value = headers.get("retry-after") if hasattr(headers, "get") else None
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > 128 or not value.isascii():
        return None
    if value.isdecimal():
        return value
    try:
        parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return value


def _observe_provider(
    prepared: PreparedInference,
    status: str,
    started_at: float,
) -> None:
    labels = {
        "provider": bounded_label("provider", prepared.provider),
        "model": bounded_label("model", prepared.model),
    }
    PROVIDER_REQUESTS_TOTAL.labels(**labels, status=status).inc()
    PROVIDER_LATENCY_MS.labels(**labels).observe((perf_counter() - started_at) * 1_000)
