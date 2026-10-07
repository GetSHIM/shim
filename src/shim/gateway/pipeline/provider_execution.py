"""Shared provider execution results and accounting stage."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from email.utils import parsedate_to_datetime
from inspect import signature
from time import perf_counter
from typing import Any

import httpx

from shim.core.circuit_breaker import CircuitBreaker
from shim.gateway.kernel.result import PreparedInference
from shim.gateway.kernel.stage import TraceValue
from shim.gateway.streaming.session import MeterOnly
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
    message: str | None = field(default=None, repr=False)
    shim_request_id: str | None = None

    def __str__(self) -> str:
        return self.error_code


@dataclass(frozen=True, slots=True)
class ProviderNonStream:
    payload: dict[str, Any]
    request_id: str | None
    latency_ms: float | None = None


@dataclass(frozen=True, slots=True)
class ProviderStream:
    events: AsyncIterator[bytes | MeterOnly]
    request_id: str | None
    close: Callable[[], Awaitable[None]]
    prefetched_events: tuple[bytes, ...] = ()
    started_at_monotonic: float | None = None


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
        provider_started_at: float | None = None

        async def mark_started() -> None:
            nonlocal provider_started_at
            await self.usage.mark_provider_started(value)
            provider_started_at = perf_counter()

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
        return replace(output, started_at_monotonic=provider_started_at)

    def trace_metadata(
        self,
        output: ProviderNonStream | ProviderStream,
    ) -> Mapping[str, TraceValue]:
        return {
            "provider": str(self.invocation.provider),
            "streaming": isinstance(output, ProviderStream),
        }


_GOOGLE_RPC_STATUSES = {
    400: "INVALID_ARGUMENT",
    401: "UNAUTHENTICATED",
    403: "PERMISSION_DENIED",
    404: "NOT_FOUND",
    408: "DEADLINE_EXCEEDED",
    409: "ABORTED",
    413: "INVALID_ARGUMENT",
    422: "INVALID_ARGUMENT",
    429: "RESOURCE_EXHAUSTED",
    500: "INTERNAL",
    502: "UNAVAILABLE",
    503: "UNAVAILABLE",
    504: "DEADLINE_EXCEEDED",
    529: "UNAVAILABLE",
}
_FORWARDED_REASON_STATUSES = frozenset({400, 404, 413, 422})
_REASON_LIMIT = 500
ERROR_HINTS = {
    "MISSING_API_KEY": "Send the shim key in Authorization: Bearer, x-shim-key, or the SDK's own key header.",
    "INVALID_API_KEY": "Check the shim key. A provider key is sent in x-provider-key, never as the shim key.",
    "INVALID_PROVIDER_CREDENTIAL": "Check the provider key sent in x-provider-key or configured on the gateway.",
    "INVALID_REQUEST": "Correct the request as the message says; sending it again unchanged fails again.",
    "REQUEST_TOO_LARGE": "Send a smaller request body.",
    "MODEL_NOT_FOUND": "List the available models with GET /v1/models.",
    "MODEL_NOT_PRICED": "Use a model listed by GET /v1/models.",
    "PROVIDER_NOT_ALLOWED": "Use a provider your tenant policy allows, or ask an administrator to allow this one.",
    "ZERO_RETENTION_REQUIRED": "Send a request the provider enforces zero retention for, as your tenant policy requires.",
    "RATE_LIMIT_EXCEEDED": "Wait the number of seconds in Retry-After, then retry.",
    "PRIVACY_POLICY_BLOCKED": "Remove the content the privacy policy blocks, or ask an administrator to change the policy.",
    "SECRET_BLOCKED": "Remove the credential from the request; the privacy policy refuses to send it.",
    "PII_BLOCKED": "Remove the personal data the message names, or ask an administrator to change the policy.",
    "PRIVACY_STATE_UNAVAILABLE": "Start a new conversation; the privacy state this one refers to is gone.",
    "PROVIDER_NOT_CONFIGURED": "Configure a provider key on the gateway or send one in x-provider-key.",
    "PROVIDER_RATE_LIMITED": "The provider's quota for your provider key is spent; wait for retry-after or raise that quota.",
    "PROVIDER_REJECTED_REQUEST": "Correct the request as the provider's message says; retrying it unchanged fails again.",
    "PROVIDER_UNAVAILABLE": "The provider failed or could not be reached; retry later.",
    "PROVIDER_TIMEOUT": "Retry, stream the response, or ask for fewer output tokens.",
    "INTERNAL_ERROR": "Retry later, and quote X-Shim-Request-Id if it persists.",
    "MODEL_NOT_ALLOWED": "Use a model this key may call, or ask an administrator to enable it.",
    "MODEL_NOT_REGISTERED": "Use a model registered for your tenant, listed by GET /v1/models.",
    "DEPLOYMENT_NOT_APPROVED": "Ask the gateway operator to approve the deployment's destination.",
    "DEPLOYMENT_UNHEALTHY": "Wait the number of seconds in Retry-After, or use another model.",
    "MODEL_PRICE_UNKNOWN": "Use a priced model, or ask an administrator to price this deployment.",
    "MONTHLY_QUOTA_EXCEEDED": "Wait for the next period, or ask an administrator to raise the quota.",
    "SPEND_LIMIT_EXCEEDED": "Ask an administrator to raise the spend limit, or wait for the next period.",
    "SCAN_LIMIT_EXCEEDED": "Wait for the next month, or ask an administrator to raise the scan limit.",
    "TENANT_NOT_FOUND": "Ask an administrator to check this key's tenant and plan.",
    "AUDIT_INTENT_FAILED": "Retry later; the request was not sent because its audit record could not be saved.",
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


def google_error(
    status_code: int, message: str, code: str | None, hint: str | None = None
) -> dict[str, Any]:
    error: dict[str, Any] = {
        "code": status_code,
        "message": message,
        "status": _GOOGLE_RPC_STATUSES.get(
            status_code, "INTERNAL" if status_code >= 500 else "INVALID_ARGUMENT"
        ),
    }
    if code:
        error["details"] = [
            {
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": code,
                "domain": "getshim.tech",
                **({"metadata": {"hint": hint}} if hint else {}),
            }
        ]
    return {"error": error}


def status_error_code(status_code: int) -> str:
    if status_code == 401:
        return "INVALID_PROVIDER_CREDENTIAL"
    if status_code == 403 or status_code in _FORWARDED_REASON_STATUSES:
        return "PROVIDER_REJECTED_REQUEST"
    return {408: "PROVIDER_TIMEOUT", 429: "PROVIDER_RATE_LIMITED"}.get(
        status_code, "PROVIDER_UNAVAILABLE"
    )


def provider_reason(status_code: int, body: object) -> str | None:
    """The provider's own message for a request it refused, still masked."""

    if status_code not in _FORWARDED_REASON_STATUSES or not isinstance(body, dict):
        return None
    error = body.get("error", body)
    message = error.get("message") if isinstance(error, dict) else None
    if not isinstance(message, str):
        return None
    return message.strip()[:_REASON_LIMIT] or None


def sdk_rejected_request(provider: str) -> ProviderCallError:
    return ProviderCallError(
        400,
        "INVALID_REQUEST",
        False,
        provider=provider,
        message="The request is missing a field or has a value the provider SDK refuses.",
    )


async def record_provider_error(
    circuit: CircuitBreaker,
    exc: Exception,
    status_code: int | None,
    sdk_error: type[Exception],
) -> None:
    """Count endpoint failures only; a rate limit belongs to the caller's quota."""

    if status_code == 429:
        await circuit.release_probe()
    elif (
        status_code is not None
        and 400 <= status_code < 500
        and status_code not in {408, 409}
    ):
        await circuit.record_success()
    elif isinstance(
        exc, (sdk_error, httpx.TransportError, TimeoutError, ProviderCallError)
    ):
        await circuit.record_failure()
    else:
        await circuit.release_probe()


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
