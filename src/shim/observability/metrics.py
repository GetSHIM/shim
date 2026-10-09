"""Finite-cardinality Prometheus instruments for gateway operations."""

from __future__ import annotations

from types import MappingProxyType
from typing import Final

from prometheus_client import Counter, Gauge, Histogram


LABEL_VALUES: Final = MappingProxyType(
    {
        "endpoint": frozenset(
            {
                "/v1/chat/completions",
                "/v1/responses",
                "/v1/messages",
                "/v1/messages/count_tokens",
                "/v1beta/models/*:generateContent",
                "/v1beta/models/*:streamGenerateContent",
                "/v1/scan",
                "/v1/scan/usage",
            }
        ),
        "status": frozenset(
            {
                "success",
                "rejected",
                "client_error",
                "provider_error",
                "server_error",
                "settled",
                "refunded",
                "failed",
                "reserved",
                "replayed",
            }
        ),
        "tenant_tier": frozenset(
            {
                "free",
                "managed",
                "agency",
                "enterprise",
                "custom",
                "default",
                "local",
            }
        ),
        "provider": frozenset({"openai", "anthropic", "google"}),
        "model": frozenset({"gpt-*", "claude-*", "gemini-*", "other"}),
        "terminal_state": frozenset(
            {
                "completed",
                "provider_error",
                "client_disconnected",
                "timeout",
                "cancelled",
                "internal_error",
            }
        ),
        "event_type": frozenset(
            {
                "analytics.request_completed",
                "analytics.request_failed",
                "audit.chain_append_requested",
                "budget.threshold_crossed",
                "compliance.connector_delivery_requested",
                "gateway.reconciliation",
            }
        ),
        "entity_type": frozenset(
            {
                "PERSON",
                "EMAIL_ADDRESS",
                "PHONE_NUMBER",
                "CREDIT_CARD",
                "IBAN_CODE",
                "IP_ADDRESS",
                "LOCATION",
                "NRP",
                "DATE_TIME",
                "URL",
                "CRYPTO",
                "MEDICAL_LICENSE",
                "US_SSN",
                "TR_NATIONAL_ID",
                "TR_VKN",
                "TR_LICENSE_PLATE",
                "SECRET",
                "DB_URI",
                "FILE_PATH",
                "MAC_ADDRESS",
            }
        ),
        "method": frozenset({"GET", "POST"}),
        "protocol": frozenset(
            {
                "chat",
                "responses",
                "messages",
                "count_tokens",
                "generate_content",
                "scan",
            }
        ),
        "actor_type": frozenset({"api_key", "user_jwt", "internal"}),
        "source_endpoint": frozenset(
            {"chat.completions", "responses", "messages", "generateContent", "scan"}
        ),
        "action": frozenset({"disabled", "detected", "scrubbed"}),
        "outcome": frozenset({"complete", "truncated", "empty", "refused", "filtered"}),
    }
)


REQUESTS_TOTAL = Counter(
    "requests_total",
    "Gateway requests by endpoint, outcome, and tenant tier.",
    ("endpoint", "status", "tenant_tier"),
)
PROVIDER_REQUESTS_TOTAL = Counter(
    "provider_requests_total",
    "Provider requests by provider, model family, and outcome.",
    ("provider", "model", "status"),
)
PROVIDER_LATENCY_MS = Histogram(
    "provider_latency_ms",
    "Provider request latency in milliseconds.",
    ("provider", "model"),
    buckets=(
        5,
        10,
        25,
        50,
        100,
        250,
        500,
        1_000,
        2_500,
        5_000,
        10_000,
        30_000,
        60_000,
        120_000,
        300_000,
        600_000,
    ),
)
TIME_TO_FIRST_TOKEN_SECONDS = Histogram(
    "shim_time_to_first_token_seconds",
    "Time from the provider call to the first streamed content, in seconds.",
    ("provider", "model"),
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600),
)
REQUESTS_IN_FLIGHT = Gauge(
    "shim_requests_in_flight",
    "Provider calls in progress, by provider.",
    ("provider",),
)
STREAM_TERMINAL_STATE_TOTAL = Counter(
    "stream_terminal_state_total",
    "Streaming sessions by terminal state.",
    ("terminal_state",),
)
PRIVACY_DETECTION_TOTAL = Counter(
    "privacy_detection_total",
    "Detected privacy entities by entity type.",
    ("entity_type",),
)
PRIVACY_RESPONSE_DETECTION_TOTAL = Counter(
    "shim_privacy_response_detection_total",
    "Distinct values the model returned that the request did not carry, by entity type.",
    ("entity_type",),
)
WARNINGS_TOTAL = Counter(
    "shim_warnings_total",
    "Requests that carried an X-Shim-Warnings code, by code.",
    ("code",),
)
PRIVACY_BULK_DISCLOSURES_TOTAL = Counter(
    "shim_privacy_bulk_disclosures_total",
    "Requests whose distinct detected values reached the bulk threshold.",
    ("provider",),
)


def bounded_label(kind: str, value: object) -> str:
    """Map an arbitrary runtime value into a registered label vocabulary."""

    if kind not in LABEL_VALUES:
        raise ValueError(f"unknown metric label kind: {kind}")
    normalized = str(value or "").strip()
    if kind == "endpoint":
        if normalized.startswith("/api/v1/"):
            normalized = normalized.removeprefix("/api")
        if normalized.startswith("/v1beta/models/"):
            for operation in ("generateContent", "streamGenerateContent"):
                if normalized.endswith(f":{operation}"):
                    normalized = f"/v1beta/models/*:{operation}"
                    break
    if kind == "model":
        return _model_family(normalized)
    if kind == "entity_type":
        normalized = normalized.upper()
    if normalized in LABEL_VALUES[kind]:
        return normalized
    return "other"


def _model_family(model: str) -> str:
    folded = model.casefold().rsplit("/", 1)[-1]
    for prefix in ("gpt", "claude", "gemini"):
        if folded.startswith(prefix):
            return f"{prefix}-*"
    return "other"


COMPLETION_OUTCOMES_TOTAL = Counter(
    "shim_completion_outcomes_total",
    "Settled requests by provider and completion outcome.",
    ("provider", "outcome"),
)
LOCAL_USAGE_DROPPED_TOTAL = Counter(
    "shim_local_usage_dropped_total",
    "Non-durable local usage events dropped by the bounded writer.",
    ["reason"],
)
