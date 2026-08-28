"""Allowlisted, privacy-safe OpenTelemetry tracing."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
import logging
from threading import Lock
from typing import Final

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from shim.observability.metrics import LABEL_VALUES, bounded_label

logger = logging.getLogger(__name__)

SPAN_NAMES: Final[frozenset[str]] = frozenset(
    {
        "gateway.request",
        "gateway.auth",
        "gateway.admission",
        "gateway.quota_reservation",
        "gateway.privacy",
        "gateway.provider_call",
        "gateway.postprocess",
        "gateway.stream",
        "gateway.reconciliation",
        "gateway.audit_intent",
        "gateway.outbox_append",
    }
)

ATTRIBUTE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "action",
        "actor_type",
        "endpoint",
        "entity_type",
        "estimated_input_tokens",
        "event_type",
        "maximum_output_tokens",
        "method",
        "model",
        "pii_detected",
        "protocol",
        "provider",
        "reason",
        "repeat_chain_length",
        "repeat_status",
        "reserved",
        "source_endpoint",
        "status",
        "status_code",
        "streaming",
        "tenant_tier",
        "terminal_state",
    }
)

_provider: TracerProvider | None = None
_provider_lock = Lock()


def configure_tracing(*, endpoint: str | None, service_name: str) -> None:
    global _provider
    if _provider is not None:
        return
    with _provider_lock:
        if _provider is not None:
            return
        provider = TracerProvider(
            resource=Resource.create({"service.name": service_name})
        )
        if endpoint:
            provider.add_span_processor(
                BatchSpanProcessor(
                    OTLPSpanExporter(endpoint=f"{endpoint.rstrip('/')}/v1/traces")
                )
            )
        trace.set_tracer_provider(provider)
        _provider = provider
        logger.info(
            "OpenTelemetry tracing initialized (otlp_export=%s)", bool(endpoint)
        )


def shutdown_tracing() -> None:
    if _provider is not None:
        _provider.shutdown()


def safe_attributes(
    attributes: Mapping[str, object],
) -> dict[str, str | bool | int | float]:
    unexpected = set(attributes) - ATTRIBUTE_KEYS
    if unexpected:
        raise ValueError(f"unsafe trace attribute keys: {sorted(unexpected)!r}")
    output: dict[str, str | bool | int | float] = {}
    for key, value in attributes.items():
        if value is None:
            continue
        if key in LABEL_VALUES:
            output[key] = bounded_label(key, value)
        elif isinstance(value, (str, bool, int, float)):
            output[key] = value
        else:
            raise TypeError(f"unsupported trace attribute value for {key!r}")
    return output


@contextmanager
def start_span(name: str, **attributes: object) -> Iterator[trace.Span]:
    if name not in SPAN_NAMES:
        raise ValueError(f"unregistered gateway span: {name!r}")
    tracer = trace.get_tracer("shim.gateway")
    with tracer.start_as_current_span(
        name,
        attributes=safe_attributes(attributes),
        record_exception=False,
        set_status_on_exception=False,
    ) as span:
        yield span
