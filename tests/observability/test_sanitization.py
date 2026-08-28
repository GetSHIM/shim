from __future__ import annotations

import json
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import shim.observability.logging as logging_module
import shim.observability.tracing as tracing_module
from shim.gateway.kernel.runtime import _STAGE_SPANS
from shim.observability.logging import _sanitize_error_event
from shim.observability.metrics import bounded_label
from shim.observability.tracing import SPAN_NAMES, safe_attributes


def _registered_metric_names(module: str) -> set[str]:
    code = (
        f"import {module}\n"
        "import json\n"
        "from prometheus_client import REGISTRY\n"
        "print(json.dumps(sorted(metric.name for metric in REGISTRY.collect())))"
    )
    output = subprocess.check_output([sys.executable, "-c", code], text=True)
    return set(json.loads(output.splitlines()[-1]))


def test_error_event_drops_bodies_secrets_and_exception_text() -> None:
    event = {
        "request": {
            "cookies": {"session": "private"},
            "data": {"prompt": "private"},
            "env": {"REMOTE_USER": "private"},
            "headers": {"authorization": "Bearer secret", "accept": "json"},
            "query_string": "api_key=private",
            "url": "https://example.test/chat?api_key=private",
        },
        "exception": {
            "values": [
                {
                    "value": "credential leaked",
                    "stacktrace": {"frames": [{"vars": {"token": "secret"}}]},
                }
            ]
        },
        "breadcrumbs": {"values": [{"message": "private"}]},
        "extra": {"prompt": "private"},
        "contexts": {"tenant": "private"},
        "logentry": {"message": "private"},
        "message": "private",
        "user": {"email": "private@example.test"},
    }

    sanitized = _sanitize_error_event(event, {})

    assert set(sanitized["request"]) == {"headers"}
    assert sanitized["request"]["headers"] == {
        "authorization": "[redacted]",
        "accept": "[omitted]",
    }
    exception = sanitized["exception"]["values"][0]
    assert exception["value"] == "[redacted]"
    assert "vars" not in exception["stacktrace"]["frames"][0]
    assert (
        not {
            "breadcrumbs",
            "contexts",
            "extra",
            "logentry",
            "message",
            "user",
        }
        & sanitized.keys()
    )


def test_sentry_is_error_only_and_keeps_the_error_sanitizer(monkeypatch) -> None:
    sentry_init = Mock()
    monkeypatch.setattr(logging_module.sentry_sdk, "init", sentry_init)

    logging_module.configure_error_reporting(
        sentry_dsn="https://public@example.test/1",
        environment="test",
    )

    options = sentry_init.call_args.kwargs
    assert options["dsn"] == "https://public@example.test/1"
    assert options["environment"] == "test"
    assert options["traces_sample_rate"] == 0.0
    assert options["before_send"] is _sanitize_error_event


def test_trace_attributes_reject_unregistered_sensitive_fields() -> None:
    with pytest.raises(ValueError, match="unsafe trace attribute"):
        safe_attributes({"prompt": "private"})


def test_every_gateway_stage_span_is_registered() -> None:
    assert set(_STAGE_SPANS.values()) <= SPAN_NAMES


def test_public_metrics_are_bounded_and_exclude_enterprise_families() -> None:
    assert bounded_label("model", "gpt-5.4") == "gpt-*"
    assert bounded_label("provider", "tenant-defined-provider") == "other"
    public = {
        "privacy_detection",
        "provider_latency_ms",
        "provider_requests",
        "requests",
        "stream_terminal_state",
    }
    enterprise_only = {
        "audit_worker_lag_seconds",
        "outbox_dead_letter",
        "outbox_lag_seconds",
        "quota_reservation",
        "usage_settlement",
    }

    community_metrics = _registered_metric_names("shim.application")
    assert public <= community_metrics
    assert community_metrics.isdisjoint(enterprise_only)


def test_tracing_shutdown_releases_span_processors(monkeypatch) -> None:
    provider = SimpleNamespace(shutdown=Mock())
    monkeypatch.setattr(tracing_module, "_provider", provider)

    tracing_module.shutdown_tracing()

    provider.shutdown.assert_called_once_with()


def test_tracing_appends_signal_path_to_otlp_base_endpoint(monkeypatch) -> None:
    provider = Mock()
    exporter_factory = Mock()
    monkeypatch.setattr(tracing_module, "_provider", None)
    monkeypatch.setattr(tracing_module, "TracerProvider", Mock(return_value=provider))
    monkeypatch.setattr(tracing_module, "OTLPSpanExporter", exporter_factory)
    monkeypatch.setattr(tracing_module, "BatchSpanProcessor", Mock())
    monkeypatch.setattr(tracing_module.trace, "set_tracer_provider", Mock())

    tracing_module.configure_tracing(
        endpoint="https://collector.test/otel/",
        service_name="shim-test",
    )

    exporter_factory.assert_called_once_with(
        endpoint="https://collector.test/otel/v1/traces"
    )
