from __future__ import annotations

from collections.abc import Iterator
from io import StringIO
import json
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
import pytest

from shim.application import create_community_app
from shim.core.community_config import CommunitySettings
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
    assert bounded_label("outcome", "refused") == "refused"
    assert bounded_label("outcome", "provider-defined-outcome") == "other"
    assert bounded_label("entity_type", "TR_LICENSE_PLATE") == "TR_LICENSE_PLATE"
    assert bounded_label("entity_type", "TR_PLATE_GUESS") == "other"
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


def test_usage_attribute_keys_are_allowlisted_and_unknown_keys_still_refused() -> None:
    usage = {
        "gen_ai.request.model": "gpt-5.6-luna",
        "gen_ai.usage.input_tokens": 5,
        "gen_ai.usage.output_tokens": 3,
        "gen_ai.response.finish_reasons": "stop",
        "shim.cost_usd": "0.0001",
        "shim.usage_estimated": False,
    }

    assert safe_attributes(usage) == usage
    with pytest.raises(ValueError, match="unsafe trace attribute keys"):
        safe_attributes({"gen_ai.prompt": "hello"})


@pytest.fixture
def recorded_spans(monkeypatch: pytest.MonkeyPatch) -> Iterator[InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(tracing_module.trace, "get_tracer", provider.get_tracer)
    yield exporter
    provider.shutdown()


@pytest.mark.asyncio
async def test_closing_spans_carry_model_tokens_and_cost(
    recorded_spans: InMemorySpanExporter,
) -> None:
    prompt = "observability-probe-sentence"
    completion = {
        "id": "chatcmpl_spans",
        "object": "chat.completion",
        "created": 1,
        "model": "gpt-5.6-luna",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "ok"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
    }
    chunk = {
        **completion,
        "object": "chat.completion.chunk",
        "choices": [{"index": 0, "delta": {"content": "ok"}, "finish_reason": "stop"}],
    }

    def upstream(request: httpx.Request) -> httpx.Response:
        if json.loads(request.content).get("stream"):
            return httpx.Response(
                200,
                text=f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n",
                headers={"content-type": "text/event-stream"},
            )
        return httpx.Response(200, json=completion)

    outbound = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    application = create_community_app(
        CommunitySettings(
            OPENAI_BASE_URL="https://upstream.test/v1",
            OPENAI_API_KEY="sk-provider",
            BACKEND_CORS_ORIGINS=[],
            _env_file=None,
        ),
        http_client=outbound,
        event_stream=StringIO(),
    )
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="http://127.0.0.1",
        ) as client,
    ):
        for stream in (False, True):
            response = await client.post(
                "/v1/chat/completions",
                headers={"x-openai-api-key": "sk-provider"},
                json={
                    "model": "gpt-5.6-luna",
                    "stream": stream,
                    "messages": [{"role": "user", "content": f"{prompt} {stream}"}],
                },
            )
            assert response.status_code == 200
    await outbound.aclose()

    finished = recorded_spans.get_finished_spans()
    postprocess, stream_spans = (
        [span for span in finished if span.name == name]
        for name in ("gateway.postprocess", "gateway.stream")
    )
    # The JSON request ran first; the stream request's postprocess span closes before usage exists.
    json_span = postprocess[0].attributes or {}
    stream_span = stream_spans[0].attributes or {}
    assert json_span["gen_ai.request.model"] == "gpt-5.6-luna"
    assert json_span["gen_ai.usage.input_tokens"] == 5
    assert json_span["gen_ai.usage.output_tokens"] == 3
    assert json_span["gen_ai.response.finish_reasons"] == "stop"
    assert json_span["shim.usage_estimated"] is False
    assert float(str(json_span["shim.cost_usd"])) > 0
    assert stream_span["gen_ai.request.model"] == "gpt-5.6-luna"
    assert {"gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens"} <= set(
        stream_span
    )
    for span in recorded_spans.get_finished_spans():
        assert all(
            prompt not in str(value) for value in (span.attributes or {}).values()
        )
