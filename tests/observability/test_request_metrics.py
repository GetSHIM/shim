from __future__ import annotations

from io import StringIO
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
from prometheus_client import REGISTRY
import pytest
from starlette.responses import Response

from shim.application import create_community_app
from shim.core.community_config import CommunitySettings
import shim.gateway.kernel.gateway_kernel as kernel_module
from shim.gateway.kernel.gateway_kernel import GatewayKernel
from shim.gateway.kernel.result import InferenceTiming
from shim.gateway.pipeline.postprocess import ResponsePostprocessor
from shim.gateway.pipeline.provider_execution import (
    ProviderCallError,
    ProviderNonStream,
    ProviderStream,
)
from shim.observability.metrics import PROVIDER_LATENCY_MS, REQUESTS_IN_FLIGHT
from shim.privacy.policies import PrivacyAction, PrivacyOutcome

_COMPLETION = {
    "id": "chatcmpl_metrics",
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
_CHUNK = {
    **_COMPLETION,
    "object": "chat.completion.chunk",
    "choices": [{"index": 0, "delta": {"content": "ok"}, "finish_reason": "stop"}],
}


def _in_flight(provider: str = "openai") -> float:
    return (
        REGISTRY.get_sample_value("shim_requests_in_flight", {"provider": provider})
        or 0.0
    )


def _first_token_count() -> float:
    return (
        REGISTRY.get_sample_value(
            "shim_time_to_first_token_seconds_count",
            {"provider": "openai", "model": "gpt-*"},
        )
        or 0.0
    )


def test_provider_latency_buckets_reach_ten_minutes() -> None:
    assert PROVIDER_LATENCY_MS._upper_bounds == [
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
        float("inf"),
    ]


@pytest.mark.asyncio
async def test_json_and_stream_calls_leave_nothing_in_flight_and_only_streams_have_a_first_token() -> (
    None
):
    def upstream(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if "fail" in body["messages"][0]["content"]:
            return httpx.Response(500, json={"error": {"message": "upstream down"}})
        if body.get("stream"):
            return httpx.Response(
                200,
                text=f"data: {json.dumps(_CHUNK)}\n\ndata: [DONE]\n\n",
                headers={"content-type": "text/event-stream"},
            )
        return httpx.Response(200, json=_COMPLETION)

    outbound = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    application = create_community_app(
        CommunitySettings(
            OPENAI_BASE_URL="https://upstream.test/v1",
            BACKEND_CORS_ORIGINS=[],
            _env_file=None,
        ),
        http_client=outbound,
        event_stream=StringIO(),
    )
    before, first_tokens = _in_flight(), _first_token_count()
    seen = []
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application), base_url="http://127.0.0.1"
        ) as client,
    ):
        for content, stream in (("json", False), ("fail", False), ("stream", True)):
            response = await client.post(
                "/v1/chat/completions",
                headers={"x-provider-key": "sk-provider"},
                json={
                    "model": "gpt-5.6-luna",
                    "stream": stream,
                    "messages": [{"role": "user", "content": content}],
                },
            )
            seen.append(
                (
                    response.status_code,
                    _in_flight() - before,
                    _first_token_count() - first_tokens,
                )
            )
    await outbound.aclose()

    assert seen == [(200, 0, 0), (500, 0, 0), (200, 0, 1)]


def _stream_prepared() -> SimpleNamespace:
    return SimpleNamespace(
        provider="openai",
        protocol="chat",
        stream=True,
        model="gpt-5.6-luna",
        pricing_model="gpt-5.6-luna",
        unpriced=False,
        deployment_price=None,
        target=None,
        payload={},
        response_scan="off",
        response_analysis=(),
        request_id="req_metrics",
        warnings=[],
        timing=InferenceTiming(),
        admission=SimpleNamespace(estimated_input_tokens=5),
    )


@pytest.mark.asyncio
async def test_an_abandoned_stream_releases_the_call_the_kernel_counted() -> None:
    processor = ResponsePostprocessor(
        SimpleNamespace(finalize=AsyncMock(), mark_stream_started=AsyncMock()),
        heartbeat_interval_seconds=30,
        output_hash_salt=None,
    )
    prepared = _stream_prepared()
    session = processor.create_stream_session(prepared)

    async def events():
        yield f"data: {json.dumps(_CHUNK)}\n\n".encode()

    before = _in_flight()
    REQUESTS_IN_FLIGHT.labels(provider="openai").inc()
    await processor.finalize(
        prepared, ProviderStream(events(), None, AsyncMock()), stream_session=session
    )
    assert _in_flight() == before + 1
    await session.aclose()

    assert session.terminal_status == "client_disconnected"
    assert _in_flight() == before


def _stubbed_kernel(monkeypatch, provider_output, postprocess) -> GatewayKernel:
    prepared = SimpleNamespace(
        stream=False,
        protocol="chat",
        privacy=PrivacyOutcome(action=PrivacyAction.DETECTED, pii_detected=False),
        policy_verdicts=[],
    )

    def stage(name: str):
        return lambda *_args, **_kwargs: SimpleNamespace(name=name, reserved=False)

    for class_name, name in (
        ("AuthenticateStage", "authenticate"),
        ("AdmissionStage", "admission"),
        ("PrivacyStage", "privacy"),
        ("ProviderSpendStage", "provider_spend"),
        ("ProviderExecutionStage", "provider_execution"),
        ("PostprocessStage", "postprocess"),
    ):
        monkeypatch.setattr(kernel_module, class_name, stage(name))

    async def run_stage(stage, _value):
        if stage.name == "provider_execution":
            if isinstance(provider_output, BaseException):
                raise provider_output
            return provider_output
        if stage.name == "postprocess":
            return postprocess()
        return prepared

    monkeypatch.setattr(kernel_module, "run_stage", run_stage)
    execution = SimpleNamespace(pii_scrubber=object())
    return GatewayKernel(
        {"openai": execution},
        chain_store=object(),
        policy_resolver=object(),
        rate_limiter=object(),
        loop_detector=object(),
        loop_repeat_limit=3,
        loop_window_seconds=60,
        cost_tag_max_length=64,
        usage=SimpleNamespace(record_privacy=AsyncMock(), fail=AsyncMock()),
    )


def _broken_postprocess() -> Response:
    raise RuntimeError("postprocess failed")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider_output", "postprocess", "raises", "held"),
    [
        (ProviderNonStream({}, None), lambda: Response("ok"), None, 0),
        (
            ProviderCallError(500, "PROVIDER_UNAVAILABLE", True, "openai"),
            lambda: Response("ok"),
            ProviderCallError,
            0,
        ),
        (
            ProviderStream(AsyncMock(), None, AsyncMock()),
            _broken_postprocess,
            RuntimeError,
            0,
        ),
        # A returned stream stays counted until its session reaches a terminal state.
        (
            ProviderStream(AsyncMock(), None, AsyncMock()),
            lambda: Response("ok"),
            None,
            1,
        ),
    ],
)
async def test_the_kernel_counts_each_provider_call_once(
    monkeypatch, provider_output, postprocess, raises, held
) -> None:
    kernel = _stubbed_kernel(monkeypatch, provider_output, postprocess)
    before = _in_flight()

    if raises is None:
        await kernel._execute(SimpleNamespace(provider="openai"))
    else:
        with pytest.raises(raises):
            await kernel._execute(SimpleNamespace(provider="openai"))

    assert _in_flight() - before == held
    REQUESTS_IN_FLIGHT.labels(provider="openai").dec(held)
