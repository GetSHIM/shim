from datetime import UTC, datetime
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from fastapi import HTTPException

from shim.gateway.admission import LoopDetectionResult
from shim.gateway.contracts.context import (
    AuditPolicy,
    GatewayContext,
    PrivacyPolicy,
    TierPolicy,
)
from shim.gateway.contracts.ids import ApiKeyId, ProviderId, RequestId, TenantId
from shim.gateway.kernel.result import (
    PreparedInference,
    UNSPECIFIED_PROVIDER_MODEL,
)
from shim.gateway.pipeline.admission import AdmissionStage
from shim.gateway.request_policy import RequestPolicyContext


def _prepared(
    prompt: str,
    *,
    model: str = "gpt-5.6-luna",
    provider: str = "openai",
    protocol: str = "chat",
) -> PreparedInference:
    context = GatewayContext(
        request_id=RequestId("req_admission"),
        tenant_id=TenantId(UUID("11111111-1111-1111-1111-111111111111")),
        actor_type="api_key",
        api_key_id=ApiKeyId(UUID("22222222-2222-2222-2222-222222222222")),
        user_id=None,
        endpoint="/v1/chat/completions",
        started_at=datetime(2026, 7, 22, tzinfo=UTC),
        tier_policy=TierPolicy(rate_limit_rpm=60, monthly_token_limit=1_000),
        privacy_policy=PrivacyPolicy(pii_mode="scrub"),
        audit_policy=AuditPolicy(mode="best_effort"),
    )
    return PreparedInference(
        context=context,
        payload={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
        },
        protocol=protocol,
        model=model,
        stream=False,
        policy=RequestPolicyContext(
            rate_limit_key_hash="key-hash",
            tier="managed",
            cost_center="engineering",
            team="platform",
        ),
        pii_config=None,
        provider=ProviderId(provider),
    )


@pytest.mark.asyncio
async def test_admission_blocks_repeat_before_durable_reservation() -> None:
    usage = SimpleNamespace(admit=AsyncMock())
    rate_limiter = SimpleNamespace(allow=AsyncMock(return_value=True))
    loop_detector = SimpleNamespace(
        check_exact_repeat=AsyncMock(return_value=LoopDetectionResult("BLOCKED", 9))
    )
    stage = AdmissionStage(
        SimpleNamespace(headers={}),
        usage,
        rate_limiter=rate_limiter,
        loop_detector=loop_detector,
        loop_repeat_limit=8,
        loop_window_seconds=300,
        cost_tag_max_length=64,
    )

    with pytest.raises(HTTPException) as error:
        await stage.run(_prepared("  repeated\nrequest "))

    assert error.value.status_code == 429
    assert error.value.detail["dimension"] == "repeated_requests"
    usage.admit.assert_not_awaited()
    assert "repeated\\nrequest" in loop_detector.check_exact_repeat.await_args.args[1]
    assert loop_detector.check_exact_repeat.await_args.kwargs == {
        "limit": 8,
        "window_seconds": 300,
    }


@pytest.mark.asyncio
async def test_admission_bounds_provider_payloads_and_output_limits() -> None:
    usage = SimpleNamespace(admit=AsyncMock())
    rate_limiter = SimpleNamespace(allow=AsyncMock(return_value=True))
    loop_detector = SimpleNamespace(
        check_exact_repeat=AsyncMock(return_value=LoopDetectionResult("SAFE", 1))
    )
    stage = AdmissionStage(
        SimpleNamespace(headers={}),
        usage,
        rate_limiter=rate_limiter,
        loop_detector=loop_detector,
        loop_repeat_limit=8,
        loop_window_seconds=300,
        cost_tag_max_length=64,
    )

    admitted = await stage.run(_prepared("new request"))

    assert stage.reserved is True
    assert admitted.admission is not None
    assert admitted.admission.estimated_input_tokens > 0
    assert admitted.admission.maximum_output_tokens == 128_000
    assert admitted.admission.cost_center == "engineering"
    assert admitted.policy == RequestPolicyContext(
        rate_limit_key_hash="key-hash",
        tier="managed",
        cost_center="engineering",
        team="platform",
    )
    assert not hasattr(admitted.policy, "__dict__")
    assert "max_completion_tokens" not in admitted.payload
    rate_limiter.allow.assert_awaited_once_with(
        "key-hash",
        limit=60,
        window_seconds=60,
    )
    usage.admit.assert_awaited_once()

    tokenizer_inefficient_prompt = r"!#$%&()*+,-./:;<=>?@[\]^_`{|}~" * 32
    admitted = await stage.run(_prepared(tokenizer_inefficient_prompt))
    assert admitted.admission is not None
    assert admitted.admission.estimated_input_tokens >= len(
        tokenizer_inefficient_prompt.encode("utf-8")
    )

    previously_omitted = _prepared("")
    prompt_material = r"!#$%&()*+,-./:;<=>?@[\]^_`{|}~" * 16 + " ş🙂"
    previously_omitted.payload.update(
        {
            "functions": [{"name": "legacy", "description": prompt_material}],
            "prediction": {"type": "content", "content": prompt_material},
            "prompt": {"id": prompt_material},
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "shape", "description": prompt_material},
            },
        }
    )
    admitted = await stage.run(previously_omitted)
    assert admitted.admission is not None
    assert admitted.admission.estimated_input_tokens == len(
        json.dumps(
            admitted.payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    )

    anthropic = _prepared(
        "cache warm",
        model="claude-sonnet-5",
        provider="anthropic",
        protocol="messages",
    )
    anthropic.payload["max_tokens"] = 1
    admitted = await stage.run(anthropic)
    assert admitted.admission is not None
    assert admitted.admission.maximum_output_tokens == 1

    anthropic.payload["max_tokens"] = 0
    admitted = await stage.run(anthropic)
    assert admitted.admission is not None
    assert admitted.admission.maximum_output_tokens == 0

    openai_zero = _prepared("no output")
    openai_zero.payload["max_tokens"] = 0
    with pytest.raises(HTTPException) as error:
        await stage.run(openai_zero)
    assert error.value.detail["code"] == "INVALID_REQUEST"

    choices = _prepared("three choices")
    choices.payload.update({"max_completion_tokens": 32, "n": 3})
    admitted = await stage.run(choices)
    assert admitted.admission is not None
    assert admitted.admission.maximum_output_tokens == 96

    gemini = _prepared(
        "two candidates",
        model="gemini-3.5-flash",
        provider="google",
    )
    gemini.payload["generationConfig"] = {
        "candidateCount": 2,
        "maxOutputTokens": 17,
    }
    admitted = await stage.run(gemini)
    assert admitted.admission is not None
    assert admitted.admission.maximum_output_tokens == 34

    oversized_output = _prepared("large output")
    oversized_output.payload["max_output_tokens"] = 128_001
    with pytest.raises(HTTPException) as error:
        await stage.run(oversized_output)
    assert error.value.detail["code"] == "INVALID_REQUEST"

    with pytest.raises(HTTPException) as error:
        await stage.run(_prepared("hello", model="unpriced-model"))
    assert error.value.detail["code"] == "MODEL_NOT_PRICED"

    unspecified = _prepared(
        "provider default",
        model=UNSPECIFIED_PROVIDER_MODEL,
        protocol="responses",
    )
    unspecified.payload.clear()
    unspecified.payload["input"] = "provider default"
    admitted = await stage.run(unspecified)
    assert admitted.admission is not None


@pytest.mark.parametrize(
    "limits",
    [
        {"loop_repeat_limit": 1},
        {"loop_window_seconds": 0},
        {"cost_tag_max_length": 0},
    ],
)
def test_admission_rejects_invalid_injected_bounds(limits: dict[str, int]) -> None:
    values = {
        "loop_repeat_limit": 8,
        "loop_window_seconds": 300,
        "cost_tag_max_length": 64,
        **limits,
    }

    with pytest.raises(ValueError):
        AdmissionStage(
            SimpleNamespace(headers={}),
            SimpleNamespace(admit=AsyncMock()),
            rate_limiter=SimpleNamespace(allow=AsyncMock(return_value=True)),
            loop_detector=SimpleNamespace(check_exact_repeat=AsyncMock()),
            **values,
        )
