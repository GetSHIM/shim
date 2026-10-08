from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from fastapi import HTTPException

from shim.gateway.admission import InMemoryRateLimiter, LoopDetectionResult
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
    rate_limit_rpm: int = 60,
    rate_limit_tpm: int | None = None,
) -> PreparedInference:
    context = GatewayContext(
        request_id=RequestId("req_admission"),
        tenant_id=TenantId(UUID("11111111-1111-1111-1111-111111111111")),
        actor_type="api_key",
        api_key_id=ApiKeyId(UUID("22222222-2222-2222-2222-222222222222")),
        user_id=None,
        endpoint="/v1/chat/completions",
        started_at=datetime(2026, 7, 22, tzinfo=UTC),
        tier_policy=TierPolicy(
            rate_limit_rpm=rate_limit_rpm,
            rate_limit_tpm=rate_limit_tpm,
            monthly_token_limit=1_000,
        ),
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
async def test_the_keys_cost_center_wins_and_header_tags_are_kept() -> None:
    stage = AdmissionStage(
        SimpleNamespace(headers={"x-shim-tag": "Kampanya-Ekim,batch"}),
        SimpleNamespace(admit=AsyncMock()),
        rate_limiter=SimpleNamespace(allow=AsyncMock(return_value=True)),
        loop_detector=SimpleNamespace(
            check_exact_repeat=AsyncMock(return_value=LoopDetectionResult("SAFE", 1))
        ),
        loop_repeat_limit=8,
        loop_window_seconds=300,
        cost_tag_max_length=64,
    )

    admitted = await stage.run(_prepared("tagged request"))

    assert admitted.admission is not None
    assert admitted.admission.cost_center == "engineering"
    assert admitted.admission.tags == ("kampanya-ekim", "batch")


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
        amount=1,
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


@pytest.mark.parametrize(
    "provider,protocol,payload,expected",
    [
        ("openai", "chat", {"n": 3, "generationConfig": {}}, 3),
        ("openai", "responses", {"n": 3}, 1),
        ("anthropic", "messages", {"n": 3}, 1),
        ("google", "generate_content", {"n": 3}, 1),
        ("google", "generate_content", {"generationConfig": {"candidateCount": 2}}, 2),
        *[("openai", "chat", {"n": value}, 1) for value in (True, "3", None)],
    ],
)
def test_native_candidate_counts(provider, protocol, payload, expected):
    from shim.gateway.pipeline.admission import candidate_count

    assert (
        candidate_count(
            SimpleNamespace(provider=provider, protocol=protocol, payload=payload)
        )
        == expected
    )


@pytest.mark.parametrize("count", [0, -1, 10_001])
def test_native_candidate_count_rejects_out_of_bounds(count):
    from shim.gateway.pipeline.admission import candidate_count

    with pytest.raises(HTTPException) as error:
        candidate_count(
            SimpleNamespace(provider="openai", protocol="chat", payload={"n": count})
        )
    assert error.value.status_code == 400


TWELVE_KB = "x" * 12_000


def _stage(rate_limiter, *, loop_status: str = "SAFE") -> AdmissionStage:
    return AdmissionStage(
        SimpleNamespace(headers={}),
        SimpleNamespace(admit=AsyncMock()),
        rate_limiter=rate_limiter,
        loop_detector=SimpleNamespace(
            check_exact_repeat=AsyncMock(
                return_value=LoopDetectionResult(loop_status, 1)  # type: ignore[arg-type]
            )
        ),
        loop_repeat_limit=8,
        loop_window_seconds=300,
        cost_tag_max_length=64,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(("limit", "admitted"), [(10_000, True), (2_000, False)])
async def test_tpm_counts_approximate_tokens_and_reserves_bytes(
    limit: int,
    admitted: bool,
) -> None:
    prepared = _prepared(TWELVE_KB, rate_limit_tpm=limit)
    payload_bytes = len(
        json.dumps(prepared.payload, ensure_ascii=False, separators=(",", ":")).encode()
    )

    if admitted:
        result = await _stage(InMemoryRateLimiter()).run(prepared)
        assert result.admission is not None
        assert result.admission.estimated_input_tokens == payload_bytes
    else:
        with pytest.raises(HTTPException) as error:
            await _stage(InMemoryRateLimiter()).run(prepared)
        assert error.value.status_code == 429
        assert error.value.detail["dimension"] == "tokens"

    tokens = next(v for v in prepared.policy_verdicts if v.rule_id == "rate.tokens")
    policy = {"limit": limit, "window_seconds": 60, "unit": "approximate_tokens"}
    assert (
        tokens.policy_version
        == sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()
    )


@pytest.mark.asyncio
async def test_a_request_that_can_never_fit_spends_no_rate_window() -> None:
    limiter = InMemoryRateLimiter()

    with pytest.raises(HTTPException) as refused:
        await _stage(limiter).run(
            _prepared("x" * 60_000, rate_limit_rpm=2, rate_limit_tpm=2_000)
        )
    first = await _stage(limiter).run(
        _prepared("small", rate_limit_rpm=2, rate_limit_tpm=2_000)
    )
    second = await _stage(limiter).run(
        _prepared("small again", rate_limit_rpm=2, rate_limit_tpm=2_000)
    )

    assert refused.value.detail["dimension"] == "tokens"
    assert first.admission is not None and second.admission is not None


def _approximate_tokens(prepared: PreparedInference) -> int:
    serialized = json.dumps(prepared.payload, ensure_ascii=False, separators=(",", ":"))
    return -(-len(serialized.encode()) // 4)


@pytest.mark.asyncio
async def test_a_request_larger_than_the_tpm_window_says_why_and_not_to_retry() -> None:
    limiter = SimpleNamespace(allow=AsyncMock(return_value=True))
    prepared = _prepared(TWELVE_KB, rate_limit_tpm=2_000)

    with pytest.raises(HTTPException) as refused:
        await _stage(limiter).run(prepared)

    tokens = _approximate_tokens(prepared)
    assert refused.value.status_code == 429
    assert refused.value.headers == {"x-should-retry": "false"}
    assert refused.value.detail["code"] == "RATE_LIMIT_EXCEEDED"
    assert refused.value.detail["dimension"] == "tokens"
    assert refused.value.detail["message"] == (
        f"This request is about {tokens} tokens, more than the limit of 2000 "
        "tokens per minute."
    )
    assert "smaller request" in refused.value.detail["hint"]
    limiter.allow.assert_not_awaited()
    [verdict] = [v for v in prepared.policy_verdicts if v.rule_id == "rate.tokens"]
    assert verdict.outcome == "deny"


@pytest.mark.asyncio
@pytest.mark.parametrize(("headroom", "admitted"), [(0, True), (-1, False)])
async def test_a_request_exactly_at_the_tpm_limit_is_admitted(
    headroom: int, admitted: bool
) -> None:
    prepared = _prepared(TWELVE_KB)
    limit = _approximate_tokens(prepared) + headroom
    stage = _stage(InMemoryRateLimiter())

    if admitted:
        result = await stage.run(_prepared(TWELVE_KB, rate_limit_tpm=limit))
        assert result.admission is not None
    else:
        with pytest.raises(HTTPException) as refused:
            await stage.run(_prepared(TWELVE_KB, rate_limit_tpm=limit))
        assert refused.value.headers == {"x-should-retry": "false"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("allowed", "loop_status", "dimension", "retry_after"),
    [
        ([False], "SAFE", "requests", "60"),
        ([True, False], "SAFE", "tokens", "60"),
        ([True, True], "BLOCKED", "repeated_requests", "300"),
    ],
)
async def test_every_admission_refusal_says_when_to_retry(
    allowed: list[bool],
    loop_status: str,
    dimension: str,
    retry_after: str,
) -> None:
    stage = _stage(
        SimpleNamespace(allow=AsyncMock(side_effect=allowed)),
        loop_status=loop_status,
    )

    with pytest.raises(HTTPException) as error:
        await stage.run(_prepared("hello", rate_limit_tpm=1_000))

    assert error.value.status_code == 429
    assert error.value.detail["dimension"] == dimension
    assert error.value.headers == {"Retry-After": retry_after}


def _catalog(monkeypatch, **facts) -> None:
    import shim.gateway.pipeline.admission as admission_module
    from shim.billing.pricing import DEFAULT_PRICE_BOOK, ModelPrice

    entry = ModelPrice(Decimal("1"), Decimal("2"), max_output_tokens=1_000, **facts)
    monkeypatch.setattr(
        admission_module,
        "DEFAULT_PRICE_BOOK",
        SimpleNamespace(
            version=DEFAULT_PRICE_BOOK.version,
            supports=lambda *_: True,
            maximum_output_tokens=lambda *_: 1_000,
            resolve=lambda *_: entry,
        ),
    )


@pytest.mark.parametrize(
    ("text", "words"),
    [
        ("Summarise the invoice dispute", 4),
        ("Fatura itirazını özetle, lütfen", 4),
        ("a,b 12.5! (x)", 3),
        (" \t\r\n   ", 0),
        ("日本語のテキストを要約してください", 1),
        ("ab\x1ccd ef\x1fgh\x85ij", 2),
    ],
)
def test_the_lower_bound_counts_whitespace_separated_words(text, words) -> None:
    from shim.gateway.pipeline.admission import _lower_bound_input

    assert (
        _lower_bound_input({"messages": [{"role": "user", "content": text}]}) == words
    )


def test_the_lower_bound_skips_keys_and_protocol_fields() -> None:
    from shim.gateway.pipeline.admission import _lower_bound_input

    payload = {
        "model": "m o d e l",
        "system": [
            {
                "type": "text",
                "text": "Be brief.",
                "cache_control": {"type": "ephemeral"},
            }
        ],
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "id x",
                        "content": "rows 1 2",
                    }
                ],
            }
        ],
        "tools": [{"name": "lookup", "description": "many words here"}],
    }

    assert _lower_bound_input(payload) == 5


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider", "words", "output", "facts", "refused"),
    [
        ("openai", 100, None, {"context_window": 100}, False),
        ("openai", 101, None, {"context_window": 100}, True),
        ("openai", 90, 10, {"context_window": 100}, False),
        ("openai", 91, 10, {"context_window": 100}, True),
        ("google", 100, 500, {"context_window": 100}, False),
        ("google", 101, 1, {"context_window": 100}, True),
        ("openai", 51, None, {"context_window": 1_000, "input_limit": 50}, True),
        ("openai", 50, None, {"context_window": 1_000, "input_limit": 50}, False),
    ],
)
async def test_only_a_certain_overflow_is_refused_before_any_rate_capacity(
    monkeypatch, provider, words, output, facts, refused
) -> None:
    _catalog(monkeypatch, **facts)
    prepared = _prepared(" ".join(["w"] * words), provider=provider)
    if output is not None:
        key = "maxOutputTokens" if provider == "google" else "max_tokens"
        prepared.payload.update(
            {"generationConfig": {key: output}}
            if provider == "google"
            else {key: output}
        )
    limiter = SimpleNamespace(allow=AsyncMock(return_value=True))

    if not refused:
        await _stage(limiter).run(prepared)
        limiter.allow.assert_awaited()
        return
    with pytest.raises(HTTPException) as error:
        await _stage(limiter).run(prepared)
    assert error.value.status_code == 400
    assert error.value.detail["code"] == "MODEL_CONTEXT_EXCEEDED"
    assert str(words) in error.value.detail["message"]
    limiter.allow.assert_not_awaited()
    assert [(v.rule_id, v.outcome) for v in prepared.policy_verdicts][-1] == (
        "admission.context",
        "deny",
    )


@pytest.mark.asyncio
async def test_an_uncertain_overflow_warns_and_token_counting_is_never_refused(
    monkeypatch,
) -> None:
    _catalog(monkeypatch, context_window=100)
    padded = _prepared("x" * 2_000)
    counted = _prepared(" ".join(["w"] * 500), protocol="count_tokens")

    admitted = await _stage(InMemoryRateLimiter()).run(padded)
    await _stage(InMemoryRateLimiter()).run(counted)

    assert admitted.warnings == ["CONTEXT_MAY_EXCEED"]
    assert counted.warnings == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("facts", "extra", "missing"),
    [
        (
            {"tools": False},
            {"tools": [{"type": "function", "function": {"name": "f"}}]},
            "tools",
        ),
        (
            {"tools": None},
            {"tools": [{"type": "function", "function": {"name": "f"}}]},
            None,
        ),
        (
            {"structured_output": False},
            {"response_format": {"type": "json_schema"}},
            "structured_output",
        ),
        (
            {"structured_output": False},
            {"response_format": {"type": "json_object"}},
            None,
        ),
        (
            {"structured_output": False},
            {"text": {"format": {"type": "json_schema"}}},
            "structured_output",
        ),
        (
            {"structured_output": False},
            {"generationConfig": {"responseSchema": {}}},
            "structured_output",
        ),
        (
            {"input_modalities": ("text",)},
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "image_url", "image_url": {"url": "x"}}],
                    }
                ]
            },
            "image",
        ),
        (
            {"input_modalities": ("text", "image")},
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "document", "source": {"type": "base64"}}],
                    }
                ]
            },
            "pdf",
        ),
        (
            {"input_modalities": ("text",)},
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "document", "source": {"type": "text"}}],
                    }
                ]
            },
            None,
        ),
        (
            {"input_modalities": ("text", "image", "pdf")},
            {
                "contents": [
                    {"parts": [{"inlineData": {"mimeType": "audio/wav", "data": "AA"}}]}
                ]
            },
            "audio",
        ),
        (
            {"input_modalities": None},
            {"messages": [{"role": "user", "content": [{"type": "input_audio"}]}]},
            None,
        ),
    ],
)
async def test_a_capability_is_refused_only_when_the_catalog_says_it_is_missing(
    monkeypatch, facts, extra, missing
) -> None:
    _catalog(monkeypatch, **facts)
    prepared = _prepared("hello")
    prepared.payload.update(extra)

    if missing is None:
        await _stage(InMemoryRateLimiter()).run(prepared)
        return
    with pytest.raises(HTTPException) as error:
        await _stage(InMemoryRateLimiter()).run(prepared)
    assert error.value.detail == {
        "code": "MODEL_CAPABILITY_UNSUPPORTED",
        "message": f"The model does not support {missing}.",
    }
    assert prepared.policy_verdicts[-1].rule_id == "admission.capability"


@pytest.mark.asyncio
async def test_a_deprecated_catalog_model_is_served_with_a_warning() -> None:
    prepared = _prepared("hello", model="gpt-3.5-turbo")

    admitted = await _stage(InMemoryRateLimiter()).run(prepared)

    assert admitted.warnings == ["MODEL_DEPRECATED"]


def _target(**fields) -> object:
    from shim.gateway.kernel.result import ProviderTarget

    return ProviderTarget(
        deployment_id="dep",
        base_url="https://llm.internal/v1",
        upstream_model="gpt-4",
        credential_reference="secret",
        timeout_seconds=5,
        declared_version="v1",
        **fields,
    )


@pytest.mark.parametrize(
    "fields",
    [
        {"input_per_million": Decimal("1")},
        {"output_per_million": Decimal("1")},
        {"context_window": 0},
    ],
)
def test_a_target_refuses_a_lone_price_and_a_zero_window(fields) -> None:
    with pytest.raises(ValueError):
        _target(**fields)


def test_a_target_price_wins_over_the_catalog_and_none_stays_unknown() -> None:
    from dataclasses import replace

    from shim.billing.pricing import DEFAULT_PRICE_BOOK, compute_cost_usd

    priced = replace(
        _prepared("hi"),
        target=_target(
            input_per_million=Decimal("0.5"), output_per_million=Decimal("1.5")
        ),
    )
    unknown = replace(
        _prepared("hi"), target=replace(_target(), upstream_model="custom-llama")
    )
    price = priced.deployment_price

    assert not priced.unpriced and unknown.unpriced and unknown.deployment_price is None
    assert compute_cost_usd("gpt-4", 1_000_000, 1_000_000, price=price) == Decimal("2")
    assert compute_cost_usd("gpt-4", 1_000_000, 1_000_000) != Decimal("2")
    metadata = DEFAULT_PRICE_BOOK.resolved_price_metadata(
        "gpt-4", input_tokens=1, output_tokens=1, price=price
    )
    assert (metadata["pricing_resolution"], metadata["input_per_million"]) == (
        "deployment",
        "0.5",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("window", "refused"), [(None, False), (100, True), (10_000, False)]
)
async def test_a_target_is_checked_against_its_own_window_only(window, refused) -> None:
    from dataclasses import replace

    # gpt-4's catalog window is 8,192; a deployment named after it is not held to it.
    prepared = replace(
        _prepared(" ".join(["w"] * 9_000), model="gpt-4"),
        target=_target(context_window=window),
    )

    if not refused:
        admitted = await _stage(InMemoryRateLimiter()).run(prepared)
        assert "MODEL_DEPRECATED" not in admitted.warnings
        return
    with pytest.raises(HTTPException) as error:
        await _stage(InMemoryRateLimiter()).run(prepared)
    assert error.value.detail["code"] == "MODEL_CONTEXT_EXCEEDED"
