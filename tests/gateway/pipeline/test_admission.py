from dataclasses import replace
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
        "turn_key": None,
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
            exact=lambda *_: entry,
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
async def test_a_request_too_small_to_overflow_skips_the_word_count(
    monkeypatch,
) -> None:
    import shim.gateway.pipeline.admission as admission_module

    def never(_payload) -> int:
        raise AssertionError("counted words of a request that cannot overflow")

    _catalog(monkeypatch, context_window=1_000)
    monkeypatch.setattr(admission_module, "_lower_bound_input", never)

    await _stage(InMemoryRateLimiter()).run(_prepared("w " * 400))


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
    ],
)
def test_a_target_refuses_a_lone_price(fields) -> None:
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


def _limit_rule(match: dict, *, action="block", state="enforced", scope=None):
    from shim.rules import validate_rule_set

    return validate_rule_set(
        {
            "revision": 1,
            "rules": [
                {
                    "id": "tool_cap",
                    "name": "Tool cap",
                    "kind": "request_limit",
                    "action": action,
                    "state": state,
                    "scope": scope or {},
                    "match": match,
                }
            ],
        }
    )


def _limit_stage(headers=None):
    usage = SimpleNamespace(admit=AsyncMock())
    rate_limiter = SimpleNamespace(allow=AsyncMock(return_value=True))
    stage = AdmissionStage(
        SimpleNamespace(headers=headers or {}),
        usage,
        rate_limiter=rate_limiter,
        loop_detector=SimpleNamespace(
            check_exact_repeat=AsyncMock(return_value=LoopDetectionResult("SAFE", 1))
        ),
        loop_repeat_limit=8,
        loop_window_seconds=300,
        cost_tag_max_length=64,
    )
    return stage, usage, rate_limiter


def _with_tools(prepared: PreparedInference, count: int, **values) -> PreparedInference:
    tools = [{"type": "function", "function": {"name": f"f{i}"}} for i in range(count)]
    return replace(prepared, payload={**prepared.payload, "tools": tools}, **values)


@pytest.mark.asyncio
async def test_an_enforced_cap_refuses_before_any_rate_capacity_or_reservation() -> (
    None
):
    stage, usage, rate_limiter = _limit_stage()
    prepared = _with_tools(
        _prepared("six tools"), 6, rules=_limit_rule({"max_tools": 5})
    )

    with pytest.raises(HTTPException) as refused:
        await stage.run(prepared)

    assert refused.value.status_code == 400
    assert refused.value.detail["code"] == "RULE_BLOCKED"
    assert refused.value.headers == {"X-Shim-Rule-Id": "tool_cap"}
    rate_limiter.allow.assert_not_awaited()
    usage.admit.assert_not_awaited()
    verdicts = {v.rule_id: v.reason_code for v in prepared.policy_verdicts}
    assert verdicts["rule.tool_cap"] == "RULE_BLOCKED"


@pytest.mark.asyncio
@pytest.mark.parametrize(("tools", "matched"), [(5, False), (6, True)])
async def test_a_monitor_cap_records_what_it_would_do_and_admits(
    tools, matched
) -> None:
    stage, usage, _ = _limit_stage()

    admitted = await stage.run(
        _with_tools(
            _prepared("tools"),
            tools,
            rules=_limit_rule({"max_tools": 5}, state="monitor"),
        )
    )

    usage.admit.assert_awaited_once()
    assert admitted.rules_evaluated is True
    assert [(m.rule_id, m.state, m.action, m.count) for m in admitted.rule_matches] == (
        [("tool_cap", "monitor", "block", 1)] if matched else []
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(("header", "refused"), [("batch", True), ("other", False)])
async def test_a_cap_scoped_by_tag_reads_the_resolved_tags(header, refused) -> None:
    stage, _, _ = _limit_stage({"x-shim-tag": f"Kampanya,{header}"})
    prepared = _with_tools(
        _prepared("tools"),
        6,
        rules=_limit_rule({"max_tools": 5}, scope={"tags": ["batch"]}),
    )

    if refused:
        with pytest.raises(HTTPException):
            await stage.run(prepared)
    else:
        assert (await stage.run(prepared)).rule_matches == []


@pytest.mark.asyncio
async def test_token_counting_is_never_capped_and_records_nothing() -> None:
    stage, _, _ = _limit_stage()
    prepared = _with_tools(
        _prepared(
            "count",
            provider="anthropic",
            model="claude-sonnet-4-6",
            protocol="count_tokens",
        ),
        10,
        rules=_limit_rule({"max_tools": 1}),
    )

    admitted = await stage.run(prepared)

    assert admitted.rule_matches == [] and admitted.rules_evaluated is False
    assert not any(v.rule_id.startswith("rule.") for v in admitted.policy_verdicts)


_CERTAIN = "a " * 272_001
_POSSIBLE = "x" * 1_100_000


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("prompt", "action", "refused", "warned"),
    [
        (_CERTAIN, "block", True, False),
        (_POSSIBLE, "warn", False, True),
        ("a short question", None, False, False),
    ],
)
async def test_the_price_tier_rule_refuses_only_a_certain_crossing(
    prompt, action, refused, warned
) -> None:
    stage, usage, _ = _limit_stage()
    prepared = replace(
        _prepared(prompt, model="gpt-5.4"),
        rules=_limit_rule({"below_price_tier": True}),
    )

    if refused:
        with pytest.raises(HTTPException) as error:
            await stage.run(prepared)
        assert error.value.detail["code"] == "RULE_BLOCKED"
        return
    admitted = await stage.run(prepared)
    assert [m.action for m in admitted.rule_matches] == ([action] if action else [])
    assert "PRICE_TIER_CROSSED" not in admitted.warnings


@pytest.mark.asyncio
async def test_a_registry_target_never_matches_the_price_tier_rule() -> None:
    from shim.gateway.kernel.result import ProviderTarget

    stage, _, _ = _limit_stage()
    prepared = replace(
        _prepared(_CERTAIN, model="gpt-5.4"),
        rules=_limit_rule({"below_price_tier": True}),
        target=ProviderTarget(
            deployment_id="d1",
            base_url="https://models.internal/v1",
            upstream_model="gpt-5.4",
            credential_reference="c1",
            timeout_seconds=60,
            declared_version="v1",
        ),
        price_tier_warning=True,
    )

    admitted = await stage.run(prepared)

    assert admitted.rule_matches == [] and admitted.warnings == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("model", "prompt", "switch", "protocol", "warned"),
    [
        ("gpt-5.4", _POSSIBLE, True, "chat", True),
        ("gpt-5.4", _POSSIBLE, False, "chat", False),
        ("gpt-5.4", "a short question", True, "chat", False),
        ("claude-sonnet-4-6", _POSSIBLE, True, "messages", False),
        ("claude-sonnet-4-6", _POSSIBLE, True, "count_tokens", False),
    ],
)
async def test_the_price_tier_warning_needs_the_switch_a_tier_and_the_size(
    model, prompt, switch, protocol, warned
) -> None:
    stage, _, _ = _limit_stage()
    provider = "openai" if model.startswith("gpt") else "anthropic"
    prepared = replace(
        _prepared(prompt, model=model, provider=provider, protocol=protocol),
        price_tier_warning=switch,
    )
    if provider == "anthropic":
        prepared = replace(prepared, payload={**prepared.payload, "max_tokens": 16})

    admitted = await stage.run(prepared)

    assert ("PRICE_TIER_CROSSED" in admitted.warnings) is warned


_TRACE = "0af7651916cd43dd8448eb211c80319c"
_PARENT = f"00-{_TRACE}-b7ad6b7169203331-01"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("headers", "task_id", "trace_id"),
    [
        ({"x-shim-task-id": "t" * 128}, "t" * 128, None),
        ({"x-shim-task-id": "t" * 129}, None, None),
        ({"x-shim-task-id": "  task-7/step:2  "}, "task-7/step:2", None),
        ({"x-shim-task-id": "two words"}, None, None),
        ({"x-shim-task-id": "a@b"}, None, None),
        ({"x-shim-task-id": "-leading"}, None, None),
        ({"x-shim-task-id": ""}, None, None),
        ({"traceparent": _PARENT}, _TRACE, _TRACE),
        ({"traceparent": _PARENT.upper()}, None, None),
        ({"traceparent": f"00-{'0' * 32}-b7ad6b7169203331-01"}, None, None),
        ({"traceparent": f"00-{_TRACE}-{'0' * 16}-01"}, None, None),
        ({"traceparent": f"ff-{_TRACE}-b7ad6b7169203331-01"}, None, None),
        ({"traceparent": "garbage"}, None, None),
        ({"traceparent": _PARENT, "x-shim-task-id": "task-1"}, "task-1", _TRACE),
        ({"traceparent": _PARENT, "x-shim-task-id": "bad id"}, _TRACE, _TRACE),
        ({}, None, None),
    ],
)
async def test_the_task_id_comes_from_its_header_else_the_incoming_trace(
    headers, task_id, trace_id
) -> None:
    from prometheus_client import REGISTRY

    stage, _, _ = _limit_stage(headers)
    rejected = REGISTRY.get_sample_value("shim_task_id_rejected_total") or 0

    admitted = await stage.run(_prepared("a task"))

    assert admitted.admission is not None
    assert (admitted.admission.task_id, admitted.admission.trace_id) == (
        task_id,
        trace_id,
    )
    sent = (headers.get("x-shim-task-id") or "").strip()
    assert (
        REGISTRY.get_sample_value("shim_task_id_rejected_total") or 0
    ) - rejected == (1 if sent and task_id != sent else 0)


def _history(protocol: str, arguments: str | dict, name: str = "read_file") -> dict:
    if protocol == "chat":
        return {
            "messages": [
                {"role": "user", "content": "go"},
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "c1",
                            "type": "function",
                            "function": {"name": name, "arguments": arguments},
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "c1", "content": "ok"},
            ]
        }
    if protocol == "responses":
        return {
            "input": [
                {"role": "user", "content": "go"},
                {
                    "type": "function_call",
                    "call_id": "c1",
                    "name": name,
                    "arguments": arguments,
                },
                {"type": "function_call_output", "call_id": "c1", "output": "ok"},
            ]
        }
    if protocol == "messages":
        return {
            "messages": [
                {"role": "user", "content": "go"},
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "t1",
                            "name": name,
                            "input": arguments,
                        }
                    ],
                },
            ]
        }
    return {
        "contents": [
            {"role": "user", "parts": [{"text": "go"}]},
            {
                "role": "model",
                "parts": [{"functionCall": {"name": name, "args": arguments}}],
            },
        ]
    }


@pytest.mark.parametrize(
    ("protocol", "first", "second"),
    [
        ("chat", '{"path": "a", "line": 1}', '{"line": 1, "path": "a"}'),
        ("chat", "not json at all", "not json at all"),
        ("responses", '{"path": "a"}', '{ "path" : "a" }'),
        ("messages", {"path": "a", "line": 1}, {"line": 1, "path": "a"}),
        ("generate_content", {"path": "a"}, {"path": "a"}),
    ],
)
def test_the_tool_signature_reads_the_latest_call_and_ignores_key_order(
    protocol, first, second
) -> None:
    from shim.gateway.pipeline.admission import _tool_signature

    signature = _tool_signature(_history(protocol, first), protocol)

    assert signature is not None and len(signature) == 64
    assert _tool_signature(_history(protocol, second), protocol) == signature
    assert (
        _tool_signature(_history(protocol, first, name="write_file"), protocol)
        != signature
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"messages": [{"role": "user", "content": "no tools"}]},
        {"messages": "x", "input": "plain", "contents": None},
        {},
    ],
)
def test_a_history_without_a_tool_call_has_no_signature(payload) -> None:
    from shim.gateway.pipeline.admission import _tool_signature

    for protocol in ("chat", "responses", "messages", "generate_content"):
        assert _tool_signature(payload, protocol) is None


def _loop_stage(turn_repeats: int):
    detector = SimpleNamespace(
        check_exact_repeat=AsyncMock(
            return_value=LoopDetectionResult("SAFE", 1, turn_repeats)
        )
    )
    stage = AdmissionStage(
        SimpleNamespace(headers={"x-shim-task-id": "task-1"}),
        SimpleNamespace(admit=AsyncMock()),
        rate_limiter=SimpleNamespace(allow=AsyncMock(return_value=True)),
        loop_detector=detector,
        loop_repeat_limit=8,
        loop_window_seconds=300,
        cost_tag_max_length=64,
    )
    return stage, detector


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("action", "repeats", "verdict", "refused"),
    [
        ("count", 4, None, False),
        ("count", 5, ("allow", "AGENT_LOOP_SUSPECTED"), False),
        ("count", 9, ("allow", "AGENT_LOOP_SUSPECTED"), False),
        ("block", 5, ("allow", "AGENT_LOOP_SUSPECTED"), False),
        ("block", 6, ("deny", "AGENT_LOOP_DETECTED"), True),
    ],
)
async def test_a_repeated_tool_call_is_counted_and_blocked_only_when_asked(
    action, repeats, verdict, refused
) -> None:
    from shim.gateway.request_policy import AgentLoop

    stage, detector = _loop_stage(repeats)
    prepared = replace(
        _prepared("x"),
        payload={"model": "gpt-5.6-luna", **_history("chat", '{"path": "a"}')},
        agent_loop=AgentLoop(action=action),
    )

    if refused:
        with pytest.raises(HTTPException) as error:
            await stage.run(prepared)
        assert error.value.status_code == 429
        assert error.value.detail["code"] == "AGENT_LOOP_DETECTED"
        assert error.value.headers == {"x-should-retry": "false"}
    else:
        assert (await stage.run(prepared)).admission.tool_call_repeats == repeats
    verdicts = {v.rule_id: (v.outcome, v.reason_code) for v in prepared.policy_verdicts}
    assert verdicts.get("task.agent_loop") == verdict
    assert detector.check_exact_repeat.await_args.kwargs["turn_key"] is not None


@pytest.mark.asyncio
async def test_with_the_loop_signal_off_nothing_is_computed() -> None:
    from shim.gateway.request_policy import AgentLoop

    stage, detector = _loop_stage(9)
    prepared = replace(
        _prepared("x"),
        payload={"model": "gpt-5.6-luna", **_history("chat", "{}")},
        agent_loop=AgentLoop(action="off"),
    )

    admitted = await stage.run(prepared)

    assert admitted.admission.tool_call_repeats is None
    assert detector.check_exact_repeat.await_args.kwargs["turn_key"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("headers", "refused_on"), [({"x-shim-task-id": "t-1"}, 3), ({}, None)]
)
async def test_a_task_past_its_calls_cap_is_refused_and_untasked_calls_pass(
    headers, refused_on
) -> None:
    from shim.gateway.request_policy import TaskCaps

    stage, _, _ = _limit_stage(headers)
    outcomes = []
    for _ in range(3):
        prepared = replace(_prepared("x"), task_caps=TaskCaps(max_calls=2))
        try:
            admitted = await stage.run(prepared)
            outcomes.append(admitted.admission.task_calls)
        except HTTPException as error:
            assert error.detail["code"] == "TASK_LIMIT_EXCEEDED"
            assert error.headers == {"x-should-retry": "false"}
            assert error.detail["message"] == (
                "This task reached its limit of 2 calls within 3600 seconds."
            )
            outcomes.append("refused")

    assert outcomes == ([1, 2, "refused"] if refused_on else [None, None, None])


@pytest.mark.asyncio
async def test_an_unavailable_task_counter_fails_open_with_an_error_verdict() -> None:
    from shim.gateway.admission import TaskAdmission
    from shim.gateway.request_policy import TaskCaps

    stage, _, _ = _limit_stage({"x-shim-task-id": "t-1"})
    stage.task_counter = SimpleNamespace(
        admit_call=AsyncMock(return_value=TaskAdmission(0, 0, True, unavailable=True))
    )
    prepared = replace(_prepared("x"), task_caps=TaskCaps(max_calls=1))

    await stage.run(prepared)

    verdicts = {v.rule_id: (v.outcome, v.reason_code) for v in prepared.policy_verdicts}
    assert verdicts["task.limit"] == ("error", "TASK_COUNTER_UNAVAILABLE")


def _inflight_stage(registry, admit=None) -> AdmissionStage:
    return AdmissionStage(
        SimpleNamespace(headers={}),
        SimpleNamespace(admit=admit or AsyncMock()),
        rate_limiter=SimpleNamespace(allow=AsyncMock(return_value=True)),
        loop_detector=SimpleNamespace(
            check_exact_repeat=AsyncMock(return_value=LoopDetectionResult("SAFE", 1))
        ),
        loop_repeat_limit=8,
        loop_window_seconds=300,
        cost_tag_max_length=64,
        inflight=registry,
    )


def _twin(
    request_id: str,
    *,
    key: str = "22222222-2222-2222-2222-222222222222",
    protocol: str = "chat",
    model: str = "gpt-5.6-luna",
    provider: str = "openai",
    **values,
) -> PreparedInference:
    prepared = _prepared(
        "the same question", protocol=protocol, model=model, provider=provider
    )
    payload = {**prepared.payload, **values.pop("payload", {})}
    values.setdefault("inflight_sharing", True)
    return replace(
        prepared,
        context=prepared.context.model_copy(
            update={
                "request_id": RequestId(request_id),
                "api_key_id": ApiKeyId(UUID(key)),
            }
        ),
        payload=payload,
        **values,
    )


@pytest.mark.asyncio
async def test_the_request_digest_hashes_the_bytes_as_sent_with_the_route() -> None:
    from shim.gateway.admission import InFlightRegistry

    async def digest(prepared: PreparedInference) -> str | None:
        admitted = await _inflight_stage(InFlightRegistry()).run(prepared)
        assert admitted.admission is not None
        return admitted.admission.request_digest

    base = _twin("req_1")
    reordered = replace(base, payload=dict(reversed(base.payload.items())))

    assert await digest(base) == await digest(_twin("req_2"))
    assert (
        len(
            {
                await digest(base),
                await digest(replace(base, model="gpt-5-nano")),
                await digest(replace(base, stream=True)),
                await digest(reordered),
            }
        )
        == 4
    )


@pytest.mark.asyncio
async def test_only_a_request_admitted_while_its_twin_is_in_flight_names_it() -> None:
    from shim.gateway.admission import InFlightRegistry

    registry = InFlightRegistry()
    first = await _inflight_stage(registry).run(_twin("req_1"))
    second = await _inflight_stage(registry).run(_twin("req_2"))
    assert first.admission is not None and second.admission is not None
    registry.leave(str(first.tenant_id), str(first.admission.request_digest), "req_1")
    later = await _inflight_stage(registry).run(_twin("req_3"))

    assert first.admission.inflight_duplicate_of is None
    assert second.admission.inflight_duplicate_of == "req_1"
    assert later.admission is not None
    assert later.admission.inflight_duplicate_of is None, "sequential, not overlapping"


_OTHER_KEY = "33333333-3333-3333-3333-333333333333"
_CLAUDE = {
    "protocol": "messages",
    "provider": "anthropic",
    "model": "claude-sonnet-4-6",
}
_GEMINI = {
    "protocol": "generate_content",
    "provider": "google",
    "model": "gemini-3.5-flash",
    "payload": {"generationConfig": {"temperature": 0}},
}
_HOT_GEMINI = {**_GEMINI, "payload": {"generationConfig": {"temperature": 0.9}}}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("leader", "follower", "follows"),
    [
        ({}, {}, True),
        ({"payload": {"temperature": 0}}, {"payload": {"temperature": 0}}, True),
        (_CLAUDE, _CLAUDE, True),
        (_GEMINI, _GEMINI, True),
        ({}, {"key": _OTHER_KEY}, False),
        ({}, {"inflight_sharing": False}, False),
        ({"inflight_sharing": False}, {}, False),
        ({"payload": {"temperature": 0.7}}, {"payload": {"temperature": 0.7}}, False),
        ({"payload": {"n": 2}}, {"payload": {"n": 2}}, False),
        ({"stream": True}, {"stream": True}, False),
        ({"protocol": "responses"}, {"protocol": "responses"}, False),
        (_HOT_GEMINI, _HOT_GEMINI, False),
    ],
)
async def test_only_a_shareable_twin_of_the_same_key_follows(
    leader, follower, follows
) -> None:
    from shim.gateway.admission import InFlightRegistry

    registry = InFlightRegistry()
    await _inflight_stage(registry).run(_twin("req_1", **leader))
    stage = _inflight_stage(registry)
    admitted = await stage.run(_twin("req_2", **follower))

    assert admitted.admission is not None
    assert admitted.admission.inflight_duplicate_of == "req_1"
    assert (stage.leader is not None) is follows


@pytest.mark.asyncio
async def test_a_token_count_and_a_refused_reservation_leave_nothing_behind() -> None:
    from shim.gateway.admission import InFlightRegistry

    registry = InFlightRegistry()
    counted = await _inflight_stage(registry).run(
        _twin(
            "req_1",
            protocol="count_tokens",
            model="claude-sonnet-4-6",
            provider="anthropic",
        )
    )
    with pytest.raises(RuntimeError):
        await _inflight_stage(registry, AsyncMock(side_effect=RuntimeError)).run(
            _twin("req_2")
        )

    assert counted.admission is not None
    assert counted.admission.inflight_duplicate_of is None
    assert not registry.entries


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("retires_on", "warning"),
    [
        ("2026-10-20", "MODEL_RETIRING"),
        ("2026-10-21", None),
        ("2026-07-21", "MODEL_RETIRED"),
    ],
)
async def test_a_retiring_model_is_warned_ninety_days_ahead_and_still_admitted(
    retires_on, warning
) -> None:
    from shim.billing.lifecycle import ModelLifecycle, Retirement

    lifecycle = ModelLifecycle(
        {
            "openai": {
                "gpt-5.6-luna": Retirement(
                    retires_on=retires_on,
                    source="https://developers.openai.com/api/docs/deprecations",
                    checked_on="2026-07-01",
                )
            }
        }
    )
    usage = SimpleNamespace(admit=AsyncMock())
    stage = AdmissionStage(
        SimpleNamespace(headers={}),
        usage,
        rate_limiter=SimpleNamespace(allow=AsyncMock(return_value=True)),
        loop_detector=SimpleNamespace(
            check_exact_repeat=AsyncMock(return_value=LoopDetectionResult("SAFE", 1))
        ),
        loop_repeat_limit=8,
        loop_window_seconds=300,
        cost_tag_max_length=64,
        model_lifecycle=lifecycle,
    )

    # The request starts on 2026-07-22: 2026-10-20 is 90 days ahead, 2026-10-21 is 91.
    admitted = await stage.run(_prepared("a question"))

    assert admitted.warnings == ([warning] if warning else [])
    usage.admit.assert_awaited_once()
