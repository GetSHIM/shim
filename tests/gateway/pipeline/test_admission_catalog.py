"""The admission refusals run over the shipped model catalog, model by model.

Refusals are for certain failure only: a request its provider would accept must pass for
every model in model_catalog.json, and a certain overflow must still be refused.
"""

from datetime import UTC, datetime
from functools import cache
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from fastapi import HTTPException

import shim.billing.pricing as pricing
from shim.gateway.admission import InMemoryRateLimiter, LoopDetectionResult
from shim.gateway.contracts.context import (
    AuditPolicy,
    GatewayContext,
    PrivacyPolicy,
    TierPolicy,
)
from shim.gateway.contracts.ids import ApiKeyId, ProviderId, RequestId, TenantId
from shim.gateway.kernel.result import PreparedInference
from shim.gateway.pipeline.admission import AdmissionStage
from shim.gateway.request_policy import RequestPolicyContext

_CATALOG = json.loads(
    Path(pricing.__file__).with_name("model_catalog.json").read_text(encoding="utf-8")
)
MODELS = [
    pytest.param(provider, model_id, entry, id=f"{provider}/{model_id}")
    for provider, models in _CATALOG["providers"].items()
    for model_id, entry in models.items()
]
_PROTOCOL = {"openai": "chat", "anthropic": "messages", "google": "generate_content"}
_IMAGE = {
    "openai": {"type": "image_url", "image_url": {"url": "data:image/png;base64,AA"}},
    "anthropic": {
        "type": "image",
        "source": {"type": "base64", "media_type": "image/png", "data": "AA"},
    },
    "google": {"inlineData": {"mimeType": "image/png", "data": "AA"}},
}
_MEDIA = {
    ("openai", "image"): _IMAGE["openai"],
    ("openai", "audio"): {"type": "input_audio", "input_audio": {"data": "AA"}},
    ("openai", "pdf"): {"type": "file", "file": {"file_id": "file-abc"}},
    ("anthropic", "image"): _IMAGE["anthropic"],
    ("anthropic", "pdf"): {
        "type": "document",
        "source": {"type": "base64", "media_type": "application/pdf", "data": "AA"},
    },
    ("google", "image"): _IMAGE["google"],
    ("google", "audio"): {"inlineData": {"mimeType": "audio/wav", "data": "AA"}},
    ("google", "pdf"): {"inlineData": {"mimeType": "application/pdf", "data": "AA"}},
}


@cache
def _words(count: int) -> str:
    return "w " * count


def _payload(provider: str, model: str, parts: list[Any]) -> dict[str, Any]:
    if provider == "google":
        return {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": p} if isinstance(p, str) else p for p in parts],
                }
            ]
        }
    content = [{"type": "text", "text": p} if isinstance(p, str) else p for p in parts]
    return {"model": model, "messages": [{"role": "user", "content": content}]}


async def _admit(
    provider: str,
    model: str,
    payload: dict[str, Any],
    *,
    protocol: str | None = None,
) -> PreparedInference:
    context = GatewayContext(
        request_id=RequestId("req_catalog"),
        tenant_id=TenantId(UUID("11111111-1111-1111-1111-111111111111")),
        actor_type="api_key",
        api_key_id=ApiKeyId(UUID("22222222-2222-2222-2222-222222222222")),
        user_id=None,
        endpoint="/v1/chat/completions",
        started_at=datetime(2026, 10, 8, tzinfo=UTC),
        tier_policy=TierPolicy(
            rate_limit_rpm=None, rate_limit_tpm=None, monthly_token_limit=None
        ),
        privacy_policy=PrivacyPolicy(pii_mode="scrub"),
        audit_policy=AuditPolicy(mode="best_effort"),
    )
    prepared = PreparedInference(
        context=context,
        payload=payload,
        protocol=protocol or _PROTOCOL[provider],  # type: ignore[arg-type]
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
    stage = AdmissionStage(
        SimpleNamespace(headers={}),
        SimpleNamespace(admit=AsyncMock()),
        rate_limiter=InMemoryRateLimiter(),
        loop_detector=SimpleNamespace(
            check_exact_repeat=AsyncMock(return_value=LoopDetectionResult("SAFE", 1))
        ),
        loop_repeat_limit=8,
        loop_window_seconds=300,
        cost_tag_max_length=64,
    )
    return await stage.run(prepared)


def _with_output(provider: str, payload: dict[str, Any], output: int) -> None:
    if provider == "google":
        payload["generationConfig"] = {"maxOutputTokens": output}
    else:
        payload["max_tokens"] = output


def _input_room(provider: str, entry: dict[str, Any]) -> int:
    """The most words the provider accepts with the model's largest output limit."""

    window = entry["context_window"]
    # Gemini's output limit is separate; Claude 4.5 and later accept input plus
    # max_tokens above the window and stop at it. OpenAI counts both.
    room = window - entry["max_output_tokens"] if provider == "openai" else window
    return min(room, entry.get("input_limit", room))


@pytest.mark.asyncio
@pytest.mark.parametrize(("provider", "model", "entry"), MODELS)
async def test_a_full_window_with_the_largest_output_is_admitted_and_one_more_word_is_not(
    provider, model, entry
) -> None:
    room = _input_room(provider, entry)
    fits = _payload(provider, model, [_words(room)])
    over = _payload(provider, model, [_words(room + 1)])
    for payload in (fits, over):
        _with_output(provider, payload, entry["max_output_tokens"])

    await _admit(provider, model, fits)
    with pytest.raises(HTTPException) as error:
        await _admit(provider, model, over)

    assert error.value.detail["code"] == "MODEL_CONTEXT_EXCEEDED"


@pytest.mark.asyncio
@pytest.mark.parametrize(("provider", "model", "entry"), MODELS)
async def test_a_prefix_match_never_refuses_for_the_entry_it_borrows(
    provider, model, entry
) -> None:
    # gpt-4-0125-preview resolves to gpt-4's prices, not its 8,192-token window.
    variant = f"{model}-2099-01-01"
    payload = _payload(
        provider, variant, [_words(entry["context_window"] + 1), *_IMAGE.values()]
    )

    await _admit(provider, variant, payload)


@pytest.mark.asyncio
@pytest.mark.parametrize(("provider", "model", "entry"), MODELS)
async def test_every_capability_the_catalog_does_not_deny_is_admitted(
    provider, model, entry
) -> None:
    parts: list[Any] = ["hi"]
    parts += [
        _MEDIA[provider, modality]
        for modality in entry["input_modalities"]
        if (provider, modality) in _MEDIA
    ]
    payload = _payload(provider, model, parts)
    if entry.get("tools") is not False:
        payload["tools"] = [{"name": "lookup", "input_schema": {"type": "object"}}]
    if entry.get("structured_output") is not False:
        payload["response_format"] = {"type": "json_schema"}

    await _admit(provider, model, payload)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider", "model", "entry"),
    [model for model in MODELS if model.values[0] == "openai"],
)
async def test_an_openai_file_part_is_never_refused_as_a_pdf(
    provider, model, entry
) -> None:
    # The catalog's pdf flag is unreliable for OpenAI, and a file part need not be a PDF.
    for part in (
        {"type": "file", "file": {"file_id": "file-abc"}},
        {"type": "input_file", "file_id": "file-abc", "filename": "rows.csv"},
    ):
        await _admit(provider, model, _payload(provider, model, ["read", part]))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider", "model", "payload", "protocol"),
    [
        (
            "openai",
            "gpt-5",
            {"model": "gpt-5", "input": _words(400_001), "truncation": "auto"},
            "responses",
        ),
        (
            "anthropic",
            "claude-haiku-4-5",
            {
                "model": "claude-haiku-4-5",
                "messages": [{"role": "user", "content": _words(200_001)}],
                "context_management": {"edits": [{"type": "compact_20260112"}]},
            },
            None,
        ),
        (
            "anthropic",
            "claude-opus-4-6",
            {
                "model": "claude-opus-4-6",
                "messages": [
                    {"role": "user", "content": _words(1_000_001)},
                    {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "compaction",
                                "content": "summary",
                                "signature": "s",
                            }
                        ],
                    },
                    {"role": "user", "content": "go on"},
                ],
            },
            None,
        ),
        (
            "openai",
            "gpt-5",
            {
                "model": "gpt-5",
                "input": [
                    {"role": "user", "content": _words(400_001)},
                    {"type": "compaction", "encrypted_content": "opaque"},
                ],
            },
            "responses",
        ),
    ],
)
async def test_an_overflow_the_provider_truncates_or_compacts_is_not_certain(
    provider, model, payload, protocol
) -> None:
    await _admit(provider, model, payload, protocol=protocol)


@pytest.mark.asyncio
async def test_earlier_thinking_and_reasoning_summaries_are_not_counted() -> None:
    thought = _words(200_001)
    claude = {
        "model": "claude-haiku-4-5",
        "messages": [
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": thought, "signature": "s"},
                    {"type": "redacted_thinking", "data": thought},
                    {"type": "text", "text": "hello"},
                ],
            },
            {"role": "user", "content": "go on"},
        ],
    }
    gpt = {
        "model": "o3",
        "input": [
            {"role": "user", "content": "hi"},
            {
                "type": "reasoning",
                "summary": [{"type": "summary_text", "text": thought}],
            },
            {"role": "user", "content": "go on"},
        ],
    }

    await _admit("anthropic", "claude-haiku-4-5", claude)
    await _admit("openai", "o3", gpt, protocol="responses")


@pytest.mark.asyncio
async def test_real_snapshots_named_after_a_shorter_entry_are_admitted() -> None:
    audio = {"type": "input_audio", "input_audio": {"data": "AA", "format": "wav"}}

    # gpt-4-0125-preview has a 128k window; gpt-4's entry says 8,192.
    await _admit(
        "openai",
        "gpt-4-0125-preview",
        _payload("openai", "gpt-4-0125-preview", [_words(10_000)]),
    )
    # gpt-4o-audio-preview takes audio; gpt-4o's entry does not list it.
    await _admit(
        "openai",
        "gpt-4o-audio-preview",
        _payload("openai", "gpt-4o-audio-preview", ["listen", audio]),
    )
