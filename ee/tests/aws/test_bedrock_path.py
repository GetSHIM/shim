"""Bedrock deployments run through the core executions with a minted Bedrock key."""

from __future__ import annotations

import base64
from decimal import Decimal
import json
import re
from uuid import uuid4

import httpx
import pytest
from unittest.mock import AsyncMock
from sqlalchemy import select

from ee.tests.tenants.test_deployments import _gateway, db, test_org  # noqa: F401
from shim_enterprise.billing.models import UsageLedger
from shim_enterprise.core.config import settings
from shim_enterprise.tenants.models import ModelDeployment, ProviderSecret

RUNTIME = "https://bedrock-runtime.eu-central-1.amazonaws.com"
PROFILE = "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"
AWS_KEY = json.dumps(
    {"access_key_id": "AKIA0000000000000000", "secret_access_key": "0" * 40}
)


@pytest.fixture
def bedrock_origin(monkeypatch):
    monkeypatch.setattr(settings, "MODEL_DEPLOYMENT_ALLOWED_ORIGINS", [RUNTIME])
    monkeypatch.setattr(settings, "MODEL_DEPLOYMENT_REQUIRED", True)


async def _bedrock(db, key, provider: str, alias: str, model: str) -> ModelDeployment:  # noqa: F811
    secret = ProviderSecret(
        id=uuid4(),
        organization_id=key.organization_id,
        provider=provider,
        credential_kind="aws_access_key",
        secret_ref=f"reference-{uuid4().hex}",
        secret_backend="fernet",
        secret_version="v2",
        masked_key="aws:AKIA...0000",
    )
    db.add(secret)
    await db.flush()
    row = ModelDeployment(
        organization_id=key.organization_id,
        alias=alias,
        provider=provider,
        upstream_model=model,
        base_url=RUNTIME + ("/anthropic" if provider == "anthropic" else "/openai/v1"),
        provider_secret_id=secret.id,
        timeout_seconds=5,
        deployment_kind="external",
        declared_version="bedrock",
        owner="Platform",
        enabled=True,
        upstream="aws_bedrock",
        aws_region="eu-central-1",
        input_price_per_million=Decimal("3"),
        output_price_per_million=Decimal("15"),
        cache_read_price_per_million=Decimal("0.30"),
        cache_write_price_per_million=Decimal("3.75"),
    )
    db.add(row)
    await db.flush()
    return row


def _token_region(token: str) -> str:
    url = base64.b64decode(token.removeprefix("bedrock-api-key-")).decode()
    assert url.startswith("bedrock.amazonaws.com/?Action=CallWithBearerToken&")
    assert re.search(r"&X-Amz-Signature=[0-9a-f]{64}&Version=1$", url)
    return re.search(r"%2F\d{8}%2F([a-z0-9-]+)%2Fbedrock%2F", url).group(1)


@pytest.mark.asyncio
async def test_claude_on_bedrock_gets_a_minted_key_and_settles_cache_tokens(
    db,  # noqa: F811
    test_api_key,
    bedrock_origin,
) -> None:
    await _bedrock(db, test_api_key, "anthropic", "claude-bedrock", PROFILE)
    calls = []

    def upstream(request):
        calls.append(request)
        body = json.loads(request.content)
        assert "alice@example.com" not in request.content.decode()
        return httpx.Response(
            200,
            json={
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": body["model"],
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {
                    "input_tokens": 100,
                    "output_tokens": 20,
                    "cache_read_input_tokens": 4000,
                    "cache_creation_input_tokens": 6000,
                },
            },
        )

    async with _gateway(db, test_api_key, upstream) as (client, _, store):
        store.get_secret = AsyncMock(return_value=AWS_KEY)
        answered = await client.post(
            "/v1/messages",
            json={
                "model": "claude-bedrock",
                "max_tokens": 16,
                "messages": [{"role": "user", "content": "mail alice@example.com"}],
            },
        )
        again = await client.post(
            "/v1/messages",
            json={
                "model": "claude-bedrock",
                "max_tokens": 16,
                "messages": [{"role": "user", "content": "again"}],
            },
        )
        counted = await client.post(
            "/v1/messages/count_tokens",
            json={
                "model": "claude-bedrock",
                "messages": [{"role": "user", "content": "how many"}],
            },
        )

    assert answered.status_code == 200, answered.text
    assert again.status_code == 200
    assert [request.url.path for request in calls] == [
        "/anthropic/v1/messages",
        "/anthropic/v1/messages",
    ]
    assert json.loads(calls[0].content)["model"] == PROFILE
    tokens = [request.headers["x-api-key"] for request in calls]
    assert tokens[0] == tokens[1]
    assert _token_region(tokens[0]) == "eu-central-1"
    assert store.get_secret.await_count == 1
    assert counted.status_code == 400
    assert "MODEL_CAPABILITY_UNSUPPORTED" in counted.text
    settled = await db.scalars(
        select(UsageLedger.cost_usd).where(
            UsageLedger.organization_id == test_api_key.organization_id,
            UsageLedger.event_type == "spend_settlement",
        )
    )
    expected = (
        Decimal(100) * 3
        + Decimal(20) * 15
        + Decimal(4000) * Decimal("0.30")
        + Decimal(6000) * Decimal("3.75")
    ) / 1_000_000
    assert expected in list(settled)


@pytest.mark.asyncio
async def test_an_open_model_on_bedrock_goes_through_the_openai_route(
    db,  # noqa: F811
    test_api_key,
    bedrock_origin,
) -> None:
    await _bedrock(
        db, test_api_key, "openai", "gpt-oss-bedrock", "openai.gpt-oss-120b-1:0"
    )
    calls = []

    def upstream(request):
        calls.append(request)
        if len(calls) == 2:
            return httpx.Response(
                403, json={"message": "User is not authorized to perform this action."}
            )
        return httpx.Response(
            200,
            json={
                "id": "chat-1",
                "object": "chat.completion",
                "created": 1,
                "model": "openai.gpt-oss-120b-1:0",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 4,
                    "completion_tokens": 2,
                    "total_tokens": 6,
                },
            },
        )

    async with _gateway(db, test_api_key, upstream) as (client, _, store):
        store.get_secret = AsyncMock(return_value=AWS_KEY)
        body = {
            "model": "gpt-oss-bedrock",
            "messages": [{"role": "user", "content": "hi"}],
        }
        answered = await client.post("/v1/chat/completions", json=body)
        refused = await client.post("/v1/chat/completions", json=body)

    assert answered.status_code == 200, answered.text
    assert calls[0].url.path == "/openai/v1/chat/completions"
    assert _token_region(calls[0].headers["authorization"].removeprefix("Bearer ")) == (
        "eu-central-1"
    )
    assert refused.status_code == 403
    assert "PROVIDER_REJECTED_REQUEST" in refused.text
