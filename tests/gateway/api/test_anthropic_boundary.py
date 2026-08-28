from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from anthropic.pagination import SyncPage
from anthropic.types import ModelInfo
from anthropic.types.beta import BetaModelInfo
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from shim.api.deps import get_anthropic_authenticated_principal, get_gateway_service
from shim.api.v1.chat import router as chat_router
from shim.api.v1.messages import MessagesRequest, router as messages_router
from shim.billing.pricing import DEFAULT_PRICE_BOOK
from shim.gateway.contracts.principal import AuthenticatedPrincipal


@pytest.mark.parametrize(
    "payload",
    [
        {
            "model": "claude-sonnet-4-6",
            "max_tokens": 0,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": "hello",
                            "cache_control": {"type": "ephemeral", "ttl": "1h"},
                            "citations": {"enabled": True},
                        },
                        {
                            "type": "document",
                            "source": {
                                "type": "content",
                                "content": [
                                    {"type": "text", "text": "nested document"}
                                ],
                            },
                            "context": "reference",
                        },
                    ],
                    "future_message_field": {"nested": True},
                }
            ],
            "system": [
                {
                    "type": "text",
                    "text": "Be concise",
                    "cache_control": {"type": "ephemeral", "ttl": "5m"},
                }
            ],
            "tools": [
                {
                    "name": "lookup",
                    "description": "Look up a record",
                    "input_schema": {
                        "type": "object",
                        "properties": {"id": {"type": "string"}},
                    },
                    "input_examples": [{"id": "abc"}],
                }
            ],
            "unknown_top_level": {"deep": [{"value": 1}]},
            "stream": True,
        },
        {
            "model": "claude-opus-4-8",
            "max_tokens": 0,
            "messages": [{"role": "user", "content": "hello beta"}],
            "system": "Use beta tools",
            "tools": [
                {
                    "type": "web_search_20260209",
                    "name": "web_search",
                    "allowed_domains": ["example.com"],
                    "user_location": {
                        "type": "approximate",
                        "city": "Istanbul",
                        "timezone": "Europe/Istanbul",
                    },
                }
            ],
            "output_config": {
                "format": {
                    "type": "json_schema",
                    "schema": {"type": "object", "additionalProperties": True},
                }
            },
            "beta_future_field": {"nested": [False, None, 3.5]},
        },
    ],
)
def test_anthropic_0121_regular_and_beta_payloads_round_trip(payload: dict) -> None:
    request = MessagesRequest.model_validate(payload)

    assert request.model_dump() == payload
    assert request.provider_payload() == payload


@pytest.mark.parametrize(
    "payload",
    [
        {"model": "", "messages": [], "max_tokens": 0},
        {"model": 7, "messages": [], "max_tokens": 0},
        {"model": "claude-sonnet-4-6", "messages": "hello", "max_tokens": 0},
        {"model": "claude-sonnet-4-6", "messages": [], "max_tokens": True},
        {"model": "claude-sonnet-4-6", "messages": [], "max_tokens": -1},
        {
            "model": "claude-sonnet-4-6",
            "messages": [],
            "max_tokens": 0,
            "stream": "false",
        },
    ],
)
def test_anthropic_boundary_rejects_malformed_routing_scalars(payload: dict) -> None:
    with pytest.raises(ValidationError):
        MessagesRequest.model_validate(payload)


def _endpoint_application(service) -> FastAPI:
    application = FastAPI()
    application.include_router(chat_router, prefix="/v1")
    application.include_router(messages_router, prefix="/v1")
    principal = AuthenticatedPrincipal(
        actor_type="api_key",
        api_key_id=UUID("22222222-2222-2222-2222-222222222222"),
        user_id=None,
        authenticated_at=datetime(2026, 7, 22, tzinfo=UTC),
    )
    application.dependency_overrides[get_gateway_service] = lambda: service
    application.dependency_overrides[get_anthropic_authenticated_principal] = lambda: (
        principal
    )
    return application


@pytest.mark.asyncio
async def test_anthropic_models_endpoint_returns_0121_sdk_envelopes() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=_endpoint_application(SimpleNamespace())),
        base_url="http://shim.test",
    ) as client:
        list_response = await client.get(
            "/v1/models", headers={"anthropic-version": "2023-06-01"}
        )
        model_response = await client.get(
            "/v1/models/claude-sonnet-4-6",
            headers={"anthropic-version": "2023-06-01"},
        )

    page = SyncPage[ModelInfo].model_validate(list_response.json())
    beta_page = SyncPage[BetaModelInfo].model_validate(list_response.json())
    model = ModelInfo.model_validate(model_response.json())
    assert {item.id for item in page.data} == set(
        DEFAULT_PRICE_BOOK.models("anthropic")
    )
    assert {item.id for item in beta_page.data} == set(
        DEFAULT_PRICE_BOOK.models("anthropic")
    )
    assert model.id == "claude-sonnet-4-6"
    assert model.display_name == "Claude Sonnet 4.6"


@pytest.mark.asyncio
async def test_anthropic_models_endpoint_supports_sdk_pagination() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=_endpoint_application(SimpleNamespace())),
        base_url="http://shim.test",
    ) as client:
        first = await client.get(
            "/v1/models",
            headers={"anthropic-version": "2023-06-01"},
            params={"limit": 1},
        )
        first_page = first.json()
        second = await client.get(
            "/v1/models",
            headers={"anthropic-version": "2023-06-01"},
            params={"limit": 1, "after_id": first_page["last_id"]},
        )

    assert len(first_page["data"]) == 1
    assert first_page["has_more"] is True
    assert len(second.json()["data"]) == 1
    assert second.json()["data"][0]["id"] != first_page["data"][0]["id"]


@pytest.mark.asyncio
async def test_messages_endpoint_preserves_body_and_header_profile_wins() -> None:
    service = SimpleNamespace(
        dispatch_inference=AsyncMock(
            return_value=JSONResponse(
                {
                    "id": "msg_1",
                    "type": "message",
                    "role": "assistant",
                    "content": [],
                }
            )
        )
    )
    payload = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 0,
        "messages": [{"role": "user", "content": "hello", "future": True}],
        "user_profile_id": "body-profile",
        "unknown": {"nested": [1, True, None]},
    }
    async with AsyncClient(
        transport=ASGITransport(app=_endpoint_application(service)),
        base_url="http://shim.test",
    ) as client:
        response = await client.post(
            "/v1/messages",
            headers={
                "x-shim-key": "shim-tenant-key",
                "x-api-key": "shim-tenant-key",
                "x-provider-key": "sk-ant-tenant",
                "anthropic-user-profile-id": "header-profile",
            },
            json=payload,
        )

    assert response.json()["id"] == "msg_1"
    call = service.dispatch_inference.await_args.kwargs
    assert call["payload"] == {**payload, "user_profile_id": "header-profile"}
    assert call["provider_credential"].consume() == "sk-ant-tenant"
