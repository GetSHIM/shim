from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient
from openai.pagination import SyncPage
from openai.types import Model
from pydantic import ValidationError

from shim.api.deps import (
    get_anthropic_authenticated_principal,
    get_authenticated_principal,
    get_gateway_service,
)
from shim.api.v1.chat import ChatRequest, router as chat_router
from shim.api.v1.responses import ResponsesRequest, router as responses_router
from shim.billing.pricing import DEFAULT_PRICE_BOOK
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.gateway.kernel.result import UNSPECIFIED_PROVIDER_MODEL


def test_openai_253_chat_payload_round_trips_without_schema_drift() -> None:
    payload = {
        "model": "gpt-5.6-luna",
        "messages": [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_custom",
                        "type": "custom",
                        "custom": {"name": "exec", "input": "text('ok')"},
                        "future_item_field": {"nested": [1, True, None]},
                    }
                ],
            }
        ],
        "tools": [
            {
                "type": "custom",
                "custom": {
                    "name": "exec",
                    "description": "Run code",
                    "format": {
                        "type": "grammar",
                        "grammar": {"syntax": "lark", "definition": "start: /.+/"},
                    },
                },
            }
        ],
        "prompt_cache_key": "cache-key",
        "prompt_cache_options": {"retention": "24h", "future": {"nested": True}},
        "prompt_cache_retention": "24h",
        "reasoning_effort": "xhigh",
        "service_tier": "fast",
        "future_top_level": {"deep": [{"value": 1}]},
        "stream": True,
    }

    request = ChatRequest.model_validate(payload)

    assert request.model_dump() == payload
    assert request.provider_payload() == payload


def test_openai_253_responses_payload_round_trips_without_schema_drift() -> None:
    payload = {
        "model": "gpt-5.6-sol",
        "input": [
            {
                "type": "additional_tools",
                "role": "developer",
                "tools": [
                    {
                        "type": "namespace",
                        "name": "repo",
                        "description": "Repository tools",
                        "tools": [
                            {
                                "type": "custom",
                                "name": "exec",
                                "format": {"type": "text"},
                            }
                        ],
                    }
                ],
            },
            {
                "type": "message",
                "role": "user",
                "content": [
                    {
                        "type": "input_file",
                        "file_data": "data:application/pdf;base64,AA==",
                        "filename": "brief.pdf",
                    }
                ],
            },
            {
                "type": "custom_tool_call_output",
                "call_id": "call_exec",
                "output": [{"type": "input_text", "text": "done"}],
                "future_item_field": {"nested": [1, 2, 3]},
            },
            {
                "type": "reasoning",
                "summary": [],
                "encrypted_content": "opaque",
            },
        ],
        "tools": [
            {
                "type": "namespace",
                "name": "repo",
                "description": "Repository tools",
                "tools": [
                    {
                        "type": "custom",
                        "name": "exec",
                        "format": {"type": "grammar", "syntax": "lark"},
                    }
                ],
                "allowed_callers": ["direct", "programmatic"],
            }
        ],
        "background": False,
        "prompt_cache_key": "cache-key",
        "prompt_cache_options": {"retention": "24h", "future": {"nested": True}},
        "prompt_cache_retention": "24h",
        "reasoning": {
            "effort": "xhigh",
            "summary": "detailed",
            "context": "all_turns",
            "future_reasoning_field": {"nested": True},
        },
        "service_tier": "fast",
        "client_metadata": {"thread_id": "thread_1"},
        "unknown_top_level": {"deep": [{"value": 1}]},
        "stream": True,
    }

    request = ResponsesRequest.model_validate(payload)

    assert request.model_dump() == payload
    assert request.provider_payload("client_metadata") == {
        key: value for key, value in payload.items() if key != "client_metadata"
    }


@pytest.mark.parametrize(
    ("request_type", "payload"),
    [
        (ChatRequest, {"model": "", "messages": []}),
        (ChatRequest, {"model": 7, "messages": []}),
        (ChatRequest, {"model": "gpt-5.6", "messages": "hello"}),
        (ChatRequest, {"model": "gpt-5.6", "messages": [], "stream": 1}),
        (ResponsesRequest, {"model": " "}),
        (ResponsesRequest, {"model": ["gpt-5.6"]}),
        (ResponsesRequest, {"input": {"role": "user"}}),
        (ResponsesRequest, {"stream": "false"}),
        (ResponsesRequest, {"background": 1}),
        (ResponsesRequest, {"background": True}),
    ],
)
def test_openai_boundary_rejects_only_malformed_routing_scalars(
    request_type: type[ChatRequest] | type[ResponsesRequest], payload: dict
) -> None:
    with pytest.raises(ValidationError):
        request_type.model_validate(payload)


def test_responses_allows_omitted_model_and_input() -> None:
    request = ResponsesRequest.model_validate({"background": False, "unknown": 1})

    assert request.model == UNSPECIFIED_PROVIDER_MODEL
    assert request.provider_payload() == {"background": False, "unknown": 1}


def test_request_openapi_is_an_extensible_json_object() -> None:
    application = FastAPI()
    application.include_router(responses_router, prefix="/v1")
    schemas = application.openapi()["components"]["schemas"]

    assert schemas["ResponsesRequest"]["type"] == "object"
    assert "additionalProperties" in schemas["ResponsesRequest"]
    assert not any(name.startswith("ResponsesTool") for name in schemas)


def test_public_catalog_contains_only_approved_openai_models() -> None:
    assert DEFAULT_PRICE_BOOK.prices
    assert all("embedding" not in model for model in DEFAULT_PRICE_BOOK.prices)


def _endpoint_application(service) -> FastAPI:
    application = FastAPI()
    application.include_router(responses_router, prefix="/v1")
    application.include_router(chat_router, prefix="/v1")
    principal = AuthenticatedPrincipal(
        actor_type="api_key",
        api_key_id=UUID("22222222-2222-2222-2222-222222222222"),
        user_id=None,
        authenticated_at=datetime(2026, 7, 22, tzinfo=UTC),
    )
    application.dependency_overrides[get_gateway_service] = lambda: service
    application.dependency_overrides[get_authenticated_principal] = lambda: principal
    application.dependency_overrides[get_anthropic_authenticated_principal] = lambda: (
        principal
    )
    return application


@pytest.mark.asyncio
async def test_models_endpoint_returns_latest_openai_sdk_envelopes() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=_endpoint_application(SimpleNamespace())),
        base_url="http://shim.test",
    ) as client:
        codex_response = await client.get(
            "/v1/models", params={"client_version": "0.145.0"}
        )
        list_response = await client.get("/v1/models")
        model_response = await client.get("/v1/models/gpt-5.6-sol")

    assert codex_response.json() == {"models": []}
    page = SyncPage[Model].model_validate(list_response.json())
    model = Model.model_validate(model_response.json())
    assert {item.id for item in page.data} == set(DEFAULT_PRICE_BOOK.prices)
    assert model.id == "gpt-5.6-sol"
    assert model.created > 0


@pytest.mark.asyncio
async def test_responses_endpoint_preserves_provider_json_and_drops_client_metadata() -> (
    None
):
    service = SimpleNamespace(
        dispatch_inference=AsyncMock(
            return_value=JSONResponse(
                {"id": "resp_1", "object": "response", "status": "completed"}
            )
        )
    )
    payload = {
        "input": "hello",
        "background": False,
        "service_tier": "fast",
        "unknown": {"nested": [1, True, None]},
        "client_metadata": {"thread_id": "thread_1"},
    }
    async with AsyncClient(
        transport=ASGITransport(app=_endpoint_application(service)),
        base_url="http://shim.test",
    ) as client:
        response = await client.post(
            "/v1/responses",
            headers={"x-openai-api-key": "sk-openai-tenant"},
            json=payload,
        )

    assert response.json()["id"] == "resp_1"
    call = service.dispatch_inference.await_args.kwargs
    assert call["model"] == UNSPECIFIED_PROVIDER_MODEL
    assert call["payload"] == {
        key: value for key, value in payload.items() if key != "client_metadata"
    }
    assert call["provider_credential"].consume() == "sk-openai-tenant"


@pytest.mark.asyncio
async def test_chat_endpoint_forwards_body_without_narrowing() -> None:
    service = SimpleNamespace(
        dispatch_inference=AsyncMock(
            return_value=JSONResponse(
                {"id": "chatcmpl_1", "object": "chat.completion", "choices": []}
            )
        )
    )
    payload = {
        "model": "gpt-5.6-luna",
        "messages": [{"role": "user", "content": "hello", "future": True}],
        "service_tier": "fast",
        "unknown": {"nested": True},
    }
    async with AsyncClient(
        transport=ASGITransport(app=_endpoint_application(service)),
        base_url="http://shim.test",
    ) as client:
        response = await client.post(
            "/v1/chat/completions",
            headers={"x-openai-api-key": "sk-chat-tenant"},
            json=payload,
        )

    assert response.json()["id"] == "chatcmpl_1"
    call = service.dispatch_inference.await_args.kwargs
    assert call["payload"] == payload
    assert call["provider_credential"].consume() == "sk-chat-tenant"
