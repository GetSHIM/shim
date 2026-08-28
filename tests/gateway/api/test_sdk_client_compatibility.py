from __future__ import annotations

import json
from datetime import UTC, datetime
from importlib.metadata import version
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

import httpx
import pytest
from anthropic import AsyncAnthropic
from anthropic import AuthenticationError as AnthropicAuthenticationError
from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from openai import AsyncOpenAI
from openai import AuthenticationError as OpenAIAuthenticationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, StreamingResponse

from shim.api.deps import (
    get_anthropic_authenticated_principal,
    get_authenticated_principal,
    get_gateway_service,
)
from shim.api.v1.chat import router as chat_router
from shim.api.v1.messages import router as messages_router
from shim.api.v1.responses import router as responses_router
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.gateway.api.errors import gateway_exception_handler


def _application(service) -> FastAPI:
    application = FastAPI()
    application.add_exception_handler(
        StarletteHTTPException,
        gateway_exception_handler,
    )
    application.add_exception_handler(
        RequestValidationError,
        gateway_exception_handler,
    )
    application.include_router(chat_router, prefix="/v1")
    application.include_router(messages_router, prefix="/v1")
    application.include_router(responses_router, prefix="/v1")
    principal = AuthenticatedPrincipal(
        actor_type="api_key",
        api_key_id=UUID("22222222-2222-2222-2222-222222222222"),
        user_id=None,
        authenticated_at=datetime(2026, 8, 11, tzinfo=UTC),
    )
    application.dependency_overrides[get_gateway_service] = lambda: service
    application.dependency_overrides[get_authenticated_principal] = lambda: principal
    application.dependency_overrides[get_anthropic_authenticated_principal] = lambda: (
        principal
    )
    return application


@pytest.mark.asyncio
async def test_native_clients_receive_gateway_auth_error_envelopes() -> None:
    def reject_auth() -> None:
        raise HTTPException(
            status_code=401,
            detail={"code": "INVALID_API_KEY", "message": "Invalid API Key"},
        )

    application = _application(SimpleNamespace())
    application.dependency_overrides[get_authenticated_principal] = reject_auth
    application.dependency_overrides[get_anthropic_authenticated_principal] = (
        reject_auth
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application)
    ) as http:
        openai = AsyncOpenAI(
            api_key="invalid",
            base_url="http://shim.test/v1",
            http_client=http,
            max_retries=0,
        )
        anthropic = AsyncAnthropic(
            api_key="invalid",
            base_url="http://shim.test",
            http_client=http,
            max_retries=0,
        )

        with pytest.raises(OpenAIAuthenticationError) as openai_error:
            await openai.responses.create(model="gpt-5", input="hello")
        with pytest.raises(AnthropicAuthenticationError) as anthropic_error:
            await anthropic.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=1,
                messages=[{"role": "user", "content": "hello"}],
            )

    assert openai_error.value.response.json() == {
        "error": {
            "message": "Invalid API Key",
            "type": "authentication_error",
            "param": None,
            "code": "INVALID_API_KEY",
        }
    }
    assert anthropic_error.value.response.json() == {
        "type": "error",
        "error": {
            "type": "authentication_error",
            "message": "Invalid API Key",
        },
    }


@pytest.mark.asyncio
async def test_validation_errors_use_the_route_native_envelope() -> None:
    application = _application(SimpleNamespace())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://shim.test",
    ) as http:
        openai = await http.post("/v1/chat/completions", json={})
        anthropic = await http.post(
            "/v1/messages",
            headers={"anthropic-version": "2023-06-01"},
            json={},
        )

    assert openai.status_code == anthropic.status_code == 422
    assert set(openai.json()) == {"error"}
    assert openai.json()["error"]["type"] == "invalid_request_error"
    assert anthropic.json()["type"] == "error"
    assert anthropic.json()["error"]["type"] == "invalid_request_error"


def test_provider_sdk_versions_are_the_reviewed_pins() -> None:
    assert version("openai") == "2.53.0"
    assert version("anthropic") == "0.121.0"


def _openai_response(response_id: str) -> dict:
    return {
        "id": response_id,
        "object": "response",
        "created_at": 1.0,
        "status": "completed",
        "model": "gpt-5.6-luna",
        "output": [],
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "usage": {
            "input_tokens": 1,
            "input_tokens_details": {
                "cached_tokens": 0,
                "cache_write_tokens": 0,
            },
            "output_tokens": 2,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 3,
        },
    }


def _anthropic_message(message_id: str) -> dict:
    return {
        "id": message_id,
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "ok"}],
        "model": "claude-sonnet-4-6",
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }


@pytest.mark.asyncio
async def test_latest_openai_client_uses_gateway_routes_without_adaptation() -> None:
    async def dispatch(**kwargs):
        if kwargs["protocol"] == "responses":
            return JSONResponse(_openai_response("resp_sdk"))
        return JSONResponse(
            {
                "id": "chatcmpl_sdk",
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
            }
        )

    service = SimpleNamespace(dispatch_inference=AsyncMock(side_effect=dispatch))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_application(service))
    ) as http:
        client = AsyncOpenAI(
            api_key="shim-key",
            base_url="http://shim.test/v1",
            http_client=http,
            max_retries=0,
        )
        response = await client.responses.create(
            model="gpt-5.6-luna",
            input="hello",
            background=False,
            reasoning={"effort": "max"},
            service_tier="fast",
            tools=[{"type": "file_search", "vector_store_ids": ["vs_1"]}],
        )
        chat = await client.chat.completions.create(
            model="gpt-5.6-luna",
            messages=[{"role": "user", "content": "hello"}],
            reasoning_effort="max",
            service_tier="fast",
            tools=[
                {
                    "type": "custom",
                    "custom": {"name": "exec", "description": "Run code"},
                }
            ],
        )
        models = await client.models.list()
        model = await client.models.retrieve("gpt-5.6-luna")

    assert response.id == "resp_sdk"
    assert chat.id == "chatcmpl_sdk"
    assert any(model.id == "gpt-5.6-luna" for model in models.data)
    assert model.id == "gpt-5.6-luna"
    response_call, chat_call = service.dispatch_inference.await_args_list[:2]
    assert response_call.kwargs["payload"]["tools"][0]["type"] == "file_search"
    assert response_call.kwargs["payload"]["service_tier"] == "fast"
    assert chat_call.kwargs["payload"]["tools"][0]["type"] == "custom"
    assert response_call.kwargs["provider_credential"] is None
    assert chat_call.kwargs["provider_credential"] is None


@pytest.mark.asyncio
async def test_latest_anthropic_client_uses_gateway_routes_without_adaptation() -> None:
    service = SimpleNamespace(
        dispatch_inference=AsyncMock(
            return_value=JSONResponse(_anthropic_message("msg_sdk"))
        )
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_application(service))
    ) as http:
        client = AsyncAnthropic(
            api_key="shim-key",
            base_url="http://shim.test",
            http_client=http,
            max_retries=0,
        )
        message = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=0,
            messages=[{"role": "user", "content": "hello"}],
            service_tier="auto",
            user_profile_id="profile_1",
        )
        beta_message = await client.beta.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1,
            messages=[{"role": "user", "content": "hello"}],
            betas=["fast-mode-2026-02-01"],
            speed="fast",
        )
        models = await client.models.list(limit=1)
        next_models = await models.get_next_page()
        model = await client.models.retrieve("claude-sonnet-4-6")
        beta_model = await client.beta.models.retrieve("claude-sonnet-4-6")

    assert message.id == "msg_sdk"
    assert beta_message.id == "msg_sdk"
    assert len(models.data) == 1
    assert models.has_more is True
    assert len(next_models.data) == 1
    assert next_models.data[0].id != models.data[0].id
    assert model.id == "claude-sonnet-4-6"
    assert beta_model.id == "claude-sonnet-4-6"
    regular_call, beta_call = service.dispatch_inference.await_args_list
    assert regular_call.kwargs["payload"]["max_tokens"] == 0
    assert regular_call.kwargs["payload"]["user_profile_id"] == "profile_1"
    assert regular_call.kwargs["provider_credential"] is None
    assert beta_call.kwargs["payload"]["speed"] == "fast"
    assert ("beta", "true") in beta_call.kwargs["request_metadata"].query_params


@pytest.mark.asyncio
async def test_latest_clients_parse_all_gateway_stream_protocols() -> None:
    async def dispatch(**kwargs):
        protocol = kwargs["protocol"]
        if protocol == "responses":
            response = _openai_response("resp_stream")
            events = [
                {
                    "type": "response.created",
                    "response": response,
                    "sequence_number": 0,
                },
                {
                    "type": "response.completed",
                    "response": response,
                    "sequence_number": 1,
                },
            ]
            wire = b"".join(
                f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()
                for event in events
            )
        elif protocol == "chat":
            chunks = [
                {
                    "id": "chatcmpl_stream",
                    "object": "chat.completion.chunk",
                    "created": 1,
                    "model": "gpt-5.6-luna",
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"role": "assistant", "content": "ok"},
                            "finish_reason": None,
                        }
                    ],
                },
                {
                    "id": "chatcmpl_stream",
                    "object": "chat.completion.chunk",
                    "created": 1,
                    "model": "gpt-5.6-luna",
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                },
            ]
            wire = (
                b"".join(f"data: {json.dumps(chunk)}\n\n".encode() for chunk in chunks)
                + b"data: [DONE]\n\n"
            )
        else:
            message = _anthropic_message("msg_stream")
            events = [
                {"type": "message_start", "message": message},
                {"type": "message_stop"},
            ]
            wire = b"".join(
                f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()
                for event in events
            )
        return StreamingResponse(iter([wire]), media_type="text/event-stream")

    service = SimpleNamespace(dispatch_inference=AsyncMock(side_effect=dispatch))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_application(service))
    ) as http:
        openai = AsyncOpenAI(
            api_key="shim-key",
            base_url="http://shim.test/v1",
            http_client=http,
            max_retries=0,
        )
        anthropic = AsyncAnthropic(
            api_key="shim-key",
            base_url="http://shim.test",
            http_client=http,
            max_retries=0,
        )
        response_stream = await openai.responses.create(
            model="gpt-5.6-luna", input="hello", stream=True
        )
        response_types = [event.type async for event in response_stream]
        chat_stream = await openai.chat.completions.create(
            model="gpt-5.6-luna",
            messages=[{"role": "user", "content": "hello"}],
            stream=True,
        )
        chat_chunks = [chunk async for chunk in chat_stream]
        message_stream = await anthropic.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1,
            messages=[{"role": "user", "content": "hello"}],
            stream=True,
        )
        message_types = [event.type async for event in message_stream]

    assert response_types == ["response.created", "response.completed"]
    assert chat_chunks[0].choices[0].delta.content == "ok"
    assert chat_chunks[-1].choices[0].finish_reason == "stop"
    assert message_types == ["message_start", "message_stop"]
