from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from io import StringIO
import json

import httpx
import pytest
from anthropic import APIStatusError as AnthropicStatusError
from anthropic import AsyncAnthropic
from google import genai
from google.genai import errors as genai_errors
from google.genai import types as genai_types
from openai import APIStatusError as OpenAIStatusError
from openai import AsyncOpenAI

from shim.application import create_community_app
from shim.core.community_config import CommunitySettings
from shim.gateway.api.errors import (
    native_gateway_error_response,
    provider_error_response,
)
from shim.gateway.pipeline.provider_execution import (
    ERROR_HINTS,
    ProviderCallError,
    provider_reason,
)


def _error_info(code: str) -> dict[str, object]:
    return {
        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        "reason": code,
        "domain": "getshim.tech",
        "metadata": {"hint": ERROR_HINTS[code]},
    }


_OPENAI_ERROR_TYPES = {
    401: "authentication_error",
    403: "permission_error",
    404: "not_found_error",
    409: "conflict_error",
    429: "rate_limit_error",
}


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["openai", "anthropic"])
@pytest.mark.parametrize(
    ("status_code", "openai_error", "anthropic_error"),
    [
        (400, "BadRequestError", "BadRequestError"),
        (401, "AuthenticationError", "AuthenticationError"),
        (402, "APIStatusError", "APIStatusError"),
        (403, "PermissionDeniedError", "PermissionDeniedError"),
        (404, "NotFoundError", "NotFoundError"),
        (408, "APIStatusError", "APIStatusError"),
        (409, "ConflictError", "ConflictError"),
        (413, "APIStatusError", "RequestTooLargeError"),
        (422, "UnprocessableEntityError", "UnprocessableEntityError"),
        (429, "RateLimitError", "RateLimitError"),
        (500, "InternalServerError", "InternalServerError"),
        (502, "InternalServerError", "InternalServerError"),
        (504, "InternalServerError", "InternalServerError"),
        (529, "InternalServerError", "OverloadedError"),
    ],
)
async def test_provider_errors_preserve_status_and_real_sdk_exception_types(
    provider: str,
    status_code: int,
    openai_error: str,
    anthropic_error: str,
) -> None:
    attempts = 0
    wire_body = b""

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts, wire_body
        attempts += 1
        response = provider_error_response(
            ProviderCallError(
                status_code=status_code,
                error_code="PROVIDER_UNAVAILABLE",
                retryable=status_code in {408, 409, 429} or status_code >= 500,
                provider=provider,
                request_id="upstream_req_safe",
                retry_after="7",
            )
        )
        wire_body = response.body
        return httpx.Response(
            response.status_code,
            content=response.body,
            headers=dict(response.headers),
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        if provider == "openai":
            client = AsyncOpenAI(
                api_key="gateway-key",
                base_url="https://gateway.test/v1",
                http_client=http,
                max_retries=0,
            )
            expected_base = OpenAIStatusError
            call = client.responses.create(model="gpt-5.6-luna", input="hello")
            expected_error = openai_error
        else:
            client = AsyncAnthropic(
                api_key="gateway-key",
                base_url="https://gateway.test",
                http_client=http,
                max_retries=0,
            )
            expected_base = AnthropicStatusError
            call = client.messages.create(
                model="claude-sonnet-4-5",
                max_tokens=1,
                messages=[{"role": "user", "content": "hello"}],
            )
            expected_error = anthropic_error

        with pytest.raises(expected_base) as raised:
            await call

    assert attempts == 1
    assert type(raised.value).__name__ == expected_error
    assert raised.value.status_code == status_code
    assert raised.value.response.headers["x-shim-error-code"] == "PROVIDER_UNAVAILABLE"
    assert raised.value.request_id == "upstream_req_safe"
    assert raised.value.response.headers["retry-after"] == "7"
    payload = raised.value.response.json()
    assert "detail" not in payload
    assert b"gateway-key" not in wire_body
    if provider == "openai":
        assert set(payload) == {"error"}
        assert set(payload["error"]) == {"message", "type", "param", "code", "hint"}
        assert payload["error"]["type"] == _OPENAI_ERROR_TYPES.get(
            status_code,
            "invalid_request_error" if status_code < 500 else "server_error",
        )
    else:
        assert set(payload) == {"type", "error", "request_id"}
        assert payload["type"] == "error"
        assert set(payload["error"]) == {"type", "message", "code", "hint"}
        assert payload["error"]["code"] == "PROVIDER_UNAVAILABLE"
    assert payload["error"]["hint"] == ERROR_HINTS["PROVIDER_UNAVAILABLE"]


@pytest.mark.parametrize(
    ("error_code", "retryable", "status_code", "message", "status"),
    [
        (
            "PROVIDER_TIMEOUT",
            True,
            504,
            "The Google request timed out.",
            "DEADLINE_EXCEEDED",
        ),
        (
            "PROVIDER_UNAVAILABLE",
            True,
            503,
            "The Google request failed.",
            "UNAVAILABLE",
        ),
        (
            "PROVIDER_UNAVAILABLE",
            False,
            502,
            "The Google request failed.",
            "UNAVAILABLE",
        ),
        (
            "PROVIDER_RATE_LIMITED",
            True,
            429,
            "The Google request was rate limited.",
            "RESOURCE_EXHAUSTED",
        ),
        (
            "PROVIDER_NOT_CONFIGURED",
            False,
            503,
            "No Google credential is configured for this gateway. "
            "Add a provider credential before sending requests.",
            "UNAVAILABLE",
        ),
    ],
)
def test_google_errors_use_native_gemini_envelope(
    error_code: str,
    retryable: bool,
    status_code: int,
    message: str,
    status: str,
) -> None:
    response = provider_error_response(
        ProviderCallError(
            status_code=status_code,
            error_code=error_code,
            retryable=retryable,
            provider="google",
            request_id="google_req_safe",
            retry_after="7",
        )
    )

    assert response.status_code == status_code
    payload = json.loads(response.body)
    assert payload == {
        "error": {
            "code": status_code,
            "message": message,
            "status": status,
            "details": [_error_info(error_code)],
        }
    }
    assert response.headers["x-shim-error-code"] == error_code
    assert response.headers["x-goog-request-id"] == "google_req_safe"
    assert response.headers["retry-after"] == "7"


@pytest.mark.parametrize(
    ("provider", "provider_label"),
    [("openai", "OpenAI"), ("anthropic", "Anthropic"), ("google", "Google")],
)
def test_rate_limit_keeps_status_retry_after_and_its_own_code(
    provider: str,
    provider_label: str,
) -> None:
    response = provider_error_response(
        ProviderCallError(
            status_code=429,
            error_code="PROVIDER_RATE_LIMITED",
            retryable=True,
            provider=provider,
            retry_after="7",
        )
    )

    payload = json.loads(response.body)
    assert response.status_code == 429
    assert response.headers["retry-after"] == "7"
    assert response.headers["x-shim-error-code"] == "PROVIDER_RATE_LIMITED"
    assert (
        payload["error"]["message"] == f"The {provider_label} request was rate limited."
    )
    if provider == "openai":
        assert payload["error"]["code"] == "PROVIDER_RATE_LIMITED"


@pytest.mark.parametrize(
    ("provider", "provider_label"),
    [("openai", "OpenAI"), ("anthropic", "Anthropic"), ("google", "Google")],
)
def test_unconfigured_provider_reports_setup_not_outage(
    provider: str,
    provider_label: str,
) -> None:
    response = provider_error_response(
        ProviderCallError(
            status_code=503,
            error_code="PROVIDER_NOT_CONFIGURED",
            retryable=False,
            provider=provider,
        )
    )
    payload = json.loads(response.body)
    message = payload["error"]["message"]
    assert message == (
        f"No {provider_label} credential is configured for this gateway. "
        "Add a provider credential before sending requests."
    )
    assert "request failed" not in message
    if provider == "openai":
        assert payload["error"]["code"] == "PROVIDER_NOT_CONFIGURED"


def test_gemini_route_errors_use_native_envelope_not_detail() -> None:
    response = native_gateway_error_response(
        path="/v1beta/models/gemini-2.0-flash:generateContent",
        request_headers={},
        status_code=400,
        detail={
            "code": "MODEL_NOT_PRICED",
            "message": "The requested model is not in this gateway's supported model catalog. Use a supported model.",
        },
    )

    assert response is not None
    payload = json.loads(response.body)
    assert payload == {
        "error": {
            "code": 400,
            "message": "The requested model is not in this gateway's supported model catalog. Use a supported model.",
            "status": "INVALID_ARGUMENT",
            "details": [_error_info("MODEL_NOT_PRICED")],
        }
    }
    assert response.headers["x-shim-error-code"] == "MODEL_NOT_PRICED"


_EMAIL = "alice@example.com"


@asynccontextmanager
async def _gateway(
    handler: Callable[[httpx.Request], httpx.Response],
) -> AsyncIterator[httpx.AsyncClient]:
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    application = create_community_app(
        CommunitySettings(
            OPENAI_BASE_URL="https://upstream.test/v1",
            ANTHROPIC_BASE_URL="https://upstream.test",
            GOOGLE_BASE_URL="https://upstream.test",
            BACKEND_CORS_ORIGINS=[],
            _env_file=None,
        ),
        http_client=upstream,
        event_stream=StringIO(),
    )
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="http://127.0.0.1",
        ) as http,
    ):
        yield http
    await upstream.aclose()


async def _sdk_call(
    protocol: str, http: httpx.AsyncClient, model: str | None = None
) -> None:
    headers = {"x-provider-key": "provider-key-000000"}
    prompt = f"Email {_EMAIL} about the invoice"
    if protocol == "openai":
        await AsyncOpenAI(
            api_key="unused",
            base_url="http://127.0.0.1/v1",
            http_client=http,
            max_retries=0,
            default_headers=headers,
        ).chat.completions.create(
            model=model or "gpt-5.6-luna",
            messages=[{"role": "user", "content": prompt}],
        )
    elif protocol == "anthropic":
        await AsyncAnthropic(
            api_key="unused",
            base_url="http://127.0.0.1",
            http_client=http,
            max_retries=0,
            default_headers=headers,
        ).messages.create(
            model=model or "claude-sonnet-4-5",
            max_tokens=16,
            messages=[{"role": "user", "content": prompt}],
        )
    else:
        await genai.Client(
            api_key="unused",
            http_options=genai_types.HttpOptions(
                base_url="http://127.0.0.1",
                api_version="v1beta",
                retry_options=genai_types.HttpRetryOptions(attempts=1),
                httpx_async_client=http,
                headers=headers,
            ),
        ).aio.models.generate_content(
            model=model or "gemini-3.5-flash", contents=prompt
        )


def _sent_prompt(protocol: str, request: httpx.Request) -> str:
    body = json.loads(request.content)
    if protocol == "google":
        return body["contents"][0]["parts"][0]["text"]
    return body["messages"][0]["content"]


def _provider_error_body(protocol: str, status_code: int, message: str) -> dict:
    if protocol == "openai":
        return {"error": {"message": message, "type": "invalid_request_error"}}
    if protocol == "anthropic":
        return {
            "type": "error",
            "error": {"type": "invalid_request_error", "message": message},
        }
    return {"error": {"code": status_code, "message": message, "status": "X"}}


async def _gateway_error(protocol: str, http: httpx.AsyncClient, **kwargs):
    with pytest.raises(
        (OpenAIStatusError, AnthropicStatusError, genai_errors.APIError)
    ) as raised:
        await _sdk_call(protocol, http, **kwargs)
    return raised.value.response


def _error_fields(protocol: str, body: dict) -> tuple[str, str | None, str | None]:
    error = body["error"]
    if protocol == "google":
        [info] = error["details"]
        return error["message"], info["reason"], info["metadata"]["hint"]
    return error["message"], error.get("code"), error.get("hint")


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["openai", "anthropic", "google"])
@pytest.mark.parametrize("status_code", [400, 404, 413, 422])
async def test_a_provider_rejection_keeps_its_reason_masked_with_code_and_hint(
    protocol: str, status_code: int
) -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        reason = f"Unsupported value in: {_sent_prompt(protocol, request)}"
        return httpx.Response(
            status_code, json=_provider_error_body(protocol, status_code, reason)
        )

    async with _gateway(handler) as http:
        response = await _gateway_error(protocol, http)

    message, code, hint = _error_fields(protocol, response.json())
    assert attempts == 1
    assert response.status_code == status_code
    assert response.headers["x-shim-error-code"] == "PROVIDER_REJECTED_REQUEST"
    assert response.headers["x-shim-request-id"].startswith("req_")
    assert code == "PROVIDER_REJECTED_REQUEST"
    assert hint == ERROR_HINTS["PROVIDER_REJECTED_REQUEST"]
    assert message.startswith("Unsupported value in: Email ")
    assert _EMAIL not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["openai", "anthropic", "google"])
async def test_a_provider_credential_rejection_is_not_a_shim_key_rejection(
    protocol: str,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json=_provider_error_body(
                protocol, 401, "Incorrect API key provided: provider-key-000000"
            ),
        )

    async with _gateway(handler) as http:
        response = await _gateway_error(protocol, http)

    message, code, hint = _error_fields(protocol, response.json())
    assert response.status_code == 401
    assert response.headers["x-shim-error-code"] == "INVALID_PROVIDER_CREDENTIAL"
    assert code == "INVALID_PROVIDER_CREDENTIAL"
    assert hint == ERROR_HINTS["INVALID_PROVIDER_CREDENTIAL"]
    assert message.endswith("rejected the provider credential.")
    assert "provider-key-000000" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("protocol", "body"),
    [
        ("openai", b"not json{"),
        ("anthropic", b"not json{"),
        ("google", b"not json{"),
        ("google", b'{"candidates":[{"content":{"parts":"x"}}]}'),
    ],
)
async def test_a_malformed_provider_answer_stays_a_bad_gateway(
    protocol: str, body: bytes
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=body, headers={"content-type": "application/json"}
        )

    async with _gateway(handler) as http:
        response = await _gateway_error(protocol, http)

    assert response.status_code == 502
    assert response.headers["x-shim-error-code"] == "PROVIDER_UNAVAILABLE"
    assert _error_fields(protocol, response.json())[1:] == (
        "PROVIDER_UNAVAILABLE",
        ERROR_HINTS["PROVIDER_UNAVAILABLE"],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["openai", "anthropic", "google"])
async def test_gateway_refusals_carry_a_hint_and_the_request_id(protocol: str) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("an unpriced model never reaches the provider")

    async with _gateway(handler) as http:
        response = await _gateway_error(protocol, http, model="not-in-the-catalog")

    assert response.status_code == 400
    assert response.headers["x-shim-request-id"].startswith("req_")
    assert _error_fields(protocol, response.json())[1:] == (
        "MODEL_NOT_PRICED",
        ERROR_HINTS["MODEL_NOT_PRICED"],
    )


@pytest.mark.parametrize(
    ("status_code", "body", "reason"),
    [
        (400, {"error": {"message": "  bad value  "}}, "bad value"),
        (422, {"message": "flat"}, "flat"),
        (400, {"error": {"message": "x" * 600}}, "x" * 500),
        (404, {"error": {"message": "   "}}, None),
        (400, {"error": "not an object"}, None),
        (400, {"error": {"message": 7}}, None),
        (400, ["not", "an", "object"], None),
        (400, None, None),
        (403, {"error": {"message": "policy detail"}}, None),
        (401, {"error": {"message": "key detail"}}, None),
        (429, {"error": {"message": "quota detail"}}, None),
        (500, {"error": {"message": "server detail"}}, None),
    ],
)
def test_only_bounded_reasons_of_correctable_rejections_are_forwarded(
    status_code: int, body: object, reason: str | None
) -> None:
    assert provider_reason(status_code, body) == reason


@pytest.mark.parametrize("code", ["MODEL_NOT_PRICED", None])
def test_a_raise_site_hint_overrides_the_table(code: str | None) -> None:
    response = native_gateway_error_response(
        path="/v1/messages",
        request_headers={},
        status_code=400,
        detail={"code": code, "message": "Refused.", "hint": "Do this instead."},
    )

    assert response is not None
    assert json.loads(response.body)["error"]["hint"] == "Do this instead."


_TRUNCATED_STREAMS = {
    "/v1/chat/completions": (
        {
            "model": "gpt-5.6-luna",
            "stream": True,
            "messages": [{"role": "user", "content": "hello"}],
        },
        {
            "id": "chat_cut",
            "object": "chat.completion.chunk",
            "created": 1,
            "model": "gpt-5.6-luna",
            "choices": [{"index": 0, "delta": {"content": "par"}}],
        },
    ),
    "/v1/messages": (
        {
            "model": "claude-sonnet-4-5",
            "max_tokens": 16,
            "stream": True,
            "messages": [{"role": "user", "content": "hello"}],
        },
        {
            "type": "message_start",
            "message": {
                "id": "msg_cut",
                "type": "message",
                "role": "assistant",
                "content": [],
                "model": "claude-sonnet-4-5",
                "stop_reason": None,
                "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 0},
            },
        },
    ),
    "/v1beta/models/gemini-3.5-flash:streamGenerateContent?alt=sse": (
        {"contents": [{"role": "user", "parts": [{"text": "hello"}]}]},
        {
            "candidates": [
                {"index": 0, "content": {"parts": [{"text": "par"}], "role": "model"}}
            ]
        },
    ),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("path", list(_TRUNCATED_STREAMS))
async def test_a_stream_error_event_carries_the_code_and_hint(path: str) -> None:
    body, event = _TRUNCATED_STREAMS[path]

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=f"data: {json.dumps(event)}\n\n".encode(),
            headers={"content-type": "text/event-stream"},
        )

    async with _gateway(handler) as http:
        response = await http.post(
            path, json=body, headers={"x-provider-key": "provider-key-000000"}
        )

    data = [
        json.loads(line.removeprefix("data: "))
        for line in response.text.splitlines()
        if line.startswith("data: {")
    ]
    error = data[-1]["error"]
    code = error["details"][0]["reason"] if "details" in error else error["code"]
    hint = (
        error["details"][0]["metadata"]["hint"] if "details" in error else error["hint"]
    )
    assert response.headers["x-shim-request-id"].startswith("req_")
    assert (code, hint) == ("PROVIDER_UNAVAILABLE", ERROR_HINTS["PROVIDER_UNAVAILABLE"])
