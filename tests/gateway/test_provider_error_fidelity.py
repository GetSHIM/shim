from __future__ import annotations

import json

import httpx
import pytest
from anthropic import APIStatusError as AnthropicStatusError
from anthropic import AsyncAnthropic
from openai import APIStatusError as OpenAIStatusError
from openai import AsyncOpenAI

from shim.gateway.api.errors import (
    native_gateway_error_response,
    provider_error_response,
)
from shim.gateway.pipeline.provider_execution import ProviderCallError

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
    assert raised.value.request_id == "upstream_req_safe"
    assert raised.value.response.headers["retry-after"] == "7"
    payload = raised.value.response.json()
    assert "detail" not in payload
    assert b"gateway-key" not in wire_body
    if provider == "openai":
        assert set(payload) == {"error"}
        assert set(payload["error"]) == {"message", "type", "param", "code"}
        assert payload["error"]["type"] == _OPENAI_ERROR_TYPES.get(
            status_code,
            "invalid_request_error" if status_code < 500 else "server_error",
        )
    else:
        assert set(payload) == {"type", "error", "request_id"}
        assert payload["type"] == "error"
        assert set(payload["error"]) == {"type", "message"}


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
            "PROVIDER_UNAVAILABLE",
            True,
            429,
            "The Google request failed.",
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
        "error": {"code": status_code, "message": message, "status": status}
    }
    assert response.headers["x-goog-request-id"] == "google_req_safe"
    assert response.headers["retry-after"] == "7"


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
        }
    }
