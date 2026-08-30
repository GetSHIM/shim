from __future__ import annotations

import json

import httpx
import pytest
from anthropic import APIStatusError as AnthropicStatusError
from anthropic import AsyncAnthropic
from fastapi import HTTPException
from openai import APIStatusError as OpenAIStatusError
from openai import AsyncOpenAI

from shim.gateway.api.errors import provider_error_response
from shim.gateway.pipeline.provider_execution import ProviderCallError


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
        assert payload["error"]["type"] == (
            "rate_limit_error"
            if status_code == 429
            else "authentication_error"
            if status_code == 401
            else "permission_error"
            if status_code == 403
            else "not_found_error"
            if status_code == 404
            else "conflict_error"
            if status_code == 409
            else "invalid_request_error"
            if status_code < 500
            else "server_error"
        )
    else:
        assert set(payload) == {"type", "error", "request_id"}
        assert payload["type"] == "error"
        assert set(payload["error"]) == {"type", "message"}


@pytest.mark.parametrize(
    ("error_code", "retryable", "status_code", "message"),
    [
        ("PROVIDER_TIMEOUT", True, 504, "The Google request timed out."),
        ("PROVIDER_UNAVAILABLE", True, 503, "Google is unavailable."),
        ("PROVIDER_UNAVAILABLE", False, 502, "Google is unavailable."),
        (
            "PROVIDER_NOT_CONFIGURED",
            False,
            502,
            "No Google credential is configured for this gateway. "
            "Add a provider credential before sending requests.",
        ),
    ],
)
def test_google_errors_preserve_generic_status_body_and_request_id_header(
    error_code: str,
    retryable: bool,
    status_code: int,
    message: str,
) -> None:
    with pytest.raises(HTTPException) as raised:
        provider_error_response(
            ProviderCallError(
                status_code=418,
                error_code=error_code,
                retryable=retryable,
                provider="google",
                request_id="google_req_safe",
                retry_after="7",
            )
        )

    assert raised.value.status_code == status_code
    assert raised.value.detail == {
        "code": error_code,
        "message": message,
        "retryable": retryable,
        "provider": "google",
    }
    assert raised.value.headers == {"x-goog-request-id": "google_req_safe"}


@pytest.mark.parametrize(
    ("provider", "provider_label"),
    [("openai", "OpenAI"), ("anthropic", "Anthropic")],
)
def test_unconfigured_provider_reports_setup_not_outage(
    provider: str,
    provider_label: str,
) -> None:
    # A workspace with no provider credential must not be told the provider
    # call "failed" — that reads as an outage and hides the real fix.
    response = provider_error_response(
        ProviderCallError(
            status_code=503,
            error_code="PROVIDER_NOT_CONFIGURED",
            retryable=False,
            provider=provider,
        )
    )
    payload = json.loads(bytes(response.body))
    # Native OpenAI and Anthropic envelopes both carry the human message at
    # error.message; only the surrounding envelope shape differs.
    message = payload["error"]["message"]
    assert message == (
        f"No {provider_label} credential is configured for this gateway. "
        "Add a provider credential before sending requests."
    )
    assert "request failed" not in message
    if provider == "openai":
        assert payload["error"]["code"] == "PROVIDER_NOT_CONFIGURED"
