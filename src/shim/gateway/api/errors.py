"""Stable public gateway errors."""

from collections.abc import Mapping, Sequence
from http import HTTPStatus
from typing import Any, NoReturn

from fastapi import HTTPException, Request
from fastapi.exception_handlers import (
    http_exception_handler,
    request_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, JsonValue
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, Response

from shim.gateway.contracts.ids import CURRENT_REQUEST_ID
from shim.gateway.pipeline.provider_execution import (
    ERROR_HINTS,
    ProviderCallError,
    google_error,
)


class OpenAIErrorDetail(BaseModel):
    message: str
    type: str
    param: JsonValue | None = None
    code: str | None = None
    hint: str | None = None


class OpenAIErrorResponse(BaseModel):
    error: OpenAIErrorDetail


class AnthropicErrorDetail(BaseModel):
    type: str
    message: str
    code: str | None = None
    hint: str | None = None


class AnthropicErrorResponse(BaseModel):
    type: str
    error: AnthropicErrorDetail
    request_id: str | None = None


_PROVIDER_ERROR_STATUSES = (
    400,
    401,
    402,
    403,
    404,
    408,
    409,
    413,
    422,
    429,
    500,
    502,
    503,
    504,
    529,
)
OPENAI_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status_code: {
        "model": OpenAIErrorResponse,
        "description": "Sanitized OpenAI-compatible error.",
    }
    for status_code in _PROVIDER_ERROR_STATUSES
}
ANTHROPIC_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status_code: {
        "model": AnthropicErrorResponse,
        "description": "Sanitized Anthropic-compatible error.",
    }
    for status_code in _PROVIDER_ERROR_STATUSES
}
MODEL_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status_code: {
        "model": OpenAIErrorResponse | AnthropicErrorResponse,
        "description": "OpenAI- or Anthropic-compatible error selected by headers.",
    }
    for status_code in (400, 401, 403, 404, 422, 429, 503)
}


async def gateway_exception_handler(
    request: Request,
    exc: Exception,
) -> Response:
    if isinstance(exc, RequestValidationError):
        response = native_gateway_error_response(
            path=request.url.path,
            request_headers=request.headers,
            status_code=422,
            detail=exc.errors(),
        )
        return response or await request_validation_exception_handler(request, exc)

    assert isinstance(exc, StarletteHTTPException)
    headers = dict(exc.headers or {})
    # Refusals raised after the request was admitted, such as an enterprise
    # quota or ledger failure, reach here without the id the kernel assigned.
    request_id = CURRENT_REQUEST_ID.get()
    if request_id is not None:
        headers.setdefault("X-Shim-Request-Id", request_id)
    response = native_gateway_error_response(
        path=request.url.path,
        request_headers=request.headers,
        status_code=exc.status_code,
        detail=exc.detail,
        headers=headers or None,
    )
    return response or await http_exception_handler(request, exc)


def native_gateway_error_response(
    *,
    path: str,
    request_headers: Mapping[str, str],
    status_code: int,
    detail: Any,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse | None:
    provider = _gateway_provider(path, request_headers)
    if provider is None:
        return None
    message, code, param, hint = _error_parts(detail, status_code)
    if code is None and headers is not None:
        code = headers.get("X-Shim-Error-Code")
    return _native_error_response(
        provider=provider,
        status_code=status_code,
        message=message,
        code=code,
        param=param,
        hint=hint,
        headers=headers,
    )


def _native_error_response(
    *,
    provider: str,
    status_code: int,
    message: str,
    code: str | None = None,
    param: JsonValue = None,
    hint: str | None = None,
    headers: Mapping[str, str] | None = None,
    request_id: str | None = None,
) -> JSONResponse:
    hint = hint or ERROR_HINTS.get(code or "")
    if provider == "openai":
        content = {
            "error": {
                "message": message,
                "type": _openai_error_type(status_code),
                "param": param,
                "code": code,
                "hint": hint,
            }
        }
    elif provider == "google":
        content = google_error(status_code, message, code, hint)
    else:
        error = {"type": _anthropic_error_type(status_code), "message": message}
        if code:
            error["code"] = code
        if hint:
            error["hint"] = hint
        content = {"type": "error", "error": error}
        if request_id:
            content["request_id"] = request_id
    if code:
        headers = {**(headers or {}), "X-Shim-Error-Code": code}
    return JSONResponse(status_code=status_code, content=content, headers=headers)


def _gateway_provider(
    path: str,
    headers: Mapping[str, str],
) -> str | None:
    normalized = path.rstrip("/")
    if normalized in {"/v1/messages", "/v1/messages/count_tokens"}:
        return "anthropic"
    if normalized in {"/v1/chat/completions", "/v1/responses"}:
        return "openai"
    if normalized == "/v1/models" or normalized.startswith("/v1/models/"):
        return "anthropic" if headers.get("anthropic-version") else "openai"
    if normalized.startswith("/v1beta/models/"):
        return "google"
    return None


def _error_parts(
    detail: Any, status_code: int
) -> tuple[str, str | None, JsonValue, str | None]:
    if isinstance(detail, str):
        return detail, None, None, None
    if isinstance(detail, Mapping):
        message = detail.get("message")
        code = detail.get("code")
        param = detail.get("param", detail.get("dimension"))
        hint = detail.get("hint")
        return (
            message if isinstance(message, str) else _status_message(status_code, code),
            code if isinstance(code, str) else None,
            param if isinstance(param, (str, int, float, bool)) else None,
            hint if isinstance(hint, str) else None,
        )
    if isinstance(detail, Sequence) and detail:
        first = detail[0]
        if isinstance(first, Mapping):
            message = first.get("msg")
            error_type = first.get("type")
            location = first.get("loc")
            param = (
                ".".join(str(part) for part in location if part != "body")
                if isinstance(location, Sequence)
                and not isinstance(location, (str, bytes))
                else None
            )
            return (
                message if isinstance(message, str) else _status_message(status_code),
                error_type if isinstance(error_type, str) else "INVALID_REQUEST",
                param or None,
                None,
            )
    return _status_message(status_code), None, None, None


def _status_message(status_code: int, code: object = None) -> str:
    if isinstance(code, str):
        return f"{code.replace('_', ' ').capitalize()}."
    try:
        return HTTPStatus(status_code).phrase
    except ValueError:
        return "Request failed."


def raise_privacy_continuation_error() -> NoReturn:
    raise HTTPException(
        status_code=503,
        detail={
            "code": "PRIVACY_STATE_UNAVAILABLE",
            "message": "Privacy continuation state is unavailable.",
        },
    ) from None


def provider_error_response(exc: ProviderCallError) -> JSONResponse:
    headers: dict[str, str] = {}
    if exc.request_id:
        headers[
            {
                "anthropic": "request-id",
                "google": "x-goog-request-id",
            }.get(exc.provider, "x-request-id")
        ] = exc.request_id
    if exc.retry_after:
        headers["retry-after"] = exc.retry_after
    if exc.shim_request_id:
        headers["X-Shim-Request-Id"] = exc.shim_request_id
    return _native_error_response(
        provider=exc.provider,
        status_code=exc.status_code,
        message=_provider_message(exc),
        code=exc.error_code,
        headers=headers,
        request_id=exc.request_id,
    )


def _provider_message(exc: ProviderCallError) -> str:
    provider = {
        "openai": "OpenAI",
        "anthropic": "Anthropic",
        "google": "Google",
    }.get(exc.provider, "Provider")
    if exc.message:
        return exc.message
    if exc.error_code == "PROVIDER_NOT_CONFIGURED":
        return (
            f"No {provider} credential is configured for this gateway. "
            "Add a provider credential before sending requests."
        )
    if exc.error_code == "PROVIDER_RATE_LIMITED":
        return f"The {provider} request was rate limited."
    if exc.error_code == "INVALID_PROVIDER_CREDENTIAL":
        return f"{provider} rejected the provider credential."
    if exc.error_code == "PROVIDER_REJECTED_REQUEST":
        return f"{provider} rejected the request."
    return (
        f"The {provider} request timed out."
        if exc.error_code == "PROVIDER_TIMEOUT"
        else f"The {provider} request failed."
    )


def _anthropic_error_type(status_code: int) -> str:
    return {
        400: "invalid_request_error",
        401: "authentication_error",
        402: "billing_error",
        403: "permission_error",
        404: "not_found_error",
        413: "request_too_large",
        422: "invalid_request_error",
        429: "rate_limit_error",
        529: "overloaded_error",
    }.get(status_code, "api_error")


def _openai_error_type(status_code: int) -> str:
    return {
        401: "authentication_error",
        403: "permission_error",
        404: "not_found_error",
        409: "conflict_error",
        429: "rate_limit_error",
    }.get(
        status_code,
        "invalid_request_error" if status_code < 500 else "server_error",
    )
