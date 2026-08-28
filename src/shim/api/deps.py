"""Public inference HTTP dependencies."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import HTTPException, Request, Security
from fastapi.security import (
    APIKeyHeader,
    HTTPAuthorizationCredentials,
    HTTPBearer,
)
from starlette.responses import Response

from shim.gateway.auth import GatewayAuthenticator, select_gateway_credential
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.gateway.pipeline.authenticate import GatewayRequestMetadata
from shim.secrets.credentials import extract_provider_credential
from shim.services.gateway.service import GatewayService


api_key_header_scheme = APIKeyHeader(
    name="x-shim-key",
    scheme_name="ShimAPIKey",
    auto_error=False,
)
anthropic_api_key_header_scheme = APIKeyHeader(
    name="x-api-key",
    scheme_name="AnthropicAPIKey",
    auto_error=False,
)
bearer_scheme = HTTPBearer(auto_error=False)


def get_gateway_service(request: Request) -> GatewayService:
    gateway_service = getattr(request.app.state, "gateway_service", None)
    if gateway_service is None:
        raise HTTPException(status_code=503, detail="Gateway Service not available")
    return gateway_service


def _get_gateway_authenticator(request: Request) -> GatewayAuthenticator:
    authenticator = getattr(request.app.state, "gateway_authenticator", None)
    if authenticator is None:
        raise HTTPException(
            status_code=503,
            detail="Gateway authenticator not available",
        )
    return authenticator


async def get_authenticated_principal(
    request: Request,
    _api_key_header: str | None = Security(api_key_header_scheme),
    _bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> AuthenticatedPrincipal:
    return await _get_gateway_authenticator(request).resolve(
        select_gateway_credential(request.headers)
    )


async def get_anthropic_authenticated_principal(
    request: Request,
    _api_key_header: str | None = Security(api_key_header_scheme),
    _bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    _anthropic_api_key_header: str | None = Security(anthropic_api_key_header_scheme),
) -> AuthenticatedPrincipal:
    return await _get_gateway_authenticator(request).resolve(
        select_gateway_credential(
            request.headers,
            accept_anthropic_key=True,
        )
    )


async def dispatch_gateway_inference(
    *,
    request: Request,
    payload: dict[str, Any],
    provider: Literal["openai", "anthropic", "google"],
    protocol: Literal["chat", "responses", "messages", "generate_content"],
    model: str,
    stream: bool,
    gateway_service: GatewayService,
    principal: AuthenticatedPrincipal,
) -> Response:
    try:
        headers, provider_credential = extract_provider_credential(
            dict(request.headers), provider
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_PROVIDER_CREDENTIAL",
                "message": "Provider credential headers must not be empty.",
            },
        ) from None
    return await gateway_service.dispatch_inference(
        payload=payload,
        provider=provider,
        protocol=protocol,
        model=model,
        stream=stream,
        headers=headers,
        provider_credential=provider_credential,
        principal=principal,
        request_metadata=GatewayRequestMetadata(
            endpoint=request.url.path,
            method=request.method,
            query_params=tuple(request.query_params.multi_items()),
        ),
    )
