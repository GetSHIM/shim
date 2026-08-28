"""Anthropic-native Messages API route."""

from __future__ import annotations

from typing import Self

from fastapi import APIRouter, Depends, Request
from pydantic import model_validator

from shim.api.deps import (
    dispatch_gateway_inference,
    get_anthropic_authenticated_principal,
    get_gateway_service,
)
from shim.api.v1.provider_request import ProviderRequest
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.gateway.api.errors import ANTHROPIC_ERROR_RESPONSES
from shim.services.gateway.service import GatewayService

router = APIRouter()


class MessagesRequest(ProviderRequest):
    @model_validator(mode="after")
    def validate_routing_fields(self) -> Self:
        self.require_nonempty_string("model")
        self.require("messages", list)
        max_tokens = self.require("max_tokens", int)
        if isinstance(max_tokens, bool) or max_tokens < 0:
            raise ValueError("max_tokens must be a non-negative integer")
        self.optional("stream", bool)
        return self

    @property
    def model(self) -> str:
        return self.require_nonempty_string("model")

    @property
    def stream(self) -> bool:
        value = self.optional("stream", bool)
        return value if isinstance(value, bool) else False


@router.post(
    "/messages",
    responses={
        200: {
            "description": "Native Anthropic Message JSON or server-sent events.",
            "content": {"text/event-stream": {"schema": {"type": "string"}}},
        },
        **ANTHROPIC_ERROR_RESPONSES,
    },
)
async def messages(
    request: Request,
    payload: MessagesRequest,
    gateway_service: GatewayService = Depends(get_gateway_service),
    principal: AuthenticatedPrincipal = Depends(get_anthropic_authenticated_principal),
):
    provider_payload = payload.provider_payload()
    user_profile_id = request.headers.get("anthropic-user-profile-id")
    if user_profile_id is not None:
        provider_payload["user_profile_id"] = user_profile_id
    return await dispatch_gateway_inference(
        request=request,
        payload=provider_payload,
        provider="anthropic",
        protocol="messages",
        model=payload.model,
        stream=payload.stream,
        gateway_service=gateway_service,
        principal=principal,
    )
