"""OpenAI-compatible Responses API route."""

from __future__ import annotations

from typing import Self

from fastapi import APIRouter, Depends, Request
from pydantic import model_validator

from shim.api.deps import (
    dispatch_gateway_inference,
    get_authenticated_principal,
    get_gateway_service,
)
from shim.api.v1.provider_request import ProviderRequest
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.gateway.api.errors import OPENAI_ERROR_RESPONSES
from shim.gateway.kernel.result import UNSPECIFIED_PROVIDER_MODEL
from shim.services.gateway.service import GatewayService

router = APIRouter()


class ResponsesRequest(ProviderRequest):
    @model_validator(mode="after")
    def validate_routing_fields(self) -> Self:
        self.optional_nonempty_string("model")
        if "input" in self.root and not isinstance(self.root["input"], (str, list)):
            raise ValueError("input must be str or list")
        self.optional("stream", bool)
        background = self.optional("background", bool)
        if background:
            raise ValueError("background execution is not supported")
        return self

    @property
    def model(self) -> str:
        return self.optional_nonempty_string("model") or UNSPECIFIED_PROVIDER_MODEL

    @property
    def stream(self) -> bool:
        value = self.optional("stream", bool)
        return value if isinstance(value, bool) else False


@router.post(
    "/responses",
    responses={
        200: {
            "description": "Native OpenAI Response JSON or server-sent events.",
            "content": {"text/event-stream": {"schema": {"type": "string"}}},
        },
        **OPENAI_ERROR_RESPONSES,
    },
)
async def responses(
    request: Request,
    payload: ResponsesRequest,
    gateway_service: GatewayService = Depends(get_gateway_service),
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
):
    return await dispatch_gateway_inference(
        request=request,
        payload=payload.provider_payload("client_metadata"),
        provider="openai",
        protocol="responses",
        model=payload.model,
        stream=payload.stream,
        gateway_service=gateway_service,
        principal=principal,
    )
