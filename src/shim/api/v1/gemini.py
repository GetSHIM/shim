"""Gemini Developer API-native generate-content routes."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Path, Query, Request
from google.genai import types
from pydantic import BaseModel, ConfigDict, Field, field_validator

from shim.api.deps import (
    dispatch_gateway_inference,
    get_authenticated_principal,
    get_gateway_service,
)
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.services.gateway.service import GatewayService

router = APIRouter()
ModelId = Annotated[
    str,
    Path(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
]


class GenerateContentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contents: list[types.Content] = Field(min_length=1, max_length=100_000)
    tools: list[types.Tool] | None = None
    tool_config: types.ToolConfig | None = Field(default=None, alias="toolConfig")
    safety_settings: list[types.SafetySetting] | None = Field(
        default=None,
        alias="safetySettings",
    )
    system_instruction: types.Content | None = Field(
        default=None,
        alias="systemInstruction",
    )
    generation_config: types.GenerationConfig | None = Field(
        default=None,
        alias="generationConfig",
    )
    cached_content: str | None = Field(
        default=None,
        alias="cachedContent",
        min_length=1,
    )
    service_tier: types.ServiceTier | None = Field(default=None, alias="serviceTier")
    store: bool | None = None

    @field_validator("contents")
    @classmethod
    def require_content_parts(
        cls,
        contents: list[types.Content],
    ) -> list[types.Content]:
        if any(not content.parts for content in contents):
            raise ValueError("each content item must contain at least one part")
        return contents


@router.post("/v1beta/models/{model}:generateContent")
async def generate_content(
    model: ModelId,
    request: Request,
    payload: GenerateContentRequest,
    gateway_service: GatewayService = Depends(get_gateway_service),
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
):
    return await _dispatch(
        model=model,
        request=request,
        payload=payload,
        stream=False,
        gateway_service=gateway_service,
        principal=principal,
    )


@router.post(
    "/v1beta/models/{model}:streamGenerateContent",
    responses={
        200: {
            "description": "Native Gemini server-sent events.",
            "content": {"text/event-stream": {"schema": {"type": "string"}}},
        }
    },
)
async def stream_generate_content(
    model: ModelId,
    request: Request,
    payload: GenerateContentRequest,
    _alt: Literal["sse"] = Query(alias="alt"),
    gateway_service: GatewayService = Depends(get_gateway_service),
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
):
    return await _dispatch(
        model=model,
        request=request,
        payload=payload,
        stream=True,
        gateway_service=gateway_service,
        principal=principal,
    )


async def _dispatch(
    *,
    model: str,
    request: Request,
    payload: GenerateContentRequest,
    stream: bool,
    gateway_service: GatewayService,
    principal: AuthenticatedPrincipal,
):
    return await dispatch_gateway_inference(
        request=request,
        payload=payload.model_dump(mode="json", exclude_none=True, by_alias=True),
        provider="google",
        protocol="generate_content",
        model=model,
        stream=stream,
        gateway_service=gateway_service,
        principal=principal,
    )
