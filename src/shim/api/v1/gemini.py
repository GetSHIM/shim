"""Gemini Developer API-native generate-content routes."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from google.genai import types
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from shim.api.deps import (
    dispatch_gateway_inference,
    get_gateway_service,
    get_google_authenticated_principal,
)
from shim.api.v1.provider_request import ProviderRequest
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


def _has_parts(item: object) -> bool:
    content = item.get("content") if isinstance(item, dict) else None
    parts = content.get("parts") if isinstance(content, dict) else None
    return isinstance(parts, list) and bool(parts)


class EmbedContentRequest(ProviderRequest):
    """Native `:embedContent` or `:batchEmbedContents` JSON, kept as sent."""

    @model_validator(mode="after")
    def validate_content(self) -> EmbedContentRequest:
        items = (
            self.require("requests", list) if "requests" in self.root else [self.root]
        )
        if not items or not all(_has_parts(item) for item in items):
            raise ValueError("each request needs content with at least one part")
        return self


@router.post("/v1beta/models/{model}:embedContent")
@router.post("/v1beta/models/{model}:batchEmbedContents")
async def embed_content(
    model: ModelId,
    request: Request,
    payload: EmbedContentRequest,
    gateway_service: GatewayService = Depends(get_gateway_service),
    principal: AuthenticatedPrincipal = Depends(get_google_authenticated_principal),
):
    # The route names the shape: a batch sends `requests`, one call its `content`.
    if ("requests" in payload.root) != request.url.path.endswith(":batchEmbedContents"):
        raise RequestValidationError(
            [
                {
                    "type": "value_error",
                    "loc": ("body",),
                    "msg": "batchEmbedContents takes requests, embedContent content",
                }
            ]
        )
    return await dispatch_gateway_inference(
        request=request,
        payload=payload.provider_payload(),
        provider="google",
        protocol="embed_content",
        model=model,
        stream=False,
        gateway_service=gateway_service,
        principal=principal,
    )


@router.post("/v1beta/models/{model}:generateContent")
async def generate_content(
    model: ModelId,
    request: Request,
    payload: GenerateContentRequest,
    gateway_service: GatewayService = Depends(get_gateway_service),
    principal: AuthenticatedPrincipal = Depends(get_google_authenticated_principal),
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
    principal: AuthenticatedPrincipal = Depends(get_google_authenticated_principal),
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
