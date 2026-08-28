"""OpenAI-compatible Chat Completions and model-discovery routes."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Self

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, JsonValue, model_validator

from shim.api.deps import (
    dispatch_gateway_inference,
    get_anthropic_authenticated_principal,
    get_authenticated_principal,
    get_gateway_service,
)
from shim.api.v1.provider_request import ProviderRequest
from shim.billing.pricing import (
    DEFAULT_PRICE_BOOK,
    model_display_name,
    model_release_date,
)
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.gateway.api.errors import (
    MODEL_ERROR_RESPONSES,
    OPENAI_ERROR_RESPONSES,
)
from shim.services.gateway.service import GatewayService

router = APIRouter()


class ChatRequest(ProviderRequest):
    @model_validator(mode="after")
    def validate_routing_fields(self) -> Self:
        self.require_nonempty_string("model")
        self.require("messages", list)
        self.optional("stream", bool)
        return self

    @property
    def model(self) -> str:
        return self.require_nonempty_string("model")

    @property
    def stream(self) -> bool:
        value = self.optional("stream", bool)
        return value if isinstance(value, bool) else False


class ModelRecordView(BaseModel):
    id: str
    object: str
    created: int
    owned_by: str


class ModelListView(BaseModel):
    object: str
    data: list[ModelRecordView]


class CodexModelListView(BaseModel):
    models: list[dict[str, JsonValue]]


class AnthropicModelRecordView(BaseModel):
    id: str
    created_at: datetime
    display_name: str
    type: str


class AnthropicModelListView(BaseModel):
    data: list[AnthropicModelRecordView]
    has_more: bool
    first_id: str | None
    last_id: str | None


def model_record(model_id: str, provider: str = "openai") -> dict[str, object]:
    if model_id not in DEFAULT_PRICE_BOOK.models(provider):
        raise ValueError("model is absent from the public catalog")
    released = model_release_date(model_id, provider)
    created_at = (
        datetime(released.year, released.month, released.day, tzinfo=UTC)
        if released is not None
        else datetime.fromtimestamp(0, UTC)
    )
    if provider == "anthropic":
        return {
            "id": model_id,
            "created_at": created_at,
            "display_name": model_display_name(model_id, provider),
            "type": "model",
        }
    return {
        "id": model_id,
        "object": "model",
        "created": int(created_at.timestamp()),
        "owned_by": "openai",
    }


def _anthropic_model_page(
    model_ids: tuple[str, ...],
    *,
    after_id: str | None,
    before_id: str | None,
    limit: int,
) -> dict[str, object]:
    if after_id is not None and before_id is not None:
        raise HTTPException(status_code=400, detail="Use only one model cursor.")
    if after_id is not None or before_id is not None:
        cursor = after_id if after_id is not None else before_id
        assert cursor is not None
        try:
            cursor_index = model_ids.index(cursor)
        except ValueError:
            raise HTTPException(
                status_code=400, detail="Invalid model cursor."
            ) from None
    if after_id is not None:
        start = cursor_index + 1
        page = model_ids[start : start + limit]
        has_more = start + len(page) < len(model_ids)
    elif before_id is not None:
        start = max(0, cursor_index - limit)
        page = model_ids[start:cursor_index]
        has_more = start > 0
    else:
        page = model_ids[:limit]
        has_more = len(page) < len(model_ids)
    return {
        "data": [model_record(model_id, "anthropic") for model_id in page],
        "has_more": has_more,
        "first_id": page[0] if page else None,
        "last_id": page[-1] if page else None,
    }


@router.get(
    "/models",
    response_model=ModelListView | CodexModelListView | AnthropicModelListView,
    responses=MODEL_ERROR_RESPONSES,
)
async def list_models(
    _principal: AuthenticatedPrincipal = Depends(get_anthropic_authenticated_principal),
    anthropic_version: str | None = Header(None, alias="anthropic-version"),
    client_version: str | None = None,
    after_id: str | None = None,
    before_id: str | None = None,
    limit: int = Query(20, ge=1, le=1_000),
):
    if anthropic_version is not None:
        model_ids = DEFAULT_PRICE_BOOK.models("anthropic")
        return _anthropic_model_page(
            model_ids,
            after_id=after_id,
            before_id=before_id,
            limit=limit,
        )
    if client_version is not None:
        # Codex merges an empty remote catalog with its version-matched bundled metadata.
        return {"models": []}
    return {
        "object": "list",
        "data": [model_record(model_id) for model_id in DEFAULT_PRICE_BOOK.prices],
    }


@router.get(
    "/models/{model_id}",
    response_model=ModelRecordView | AnthropicModelRecordView,
    responses=MODEL_ERROR_RESPONSES,
)
async def retrieve_model(
    model_id: str,
    _principal: AuthenticatedPrincipal = Depends(get_anthropic_authenticated_principal),
    anthropic_version: str | None = Header(None, alias="anthropic-version"),
):
    provider = "anthropic" if anthropic_version is not None else "openai"
    try:
        return model_record(model_id, provider)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "MODEL_NOT_FOUND",
                "message": "The requested model is not in the public catalog.",
            },
        ) from None


@router.post(
    "/chat/completions",
    responses={
        200: {
            "description": "Native Chat Completion JSON or server-sent events.",
            "content": {"text/event-stream": {"schema": {"type": "string"}}},
        },
        **OPENAI_ERROR_RESPONSES,
    },
)
async def chat_completions(
    request: Request,
    payload: ChatRequest,
    gateway_service: GatewayService = Depends(get_gateway_service),
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
):
    return await dispatch_gateway_inference(
        request=request,
        payload=payload.provider_payload(),
        provider="openai",
        protocol="chat",
        model=payload.model,
        stream=payload.stream,
        gateway_service=gateway_service,
        principal=principal,
    )
