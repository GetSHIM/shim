"""Authenticated creation and bounded public access for Playground shares."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import re
import secrets

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import get_current_api_key
from shim_enterprise.core.database import get_db
from shim.privacy.pii_scrubber import PIIScrubberService
from shim_enterprise.shared_results.models import SharedResult
from shim_enterprise.tenants.models import ApiKey


SHARE_LIFETIME = timedelta(hours=24)
SHARE_MAX_VIEWS = 25
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43,64}")

authenticated_router = APIRouter(prefix="/shared-results", tags=["shared-results"])
public_router = APIRouter(prefix="/shared-results", tags=["shared-results"])


class SharedResultCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt: str = Field(min_length=1, max_length=4_000)
    response: str = Field(min_length=1, max_length=12_000)

    @field_validator("prompt", "response")
    @classmethod
    def reject_blank_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("shared text cannot be blank")
        return value


class SharedResultCreated(BaseModel):
    token: str
    expires_at: datetime
    max_views: int


class SharedResultView(BaseModel):
    prompt: str
    response: str
    created_at: datetime
    expires_at: datetime
    view_count: int
    max_views: int


@authenticated_router.post(
    "",
    response_model=SharedResultCreated,
    status_code=status.HTTP_201_CREATED,
)
async def create_shared_result(
    payload: SharedResultCreate,
    response: Response,
    api_key: ApiKey = Depends(get_current_api_key),
    session: AsyncSession = Depends(get_db),
) -> SharedResultCreated:
    scrubber = PIIScrubberService()
    prompt, prompt_map = scrubber.scrub(payload.prompt)
    result, _ = scrubber.scrub(
        payload.response,
        known_placeholders=prompt_map,
    )
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + SHARE_LIFETIME
    session.add(
        SharedResult(
            organization_id=api_key.organization_id,
            token_hash=_token_digest(token),
            prompt=prompt,
            response=result,
            expires_at=expires_at,
            max_views=SHARE_MAX_VIEWS,
        )
    )
    await session.commit()
    response.headers["Cache-Control"] = "no-store"
    return SharedResultCreated(
        token=token,
        expires_at=expires_at,
        max_views=SHARE_MAX_VIEWS,
    )


@public_router.get("/{token}", response_model=SharedResultView)
async def view_shared_result(
    token: str,
    response: Response,
    session: AsyncSession = Depends(get_db),
) -> SharedResultView:
    if _TOKEN_PATTERN.fullmatch(token) is None:
        raise _not_found()
    shared = (
        await session.execute(
            update(SharedResult)
            .where(
                SharedResult.token_hash == _token_digest(token),
                SharedResult.expires_at > datetime.now(timezone.utc),
                SharedResult.view_count < SharedResult.max_views,
            )
            .values(view_count=SharedResult.view_count + 1)
            .returning(SharedResult)
        )
    ).scalar_one_or_none()
    if shared is None:
        raise _not_found()
    await session.commit()
    response.headers["Cache-Control"] = "no-store"
    return SharedResultView(
        prompt=shared.prompt,
        response=shared.response,
        created_at=shared.created_at,
        expires_at=shared.expires_at,
        view_count=shared.view_count,
        max_views=shared.max_views,
    )


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Not found.",
        headers={"Cache-Control": "no-store"},
    )
