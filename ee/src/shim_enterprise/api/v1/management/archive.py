"""Request archive: opening content, the openings log and purge."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import AwareDatetime, BaseModel, Field
from sqlalchemy import Text, cast as sql_cast, delete as sql_delete, func, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import get_current_user, get_org_owner, require
from shim_enterprise.ai_act.models import AIActAuditLog
from shim_enterprise.archive.models import RequestArchive
from shim_enterprise.archive.service import ArchiveUndecryptable, opened
from shim_enterprise.core.database import get_db
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim_enterprise.tenants.models import ApiKey, User
from shim_enterprise.tenants.permissions import user_permissions
from shim_enterprise.api.v1.management._common import (
    _tenant_id,
    _validate_sync_window,
)


router = APIRouter()


class ArchivedContentView(BaseModel):
    request_id: str
    archived_at: datetime
    expires_at: datetime
    protocol: str
    model: str
    matched: list[dict[str, Any]]
    masked_payload: Any
    replacements: list[dict[str, str]]
    original_payload: Any


@router.get("/requests/{request_id}/content", response_model=ArchivedContentView)
async def open_request_content(
    request_id: str,
    response: Response,
    user: User = Depends(require("content.read")),
    session: AsyncSession = Depends(get_db),
) -> ArchivedContentView:
    """The archived request as sent and as shim changed it; the opening is audited first."""
    if user.kind != "human":
        raise HTTPException(
            status_code=403, detail="Service accounts cannot open archived content"
        )
    tenant_id = _tenant_id(user)
    row = await session.scalar(
        select(RequestArchive).where(
            RequestArchive.organization_id == tenant_id,
            RequestArchive.request_id == request_id,
            RequestArchive.expires_at > func.now(),
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Archived request not found")
    await _audit(
        session,
        user,
        "tenant.request_content_opened",
        request_id,
        details={"api_key_id": None if row.api_key_id is None else str(row.api_key_id)},
    )
    # The opening is recorded before any content is decrypted.
    await session.commit()
    try:
        parts = await asyncio.to_thread(opened, row)
    except ArchiveUndecryptable:
        raise HTTPException(
            status_code=410,
            detail="archived content cannot be decrypted with the current ENCRYPTION_KEY",
        ) from None
    response.headers["Cache-Control"] = "no-store"
    return ArchivedContentView(
        request_id=row.request_id,
        archived_at=row.created_at,
        expires_at=row.expires_at,
        protocol=row.protocol,
        model=row.model,
        matched=row.matched,
        **parts,
    )


class ContentOpeningView(BaseModel):
    opened_at: datetime
    actor_user_id: str | None
    request_id: str | None


class ContentOpeningPage(BaseModel):
    items: list[ContentOpeningView]
    total: int
    limit: int
    offset: int


@router.get("/request-archive/openings", response_model=ContentOpeningPage)
async def list_content_openings(
    start: AwareDatetime | None = Query(default=None),
    end: AwareDatetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> ContentOpeningPage:
    """Readers see every opening; anyone else the openings of their own keys' requests."""
    tenant_id = _tenant_id(user)
    end_at = end or datetime.now(timezone.utc)
    start_at = start or end_at - timedelta(days=30)
    _validate_sync_window(start_at, end_at)
    filters = [
        AIActAuditLog.organization_id == tenant_id,
        AIActAuditLog.endpoint == "tenant.request_content_opened",
        AIActAuditLog.created_at >= start_at,
        AIActAuditLog.created_at <= end_at,
    ]
    if "audit.read" not in await user_permissions(session, user):
        filters.append(
            AIActAuditLog.extra["api_key_id"]
            .as_string()
            .in_(
                select(sql_cast(ApiKey.id, Text)).where(
                    ApiKey.organization_id == tenant_id, ApiKey.user_id == user.id
                )
            )
        )
    total = await session.scalar(select(func.count()).where(*filters))
    rows = await session.scalars(
        select(AIActAuditLog)
        .where(*filters)
        .order_by(AIActAuditLog.created_at.desc(), AIActAuditLog.id)
        .limit(limit)
        .offset(offset)
    )
    return ContentOpeningPage(
        items=[
            ContentOpeningView(
                opened_at=row.created_at,
                actor_user_id=row.actor,
                request_id=(row.extra or {}).get("subject_id"),
            )
            for row in rows
        ],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


class ArchivePurgeView(BaseModel):
    rows_deleted: int = Field(ge=0)


@router.delete("/request-archive", response_model=ArchivePurgeView)
async def purge_request_archive(
    user: User = Depends(get_org_owner),
    session: AsyncSession = Depends(get_db),
) -> ArchivePurgeView:
    tenant_id = _tenant_id(user)
    deleted = cast(
        CursorResult[Any],
        await session.execute(
            sql_delete(RequestArchive).where(
                RequestArchive.organization_id == tenant_id
            )
        ),
    ).rowcount
    await _audit(
        session,
        user,
        "tenant.request_archive_purged",
        str(tenant_id),
        details={"rows": deleted},
    )
    await session.commit()
    return ArchivePurgeView(rows_deleted=deleted)
