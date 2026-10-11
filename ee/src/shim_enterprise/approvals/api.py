"""The approver's view of held requests, and the one decision on each."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import AwareDatetime, BaseModel, ConfigDict
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import require
from shim_enterprise.approvals.gate import APPROVAL_USE_TTL, expire_overdue
from shim_enterprise.approvals.models import ApprovalStatus, RequestApproval
from shim_enterprise.archive.models import RequestArchive
from shim_enterprise.core.database import get_db
from shim_enterprise.observability.enterprise_metrics import (
    REQUEST_APPROVAL_DECISIONS_TOTAL,
)
from shim_enterprise.policy.plans import key_holders
from shim_enterprise.rules.models import OrganizationRuleSet
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim_enterprise.tenants.models import ApiKey, Team, User

router = APIRouter(prefix="/management/approvals", tags=["approvals"])

_READ = require("requests.approve", "audit.read")
_DECIDE = require("requests.approve")


class ApprovalRule(BaseModel):
    id: str
    name: str | None


class ApprovalKey(BaseModel):
    id: UUID
    name: str | None
    prefix: str | None


class ApprovalRequester(BaseModel):
    user_id: UUID
    email: str | None


class ApprovalTeam(BaseModel):
    id: UUID
    name: str | None


class ApprovalView(BaseModel):
    id: UUID
    status: ApprovalStatus
    created_at: datetime
    expires_at: datetime
    decided_by: UUID | None
    decided_at: datetime | None
    use_by: datetime | None
    used_at: datetime | None
    request_id: str
    used_request_id: str | None
    rules: list[ApprovalRule]
    api_key: ApprovalKey
    requested_by: ApprovalRequester | None
    team: ApprovalTeam | None
    protocol: str
    provider: str
    model: str
    stream: bool
    detected: dict[str, Any]
    input_bytes: int
    estimated_input_tokens: int | None
    content: None = None
    content_note: Literal[
        "content is not stored", "content is in the request archive"
    ] = "content is not stored"


class ApprovalPage(BaseModel):
    items: list[ApprovalView]


class BulkReject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api_key_id: UUID


class BulkRejected(BaseModel):
    rejected: int


async def _views(
    session: AsyncSession, tenant: UUID, rows: list[RequestApproval]
) -> list[ApprovalView]:
    """Names as they are now: a renamed key, user, team or rule shows its new name."""
    keys = {
        key.id: key
        for key in await session.scalars(
            select(ApiKey).where(
                ApiKey.organization_id == tenant,
                ApiKey.id.in_({row.api_key_id for row in rows}),
            )
        )
    }
    emails = {
        user_id: email
        for user_id, email in await session.execute(
            select(User.id, User.email).where(
                User.organization_id == tenant,
                User.id.in_({row.requested_by for row in rows} - {None}),
            )
        )
    }
    teams = {
        team_id: name
        for team_id, name in await session.execute(
            select(Team.id, Team.name).where(
                Team.organization_id == tenant,
                Team.id.in_({row.team_id for row in rows} - {None}),
            )
        )
    }
    stored = await session.scalar(
        select(OrganizationRuleSet.rules).where(
            OrganizationRuleSet.organization_id == tenant
        )
    )
    names = {rule.get("id"): rule.get("name") for rule in stored or []}
    archived = set(
        await session.scalars(
            select(RequestArchive.request_id).where(
                RequestArchive.organization_id == tenant,
                RequestArchive.request_id.in_({row.request_id for row in rows}),
            )
        )
    )
    views = []
    for row in rows:
        key = keys.get(row.api_key_id)
        views.append(
            ApprovalView(
                id=row.id,
                status=row.status,
                created_at=row.created_at,
                expires_at=row.expires_at,
                decided_by=row.decided_by,
                decided_at=row.decided_at,
                use_by=row.use_by,
                used_at=row.used_at,
                request_id=row.request_id,
                used_request_id=row.used_request_id,
                rules=[
                    ApprovalRule(id=rule_id, name=names.get(rule_id))
                    for rule_id in row.rule_ids
                ],
                api_key=ApprovalKey(
                    id=row.api_key_id,
                    name=None if key is None else key.name,
                    prefix=None if key is None else key.prefix,
                ),
                requested_by=None
                if row.requested_by is None
                else ApprovalRequester(
                    user_id=row.requested_by, email=emails.get(row.requested_by)
                ),
                team=None
                if row.team_id is None
                else ApprovalTeam(id=row.team_id, name=teams.get(row.team_id)),
                protocol=row.protocol,
                provider=row.provider,
                model=row.model,
                stream=row.stream,
                detected=row.detected,
                input_bytes=row.input_bytes,
                estimated_input_tokens=row.estimated_input_tokens,
                content_note="content is in the request archive"
                if row.request_id in archived
                else "content is not stored",
            )
        )
    return views


@router.get("", response_model=ApprovalPage)
async def list_approvals(
    status: ApprovalStatus | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    before: AwareDatetime | None = Query(
        default=None, description="Only approvals created before this time."
    ),
    user: User = Depends(_READ),
    session: AsyncSession = Depends(get_db),
) -> ApprovalPage:
    tenant = user.organization_id
    await expire_overdue(session, tenant)
    await session.commit()
    filters = [RequestApproval.organization_id == tenant]
    if status is not None:
        filters.append(RequestApproval.status == status)
    if before is not None:
        filters.append(RequestApproval.created_at < before)
    rows = list(
        await session.scalars(
            select(RequestApproval)
            .where(*filters)
            .order_by(RequestApproval.created_at.desc(), RequestApproval.id)
            .limit(limit)
        )
    )
    return ApprovalPage(items=await _views(session, tenant, rows))


async def _owned(
    session: AsyncSession, tenant: UUID, approval_id: UUID, *, lock: bool = False
) -> RequestApproval:
    await expire_overdue(session, tenant, RequestApproval.id == approval_id)
    statement = select(RequestApproval).where(
        RequestApproval.organization_id == tenant, RequestApproval.id == approval_id
    )
    row = await session.scalar(
        statement.with_for_update()
        if lock
        else statement.execution_options(populate_existing=True)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    return row


@router.get("/{approval_id}", response_model=ApprovalView)
async def get_approval(
    approval_id: UUID,
    user: User = Depends(_READ),
    session: AsyncSession = Depends(get_db),
) -> ApprovalView:
    tenant = user.organization_id
    row = await _owned(session, tenant, approval_id)
    await session.commit()
    [view] = await _views(session, tenant, [row])
    return view


async def _may_decide(
    session: AsyncSession, user: User, api_key_id: UUID, requesters: set[UUID | None]
) -> None:
    """Refuse service accounts, and anyone who holds the key: its owner, the
    recorded requester, and whoever created or rotated their service-account key.
    With nobody on record to exclude, nobody decides."""
    tenant = user.organization_id
    owner = await session.scalar(
        select(ApiKey.user_id).where(
            ApiKey.organization_id == tenant, ApiKey.id == api_key_id
        )
    )
    known = {value for value in (owner, *requesters) if value is not None}
    holders = await key_holders(session, tenant, known)
    if user.kind != "human" or not holders or user.id in holders:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "APPROVER_NOT_ELIGIBLE",
                "hint": "Ask another administrator; the key owner, whoever holds "
                "its service account's key, and service accounts cannot decide.",
            },
        )


async def _decide(
    session: AsyncSession,
    user: User,
    approval_id: UUID,
    decision: Literal["approved", "rejected"],
) -> ApprovalView:
    tenant = user.organization_id
    row = await _owned(session, tenant, approval_id, lock=True)
    if row.status != "pending":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "APPROVAL_STATE_CONFLICT",
                "status": row.status,
                "hint": "Only a pending approval can be decided; the client can "
                "send the request again for a new one.",
            },
        )
    await _may_decide(session, user, row.api_key_id, {row.requested_by})
    # A rejected row can no longer be used, so it keeps no digest.
    kept = {} if decision == "approved" else {"request_digest": None}
    row = await session.scalar(
        update(RequestApproval)
        .where(RequestApproval.id == row.id)
        .values(
            status=decision,
            decided_by=user.id,
            decided_at=func.now(),
            use_by=func.now() + APPROVAL_USE_TTL if decision == "approved" else None,
            **kept,
        )
        .returning(RequestApproval)
        .execution_options(populate_existing=True)
    )
    assert row is not None
    await _audit(
        session,
        user,
        f"tenant.request_approval_{decision}",
        str(row.id),
        details={
            "rule_ids": row.rule_ids,
            "api_key_id": str(row.api_key_id),
            "model": row.model,
            "request_id": row.request_id,
        },
    )
    await session.commit()
    REQUEST_APPROVAL_DECISIONS_TOTAL.labels(decision=decision).inc()
    [view] = await _views(session, tenant, [row])
    return view


@router.post("/{approval_id}/approve", response_model=ApprovalView)
async def approve_request(
    approval_id: UUID,
    user: User = Depends(_DECIDE),
    session: AsyncSession = Depends(get_db),
) -> ApprovalView:
    return await _decide(session, user, approval_id, "approved")


@router.post("/{approval_id}/reject", response_model=ApprovalView)
async def reject_request(
    approval_id: UUID,
    user: User = Depends(_DECIDE),
    session: AsyncSession = Depends(get_db),
) -> ApprovalView:
    return await _decide(session, user, approval_id, "rejected")


@router.post("/reject", response_model=BulkRejected)
async def reject_pending(
    payload: BulkReject,
    user: User = Depends(_DECIDE),
    session: AsyncSession = Depends(get_db),
) -> BulkRejected:
    """Reject every pending request of one key, as one decision."""
    tenant = user.organization_id
    key = RequestApproval.api_key_id == payload.api_key_id
    await expire_overdue(session, tenant, key)
    pending = (
        await session.execute(
            select(RequestApproval.id, RequestApproval.requested_by)
            .where(
                RequestApproval.organization_id == tenant,
                key,
                RequestApproval.status == "pending",
            )
            .with_for_update()
        )
    ).all()
    await _may_decide(
        session, user, payload.api_key_id, {row.requested_by for row in pending}
    )
    if pending:
        await session.execute(
            update(RequestApproval)
            .where(RequestApproval.id.in_([row.id for row in pending]))
            .values(
                status="rejected",
                decided_by=user.id,
                decided_at=func.now(),
                request_digest=None,
            )
        )
        await _audit(
            session,
            user,
            "tenant.request_approvals_rejected",
            str(payload.api_key_id),
            details={"rejected": len(pending)},
        )
    await session.commit()
    REQUEST_APPROVAL_DECISIONS_TOTAL.labels(decision="rejected").inc(len(pending))
    return BulkRejected(rejected=len(pending))
