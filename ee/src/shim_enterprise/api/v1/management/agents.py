"""The agent under management: its gateway key, a freeze switch, and what it did."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act.models import AIActAuditLog
from shim_enterprise.api.enterprise_deps import OWNER_REQUIRED, require
from shim_enterprise.api.v1.management._common import _tenant_id
from shim_enterprise.api.v1.management.api_keys import (
    ApiKeyView,
    CreatedApiKey,
    _validate_allowed_models,
)
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.core.database import bounded_read, get_db
from shim_enterprise.findings.models import Finding
from shim_enterprise.findings.service import STATUS_IDS
from shim_enterprise.policy.models import PolicyPlan, PolicyRemediation, PolicyVersion
from shim_enterprise.policy.plans import key_holders, lock_tenant
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim_enterprise.tenants.deployments import require_model_aliases
from shim_enterprise.tenants.models import (
    ApiKey,
    ServiceAccountCredential,
    Team,
    TeamMembership,
    User,
)
from shim_enterprise.tenants.permissions import user_permissions
from shim_enterprise.tenants.service import create_api_key

router = APIRouter()

# An agent rotates by holding two keys for a moment; more is a leak.
MAX_AGENT_KEYS = 2
_FAILED = ("provider_error", "failed", "rejected", "internal_error", "timeout")


class AgentKeyInput(BaseModel):
    name: str = Field(min_length=1, max_length=50)
    allowed_models: list[str] = Field(min_length=1, max_length=200)
    team_id: UUID | None = None
    expires_in_days: int = Field(ge=1, le=365)

    validate_models = field_validator("allowed_models")(_validate_allowed_models)


async def _service_account(
    session: AsyncSession, user: User, account_id: UUID, *, lock: bool = False
) -> User:
    statement = select(User).where(
        User.id == account_id,
        User.organization_id == _tenant_id(user),
        User.kind == "service",
    )
    account = await session.scalar(
        statement.with_for_update(of=User) if lock else statement
    )
    if account is None:
        raise HTTPException(status_code=404, detail="Service account not found")
    return account


async def _credential(
    session: AsyncSession, account: User
) -> ServiceAccountCredential | None:
    return await session.scalar(
        select(ServiceAccountCredential).where(
            ServiceAccountCredential.user_id == account.id,
            ServiceAccountCredential.revoked_at.is_(None),
        )
    )


@router.post(
    "/service-accounts/{account_id}/gateway-keys",
    response_model=CreatedApiKey,
    status_code=201,
)
async def issue_agent_gateway_key(
    account_id: UUID,
    payload: AgentKeyInput,
    user: User = Depends(require("roles.manage", legacy_detail=OWNER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> CreatedApiKey:
    tenant_id = _tenant_id(user)
    await lock_tenant(session, tenant_id)
    account = await _service_account(session, user, account_id, lock=True)
    if not account.is_active or await _credential(session, account) is None:
        raise HTTPException(status_code=404, detail="Service account not found")
    # Whoever else mints the plaintext could approve the key's held requests (§15).
    if user.id not in await key_holders(session, tenant_id, {account.id}):
        raise HTTPException(
            status_code=403,
            detail={
                "code": "AGENT_KEY_ISSUER_NOT_HOLDER",
                "message": "Only whoever created or last rotated the account's "
                "credential issues its gateway key.",
            },
        )
    if "keys.hold" not in await user_permissions(session, account):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "ACCOUNT_CANNOT_HOLD_KEYS",
                "message": "Only a recommender account holds a gateway key.",
            },
        )
    held = await session.scalar(
        select(func.count()).where(
            ApiKey.user_id == account.id,
            ApiKey.is_active.is_(True),
            ApiKey.expires_at.is_(None)
            | (ApiKey.expires_at > datetime.now(timezone.utc)),
        )
    )
    if (held or 0) >= MAX_AGENT_KEYS:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "AGENT_KEY_LIMIT",
                "hint": "Revoke a current key.",
            },
        )
    await require_model_aliases(session, tenant_id, payload.allowed_models)
    if payload.team_id is not None:
        team = await session.scalar(
            select(Team.id).where(
                Team.organization_id == tenant_id, Team.id == payload.team_id
            )
        )
        if team is None:
            raise HTTPException(status_code=404, detail="Team not found")
        if (
            await session.get(TeamMembership, (tenant_id, payload.team_id, account.id))
            is None
        ):
            # The reservation lets a member hold a key on its own team only.
            session.add(
                TeamMembership(
                    organization_id=tenant_id,
                    team_id=payload.team_id,
                    user_id=account.id,
                    role="member",
                    source="local",
                )
            )
            await session.flush()
    plaintext, api_key = await create_api_key(
        session,
        user_id=account.id,
        name=payload.name,
        team_id=payload.team_id,
        allowed_models=payload.allowed_models,
        expires_at=datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days),
    )
    await _audit(
        session,
        user,
        "tenant.agent_gateway_key_issued",
        str(account.id),
        details={
            "account_id": str(account.id),
            "api_key_id": str(api_key.id),
            "team_id": None if payload.team_id is None else str(payload.team_id),
            "models": len(payload.allowed_models),
        },
    )
    await session.commit()
    await session.refresh(api_key)
    return CreatedApiKey(
        **ApiKeyView.model_validate(api_key).model_dump(), plaintext=plaintext
    )


class FrozenView(BaseModel):
    id: UUID
    active: bool


@router.post("/service-accounts/{account_id}/freeze", response_model=FrozenView)
async def freeze_service_account(
    account_id: UUID,
    user: User = Depends(require("roles.manage", legacy_detail=OWNER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> FrozenView:
    account = await _service_account(session, user, account_id, lock=True)
    if await _credential(session, account) is None:
        raise HTTPException(status_code=404, detail="Service account not found")
    # Both its management key and its gateway keys read the user on every request.
    account.is_active = False
    await _audit(session, user, "tenant.service_account_frozen", str(account.id))
    await session.commit()
    return FrozenView(id=account.id, active=False)


@router.post("/service-accounts/{account_id}/unfreeze", response_model=FrozenView)
async def unfreeze_service_account(
    account_id: UUID,
    user: User = Depends(require("roles.manage", legacy_detail=OWNER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> FrozenView:
    account = await _service_account(session, user, account_id, lock=True)
    if await _credential(session, account) is None:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "SERVICE_ACCOUNT_DELETED",
                "message": "A deleted service account cannot be unfrozen.",
            },
        )
    account.is_active = True
    await _audit(session, user, "tenant.service_account_unfrozen", str(account.id))
    await session.commit()
    return FrozenView(id=account.id, active=True)


class ActivityAccount(BaseModel):
    id: UUID
    name: str | None
    role: str
    active: bool
    expires_at: datetime | None
    last_used_at: datetime | None


class ActivityKey(BaseModel):
    id: UUID
    prefix: str
    name: str | None
    team_id: UUID | None
    allowed_models: list[str] | None
    is_active: bool
    expires_at: datetime | None


class ModelCount(BaseModel):
    model: str | None
    requests: int


class ModelUsage(BaseModel):
    requests: int
    failed: int
    cost_usd: Decimal
    by_model: list[ModelCount]


class ManagementActivity(BaseModel):
    plans_by_status: dict[str, int]
    versions: list[int]
    remediations_by_status: dict[str, int]
    refused_applies: int


class OpenFinding(BaseModel):
    id: UUID
    rule_id: str


class ActivityWindow(BaseModel):
    start: datetime
    end: datetime


class AccountActivity(BaseModel):
    account: ActivityAccount
    gateway_keys: list[ActivityKey]
    model_usage: ModelUsage
    management: ManagementActivity
    findings_open: list[OpenFinding]
    window: ActivityWindow


async def _by_status(session: AsyncSession, column: Any, *where: Any) -> dict[str, int]:
    rows = await session.execute(
        select(column, func.count()).where(*where).group_by(column)
    )
    return {status: count for status, count in rows}


@router.get("/service-accounts/{account_id}/activity", response_model=AccountActivity)
async def service_account_activity(
    account_id: UUID,
    hours: int = Query(default=24, ge=1, le=720),
    user: User = Depends(require("audit.read")),
    session: AsyncSession = Depends(get_db),
) -> AccountActivity:
    tenant_id = _tenant_id(user)
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    account = await _service_account(session, user, account_id)
    credential = await _credential(session, account)
    actor = str(account.id)
    async with bounded_read(session):
        keys = list(
            await session.scalars(
                select(ApiKey)
                .where(
                    ApiKey.organization_id == tenant_id, ApiKey.user_id == account.id
                )
                .order_by(ApiKey.created_at.desc())
                .limit(50)
            )
        )
        key_ids = [key.id for key in keys]
        in_window = (
            RequestLifecycle.organization_id == tenant_id,
            RequestLifecycle.api_key_id.in_(key_ids),
            RequestLifecycle.started_at >= start,
            RequestLifecycle.started_at < end,
        )
        requests, failed = (
            await session.execute(
                select(
                    func.count(),
                    func.count().filter(RequestLifecycle.status.in_(_FAILED)),
                ).where(*in_window)
            )
        ).one()
        by_model = await session.execute(
            select(RequestLifecycle.requested_model, func.count())
            .where(*in_window)
            .group_by(RequestLifecycle.requested_model)
            .order_by(func.count().desc(), RequestLifecycle.requested_model)
            .limit(20)
        )
        cost = await session.scalar(
            select(func.coalesce(func.sum(UsageLedger.cost_usd), 0)).where(
                UsageLedger.organization_id == tenant_id,
                UsageLedger.api_key_id.in_(key_ids),
                UsageLedger.event_type == "spend_settlement",
                UsageLedger.created_at >= start,
                UsageLedger.created_at < end,
            )
        )
        plans = await _by_status(
            session,
            PolicyPlan.status,
            PolicyPlan.organization_id == tenant_id,
            PolicyPlan.created_by == actor,
            PolicyPlan.created_at >= start,
        )
        versions = list(
            await session.scalars(
                select(PolicyVersion.version)
                .where(
                    PolicyVersion.organization_id == tenant_id,
                    PolicyVersion.created_by == actor,
                    PolicyVersion.created_at >= start,
                )
                .order_by(PolicyVersion.version.desc())
                .limit(50)
            )
        )
        remediations = await _by_status(
            session,
            PolicyRemediation.status,
            PolicyRemediation.organization_id == tenant_id,
            PolicyRemediation.actor_id == actor,
            PolicyRemediation.created_at >= start,
        )
        refused = await session.scalar(
            select(func.count()).where(
                AIActAuditLog.organization_id == tenant_id,
                AIActAuditLog.event_type == "management_action",
                AIActAuditLog.endpoint == "tenant.policy_plan_apply_refused",
                AIActAuditLog.actor == actor,
                AIActAuditLog.created_at >= start,
            )
        )
        findings = await session.execute(
            select(Finding.id, Finding.rule_id)
            .where(
                Finding.organization_id == tenant_id,
                Finding.status_id.in_((STATUS_IDS["new"], STATUS_IDS["in_progress"])),
                Finding.subject["api_key_id"]
                .as_string()
                .in_([str(k) for k in key_ids]),
            )
            .order_by(Finding.first_seen_at.desc())
            .limit(50)
        )
    return AccountActivity(
        account=ActivityAccount(
            id=account.id,
            name=account.full_name,
            role=account.role,
            active=account.is_active,
            expires_at=None if credential is None else credential.expires_at,
            last_used_at=None if credential is None else credential.last_used_at,
        ),
        gateway_keys=[
            ActivityKey.model_validate(key, from_attributes=True) for key in keys
        ],
        model_usage=ModelUsage(
            requests=requests,
            failed=failed,
            cost_usd=cost or Decimal(0),
            by_model=[
                ModelCount(model=model, requests=count) for model, count in by_model
            ],
        ),
        management=ManagementActivity(
            plans_by_status=plans,
            versions=sorted(versions),
            remediations_by_status=remediations,
            refused_applies=refused or 0,
        ),
        findings_open=[OpenFinding(id=id_, rule_id=rule) for id_, rule in findings],
        window=ActivityWindow(start=start, end=end),
    )
