"""JWT-authenticated tenant management API."""

from __future__ import annotations

from collections.abc import AsyncIterator
import csv
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import io
import logging
import secrets
from typing import Any, Literal, cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)
from sqlalchemy import case, cast as sql_cast, func, or_, select, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import (
    get_current_user,
    get_invite_user,
    get_org_admin,
    get_org_owner,
)
from shim.billing.attribution import normalize_attribution
from shim_enterprise.billing.models import AuditIntent, CostBudget, UsageLedger
from shim_enterprise.billing.read_models import (
    MAX_BILLING_DAILY_ROWS,
    MAX_BILLING_BREAKDOWN_ROWS,
    BillingBreakdownGroup,
    BillingReadModels,
)
from shim_enterprise.billing.spend import (
    MAX_BUDGET_ALERT_THRESHOLDS,
    MAX_BUDGET_NOTIFY_TARGETS,
    BudgetConfigurationError,
    BudgetEvaluator,
    validate_budget_notification_config,
)
from shim_enterprise.cache.redis_index import CacheManager, CacheService
from shim_enterprise.compliance.url_guard import (
    UnsafeForwardURL,
    assert_safe_forward_url,
)
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim.gateway.contracts.ids import SecretRef, TenantId
from shim_enterprise.observability.analytics_projection import RequestLog
from shim_enterprise.observability.overview import OverviewReadModel
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.outbox.publisher import OutboxWriter
from shim_enterprise.secrets.migration import assign_secret_reference
from shim_enterprise.secrets.store import get_secret_store
from shim_enterprise.tenants.models import (
    ApiKey,
    OrganizationInvite,
    Organization,
    ProviderSecret,
    TierDefinition,
    User,
)
from shim_enterprise.tenants.service import create_api_key as create_tenant_api_key
from shim_enterprise.tenants.service import ensure_privacy_defaults
from shim_enterprise.tenants.service import move_user_from_bootstrap
from shim_enterprise.tenants.subscriptions import checkout_urls


router = APIRouter()
logger = logging.getLogger(__name__)
_PROVIDER_VERIFICATION_REQUESTS: dict[str, tuple[str, str, str, dict[str, str]]] = {
    "openai": (
        "OPENAI_BASE_URL",
        "https://api.openai.com/v1",
        "/models",
        {"authorization": "Bearer {credential}"},
    ),
    "anthropic": (
        "ANTHROPIC_BASE_URL",
        "https://api.anthropic.com",
        "/v1/models",
        {
            "x-api-key": "{credential}",
            "anthropic-version": "2023-06-01",
        },
    ),
    "google": (
        "GOOGLE_BASE_URL",
        "https://generativelanguage.googleapis.com",
        "/v1beta/models",
        {"x-goog-api-key": "{credential}"},
    ),
}
_CSV_EXPORT_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {
        "description": "CSV attachment.",
        "content": {"text/csv": {"schema": {"type": "string", "format": "binary"}}},
        "headers": {
            "Content-Disposition": {
                "description": "Attachment disposition and filename.",
                "schema": {"type": "string"},
            }
        },
    }
}
_BILLING_EXPORT_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {
        "description": "CSV or PDF attachment.",
        "content": {
            "application/pdf": {"schema": {"type": "string", "format": "binary"}},
            "text/csv": {"schema": {"type": "string", "format": "binary"}},
        },
        "headers": {
            "Content-Disposition": {
                "description": "Attachment disposition and filename.",
                "schema": {"type": "string"},
            }
        },
    }
}
_MAX_SYNC_WINDOW = timedelta(days=31)
_MAX_SYNC_REQUEST_EXPORT_ROWS = 10_000
_MAX_SYNC_BUDGETS = 100
_MAX_SYNC_BUDGET_DELIVERIES = 100


class UserView(BaseModel):
    id: UUID
    email: EmailStr
    full_name: str | None
    organization_name: str
    role: Literal["owner", "admin", "member"]
    is_active: bool
    is_verified: bool
    created_at: datetime


class UserPatch(BaseModel):
    full_name: str | None = Field(default=None, max_length=200)
    organization_name: str | None = Field(default=None, min_length=1, max_length=200)


class ApiKeyInput(BaseModel):
    name: str = Field(min_length=1, max_length=50)
    cost_center: str | None = None
    team: str | None = None

    @field_validator("cost_center", "team")
    @classmethod
    def validate_attribution(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return normalize_attribution(
            value,
            maximum_length=settings.COST_TAG_MAX_LENGTH,
        )


class ApiKeyPatch(BaseModel):
    cost_center: str | None = None
    team: str | None = None

    @field_validator("cost_center", "team")
    @classmethod
    def validate_attribution(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return normalize_attribution(
            value,
            maximum_length=settings.COST_TAG_MAX_LENGTH,
        )


class ApiKeyView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str | None
    prefix: str
    tier: str
    created_at: datetime
    is_active: bool
    expires_at: datetime | None
    cost_center: str | None
    team: str | None


class CreatedApiKey(ApiKeyView):
    plaintext: str


class ProviderSecretInput(BaseModel):
    provider: Literal["openai", "anthropic", "google"]
    name: str | None = Field(default=None, max_length=100)
    key: str = Field(min_length=10, max_length=10_000)
    monthly_limit_usd: Decimal | None = Field(default=None, ge=0)


class ProviderSecretPatch(BaseModel):
    name: str | None = Field(default=None, max_length=100)
    key: str | None = Field(default=None, min_length=10, max_length=10_000)
    monthly_limit_usd: Decimal | None = Field(default=None, ge=0)


class ProviderSecretView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    provider: str
    name: str | None
    masked_key: str
    created_at: datetime
    monthly_limit_usd: Decimal | None
    verified_at: datetime | None


class PrivacySettings(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    block_email: bool
    block_phone: bool
    block_credit_card: bool
    block_secrets: bool
    block_pii_tr: bool


class PrivacyPatch(BaseModel):
    block_email: bool | None = None
    block_phone: bool | None = None
    block_credit_card: bool | None = None
    block_secrets: bool | None = None
    block_pii_tr: bool | None = None


class TierView(BaseModel):
    tier: str
    name: str
    rate_limit_rpm: int
    rate_limit_tpm: int
    daily_request_limit: int | None
    monthly_request_limit: int
    monthly_token_limit: int


class SubscriptionView(BaseModel):
    plan: Literal["free", "managed", "agency", "enterprise"]
    status: str
    source: str | None
    current_period_end: datetime | None
    cancel_at_period_end: bool
    entitlements: dict[str, bool]
    checkout_urls: dict[str, dict[Literal["monthly", "yearly"], str]]
    customer_portal_url: str | None


class TeamMemberView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    full_name: str | None
    role: Literal["owner", "admin", "member"]
    is_active: bool
    created_at: datetime


class TeamInviteInput(BaseModel):
    email: EmailStr
    role: Literal["admin", "member"] = "member"


class TeamInviteView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    role: Literal["owner", "admin", "member"]
    expires_at: datetime
    accepted_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class CreatedTeamInvite(TeamInviteView):
    token: str


class AcceptTeamInvite(BaseModel):
    token: str = Field(min_length=32, max_length=512)


class TeamRolePatch(BaseModel):
    role: Literal["owner", "admin", "member"]


class NotificationTargetInput(BaseModel):
    kind: Literal["slack", "webhook"]
    endpoint: str = Field(min_length=1, max_length=2_048)


class NotificationTargetView(BaseModel):
    kind: Literal["slack", "webhook"]
    endpoint_origin: str


class BudgetInput(BaseModel):
    scope_type: Literal["tag", "team", "org"]
    scope_value: str | None = None
    limit_usd: Decimal | None = Field(default=None, ge=0)
    limit_tokens: int | None = Field(default=None, ge=0)
    alert_thresholds: list[float] = Field(
        default_factory=lambda: [0.8, 1.0],
        max_length=MAX_BUDGET_ALERT_THRESHOLDS,
    )
    notify_targets: list[NotificationTargetInput] = Field(
        default_factory=list,
        max_length=MAX_BUDGET_NOTIFY_TARGETS,
    )
    enabled: bool = True

    @field_validator("alert_thresholds")
    @classmethod
    def validate_alert_thresholds(cls, values: list[float] | None) -> list[float]:
        if values is None or any(not 0 < value <= 5 for value in values):
            raise ValueError("alert thresholds must be within (0, 5]")
        if len(values) != len(set(values)):
            raise ValueError("alert thresholds must be unique")
        return values

    @field_validator("notify_targets")
    @classmethod
    def validate_notify_targets(
        cls, values: list[NotificationTargetInput]
    ) -> list[NotificationTargetInput]:
        keys = [(target.kind, target.endpoint.strip()) for target in values]
        if len(keys) != len(set(keys)):
            raise ValueError("notification targets must be unique")
        return values

    @model_validator(mode="after")
    def validate_budget(self) -> BudgetInput:
        if self.scope_type != "org" and not self.scope_value:
            raise ValueError("scoped budgets require scope_value")
        if self.limit_usd is None and self.limit_tokens is None:
            raise ValueError("a budget requires a cost or token limit")
        return self


class BudgetPatch(BaseModel):
    limit_usd: Decimal | None = Field(default=None, ge=0)
    limit_tokens: int | None = Field(default=None, ge=0)
    alert_thresholds: list[float] | None = Field(
        default=None,
        max_length=MAX_BUDGET_ALERT_THRESHOLDS,
    )
    notify_targets: list[NotificationTargetInput] | None = Field(
        default=None,
        max_length=MAX_BUDGET_NOTIFY_TARGETS,
    )
    enabled: bool | None = None

    @field_validator("alert_thresholds")
    @classmethod
    def validate_alert_thresholds(cls, values: list[float] | None) -> list[float]:
        return BudgetInput.validate_alert_thresholds(values)

    @field_validator("notify_targets")
    @classmethod
    def validate_notify_targets(
        cls, values: list[NotificationTargetInput] | None
    ) -> list[NotificationTargetInput] | None:
        if values is None:
            return values
        return BudgetInput.validate_notify_targets(values)

    @field_validator("notify_targets", "enabled")
    @classmethod
    def reject_null(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("field cannot be null")
        return value


class BudgetView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    scope_type: Literal["tag", "team", "org"]
    scope_value: str | None
    period: str
    limit_usd: Decimal | None
    limit_tokens: int | None
    alert_thresholds: list[float]
    notify_targets: list[NotificationTargetView]
    enabled: bool
    created_at: datetime


class BudgetEvaluationItem(BaseModel):
    budget_id: UUID
    fraction: float
    fired: list[float]
    enqueued: int


class BudgetEvaluationView(BaseModel):
    period: str
    results: list[BudgetEvaluationItem]


class BillingPeriodView(BaseModel):
    start: datetime
    end: datetime


class DailyUsageView(BaseModel):
    date: date
    model: str
    request_count: int
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float


class BillingUsageView(BaseModel):
    period: BillingPeriodView
    daily_usage: list[DailyUsageView]
    total_cost: float


KNOWN_REQUEST_ACTIVITY_STATUSES = (
    "completed",
    "provider_error",
    "client_disconnected",
    "timeout",
    "cancelled",
    "internal_error",
    "rejected",
    "failed",
)

RequestActivityStatus = Literal[
    "completed",
    "provider_error",
    "client_disconnected",
    "timeout",
    "cancelled",
    "internal_error",
    "rejected",
    "failed",
    "unknown",
]


class RequestActivityView(BaseModel):
    request_id: str
    created_at: datetime
    endpoint: str | None
    model: str | None
    status: RequestActivityStatus
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    usage_estimated: bool
    cost_usd: Decimal = Field(ge=0)
    latency_ms: int = Field(ge=0)
    pii_detected: bool
    tags: list[str] = Field(default_factory=list)
    cost_center: str | None
    provider: str | None
    team: str | None


class RequestActivityStatusCountsView(BaseModel):
    completed: int = Field(ge=0)
    provider_error: int = Field(ge=0)
    client_disconnected: int = Field(ge=0)
    timeout: int = Field(ge=0)
    cancelled: int = Field(ge=0)
    internal_error: int = Field(ge=0)
    rejected: int = Field(ge=0)
    failed: int = Field(ge=0)
    unknown: int = Field(ge=0)


class RequestActivitySummaryView(BaseModel):
    requests: int = Field(ge=0)
    technical_success_rate: float | None = Field(ge=0, le=1)
    p95_completed_latency_ms: int | None = Field(ge=0)
    settled_spend_usd: Decimal = Field(ge=0)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    pii_detected_requests: int = Field(ge=0)
    technical_failures: int = Field(ge=0)
    policy_rejections: int = Field(ge=0)
    status_counts: RequestActivityStatusCountsView


class RequestActivityPage(BaseModel):
    generated_at: datetime
    summary: RequestActivitySummaryView
    items: list[RequestActivityView]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


class OverviewPeriodView(BaseModel):
    start: datetime
    end: datetime
    previous_start: datetime
    previous_end: datetime
    bucket: Literal["hour", "day"]


class OverviewStatusCountsView(BaseModel):
    completed: int = Field(ge=0)
    provider_error: int = Field(ge=0)
    client_disconnected: int = Field(ge=0)
    timeout: int = Field(ge=0)
    cancelled: int = Field(ge=0)
    internal_error: int = Field(ge=0)
    rejected: int = Field(ge=0)
    failed: int = Field(ge=0)


class OverviewSummaryView(BaseModel):
    requests: int = Field(ge=0)
    technical_failures: int = Field(ge=0)
    policy_rejections: int = Field(ge=0)
    technical_success_rate: float | None = Field(ge=0, le=1)
    p95_completed_latency_ms: int | None = Field(ge=0)
    settled_spend_usd: Decimal = Field(ge=0)
    status_counts: OverviewStatusCountsView


class OverviewTrendPointView(BaseModel):
    start: datetime
    requests: int = Field(ge=0)
    settled_spend_usd: Decimal = Field(ge=0)


class OverviewExceptionView(BaseModel):
    request_id: str
    occurred_at: datetime
    status: Literal[
        "provider_error",
        "client_disconnected",
        "timeout",
        "cancelled",
        "internal_error",
        "rejected",
        "failed",
    ]
    category: Literal["technical_failure", "policy_rejection", "client_cancelled"]
    provider: str | None
    model: str | None
    error_code: str | None


class OverviewSetupView(BaseModel):
    verified_provider: bool
    active_gateway_key: bool
    protection_enabled: bool
    first_successful_request: bool
    complete: bool


class OverviewDashboardView(BaseModel):
    generated_at: datetime
    period: OverviewPeriodView
    current: OverviewSummaryView
    previous: OverviewSummaryView
    trend: list[OverviewTrendPointView]
    recent_exceptions: list[OverviewExceptionView]
    setup: OverviewSetupView


class BillingBreakdownRow(BaseModel):
    key: str = Field(min_length=1)
    request_count: int = Field(ge=0)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    cost_usd: Decimal = Field(ge=0)


class BillingBreakdownView(BaseModel):
    period: BillingPeriodView
    group_by: BillingBreakdownGroup
    rows: list[BillingBreakdownRow]
    limit: int = Field(ge=1, le=500)


@router.get("/auth/me", response_model=UserView)
async def current_profile(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> UserView:
    return await _user_view(session, user)


@router.put("/auth/me", response_model=UserView)
async def update_profile(
    patch: UserPatch,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> UserView:
    if "full_name" in patch.model_fields_set:
        user.full_name = patch.full_name
    if patch.organization_name is not None:
        _require_role(user, "owner", "admin")
        tenant = await session.get(Organization, _tenant_id(user))
        if tenant is None:
            raise HTTPException(status_code=403, detail="Tenant does not exist")
        tenant.name = patch.organization_name.strip()
    await _audit(session, user, "tenant.profile_updated", str(user.id))
    await session.commit()
    await session.refresh(user)
    return await _user_view(session, user)


@router.get("/subscription", response_model=SubscriptionView)
async def get_subscription(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> SubscriptionView:
    organization = await session.get(Organization, _tenant_id(user))
    if organization is None:
        raise HTTPException(status_code=403, detail="Tenant does not exist")
    tier = await session.get(TierDefinition, organization.tier)
    if tier is None:
        raise HTTPException(
            status_code=503, detail="Organization tier is not configured"
        )
    purchase_urls = (
        checkout_urls(organization.id, user.id)
        if user.role == "owner" and organization.tier == "free"
        else {}
    )
    return SubscriptionView(
        plan=cast(
            Literal["free", "managed", "agency", "enterprise"],
            organization.tier,
        ),
        status=organization.billing_status,
        source=organization.billing_source,
        current_period_end=organization.current_period_end,
        cancel_at_period_end=organization.cancel_at_period_end,
        entitlements={key: bool(value) for key, value in tier.features.items()},
        checkout_urls=purchase_urls,
        customer_portal_url=(
            organization.customer_portal_url if user.role == "owner" else None
        ),
    )


@router.get("/team/members", response_model=list[TeamMemberView])
async def list_team_members(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[User]:
    return list(
        (
            await session.execute(
                select(User)
                .where(
                    User.organization_id == _tenant_id(user),
                    User.is_active.is_(True),
                )
                .order_by(User.created_at, User.id)
            )
        )
        .scalars()
        .all()
    )


@router.get("/team/invites", response_model=list[TeamInviteView])
async def list_team_invites(
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> list[OrganizationInvite]:
    return list(
        (
            await session.execute(
                select(OrganizationInvite)
                .where(OrganizationInvite.organization_id == _tenant_id(user))
                .order_by(OrganizationInvite.created_at.desc())
            )
        )
        .scalars()
        .all()
    )


@router.post(
    "/team/invites",
    response_model=CreatedTeamInvite,
    status_code=status.HTTP_201_CREATED,
)
async def create_team_invite(
    payload: TeamInviteInput,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> CreatedTeamInvite:
    if user.role == "admin" and payload.role != "member":
        raise HTTPException(status_code=403, detail="Only owners can invite admins")
    tenant_id = _tenant_id(user)
    await _require_entitlement(session, tenant_id, "team_rbac")
    await session.execute(
        select(Organization)
        .where(Organization.id == tenant_id)
        .with_for_update(of=Organization)
    )
    normalized_email = str(payload.email).strip().casefold()
    member = (
        await session.execute(
            select(User).where(
                func.lower(User.email) == normalized_email,
                User.organization_id == tenant_id,
                User.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()
    if member is not None:
        raise HTTPException(status_code=409, detail="User is already a team member")
    now = datetime.now(timezone.utc)
    await session.execute(
        update(OrganizationInvite)
        .where(
            OrganizationInvite.organization_id == tenant_id,
            func.lower(OrganizationInvite.email) == normalized_email,
            OrganizationInvite.accepted_at.is_(None),
            OrganizationInvite.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    token = secrets.token_urlsafe(32)
    invite = OrganizationInvite(
        organization_id=tenant_id,
        invited_by_user_id=user.id,
        email=normalized_email,
        role=payload.role,
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        expires_at=now + timedelta(days=7),
    )
    session.add(invite)
    await session.flush()
    await _audit(session, user, "tenant.team_invited", str(invite.id))
    await session.commit()
    await session.refresh(invite)
    return CreatedTeamInvite(
        **TeamInviteView.model_validate(invite, from_attributes=True).model_dump(),
        token=token,
    )


@router.delete(
    "/team/invites/{invite_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def revoke_team_invite(
    invite_id: UUID,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> None:
    tenant_id = _tenant_id(user)
    await session.execute(
        select(Organization.id)
        .where(Organization.id == tenant_id)
        .with_for_update(of=Organization)
    )
    invite = (
        await session.execute(
            select(OrganizationInvite)
            .where(
                OrganizationInvite.id == invite_id,
                OrganizationInvite.organization_id == tenant_id,
            )
            .with_for_update(of=OrganizationInvite)
        )
    ).scalar_one_or_none()
    if invite is None:
        raise HTTPException(status_code=404, detail="Invitation not found")
    if invite.accepted_at is not None:
        raise HTTPException(
            status_code=409, detail="Accepted invitations cannot be revoked"
        )
    if user.role == "admin" and invite.role != "member":
        raise HTTPException(
            status_code=403, detail="Only owners can revoke admin invites"
        )
    if invite.revoked_at is None:
        invite.revoked_at = datetime.now(timezone.utc)
        await _audit(session, user, "tenant.team_invite_revoked", str(invite.id))
        await session.commit()


@router.post("/team/invites/accept", response_model=TeamMemberView)
async def accept_team_invite(
    payload: AcceptTeamInvite,
    user: User = Depends(get_invite_user),
    session: AsyncSession = Depends(get_db),
) -> User:
    digest = hashlib.sha256(payload.token.encode()).hexdigest()
    destination_organization_id = await session.scalar(
        select(OrganizationInvite.organization_id).where(
            OrganizationInvite.token_hash == digest
        )
    )
    if destination_organization_id is None:
        raise HTTPException(status_code=400, detail="Invitation is invalid or expired")
    await session.execute(
        select(Organization.id)
        .where(Organization.id == destination_organization_id)
        .with_for_update(of=Organization)
    )
    invite = (
        await session.execute(
            select(OrganizationInvite)
            .where(OrganizationInvite.token_hash == digest)
            .with_for_update(of=OrganizationInvite)
        )
    ).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if (
        invite is None
        or invite.organization_id != destination_organization_id
        or invite.accepted_at is not None
        or invite.revoked_at is not None
        or _aware(invite.expires_at) <= now
        or invite.email.casefold() != user.email.casefold()
    ):
        raise HTTPException(status_code=400, detail="Invitation is invalid or expired")
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Verified email required")
    await _require_entitlement(session, invite.organization_id, "team_rbac")
    previous_tenant_id = _tenant_id(user)
    changing_tenant = previous_tenant_id != invite.organization_id
    if changing_tenant:
        moved_user = await move_user_from_bootstrap(
            session,
            user_id=user.id,
            source_organization_id=previous_tenant_id,
            destination_organization_id=invite.organization_id,
            role=invite.role,
        )
        if moved_user is None:
            raise HTTPException(
                status_code=409,
                detail="Leave or empty the current organization before accepting",
            )
        user = moved_user
    else:
        user.role = invite.role
        user.is_active = True
    invite.accepted_at = now
    await _audit(session, user, "tenant.team_invite_accepted", str(invite.id))
    await session.commit()
    await session.refresh(user)
    return user


@router.patch("/team/members/{member_id}", response_model=TeamMemberView)
async def update_team_member(
    member_id: UUID,
    patch: TeamRolePatch,
    user: User = Depends(get_org_owner),
    session: AsyncSession = Depends(get_db),
) -> User:
    member = await _owned_member(session, user, member_id)
    if member.role == "owner" and patch.role != "owner":
        await _protect_last_owner(session, _tenant_id(user))
    member.role = patch.role
    await _audit(session, user, "tenant.team_role_updated", str(member.id))
    await session.commit()
    await session.refresh(member)
    return member


@router.delete(
    "/team/members/{member_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def remove_team_member(
    member_id: UUID,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> None:
    member = await _owned_member(session, user, member_id)
    if user.role == "admin" and member.role != "member":
        raise HTTPException(status_code=403, detail="Only owners can remove admins")
    if member.role == "owner":
        await _protect_last_owner(session, _tenant_id(user))
    member.is_active = False
    await session.execute(
        update(ApiKey)
        .where(ApiKey.user_id == member.id, ApiKey.is_active.is_(True))
        .values(is_active=False)
    )
    await _audit(session, user, "tenant.team_member_removed", str(member.id))
    await session.commit()


@router.get("/api-keys", response_model=list[ApiKeyView])
async def list_api_keys(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[ApiKey]:
    tenant_id = _tenant_id(user)
    statement = select(ApiKey).where(
        ApiKey.organization_id == tenant_id,
        ApiKey.is_active.is_(True),
    )
    if user.role == "member":
        statement = statement.where(ApiKey.user_id == user.id)
    now = datetime.now(timezone.utc)
    return [
        item
        for item in (await session.execute(statement)).scalars().all()
        if item.expires_at is None or _aware(item.expires_at) > now
    ]


@router.post("/api-keys", response_model=CreatedApiKey)
async def create_api_key(
    payload: ApiKeyInput,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> CreatedApiKey:
    _tenant_id(user)
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Verified email required")
    plaintext, api_key = await create_tenant_api_key(
        session,
        user_id=user.id,
        name=payload.name,
        cost_center=payload.cost_center,
        team=payload.team,
    )
    await _audit(session, user, "tenant.api_key_created", str(api_key.id))
    await session.commit()
    await session.refresh(api_key)
    return CreatedApiKey(
        **ApiKeyView.model_validate(api_key).model_dump(),
        plaintext=plaintext,
    )


@router.patch("/api-keys/{api_key_id}", response_model=ApiKeyView)
async def update_api_key(
    api_key_id: UUID,
    patch: ApiKeyPatch,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> ApiKey:
    api_key = await _owned_api_key(session, user, api_key_id)
    for field, value in patch.model_dump(exclude_unset=True).items():
        setattr(api_key, field, value)
    await _audit(session, user, "tenant.api_key_updated", str(api_key.id))
    await session.commit()
    await session.refresh(api_key)
    return api_key


@router.delete(
    "/api-keys/{api_key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def revoke_api_key(
    api_key_id: UUID,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> None:
    api_key = await _owned_api_key(session, user, api_key_id)
    api_key.is_active = False
    await _audit(session, user, "tenant.api_key_revoked", str(api_key.id))
    await session.commit()


@router.get("/providers", response_model=list[ProviderSecretView])
async def list_provider_secrets(
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> list[ProviderSecret]:
    statement = select(ProviderSecret).where(
        ProviderSecret.organization_id == _tenant_id(user)
    )
    return list((await session.execute(statement)).scalars().all())


@router.post(
    "/providers",
    response_model=ProviderSecretView,
    status_code=status.HTTP_201_CREATED,
)
async def create_provider_secret(
    payload: ProviderSecretInput,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> ProviderSecret:
    tenant_id = _tenant_id(user)
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Verified email required")
    purpose = _provider_purpose(payload.provider)
    reference = await get_secret_store().put_secret(
        TenantId(tenant_id),
        purpose,
        payload.key,
        {"provider": payload.provider},
    )
    row = ProviderSecret(
        organization_id=tenant_id,
        provider=payload.provider,
        name=payload.name,
        masked_key=_mask(payload.key),
        monthly_limit_usd=payload.monthly_limit_usd,
    )
    assign_secret_reference(row, reference)
    session.add(row)
    try:
        await session.flush()
        await _audit(session, user, "tenant.provider_secret_created", str(row.id))
        await session.commit()
    except BaseException:
        await session.rollback()
        await _delete_secret_best_effort(tenant_id, reference, purpose)
        raise
    await session.refresh(row)
    return row


@router.put("/providers/{secret_id}", response_model=ProviderSecretView)
async def update_provider_secret(
    secret_id: UUID,
    patch: ProviderSecretPatch,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> ProviderSecret:
    row = await _owned_provider_secret(session, user, secret_id)
    if row.provider not in _PROVIDER_VERIFICATION_REQUESTS:
        raise HTTPException(
            status_code=409,
            detail="Unsupported provider secrets are read-only.",
        )
    tenant_id = _tenant_id(user)
    purpose = _provider_purpose(row.provider)
    previous_reference: SecretRef | None = None
    rotated_reference: SecretRef | None = None
    if "name" in patch.model_fields_set:
        row.name = patch.name
    if "monthly_limit_usd" in patch.model_fields_set:
        row.monthly_limit_usd = patch.monthly_limit_usd
    if patch.key is not None:
        previous_reference = SecretRef(row.secret_ref)
        rotated_reference = await get_secret_store().rotate_secret(
            TenantId(tenant_id),
            previous_reference,
            patch.key,
            expected_purpose=purpose,
        )
        assign_secret_reference(row, rotated_reference)
        row.masked_key = _mask(patch.key)
        row.verified_at = None
    try:
        await _audit(session, user, "tenant.provider_secret_updated", str(row.id))
        await session.commit()
    except BaseException:
        await session.rollback()
        if rotated_reference is not None:
            await _delete_secret_best_effort(
                tenant_id,
                rotated_reference,
                purpose,
            )
        raise
    if previous_reference is not None:
        await _delete_secret_best_effort(tenant_id, previous_reference, purpose)
    await session.refresh(row)
    return row


@router.post("/providers/{secret_id}/verify", response_model=ProviderSecretView)
async def verify_provider_secret(
    secret_id: UUID,
    request: Request,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> ProviderSecret:
    row = await _owned_provider_secret(session, user, secret_id)
    verification_request = _PROVIDER_VERIFICATION_REQUESTS.get(row.provider)
    if verification_request is None:
        raise HTTPException(status_code=409, detail="Unsupported provider secret")
    tenant_id = _tenant_id(user)
    try:
        credential = await get_secret_store().get_secret(
            TenantId(tenant_id),
            SecretRef(row.secret_ref),
            expected_purpose=_provider_purpose(row.provider),
        )
    except Exception as exc:
        logger.warning("Provider verification secret lookup failed")
        raise HTTPException(
            status_code=503, detail="Provider verification unavailable"
        ) from exc
    client: httpx.AsyncClient | None = getattr(request.app.state, "http_client", None)
    if client is None:
        raise HTTPException(status_code=503, detail="Provider verification unavailable")
    setting_name, default_base_url, path, header_templates = verification_request
    base_url = cast(str | None, getattr(settings, setting_name)) or default_base_url
    try:
        response = await client.get(
            f"{base_url.rstrip('/')}{path}",
            headers={
                name: value.format(credential=credential)
                for name, value in header_templates.items()
            },
        )
    except httpx.TransportError as exc:
        raise HTTPException(
            status_code=503, detail="Provider verification unavailable"
        ) from exc
    if response.status_code in {401, 403}:
        row.verified_at = None
        await _audit(session, user, "tenant.provider_secret_rejected", str(row.id))
        await session.commit()
        raise HTTPException(status_code=400, detail="Provider rejected the credential")
    if response.status_code != 200:
        raise HTTPException(status_code=503, detail="Provider verification unavailable")
    row.verified_at = datetime.now(timezone.utc)
    await _audit(session, user, "tenant.provider_secret_verified", str(row.id))
    await session.commit()
    await session.refresh(row)
    return row


@router.delete(
    "/providers/{secret_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def delete_provider_secret(
    secret_id: UUID,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> None:
    row = await _owned_provider_secret(session, user, secret_id)
    tenant_id = _tenant_id(user)
    secret_ref = SecretRef(row.secret_ref)
    purpose = _provider_purpose(row.provider)
    await session.delete(row)
    await _audit(session, user, "tenant.provider_secret_deleted", str(row.id))
    await session.commit()
    await _delete_secret_best_effort(tenant_id, secret_ref, purpose)


@router.get("/settings/pii", response_model=PrivacySettings)
async def get_privacy_settings(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> Any:
    row = await ensure_privacy_defaults(session, _tenant_id(user))
    await session.commit()
    await session.refresh(row)
    return row


@router.put("/settings/pii", response_model=PrivacySettings)
async def update_privacy_settings(
    patch: PrivacyPatch,
    request: Request,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> Any:
    tenant_id = _tenant_id(user)
    row = await ensure_privacy_defaults(session, tenant_id)
    for field, value in patch.model_dump(exclude_unset=True).items():
        setattr(row, field, value)
    await _audit(session, user, "tenant.privacy_policy_updated", str(tenant_id))
    await session.commit()
    try:
        cache: CacheService = request.app.state.cache
        await CacheManager(cache).invalidate_pii_config(str(tenant_id))
    except Exception as exc:
        logger.warning(
            "PII policy cache invalidation failed type=%s", type(exc).__name__
        )
    await session.refresh(row)
    return row


@router.get("/tier-info", response_model=TierView)
async def tier_info(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> TierView:
    tier = (
        await session.execute(
            select(TierDefinition)
            .join(Organization, Organization.tier == TierDefinition.slug)
            .where(Organization.id == _tenant_id(user))
        )
    ).scalar_one_or_none()
    if tier is None:
        raise HTTPException(
            status_code=503, detail="Organization tier is not configured"
        )
    return TierView(
        tier=tier.slug,
        name=tier.name,
        rate_limit_rpm=tier.rate_limit_rpm,
        rate_limit_tpm=tier.rate_limit_tpm,
        daily_request_limit=tier.daily_request_limit,
        monthly_request_limit=tier.monthly_request_limit,
        monthly_token_limit=tier.monthly_token_limit,
    )


@router.get("/cost/budgets", response_model=list[BudgetView])
async def list_budgets(
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[CostBudget]:
    statement = (
        select(CostBudget)
        .where(CostBudget.organization_id == _tenant_id(user))
        .order_by(CostBudget.created_at.desc(), CostBudget.id.desc())
        .limit(limit)
        .offset(offset)
    )
    budgets = list((await session.execute(statement)).scalars().all())
    try:
        for budget in budgets:
            validate_budget_notification_config(budget)
    except BudgetConfigurationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return budgets


@router.post("/cost/budgets", response_model=BudgetView)
async def create_budget(
    payload: BudgetInput,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> CostBudget:
    await _validate_targets(payload.notify_targets)
    stored_targets = await _store_budget_targets(
        _tenant_id(user), payload.notify_targets
    )
    row = CostBudget(
        organization_id=_tenant_id(user),
        scope_type=payload.scope_type,
        scope_value=payload.scope_value,
        period="monthly",
        limit_usd=payload.limit_usd,
        limit_tokens=payload.limit_tokens,
        alert_thresholds=payload.alert_thresholds,
        notify_targets=stored_targets,
        enabled=payload.enabled,
    )
    session.add(row)
    try:
        await session.flush()
        await _audit(session, user, "tenant.budget_created", str(row.id))
        await session.commit()
    except BaseException:
        await session.rollback()
        await _delete_budget_targets(_tenant_id(user), stored_targets)
        raise
    await session.refresh(row)
    return row


@router.patch("/cost/budgets/{budget_id}", response_model=BudgetView)
async def update_budget(
    budget_id: UUID,
    patch: BudgetPatch,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> CostBudget:
    row = await _owned_budget(session, user, budget_id)
    fields_set = patch.model_fields_set
    limit_usd = patch.limit_usd if "limit_usd" in fields_set else row.limit_usd
    limit_tokens = (
        patch.limit_tokens if "limit_tokens" in fields_set else row.limit_tokens
    )
    if limit_usd is None and limit_tokens is None:
        raise HTTPException(
            status_code=422, detail="a budget requires a cost or token limit"
        )
    values = patch.model_dump(exclude_unset=True)
    replacement_targets: list[dict[str, str]] | None = None
    previous_targets = list(row.notify_targets or [])
    if patch.notify_targets is not None:
        _reject_oversized_legacy_targets(previous_targets)
        await _validate_targets(patch.notify_targets)
        replacement_targets = await _store_budget_targets(
            _tenant_id(user), patch.notify_targets
        )
        values["notify_targets"] = replacement_targets
    for field, value in values.items():
        setattr(row, field, value)
    try:
        if replacement_targets is not None:
            await _cancel_budget_deliveries(session, _tenant_id(user), row.id)
        await _audit(session, user, "tenant.budget_updated", str(row.id))
        await session.commit()
    except BaseException:
        await session.rollback()
        if replacement_targets is not None:
            await _delete_budget_targets(_tenant_id(user), replacement_targets)
        raise
    if replacement_targets is not None:
        await _delete_budget_targets(_tenant_id(user), previous_targets)
    await session.refresh(row)
    return row


@router.delete(
    "/cost/budgets/{budget_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def delete_budget(
    budget_id: UUID,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> None:
    row = await _owned_budget(session, user, budget_id)
    targets = list(row.notify_targets or [])
    _reject_oversized_legacy_targets(targets)
    await _cancel_budget_deliveries(session, _tenant_id(user), row.id)
    await session.delete(row)
    await _audit(session, user, "tenant.budget_deleted", str(row.id))
    await session.commit()
    await _delete_budget_targets(_tenant_id(user), targets)


@router.post(
    "/cost/budgets/evaluate",
    response_model=BudgetEvaluationView,
    responses={
        422: {
            "description": "Budget configuration or synchronous evaluation limit rejected."
        }
    },
)
async def evaluate_budgets(
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> BudgetEvaluationView:
    budgets = list(
        (
            await session.execute(
                select(CostBudget)
                .where(CostBudget.organization_id == _tenant_id(user))
                .with_for_update(read=True, of=CostBudget)
                .limit(_MAX_SYNC_BUDGETS + 1)
            )
        )
        .scalars()
        .all()
    )
    if len(budgets) > _MAX_SYNC_BUDGETS:
        await session.rollback()
        raise HTTPException(
            status_code=422,
            detail=f"synchronous evaluation is limited to {_MAX_SYNC_BUDGETS} budgets",
        )
    try:
        delivery_count = sum(
            len(validate_budget_notification_config(budget))
            * len(budget.notify_targets)
            for budget in budgets
            if budget.enabled
        )
    except BudgetConfigurationError as exc:
        await session.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if delivery_count > _MAX_SYNC_BUDGET_DELIVERIES:
        await session.rollback()
        raise HTTPException(
            status_code=422,
            detail=(
                "synchronous evaluation is limited to "
                f"{_MAX_SYNC_BUDGET_DELIVERIES} potential deliveries"
            ),
        )
    now = datetime.now(timezone.utc)
    evaluator = BudgetEvaluator()
    try:
        results = [
            await evaluator.evaluate(session, budget, now=now)
            for budget in budgets
            if budget.enabled
        ]
    except BudgetConfigurationError as exc:
        await session.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from None
    await session.commit()
    return BudgetEvaluationView(
        period=now.strftime("%Y-%m"),
        results=[BudgetEvaluationItem.model_validate(result) for result in results],
    )


@router.get("/overview", response_model=OverviewDashboardView)
async def dashboard_overview(
    start: datetime | None = Query(
        default=None,
        description="Inclusive UTC start; defaults to seven days before end.",
    ),
    end: datetime | None = Query(
        default=None,
        description="Exclusive UTC end; defaults to the current time.",
    ),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> OverviewDashboardView:
    generated_at = datetime.now(timezone.utc)
    end_at = _aware(end or generated_at).astimezone(timezone.utc)
    start_at = _aware(start or end_at - timedelta(days=7)).astimezone(timezone.utc)
    if start_at >= end_at:
        raise HTTPException(status_code=422, detail="start must be before end")
    _validate_sync_window(start_at, end_at)
    duration = end_at - start_at
    previous_start_at = start_at - duration
    bucket: Literal["hour", "day"] = "hour" if duration <= timedelta(days=2) else "day"
    projection = await OverviewReadModel().read(
        session,
        tenant_id=_tenant_id(user),
        start_at=start_at,
        end_at=end_at,
        previous_start_at=previous_start_at,
        bucket=bucket,
        generated_at=generated_at,
    )
    return OverviewDashboardView(
        generated_at=generated_at,
        period=OverviewPeriodView(
            start=start_at,
            end=end_at,
            previous_start=previous_start_at,
            previous_end=start_at,
            bucket=bucket,
        ),
        current=OverviewSummaryView.model_validate(
            projection.current, from_attributes=True
        ),
        previous=OverviewSummaryView.model_validate(
            projection.previous, from_attributes=True
        ),
        trend=[
            OverviewTrendPointView.model_validate(row, from_attributes=True)
            for row in projection.trend
        ],
        recent_exceptions=[
            OverviewExceptionView.model_validate(row, from_attributes=True)
            for row in projection.recent_exceptions
        ],
        setup=OverviewSetupView.model_validate(projection.setup, from_attributes=True),
    )


@router.get("/requests", response_model=RequestActivityPage)
async def list_requests(
    start: datetime | None = Query(
        default=None,
        description="Inclusive timestamp; values without an offset are UTC.",
    ),
    end: datetime | None = Query(
        default=None,
        description="Inclusive timestamp; values without an offset are UTC.",
    ),
    status_filter: RequestActivityStatus | None = Query(
        default=None,
        alias="status",
    ),
    model: str | None = Query(
        default=None,
        min_length=1,
        max_length=255,
        description="Case-insensitive model substring.",
    ),
    request_id: str | None = Query(default=None, min_length=1, max_length=255),
    pii_detected: bool | None = Query(default=None),
    tag: str | None = Query(
        default=None,
        min_length=1,
        max_length=settings.COST_TAG_MAX_LENGTH,
        description="Case-insensitive substring of any request tag.",
    ),
    cost_center: str | None = Query(
        default=None,
        min_length=1,
        max_length=settings.COST_TAG_MAX_LENGTH,
        description="Case-insensitive cost center substring.",
    ),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> RequestActivityPage:
    generated_at = datetime.now(timezone.utc)
    tenant_id = _tenant_id(user)
    filters = _request_filters(
        tenant_id,
        start=start,
        end=end,
        status_filter=status_filter,
        model=model,
        request_id=request_id,
        pii_detected=pii_detected,
        tag=tag,
        cost_center=cost_center,
    )
    summary_row = (
        await session.execute(_request_summary_statement(tenant_id, filters))
    ).one()
    summary = _request_activity_summary(summary_row)
    rows = (
        await session.execute(
            _request_rows_statement(tenant_id, filters).limit(limit).offset(offset)
        )
    ).all()
    return RequestActivityPage(
        generated_at=generated_at,
        summary=summary,
        items=[
            RequestActivityView(
                request_id=row.request_id,
                created_at=row.timestamp,
                endpoint=row.path,
                model=row.model,
                status=_request_activity_status(row.details),
                prompt_tokens=row.prompt_tokens,
                completion_tokens=row.completion_tokens,
                usage_estimated=_request_usage_estimated(row.details),
                cost_usd=Decimal(str(cost_usd)),
                latency_ms=row.latency_ms,
                pii_detected=row.pii_detected,
                tags=list(row.tags or []),
                cost_center=row.cost_center,
                provider=_request_provider(row),
                team=row.team,
            )
            for row, cost_usd in rows
        ],
        total=summary.requests,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/requests/export",
    response_class=StreamingResponse,
    responses=_CSV_EXPORT_RESPONSES,
)
async def export_requests(
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    status_filter: RequestActivityStatus | None = Query(default=None, alias="status"),
    model: str | None = Query(
        default=None,
        min_length=1,
        max_length=255,
        description="Case-insensitive model substring.",
    ),
    request_id: str | None = Query(default=None, min_length=1, max_length=255),
    pii_detected: bool | None = Query(default=None),
    tag: str | None = Query(
        default=None,
        min_length=1,
        max_length=settings.COST_TAG_MAX_LENGTH,
        description="Case-insensitive substring of any request tag.",
    ),
    cost_center: str | None = Query(
        default=None,
        min_length=1,
        max_length=settings.COST_TAG_MAX_LENGTH,
        description="Case-insensitive cost center substring.",
    ),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    tenant_id = _tenant_id(user)
    end_at = _aware(end or datetime.now(timezone.utc))
    start_at = _aware(start or end_at - timedelta(days=30))
    _validate_sync_window(start_at, end_at)
    filters = _request_filters(
        tenant_id,
        start=start_at,
        end=end_at,
        status_filter=status_filter,
        model=model,
        request_id=request_id,
        pii_detected=pii_detected,
        tag=tag,
        cost_center=cost_center,
    )
    rows_statement = _request_rows_statement(tenant_id, filters)
    bounded_count = int(
        await session.scalar(
            select(func.count()).select_from(
                select(RequestLog.id)
                .where(*filters)
                .limit(_MAX_SYNC_REQUEST_EXPORT_ROWS + 1)
                .subquery()
            )
        )
        or 0
    )
    if bounded_count > _MAX_SYNC_REQUEST_EXPORT_ROWS:
        raise HTTPException(
            status_code=422,
            detail=(
                "synchronous request exports are limited to "
                f"{_MAX_SYNC_REQUEST_EXPORT_ROWS} rows"
            ),
        )

    async def content() -> AsyncIterator[bytes]:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            (
                "request_id",
                "created_at",
                "endpoint",
                "model",
                "provider",
                "status",
                "prompt_tokens",
                "completion_tokens",
                "cost_usd",
                "latency_ms",
                "pii_detected",
                "tags",
                "cost_center",
                "team",
            )
        )
        yield output.getvalue().encode("utf-8-sig")
        result = await session.stream(
            rows_statement.limit(_MAX_SYNC_REQUEST_EXPORT_ROWS)
        )
        try:
            async for row, cost_usd in result:
                output.seek(0)
                output.truncate(0)
                writer.writerow(
                    _safe_csv(value)
                    for value in (
                        row.request_id,
                        row.timestamp.isoformat(),
                        row.path,
                        row.model,
                        _request_provider(row),
                        _request_activity_status(row.details),
                        row.prompt_tokens,
                        row.completion_tokens,
                        Decimal(str(cost_usd)),
                        row.latency_ms,
                        row.pii_detected,
                        ",".join(row.tags or []),
                        row.cost_center,
                        row.team,
                    )
                )
                yield output.getvalue().encode("utf-8")
        finally:
            await result.close()

    return StreamingResponse(
        content(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="shim_requests.csv"'},
    )


@router.get("/billing/usage", response_model=BillingUsageView)
async def billing_usage(
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> BillingUsageView:
    end = _aware(end_date or datetime.now(timezone.utc))
    start = _aware(start_date or end - timedelta(days=30))
    _validate_sync_window(start, end)
    records = await BillingReadModels().daily_usage(
        session,
        tenant_id=TenantId(_tenant_id(user)),
        start_at=start,
        end_at=end,
    )
    if len(records) > MAX_BILLING_DAILY_ROWS:
        raise HTTPException(
            status_code=422,
            detail=(
                f"synchronous billing usage is limited to {MAX_BILLING_DAILY_ROWS} rows"
            ),
        )
    rows = [record.as_public_record() for record in records]
    return BillingUsageView(
        period=BillingPeriodView(start=start, end=end),
        daily_usage=[DailyUsageView.model_validate(row) for row in rows],
        total_cost=sum(float(record.cost_usd) for record in records),
    )


@router.get("/billing/breakdown", response_model=BillingBreakdownView)
async def billing_breakdown(
    start_date: datetime | None = Query(
        default=None,
        description="Inclusive timestamp; values without an offset are UTC.",
    ),
    end_date: datetime | None = Query(
        default=None,
        description="Inclusive timestamp; values without an offset are UTC.",
    ),
    group_by: BillingBreakdownGroup = Query(
        default="model",
        description=(
            "Tag grouping counts a multi-tag request once in each matching row."
        ),
    ),
    limit: int = Query(default=100, ge=1, le=500),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> BillingBreakdownView:
    end = _aware(end_date or datetime.now(timezone.utc))
    start = _aware(start_date or end - timedelta(days=30))
    _validate_sync_window(start, end)
    records = await BillingReadModels().breakdown(
        session,
        tenant_id=TenantId(_tenant_id(user)),
        start_at=start,
        end_at=end,
        group_by=group_by,
        limit=limit,
    )
    return BillingBreakdownView(
        period=BillingPeriodView(start=start, end=end),
        group_by=group_by,
        rows=[
            BillingBreakdownRow.model_validate(record.as_public_record())
            for record in records
        ],
        limit=limit,
    )


@router.get(
    "/billing/export",
    response_class=Response,
    responses=_BILLING_EXPORT_RESPONSES,
)
async def export_billing_breakdown(
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    group_by: BillingBreakdownGroup = Query(default="model"),
    format: Literal["csv", "pdf"] = Query(default="csv"),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> Response:
    end = _aware(end_date or datetime.now(timezone.utc))
    start = _aware(start_date or end - timedelta(days=30))
    _validate_sync_window(start, end)
    records = await BillingReadModels().breakdown(
        session,
        tenant_id=TenantId(_tenant_id(user)),
        start_at=start,
        end_at=end,
        group_by=group_by,
        limit=MAX_BILLING_BREAKDOWN_ROWS + 1,
    )
    if len(records) > MAX_BILLING_BREAKDOWN_ROWS:
        raise HTTPException(
            status_code=422,
            detail=(
                "synchronous billing exports are limited to "
                f"{MAX_BILLING_BREAKDOWN_ROWS} groups"
            ),
        )
    content = (
        _billing_breakdown_csv(records)
        if format == "csv"
        else _billing_breakdown_pdf(records, group_by, start, end)
    )
    return Response(
        content,
        media_type="text/csv" if format == "csv" else "application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="shim_billing_{group_by}.{format}"'
        },
    )


def _request_filters(
    tenant_id: UUID,
    *,
    start: datetime | None,
    end: datetime | None,
    status_filter: RequestActivityStatus | None,
    model: str | None,
    request_id: str | None,
    pii_detected: bool | None,
    tag: str | None,
    cost_center: str | None,
) -> list[Any]:
    start_at = _aware(start) if start is not None else None
    end_at = _aware(end) if end is not None else None
    if start_at is not None and end_at is not None and start_at > end_at:
        raise HTTPException(status_code=422, detail="start must not be after end")
    try:
        normalized_tag = (
            normalize_attribution(tag, maximum_length=settings.COST_TAG_MAX_LENGTH)
            if tag is not None
            else None
        )
        normalized_cost_center = (
            normalize_attribution(
                cost_center,
                maximum_length=settings.COST_TAG_MAX_LENGTH,
            )
            if cost_center is not None
            else None
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    filters = [RequestLog.organization_id == tenant_id]
    if start_at is not None:
        filters.append(RequestLog.timestamp >= start_at)
    if end_at is not None:
        filters.append(RequestLog.timestamp <= end_at)
    if status_filter is not None:
        lifecycle_status = _request_lifecycle_status_expression()
        filters.append(
            or_(
                lifecycle_status.is_(None),
                lifecycle_status.not_in(KNOWN_REQUEST_ACTIVITY_STATUSES),
            )
            if status_filter == "unknown"
            else lifecycle_status == status_filter
        )
    if model is not None:
        filters.append(RequestLog.model.icontains(model, autoescape=True))
    if request_id is not None:
        filters.append(RequestLog.request_id == request_id)
    if pii_detected is not None:
        filters.append(RequestLog.pii_detected == pii_detected)
    if normalized_tag is not None:
        tag_values = func.jsonb_array_elements_text(
            func.coalesce(RequestLog.tags, sql_cast([], JSONB))
        ).table_valued("value")
        filters.append(
            select(1)
            .select_from(tag_values)
            .where(tag_values.c.value.icontains(normalized_tag, autoescape=True))
            .correlate(RequestLog)
            .exists()
        )
    if normalized_cost_center is not None:
        filters.append(
            RequestLog.cost_center.icontains(
                normalized_cost_center,
                autoescape=True,
            )
        )
    return filters


def _request_settled_spend(tenant_id: UUID):
    return (
        select(func.sum(UsageLedger.cost_usd))
        .where(
            UsageLedger.organization_id == tenant_id,
            UsageLedger.request_id == RequestLog.request_id,
            UsageLedger.event_type == "spend_settlement",
        )
        .correlate(RequestLog)
        .scalar_subquery()
    )


def _request_summary_statement(tenant_id: UUID, filters: list[Any]):
    lifecycle_status = _request_lifecycle_status_expression()
    usage_estimated = RequestLog.details["usage_estimated"].as_boolean().is_(True)
    spend = _request_settled_spend(tenant_id)
    spend_denied = (
        select(AuditIntent.id)
        .where(
            AuditIntent.organization_id == tenant_id,
            AuditIntent.request_id == RequestLog.request_id,
            AuditIntent.event_type == "preflight",
            AuditIntent.usage_summary["denial_reason"].as_string()
            == "spend_limit_exceeded",
        )
        .correlate(RequestLog)
        .exists()
    )
    return (
        select(
            func.count(RequestLog.id).label("requests"),
            *(
                func.count(RequestLog.id)
                .filter(lifecycle_status == status_name)
                .label(status_name)
                for status_name in KNOWN_REQUEST_ACTIVITY_STATUSES
            ),
            func.count(RequestLog.id)
            .filter(
                or_(
                    lifecycle_status.is_(None),
                    lifecycle_status.not_in(KNOWN_REQUEST_ACTIVITY_STATUSES),
                )
            )
            .label("unknown"),
            func.coalesce(
                func.sum(case((usage_estimated, 0), else_=RequestLog.prompt_tokens)),
                0,
            ).label("prompt_tokens"),
            func.coalesce(
                func.sum(
                    case((usage_estimated, 0), else_=RequestLog.completion_tokens)
                ),
                0,
            ).label("completion_tokens"),
            func.count(RequestLog.id)
            .filter(RequestLog.pii_detected.is_(True))
            .label("pii_detected_requests"),
            func.count(RequestLog.id)
            .filter(lifecycle_status == "failed", spend_denied)
            .label("policy_failed"),
            func.percentile_cont(0.95)
            .within_group(RequestLog.latency_ms)
            .filter(lifecycle_status == "completed")
            .label("p95_completed_latency_ms"),
            func.coalesce(
                func.sum(func.coalesce(spend, Decimal("0"))), Decimal("0")
            ).label("settled_spend_usd"),
        )
        .select_from(RequestLog)
        .where(*filters)
    )


def _request_activity_summary(row: Any) -> RequestActivitySummaryView:
    status_counts = {
        status_name: int(getattr(row, status_name) or 0)
        for status_name in (*KNOWN_REQUEST_ACTIVITY_STATUSES, "unknown")
    }
    technical_failures = sum(
        status_counts[status_name]
        for status_name in ("provider_error", "timeout", "internal_error", "failed")
    ) - int(row.policy_failed or 0)
    technical_requests = status_counts["completed"] + technical_failures
    p95 = row.p95_completed_latency_ms
    return RequestActivitySummaryView(
        requests=int(row.requests or 0),
        technical_success_rate=(
            status_counts["completed"] / technical_requests
            if technical_requests
            else None
        ),
        p95_completed_latency_ms=round(float(p95)) if p95 is not None else None,
        settled_spend_usd=Decimal(str(row.settled_spend_usd or 0)),
        prompt_tokens=int(row.prompt_tokens or 0),
        completion_tokens=int(row.completion_tokens or 0),
        pii_detected_requests=int(row.pii_detected_requests or 0),
        technical_failures=technical_failures,
        policy_rejections=status_counts["rejected"] + int(row.policy_failed or 0),
        status_counts=RequestActivityStatusCountsView(**status_counts),
    )


def _request_rows_statement(tenant_id: UUID, filters: list[Any]):
    # Correlate spend to bounded request rows; never aggregate all tenant history.
    spend = _request_settled_spend(tenant_id)
    return (
        select(
            RequestLog,
            func.coalesce(spend, Decimal("0")).label("cost_usd"),
        )
        .where(*filters)
        .order_by(RequestLog.timestamp.desc(), RequestLog.id.desc())
    )


def _request_provider(row: RequestLog) -> str | None:
    provider = (row.details or {}).get("provider")
    return provider if isinstance(provider, str) else None


def _safe_csv(value: object) -> str:
    rendered = "" if value is None else str(value)
    return (
        f"'{rendered}"
        if rendered.lstrip().startswith(("=", "+", "-", "@"))
        else rendered
    )


def _billing_breakdown_csv(records: list[Any]) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ("key", "request_count", "prompt_tokens", "completion_tokens", "cost_usd")
    )
    for record in records:
        writer.writerow(
            _safe_csv(value)
            for value in (
                record.key,
                record.request_count,
                record.prompt_tokens,
                record.completion_tokens,
                record.cost_usd,
            )
        )
    return output.getvalue().encode("utf-8-sig")


def _billing_breakdown_pdf(
    records: list[Any],
    group_by: BillingBreakdownGroup,
    start: datetime,
    end: datetime,
) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    from shim_enterprise.compliance.reporting import (
        REPORT_FONT,
        REPORT_FONT_BOLD,
        ensure_report_fonts,
        evidence_table,
    )

    ensure_report_fonts()
    styles = getSampleStyleSheet()
    styles["Title"].fontName = REPORT_FONT_BOLD
    styles["Normal"].fontName = REPORT_FONT
    output = io.BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        title="shim Cost Showback",
    )
    document.build(
        [
            Paragraph("shim Cost Showback", styles["Title"]),
            Paragraph(
                f"Group: {group_by}<br/>Period: {start:%Y-%m-%d} – {end:%Y-%m-%d}",
                styles["Normal"],
            ),
            Spacer(1, 5 * mm),
            evidence_table(
                [
                    [
                        record.key,
                        str(record.request_count),
                        str(record.prompt_tokens + record.completion_tokens),
                        str(record.cost_usd),
                    ]
                    for record in records
                ],
                ["Group", "Requests", "Tokens", "Cost (USD)"],
            ),
        ]
    )
    return output.getvalue()


async def _user_view(session: AsyncSession, user: User) -> UserView:
    tenant = await session.get(Organization, _tenant_id(user))
    if tenant is None:
        raise HTTPException(status_code=403, detail="Tenant does not exist")
    return UserView(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        organization_name=tenant.name,
        role=cast(Literal["owner", "admin", "member"], user.role),
        is_active=user.is_active,
        is_verified=user.is_verified,
        created_at=user.created_at,
    )


async def _owned_api_key(
    session: AsyncSession,
    user: User,
    api_key_id: UUID,
) -> ApiKey:
    statement = select(ApiKey).where(
        ApiKey.id == api_key_id,
        ApiKey.organization_id == _tenant_id(user),
    )
    if user.role == "member":
        statement = statement.where(ApiKey.user_id == user.id)
    row = (await session.execute(statement)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="API key not found")
    return row


async def _owned_member(
    session: AsyncSession,
    user: User,
    member_id: UUID,
) -> User:
    tenant_id = _tenant_id(user)
    await session.execute(
        select(Organization.id)
        .where(Organization.id == tenant_id)
        .with_for_update(of=Organization)
    )
    row = (
        await session.execute(
            select(User)
            .where(
                User.id == member_id,
                User.organization_id == tenant_id,
                User.is_active.is_(True),
            )
            .with_for_update(of=User)
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Team member not found")
    return row


async def _protect_last_owner(session: AsyncSession, tenant_id: UUID) -> None:
    await session.execute(
        select(Organization.id)
        .where(Organization.id == tenant_id)
        .with_for_update(of=Organization)
    )
    owners = int(
        await session.scalar(
            select(func.count(User.id)).where(
                User.organization_id == tenant_id,
                User.role == "owner",
                User.is_active.is_(True),
            )
        )
        or 0
    )
    if owners <= 1:
        raise HTTPException(status_code=409, detail="Organization needs an owner")


def _require_role(user: User, *roles: str) -> None:
    if user.role not in roles:
        raise HTTPException(status_code=403, detail="Organization admin required")


async def _require_entitlement(
    session: AsyncSession,
    tenant_id: UUID,
    feature: str,
) -> None:
    features = await session.scalar(
        select(TierDefinition.features)
        .join(Organization, Organization.tier == TierDefinition.slug)
        .where(Organization.id == tenant_id)
    )
    if not isinstance(features, dict) or features.get(feature) is not True:
        raise HTTPException(status_code=403, detail="Plan upgrade required")


async def _owned_provider_secret(
    session: AsyncSession,
    user: User,
    secret_id: UUID,
) -> ProviderSecret:
    statement = select(ProviderSecret).where(
        ProviderSecret.id == secret_id,
        ProviderSecret.organization_id == _tenant_id(user),
    )
    row = (await session.execute(statement)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Provider secret not found")
    return row


async def _owned_budget(
    session: AsyncSession,
    user: User,
    budget_id: UUID,
) -> CostBudget:
    statement = (
        select(CostBudget)
        .where(
            CostBudget.id == budget_id,
            CostBudget.organization_id == _tenant_id(user),
        )
        .with_for_update(of=CostBudget)
    )
    row = (await session.execute(statement)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Budget not found")
    return row


async def _audit(
    session: AsyncSession,
    user: User,
    action: str,
    subject_id: str,
) -> None:
    tenant_id = _tenant_id(user)
    event_id = f"management:{uuid4()}"
    now = datetime.now(timezone.utc)
    await OutboxWriter().append(
        session,
        organization_id=TenantId(tenant_id),
        values={
            "event_type": "audit.chain_append_requested",
            "aggregate_type": "management",
            "aggregate_id": event_id,
            "idempotency_key": f"{event_id}:audit",
            "payload": {
                "organization_id": str(tenant_id),
                "request_id": event_id,
                "event_type": "management_action",
                "actor": str(user.id),
                "endpoint": action,
                "extra": {"subject_id": subject_id},
            },
            "status": "pending",
            "next_attempt_at": now,
        },
    )


async def _validate_targets(targets: list[NotificationTargetInput]) -> None:
    for target in targets:
        try:
            await assert_safe_forward_url(target.endpoint)
        except UnsafeForwardURL as exc:
            raise HTTPException(
                status_code=422, detail="Unsafe notification URL"
            ) from exc


async def _store_budget_targets(
    tenant_id: UUID,
    targets: list[NotificationTargetInput],
) -> list[dict[str, str]]:
    stored: list[dict[str, str]] = []
    store = get_secret_store()
    try:
        for target in targets:
            reference = await store.put_secret(
                TenantId(tenant_id),
                "budget-alert-endpoint",
                target.endpoint,
                {"kind": target.kind},
            )
            stored.append(
                {
                    "kind": target.kind,
                    "endpoint_origin": _endpoint_origin(target.endpoint),
                    "secret_ref": str(reference),
                }
            )
    except BaseException:
        await _delete_budget_targets(tenant_id, stored)
        raise
    return stored


async def _delete_budget_targets(
    tenant_id: UUID,
    targets: list[dict[str, str]],
) -> None:
    for target in targets:
        reference = target.get("secret_ref")
        if reference is None:
            continue
        await _delete_secret_best_effort(
            tenant_id,
            SecretRef(reference),
            "budget-alert-endpoint",
        )


def _reject_oversized_legacy_targets(targets: list[dict[str, str]]) -> None:
    if len(targets) > MAX_BUDGET_NOTIFY_TARGETS:
        raise HTTPException(
            status_code=422,
            detail="legacy budget notification targets require migration",
        )


async def _cancel_budget_deliveries(
    session: AsyncSession,
    tenant_id: UUID,
    budget_id: UUID,
) -> None:
    statement = (
        select(OutboxEvent)
        .where(
            OutboxEvent.organization_id == tenant_id,
            OutboxEvent.event_type == "budget.threshold_crossed",
            OutboxEvent.aggregate_type == "budget",
            OutboxEvent.aggregate_id == str(budget_id),
            OutboxEvent.status.in_(("pending", "processing", "failed")),
        )
        .with_for_update(of=OutboxEvent)
    )
    now = datetime.now(timezone.utc)
    for event in (await session.execute(statement)).scalars():
        event.cancel(now=now)


async def _delete_secret_best_effort(
    tenant_id: UUID,
    secret_ref: SecretRef | str,
    purpose: str,
) -> None:
    try:
        await get_secret_store().delete_secret(
            TenantId(tenant_id),
            SecretRef(str(secret_ref)),
            expected_purpose=purpose,
        )
    except Exception as exc:
        logger.warning("Secret cleanup failed type=%s", type(exc).__name__)


def _endpoint_origin(endpoint: str) -> str:
    parts = urlsplit(endpoint)
    return f"{parts.scheme}://{parts.netloc}"


def _tenant_id(user: User) -> UUID:
    if user.organization_id is None:
        raise HTTPException(status_code=403, detail="Authenticated user has no tenant")
    return user.organization_id


def _provider_purpose(provider: str) -> str:
    return f"provider:{provider}:api-key"


def _mask(value: str) -> str:
    return f"{value[:3]}...{value[-4:]}"


def _request_activity_status(details: dict[str, Any] | None) -> RequestActivityStatus:
    value = (details or {}).get("lifecycle_status")
    return value if value in KNOWN_REQUEST_ACTIVITY_STATUSES else "unknown"


def _request_usage_estimated(details: dict[str, Any] | None) -> bool:
    return (details or {}).get("usage_estimated") is True


def _request_lifecycle_status_expression() -> Any:
    return RequestLog.details["lifecycle_status"].as_string()


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _validate_sync_window(start: datetime, end: datetime) -> None:
    if start > end:
        raise HTTPException(status_code=422, detail="start must not be after end")
    if end - start > _MAX_SYNC_WINDOW:
        raise HTTPException(
            status_code=422,
            detail="synchronous operations are limited to 31 days",
        )
