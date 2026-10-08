"""JWT-authenticated tenant management API."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
import asyncio
import csv
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import io
import itertools
import json
import logging
import secrets
from typing import Annotated, Any, Literal, cast, get_args
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
    computed_field,
    field_validator,
    model_validator,
)
from sqlalchemy import case, cast as sql_cast, distinct, func, or_, select, update
from sqlalchemy.dialects.postgresql import JSONB, insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from shim_enterprise.api.enterprise_deps import (
    get_current_user,
    get_invite_user,
    get_org_admin,
    get_org_owner,
    get_org_reader,
)
from shim.billing.attribution import normalize_attribution
from shim.gateway.kernel.result import ResponseWarning
from shim_enterprise.billing.models import (
    AuditIntent,
    CostBudget,
    RequestLifecycle,
    UsageLedger,
)
from shim_enterprise.billing.read_models import (
    MAX_BILLING_DAILY_ROWS,
    MAX_BILLING_BREAKDOWN_ROWS,
    BillingBreakdown,
    BillingBreakdownGroup,
    BillingReadModels,
    DailyUsage,
)
from shim_enterprise.billing.spend import (
    MAX_BUDGET_ALERT_THRESHOLDS,
    MAX_BUDGET_NOTIFY_TARGETS,
    BudgetConfigurationError,
    BudgetEvaluator,
    validate_budget_notification_config,
)
from shim_enterprise.cache.redis_index import CacheManager, CacheService
from shim_enterprise.compliance.services.forwarder import ComplianceForwarderService
from shim_enterprise.compliance.url_guard import (
    UnsafeForwardURL,
    assert_safe_forward_url,
)
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim_enterprise.findings.models import Finding
from shim_enterprise.findings.service import (
    STATUS_IDS,
    STATUS_RESOLVED,
    ocsf_detection_finding,
)
from shim.gateway.contracts.ids import SecretRef, TenantId
from shim.privacy.policies import (
    PII_CONFIG_DEFAULTS,
    EntityAction,
    effective_entity_actions,
)
from shim_enterprise.observability.analytics_projection import RequestLog
from shim_enterprise.observability.overview import OverviewReadModel
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.secrets.migration import assign_secret_reference
from shim_enterprise.secrets.store import get_secret_store
from shim_enterprise.tenants.audit import change_details, export_details
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim_enterprise.tenants.models import (
    ApiKey,
    ModelDeployment,
    OrganizationInvite,
    Organization,
    ProviderSecret,
    ServiceAccountCredential,
    TierDefinition,
    Team,
    TeamMembership,
    User,
)
from shim_enterprise.tenants.deployments import (
    require_model_aliases,
    validate_deployment_url,
)
from shim_enterprise.tenants.service import create_api_key as create_tenant_api_key
from shim_enterprise.tenants.teams import (
    ORGANIZATION_READERS,
    member_team_ids,
    require_team,
)
from shim_enterprise.tenants.service import rotate_api_key as rotate_tenant_api_key
from shim_enterprise.tenants.service import ensure_privacy_defaults
from shim_enterprise.tenants.service import (
    SERVICE_ACCOUNT_EMAIL_DOMAIN,
    WorkspaceHasRequestHistory,
    issue_service_account_key,
    move_user_from_bootstrap,
)


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
_MAX_PROMPT_VERSIONS = 200
_SYSTEM_PROMPT_HASH_PATTERN = r"^hmac-sha256:v1:[0-9a-f]{64}$"
_COMPLETION_OUTCOMES = ("complete", "truncated", "empty", "refused", "filtered")
_TECHNICAL_FAILURES = ("provider_error", "timeout", "internal_error", "failed")
_MAX_SYNC_BUDGETS = 100
_MAX_SYNC_BUDGET_DELIVERIES = 100


class UserView(BaseModel):
    id: UUID
    email: EmailStr
    full_name: str | None
    organization_name: str
    role: Literal["owner", "admin", "member", "auditor"]
    is_active: bool
    is_verified: bool
    created_at: datetime


class UserPatch(BaseModel):
    full_name: str | None = Field(default=None, max_length=200)
    organization_name: str | None = Field(default=None, min_length=1, max_length=200)


class TeamInput(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    daily_request_limit: int | None = Field(default=None, ge=0, le=2_000_000_000)
    monthly_request_limit: int | None = Field(default=None, ge=0, le=2_000_000_000)
    monthly_token_limit: int | None = Field(default=None, ge=0, le=2_000_000_000)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Team name cannot be blank")
        return value.strip()


class TeamView(TeamInput):
    model_config = ConfigDict(from_attributes=True)
    id: UUID


class MembershipInput(BaseModel):
    role: Literal["member", "team_admin"] = "member"


class MembershipView(MembershipInput):
    model_config = ConfigDict(from_attributes=True)
    user_id: UUID
    team_id: UUID
    source: Literal["local", "oidc"]


def _validate_allowed_models(value: list[str] | None) -> list[str] | None:
    if value is not None and any(
        not item or item != item.strip() or len(item) > 200 for item in value
    ):
        raise ValueError(
            "Model identifiers must be nonblank and at most 200 characters"
        )
    return list(dict.fromkeys(value)) if value is not None else None


def _validate_attribution(value: str | None) -> str | None:
    if value is None:
        return None
    return normalize_attribution(
        value,
        maximum_length=settings.COST_TAG_MAX_LENGTH,
    )


class ApiKeyInput(BaseModel):
    name: str = Field(min_length=1, max_length=50)
    cost_center: str | None = None
    team: str | None = None
    team_id: UUID | None = None
    allowed_models: list[str] | None = Field(default=None, max_length=200)

    validate_models = field_validator("allowed_models")(_validate_allowed_models)
    validate_attribution = field_validator("cost_center", "team")(_validate_attribution)


class ApiKeyPatch(BaseModel):
    cost_center: str | None = None
    team: str | None = None
    team_id: UUID | None = None
    allowed_models: list[str] | None = Field(default=None, max_length=200)

    validate_models = field_validator("allowed_models")(_validate_allowed_models)
    validate_attribution = field_validator("cost_center", "team")(_validate_attribution)


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
    team_id: UUID | None
    allowed_models: list[str] | None


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
    entity_actions: dict[str, EntityAction] = Field(
        description="Stored per-type overrides of the group switches."
    )
    bulk_threshold: int | None = Field(
        description=(
            "Distinct detected values in one request that raise a bulk-disclosure "
            "alert; null turns the alarm off."
        )
    )
    response_scan: Literal["off", "count"] = Field(
        description=(
            "count: after an answer is delivered, count personal data in it that "
            "the request did not carry. The answer is never changed or delayed."
        )
    )
    placeholder_mode: Literal["random", "stable"] = Field(
        description=(
            "random: a new placeholder per request. stable: the same value keeps "
            "its placeholder for up to 30 days, so provider prompt caching works "
            "and the provider can link the value across requests."
        )
    )

    @computed_field(description="The action every entity type gets.")
    @property
    def effective_actions(self) -> dict[str, EntityAction]:
        return effective_entity_actions(
            {field: getattr(self, field) for field in PII_CONFIG_DEFAULTS},
            self.entity_actions,
        )


class ProviderKeySettings(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    allow_customer_provider_keys: bool = Field(
        description=(
            "When false, a request carrying its own provider key (x-provider-key) "
            "on a catalog route is refused with 403 PROVIDER_KEY_NOT_ALLOWED."
        )
    )


class PrivacyPatch(BaseModel):
    block_email: bool | None = None
    block_phone: bool | None = None
    block_credit_card: bool | None = None
    block_secrets: bool | None = None
    block_pii_tr: bool | None = None
    entity_actions: dict[str, EntityAction] = Field(
        default_factory=dict,
        description="Replaces the stored overrides whole; {} removes them all.",
    )
    placeholder_mode: Literal["random", "stable"] = Field(
        default="random", description="Left unchanged when absent."
    )
    response_scan: Literal["off", "count"] = Field(
        default="off", description="Left unchanged when absent."
    )
    bulk_threshold: int | None = Field(
        default=None,
        ge=2,
        description="null turns the alarm off; left unchanged when absent.",
    )

    @field_validator("entity_actions")
    @classmethod
    def known_entity_types(
        cls, value: dict[str, EntityAction]
    ) -> dict[str, EntityAction]:
        effective_entity_actions(None, value)
        return value


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
    entitlements: dict[str, bool]


class ServiceAccountInput(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    role: Literal["admin", "auditor"]
    expires_in_days: int = Field(ge=1, le=365)


class ServiceAccountView(BaseModel):
    id: UUID
    name: str | None
    role: Literal["admin", "auditor"]
    prefix: str
    expires_at: datetime
    last_used_at: datetime | None
    created_by: UUID
    created_at: datetime


class CreatedServiceAccount(ServiceAccountView):
    plaintext: str


class TeamMemberView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    full_name: str | None
    role: Literal["owner", "admin", "member", "auditor"]
    is_active: bool
    created_at: datetime


class TeamInviteInput(BaseModel):
    email: EmailStr
    role: Literal["admin", "member", "auditor"] = "member"


class TeamInviteView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    role: Literal["owner", "admin", "member", "auditor"]
    expires_at: datetime
    accepted_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class CreatedTeamInvite(TeamInviteView):
    token: str


class AcceptTeamInvite(BaseModel):
    token: str = Field(min_length=32, max_length=512)


class TeamRolePatch(BaseModel):
    role: Literal["owner", "admin", "member", "auditor"]


class NotificationTargetInput(BaseModel):
    kind: Literal["slack", "webhook"]
    endpoint: str = Field(min_length=1, max_length=2_048)
    secret: str | None = Field(
        default=None,
        min_length=16,
        repr=False,
        description="Signs webhook deliveries with X-Shim-Signature.",
    )

    @model_validator(mode="after")
    def validate_signing(self) -> NotificationTargetInput:
        if self.secret is not None and self.kind != "webhook":
            raise ValueError("only webhook targets support signing secrets")
        return self


class NotificationTargetView(BaseModel):
    kind: Literal["slack", "webhook"]
    endpoint_origin: str
    signed: bool

    @model_validator(mode="before")
    @classmethod
    def signed_from_reference(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {**value, "signed": "signing_secret_ref" in value}
        return value


class BudgetInput(BaseModel):
    scope_type: Literal["tag", "team", "team_id", "org"]
    scope_value: str | None = None
    limit_usd: Decimal | None = Field(default=None, gt=0)
    limit_tokens: int | None = Field(default=None, gt=0)
    alert_thresholds: list[float] = Field(
        default_factory=lambda: [0.8, 1.0],
        min_length=1,
        max_length=MAX_BUDGET_ALERT_THRESHOLDS,
        description=(
            "Fractions of the budget limit, greater than 0 and at most 5. "
            "0.8 means 80 percent."
        ),
    )
    notify_targets: list[NotificationTargetInput] = Field(
        min_length=1,
        max_length=MAX_BUDGET_NOTIFY_TARGETS,
    )
    enabled: bool = True

    @field_validator("alert_thresholds")
    @classmethod
    def validate_alert_thresholds(cls, values: list[float] | None) -> list[float]:
        if values is None:
            raise ValueError("alert thresholds must be within (0, 5]")
        for value in values:
            if not 0 < value <= 5:
                raise ValueError(
                    f"{value:g} is outside (0, 5]; thresholds are fractions, "
                    "0.5 means 50 percent"
                )
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
        if self.scope_type != "org":
            if not self.scope_value:
                raise ValueError("scoped budgets require scope_value")
            if self.scope_type != "team_id":
                self.scope_value = _validate_attribution(self.scope_value)
        if self.limit_usd is None and self.limit_tokens is None:
            raise ValueError("a budget requires a cost or token limit")
        return self


class BudgetPatch(BaseModel):
    limit_usd: Decimal | None = Field(default=None, gt=0)
    limit_tokens: int | None = Field(default=None, gt=0)
    alert_thresholds: list[float] | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_BUDGET_ALERT_THRESHOLDS,
        description=(
            "Fractions of the budget limit, greater than 0 and at most 5. "
            "0.8 means 80 percent."
        ),
    )
    notify_targets: list[NotificationTargetInput] | None = Field(
        default=None,
        min_length=1,
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
    scope_type: Literal["tag", "team", "team_id", "org"]
    scope_value: str | None
    scope_label: str | None = None
    period: str
    limit_usd: Decimal | None
    limit_tokens: int | None
    alert_thresholds: list[float]
    notify_targets: list[NotificationTargetView]
    enabled: bool
    created_at: datetime

    @computed_field
    @property
    def alert_thresholds_percent(self) -> list[float]:
        return [float(Decimal(str(value)) * 100) for value in self.alert_thresholds]


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
    cost_usd: float | None
    unpriced_requests: int = 0
    cost_complete: bool = True


class BillingUsageView(BaseModel):
    period: BillingPeriodView
    daily_usage: list[DailyUsageView]
    total_cost: float | None
    unpriced_requests: int = 0
    cost_complete: bool = True


class PromptVersionOutcomes(BaseModel):
    complete: int
    truncated: int
    empty: int
    refused: int
    filtered: int


class PromptVersionView(BaseModel):
    system_prompt_hash: str | None
    first_seen: datetime
    last_seen: datetime
    requests: int
    api_keys: list[UUID] = Field(max_length=10)
    models: list[str] = Field(max_length=10)
    outcomes: PromptVersionOutcomes
    failed: int
    p95_shim_latency_ms: int | None


class PromptVersionPage(BaseModel):
    period: BillingPeriodView
    items: list[PromptVersionView]
    truncated: bool


FindingStatus = Literal["new", "in_progress", "suppressed", "resolved"]
_FINDING_STATUSES = {value: name for name, value in STATUS_IDS.items()}


class FindingView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    source: str
    rule_id: str
    rule_version: int
    subject: dict[str, Any]
    title: str
    summary: str
    severity_id: int
    status_id: int
    first_seen_at: datetime
    last_seen_at: datetime
    occurrences: int
    evidence: dict[str, Any]
    impact: dict[str, Any] | None
    remediation: dict[str, Any]
    resolved_at: datetime | None
    resolved_by: str | None

    @computed_field
    @property
    def status(self) -> FindingStatus:
        return cast(FindingStatus, _FINDING_STATUSES[self.status_id])


class FindingPage(BaseModel):
    items: list[FindingView]
    total: int
    limit: int
    offset: int


class FindingPatch(BaseModel):
    status: FindingStatus


class UsageTotalsView(BaseModel):
    requests: int
    input_tokens: int
    output_tokens: int
    cost_usd: Decimal | None
    cost_complete: bool
    unpriced_requests: int


class UsageDayView(UsageTotalsView):
    date: date


class UsageModelView(UsageTotalsView):
    model: str


class UsageKeyView(UsageTotalsView):
    api_key_id: UUID
    name: str | None
    prefix: str


class MyUsageView(BaseModel):
    period: BillingPeriodView
    totals: UsageTotalsView
    daily: list[UsageDayView]
    by_model: list[UsageModelView]
    by_api_key: list[UsageKeyView]


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
    cost_usd: Decimal | None = Field(ge=0)
    cost_complete: bool
    shim_latency_ms: int | None = Field(
        default=None,
        ge=0,
        title="shim latency (ms)",
        description="shim processing time excluding provider waiting; null when unmeasured.",
    )
    pii_detected: bool
    tags: list[str] = Field(default_factory=list)
    cost_center: str | None
    provider: str | None
    team: str | None
    provider_finish_reasons: dict[str, str] | None = None
    completion_outcome: (
        Literal["complete", "truncated", "empty", "refused", "filtered"] | None
    ) = None
    repeat_chain_length: int | None = Field(default=None, ge=1)
    ttft_ms: float | None = Field(default=None, ge=0)
    warnings: list[ResponseWarning] | None = Field(
        default=None,
        description="X-Shim-Warnings codes the request carried; null on older rows.",
    )
    cached_input_tokens: int | None = Field(
        default=None,
        ge=0,
        description=(
            "Input tokens read from or written to the provider's prompt cache; "
            "null when the provider did not report the split."
        ),
    )
    system_prompt_hash: str | None = None
    deployment_kind: Literal["internal", "external", "unknown"] | None = None
    pii_entities: dict[str, int] | None = Field(
        default=None, description="Masked values by entity type; null on older rows."
    )
    monitored_entities: dict[str, int] | None = Field(
        default=None,
        description="Values sent unchanged under a monitor action, by entity type.",
    )
    blocked_entities: dict[str, int] | None = Field(
        default=None,
        description="Values that stopped the request under a block action, by entity type.",
    )
    bulk_disclosure: dict[str, int] | None = Field(
        default=None,
        description=(
            "distinct_values and threshold when the request carried at least the "
            "tenant's bulk threshold of distinct detected values; null otherwise."
        ),
    )
    response_entities: dict[str, int] | None = Field(
        default=None,
        description=(
            "Distinct values the answer carried that the request did not, by "
            "entity type; null when the response scan was off or has not finished."
        ),
    )


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
    p95_completed_shim_latency_ms: int | None = Field(
        ge=0, title="p95 completed shim latency (ms)"
    )
    settled_spend_usd: Decimal = Field(ge=0)
    cost_complete: bool
    unpriced_requests: int = Field(ge=0)
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
    p95_completed_shim_latency_ms: int | None = Field(
        ge=0, title="p95 completed shim latency (ms)"
    )
    settled_spend_usd: Decimal | None = Field(ge=0)
    cost_complete: bool
    unpriced_requests: int = Field(ge=0)
    status_counts: OverviewStatusCountsView


class OverviewTrendPointView(BaseModel):
    start: datetime
    requests: int = Field(ge=0)
    settled_spend_usd: Decimal | None = Field(ge=0)
    cost_complete: bool
    unpriced_requests: int = Field(ge=0)


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
    unpriced_requests: int = 0
    cost_complete: bool = True
    key: str = Field(min_length=1)
    label: str | None = Field(
        default=None, description="The team's current name when grouped by team_id."
    )
    request_count: int = Field(ge=0)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    cost_usd: Decimal | None = Field(ge=0)


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
    # The audit chain is immutable, so a person's name is recorded as changed, never stored.
    previous_full_name = user.full_name
    if "full_name" in patch.model_fields_set:
        user.full_name = patch.full_name
    before: dict[str, Any] = {}
    after: dict[str, Any] = {}
    if patch.organization_name is not None:
        _require_role(user, "owner", "admin")
        tenant = await session.get(Organization, _tenant_id(user))
        if tenant is None:
            raise HTTPException(status_code=403, detail="Tenant does not exist")
        before["organization_name"] = tenant.name
        tenant.name = patch.organization_name.strip()
        after["organization_name"] = tenant.name
    await _audit(
        session,
        user,
        "tenant.profile_updated",
        str(user.id),
        details={
            **change_details(before, after),
            "full_name_changed": user.full_name != previous_full_name,
        },
    )
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
    return SubscriptionView(
        plan=cast(
            Literal["free", "managed", "agency", "enterprise"],
            organization.tier,
        ),
        status=organization.billing_status,
        source=organization.billing_source,
        entitlements={key: bool(value) for key, value in tier.features.items()},
    )


@router.get("/team/members", response_model=list[TeamMemberView])
async def list_team_members(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[User]:
    # Team admins pick members to add from this list; ordinary members do not see it.
    if user.role not in ORGANIZATION_READERS and not await session.scalar(
        select(member_team_ids(user, administer=True).exists())
    ):
        raise HTTPException(
            status_code=403, detail="Organization reader or team admin required"
        )
    return list(
        (
            await session.execute(
                select(User)
                .where(
                    User.organization_id == _tenant_id(user),
                    User.is_active.is_(True),
                    User.kind == "human",
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
    if user.kind == "service":
        raise HTTPException(
            status_code=403, detail="Service accounts cannot accept invitations"
        )
    await _require_entitlement(session, invite.organization_id, "team_rbac")
    previous_tenant_id = _tenant_id(user)
    changing_tenant = previous_tenant_id != invite.organization_id
    secrets_to_delete: list[tuple[str, str]] = []
    if changing_tenant:
        try:
            moved = await move_user_from_bootstrap(
                session,
                user_id=user.id,
                source_organization_id=previous_tenant_id,
                destination_organization_id=invite.organization_id,
                role=invite.role,
            )
        except WorkspaceHasRequestHistory as exc:
            raise HTTPException(
                status_code=409,
                detail="Your personal workspace has request history and cannot be "
                "archived; ask the inviting organization's owner to contact support.",
            ) from exc
        if moved is None:
            raise HTTPException(
                status_code=409,
                detail="Leave or empty the current organization before accepting",
            )
        user, secrets_to_delete = moved
    else:
        user.role = invite.role
        user.is_active = True
    invite.accepted_at = now
    await _audit(session, user, "tenant.team_invite_accepted", str(invite.id))
    await session.commit()
    for reference, purpose in secrets_to_delete:
        await _delete_secret_best_effort(previous_tenant_id, reference, purpose)
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
    previous_role = member.role
    member.role = patch.role
    await _audit(
        session,
        user,
        "tenant.team_role_updated",
        str(member.id),
        details={"before": previous_role, "after": patch.role},
    )
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


@router.post(
    "/service-accounts",
    response_model=CreatedServiceAccount,
    status_code=status.HTTP_201_CREATED,
)
async def create_service_account(
    payload: ServiceAccountInput,
    user: User = Depends(get_org_owner),
    session: AsyncSession = Depends(get_db),
) -> CreatedServiceAccount:
    account_id = uuid4()
    account = User(
        id=account_id,
        organization_id=_tenant_id(user),
        email=f"{account_id}@{SERVICE_ACCOUNT_EMAIL_DOMAIN}",
        full_name=payload.name,
        role=payload.role,
        kind="service",
        is_active=True,
        is_verified=True,
    )
    session.add(account)
    await session.flush()
    expires_at = datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days)
    plaintext, credential = issue_service_account_key(
        session, account, created_by=user.id, expires_at=expires_at
    )
    await session.flush()
    await _audit(
        session,
        user,
        "tenant.service_account_created",
        str(account.id),
        details={
            "after": {
                "name": payload.name,
                "role": payload.role,
                "expires_at": expires_at.isoformat(),
            }
        },
    )
    await session.commit()
    return await _created_service_account(session, account, credential, plaintext)


@router.get("/service-accounts", response_model=list[ServiceAccountView])
async def list_service_accounts(
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> list[ServiceAccountView]:
    if user.kind == "service":
        raise HTTPException(403, "Service accounts cannot manage service accounts")
    rows = await session.execute(
        select(User, ServiceAccountCredential)
        .join(
            ServiceAccountCredential,
            (ServiceAccountCredential.user_id == User.id)
            & (ServiceAccountCredential.organization_id == User.organization_id)
            & ServiceAccountCredential.revoked_at.is_(None),
        )
        .where(
            User.organization_id == _tenant_id(user),
            User.kind == "service",
            User.is_active.is_(True),
        )
        .order_by(User.created_at, User.id)
    )
    return [_service_account_row(account, credential) for account, credential in rows]


@router.post(
    "/service-accounts/{account_id}/rotate", response_model=CreatedServiceAccount
)
async def rotate_service_account(
    account_id: UUID,
    user: User = Depends(get_org_owner),
    session: AsyncSession = Depends(get_db),
) -> CreatedServiceAccount:
    account = await _owned_service_account(session, user, account_id)
    expires_at = await session.scalar(
        select(func.max(ServiceAccountCredential.expires_at)).where(
            ServiceAccountCredential.user_id == account.id,
            ServiceAccountCredential.revoked_at.is_(None),
        )
    )
    if expires_at is None:
        raise HTTPException(status_code=404, detail="Service account not found")
    await _revoke_service_account_keys(session, account)
    plaintext, credential = issue_service_account_key(
        session, account, created_by=user.id, expires_at=expires_at
    )
    await session.flush()
    await _audit(session, user, "tenant.service_account_rotated", str(account.id))
    await session.commit()
    return await _created_service_account(session, account, credential, plaintext)


@router.delete(
    "/service-accounts/{account_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def delete_service_account(
    account_id: UUID,
    user: User = Depends(get_org_owner),
    session: AsyncSession = Depends(get_db),
) -> None:
    account = await _owned_service_account(session, user, account_id)
    account.is_active = False
    await _revoke_service_account_keys(session, account)
    await session.execute(
        update(ApiKey)
        .where(ApiKey.user_id == account.id, ApiKey.is_active.is_(True))
        .values(is_active=False)
    )
    await _audit(session, user, "tenant.service_account_deleted", str(account.id))
    await session.commit()


@router.get("/teams", response_model=list[TeamView])
async def list_teams(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[Team]:
    statement = select(Team).where(Team.organization_id == _tenant_id(user))
    if user.role not in ORGANIZATION_READERS:
        statement = statement.where(Team.id.in_(member_team_ids(user)))
    return list((await session.scalars(statement.order_by(Team.name, Team.id))).all())


@router.post("/teams", response_model=TeamView, status_code=201)
async def create_team(
    payload: TeamInput,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> Team:
    statement = (
        insert(Team)
        .values(organization_id=_tenant_id(user), **payload.model_dump())
        .on_conflict_do_nothing()
        .returning(Team)
    )
    team = await session.scalar(statement)
    if team is None:
        raise HTTPException(
            status_code=409, detail="A team with this name already exists"
        )
    await _audit(
        session,
        user,
        "tenant.team_created",
        str(team.id),
        details={"after": payload.model_dump(mode="json")},
    )
    await session.commit()
    await session.refresh(team)
    return team


@router.put("/teams/{team_id}", response_model=TeamView)
async def update_team(
    team_id: UUID,
    payload: TeamInput,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> Team:
    team = await require_team(session, user, team_id, administer=True)
    duplicate = await session.scalar(
        select(Team.id).where(
            Team.organization_id == user.organization_id,
            Team.name == payload.name,
            Team.id != team_id,
        )
    )
    if duplicate is not None:
        raise HTTPException(
            status_code=409, detail="A team with this name already exists"
        )
    before = TeamView.model_validate(team).model_dump(mode="json")
    for field, value in payload.model_dump().items():
        setattr(team, field, value)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        if getattr(exc.orig, "sqlstate", None) == "23505":
            raise HTTPException(
                status_code=409, detail="A team with this name already exists"
            ) from exc
        raise
    await _audit(
        session,
        user,
        "tenant.team_policy_updated",
        str(team_id),
        details={"before": before, "after": payload.model_dump(mode="json")},
    )
    await session.commit()
    await session.refresh(team)
    return team


@router.get("/teams/{team_id}/members", response_model=list[MembershipView])
async def list_memberships(
    team_id: UUID,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[TeamMembership]:
    await require_team(session, user, team_id)
    return list(
        (
            await session.scalars(
                select(TeamMembership)
                .where(
                    TeamMembership.organization_id == _tenant_id(user),
                    TeamMembership.team_id == team_id,
                )
                .order_by(TeamMembership.user_id)
            )
        ).all()
    )


@router.put("/teams/{team_id}/members/{member_id}", response_model=MembershipView)
async def set_membership(
    team_id: UUID,
    member_id: UUID,
    payload: MembershipInput,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> TeamMembership:
    await require_team(session, user, team_id, administer=True)
    member = await _owned_member(session, user, member_id)
    existing = await session.scalar(
        select(TeamMembership)
        .where(
            TeamMembership.organization_id == user.organization_id,
            TeamMembership.team_id == team_id,
            TeamMembership.user_id == member_id,
        )
        .with_for_update()
    )
    if existing is not None and existing.source == "oidc":
        raise HTTPException(
            status_code=409, detail="Manage this membership in the identity provider"
        )
    if payload.role == "team_admin" or (
        existing is not None and existing.role == "team_admin"
    ):
        _require_role(user, "owner", "admin")
    statement = insert(TeamMembership).values(
        organization_id=user.organization_id,
        team_id=team_id,
        user_id=member.id,
        role=payload.role,
        source="local",
    )
    membership = await session.scalar(
        statement.on_conflict_do_update(
            index_elements=[
                TeamMembership.organization_id,
                TeamMembership.team_id,
                TeamMembership.user_id,
            ],
            set_={"role": payload.role},
            where=TeamMembership.source == "local",
        ).returning(TeamMembership)
    )
    if membership is None:
        raise HTTPException(
            status_code=409, detail="Membership changed; reload and try again"
        )
    await _audit(
        session,
        user,
        "tenant.team_membership_updated",
        str(team_id) + ":" + str(member_id),
    )
    await session.commit()
    await session.refresh(membership)
    return membership


@router.delete(
    "/teams/{team_id}/members/{member_id}", status_code=204, response_model=None
)
async def remove_membership(
    team_id: UUID,
    member_id: UUID,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> None:
    await require_team(session, user, team_id, administer=True)
    membership = await session.scalar(
        select(TeamMembership)
        .where(
            TeamMembership.organization_id == user.organization_id,
            TeamMembership.team_id == team_id,
            TeamMembership.user_id == member_id,
        )
        .with_for_update()
    )
    if membership is None:
        raise HTTPException(status_code=404, detail="Team membership not found")
    if membership.source == "oidc":
        raise HTTPException(
            status_code=409, detail="Manage this membership in the identity provider"
        )
    if membership.role == "team_admin":
        _require_role(user, "owner", "admin")
    await session.delete(membership)
    await _audit(
        session,
        user,
        "tenant.team_membership_removed",
        str(team_id) + ":" + str(member_id),
    )
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
    if user.role not in ORGANIZATION_READERS:
        statement = statement.where(_own_or_administered_key(user))
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
    _require_role(user, "owner", "admin", "member")
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Verified email required")
    if payload.team_id is not None:
        await require_team(session, user, payload.team_id)
    elif user.role == "member" and await session.scalar(member_team_ids(user).limit(1)):
        raise HTTPException(status_code=403, detail="Choose a team for this API key")
    await require_model_aliases(session, _tenant_id(user), payload.allowed_models)
    plaintext, api_key = await create_tenant_api_key(
        session,
        user_id=user.id,
        name=payload.name,
        cost_center=payload.cost_center,
        team=payload.team,
        team_id=payload.team_id,
        allowed_models=payload.allowed_models,
    )
    await _audit(session, user, "tenant.api_key_created", str(api_key.id))
    await session.commit()
    await session.refresh(api_key)
    return CreatedApiKey(
        **ApiKeyView.model_validate(api_key).model_dump(),
        plaintext=plaintext,
    )


@router.post("/api-keys/{api_key_id}/rotate", response_model=CreatedApiKey)
async def rotate_api_key(
    api_key_id: UUID,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> CreatedApiKey:
    api_key = await _owned_api_key(session, user, api_key_id)
    if not api_key.is_active or (
        api_key.expires_at is not None
        and _aware(api_key.expires_at) <= datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=409, detail="Only active API keys can be rotated"
        )
    plaintext = rotate_tenant_api_key(api_key)
    await _audit(
        session,
        user,
        "tenant.api_key_rotated",
        str(api_key.id),
        details={"rotation_policy": "immediate"},
    )
    await session.commit()
    await session.refresh(api_key)
    return CreatedApiKey(
        **ApiKeyView.model_validate(api_key).model_dump(), plaintext=plaintext
    )


@router.patch("/api-keys/{api_key_id}", response_model=ApiKeyView)
async def update_api_key(
    api_key_id: UUID,
    patch: ApiKeyPatch,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> ApiKey:
    api_key = await _owned_api_key(session, user, api_key_id)
    if {"team_id", "allowed_models"} & patch.model_fields_set:
        if api_key.team_id is None:
            _require_role(user, "owner", "admin")
        else:
            await require_team(session, user, api_key.team_id, administer=True)
    if "team_id" in patch.model_fields_set and patch.team_id != api_key.team_id:
        _require_role(user, "owner", "admin")
        if patch.team_id is not None:
            await require_team(session, user, patch.team_id, administer=True)
    if "allowed_models" in patch.model_fields_set:
        await require_model_aliases(session, _tenant_id(user), patch.allowed_models)
    changes = patch.model_dump(exclude_unset=True)
    before = {field: getattr(api_key, field) for field in changes}
    for field, value in changes.items():
        setattr(api_key, field, value)
    await _audit(
        session,
        user,
        "tenant.api_key_updated",
        str(api_key.id),
        details=change_details(before, changes),
    )
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
        await _audit(
            session,
            user,
            "tenant.provider_secret_created",
            str(row.id),
            details=_provider_secret_details(row),
        )
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
    before = _provider_secret_details(row)
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
        await _audit(
            session,
            user,
            "tenant.provider_secret_updated",
            str(row.id),
            details={
                **change_details(before, _provider_secret_details(row)),
                "key_rotated": patch.key is not None,
            },
        )
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
        await _audit(
            session,
            user,
            "tenant.provider_secret_rejected",
            str(row.id),
            details=_provider_secret_details(row),
        )
        await session.commit()
        raise HTTPException(status_code=400, detail="Provider rejected the credential")
    if response.status_code != 200:
        raise HTTPException(status_code=503, detail="Provider verification unavailable")
    row.verified_at = datetime.now(timezone.utc)
    await _audit(
        session,
        user,
        "tenant.provider_secret_verified",
        str(row.id),
        details=_provider_secret_details(row),
    )
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
    details = _provider_secret_details(row)
    await session.delete(row)
    await _audit(
        session, user, "tenant.provider_secret_deleted", str(row.id), details=details
    )
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
    before = PrivacySettings.model_validate(row).model_dump()
    for field, value in patch.model_dump(exclude_unset=True).items():
        setattr(row, field, value)
    after = PrivacySettings.model_validate(row).model_dump()
    await _audit(
        session,
        user,
        "tenant.privacy_policy_updated",
        str(tenant_id),
        details=change_details(
            {field: before[field] for field in PrivacySettings.model_fields},
            {field: after[field] for field in PrivacySettings.model_fields},
        ),
    )
    relaxed = [
        field for field in PII_CONFIG_DEFAULTS if before[field] and not after[field]
    ]
    if before["placeholder_mode"] == "random" and after["placeholder_mode"] == "stable":
        relaxed.append("placeholder_mode")
    if before["bulk_threshold"] is not None and (
        after["bulk_threshold"] is None
        or after["bulk_threshold"] > before["bulk_threshold"]
    ):
        relaxed.append("bulk_threshold")
    if before["response_scan"] == "count" and after["response_scan"] == "off":
        relaxed.append("response_scan")
    relaxed += [
        f"entity_actions.{entity_type}"
        for entity_type, action in after["effective_actions"].items()
        if get_args(EntityAction).index(action)
        < get_args(EntityAction).index(before["effective_actions"][entity_type])
        and before["entity_actions"].get(entity_type)
        != after["entity_actions"].get(entity_type)
    ]
    if relaxed:
        event_id = await _audit(
            session,
            user,
            "tenant.privacy_protection_relaxed",
            str(tenant_id),
            details={"relaxed": relaxed},
        )
        await ComplianceForwarderService().send_privacy_protection_relaxed(
            session,
            TenantId(tenant_id),
            fields=relaxed,
            actor=str(user.id),
            actor_email=user.email,
            event_id=event_id,
        )
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


@router.get("/settings/provider-keys", response_model=ProviderKeySettings)
async def get_provider_key_settings(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> Any:
    tenant = await session.get(Organization, _tenant_id(user))
    if tenant is None:
        raise HTTPException(status_code=403, detail="Tenant does not exist")
    return tenant


@router.put("/settings/provider-keys", response_model=ProviderKeySettings)
async def update_provider_key_settings(
    payload: ProviderKeySettings,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> Any:
    tenant = await session.get(Organization, _tenant_id(user), with_for_update=True)
    if tenant is None:
        raise HTTPException(status_code=403, detail="Tenant does not exist")
    before = {"allow_customer_provider_keys": tenant.allow_customer_provider_keys}
    tenant.allow_customer_provider_keys = payload.allow_customer_provider_keys
    await _audit(
        session,
        user,
        "tenant.provider_key_policy_updated",
        str(tenant.id),
        details=change_details(before, payload.model_dump()),
    )
    await session.commit()
    return tenant


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
    user: User = Depends(get_org_reader),
    session: AsyncSession = Depends(get_db),
) -> list[BudgetView]:
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
    return await _budget_views(session, budgets)


@router.post("/cost/budgets", response_model=BudgetView)
async def create_budget(
    payload: BudgetInput,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> BudgetView:
    if payload.scope_type == "team_id":
        try:
            team_id = UUID(payload.scope_value or "")
        except ValueError:
            team_id = None
        if team_id is None or not await session.scalar(
            select(Team.id).where(
                Team.id == team_id, Team.organization_id == _tenant_id(user)
            )
        ):
            raise HTTPException(status_code=422, detail="Unknown team")
        payload.scope_value = str(team_id)
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
        await _audit(
            session,
            user,
            "tenant.budget_created",
            str(row.id),
            details=change_details(None, _budget_facts(row)),
        )
        await session.commit()
    except BaseException:
        await session.rollback()
        await _delete_budget_targets(_tenant_id(user), stored_targets)
        raise
    await session.refresh(row)
    return (await _budget_views(session, [row]))[0]


@router.patch("/cost/budgets/{budget_id}", response_model=BudgetView)
async def update_budget(
    budget_id: UUID,
    patch: BudgetPatch,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> BudgetView:
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
    before = _budget_facts(row)
    for field, value in values.items():
        setattr(row, field, value)
    try:
        if replacement_targets is not None:
            await _cancel_budget_deliveries(session, _tenant_id(user), row.id)
        await _audit(
            session,
            user,
            "tenant.budget_updated",
            str(row.id),
            details=change_details(before, _budget_facts(row)),
        )
        await session.commit()
    except BaseException:
        await session.rollback()
        if replacement_targets is not None:
            await _delete_budget_targets(_tenant_id(user), replacement_targets)
        raise
    if replacement_targets is not None:
        await _delete_budget_targets(_tenant_id(user), previous_targets)
    await session.refresh(row)
    return (await _budget_views(session, [row]))[0]


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
    details = change_details(_budget_facts(row), None)
    await session.delete(row)
    await _audit(session, user, "tenant.budget_deleted", str(row.id), details=details)
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
    await _audit(
        session,
        user,
        "tenant.budgets_evaluated",
        str(_tenant_id(user)),
        details={"budgets_evaluated": len(results)},
    )
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
    user: User = Depends(get_org_reader),
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
    warning: Annotated[
        ResponseWarning | None,
        Query(description="Only requests that carried this warning code."),
    ] = None,
    system_prompt_hash: Annotated[
        str | None, Query(pattern=_SYSTEM_PROMPT_HASH_PATTERN)
    ] = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> RequestActivityPage:
    generated_at = datetime.now(timezone.utc)
    tenant_id = _tenant_id(user)
    filters = _request_filters(
        user,
        start=start,
        end=end,
        status_filter=status_filter,
        model=model,
        request_id=request_id,
        pii_detected=pii_detected,
        tag=tag,
        cost_center=cost_center,
        warning=warning,
        system_prompt_hash=system_prompt_hash,
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
                cost_usd=Decimal(str(cost_usd)) if cost_usd is not None else None,
                cost_complete=cost_usd is not None,
                pii_detected=row.pii_detected,
                tags=list(row.tags or []),
                cost_center=row.cost_center,
                provider=_request_provider(row),
                team=row.team,
                **{
                    field: (row.details or {}).get(field)
                    for field in (
                        "provider_finish_reasons",
                        "completion_outcome",
                        "repeat_chain_length",
                        "ttft_ms",
                        "cached_input_tokens",
                        "warnings",
                        "shim_latency_ms",
                        "system_prompt_hash",
                        "deployment_kind",
                        "pii_entities",
                        "monitored_entities",
                        "blocked_entities",
                        "bulk_disclosure",
                    )
                },
                response_entities=response_entities,
            )
            for row, cost_usd, response_entities in rows
        ],
        total=summary.requests,
        limit=limit,
        offset=offset,
    )


@router.get("/prompt-versions", response_model=PromptVersionPage)
async def list_prompt_versions(
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    api_key_id: UUID | None = Query(default=None),
    model: str | None = Query(
        default=None,
        min_length=1,
        max_length=255,
        description="Case-insensitive model substring.",
    ),
    user: User = Depends(get_org_reader),
    session: AsyncSession = Depends(get_db),
) -> PromptVersionPage:
    end_at = _aware(end or datetime.now(timezone.utc))
    start_at = _aware(start or end_at - timedelta(days=7))
    _validate_sync_window(start_at, end_at)
    metadata = RequestLifecycle.lifecycle_metadata
    prompt_hash = metadata["system_prompt_hash"].as_string()
    outcome = metadata["completion_outcome"].as_string()
    filters = [
        RequestLifecycle.organization_id == _tenant_id(user),
        RequestLifecycle.started_at >= start_at,
        RequestLifecycle.started_at <= end_at,
        RequestLifecycle.source_endpoint != "scan",
    ]
    if api_key_id is not None:
        filters.append(RequestLifecycle.api_key_id == api_key_id)
    if model is not None:
        filters.append(
            RequestLifecycle.requested_model.icontains(model, autoescape=True)
        )
    first_seen = func.min(RequestLifecycle.started_at)
    rows = (
        await session.execute(
            select(
                prompt_hash.label("system_prompt_hash"),
                first_seen.label("first_seen"),
                func.max(RequestLifecycle.started_at).label("last_seen"),
                func.count().label("requests"),
                func.array_agg(distinct(RequestLifecycle.api_key_id)).label("api_keys"),
                func.array_agg(distinct(RequestLifecycle.requested_model)).label(
                    "models"
                ),
                *(
                    func.count().filter(outcome == name).label(name)
                    for name in _COMPLETION_OUTCOMES
                ),
                func.count()
                .filter(RequestLifecycle.status.in_(_TECHNICAL_FAILURES))
                .label("failed"),
                func.percentile_cont(0.95)
                .within_group(metadata["shim_latency_ms"].as_integer())
                .filter(RequestLifecycle.status == "completed")
                .label("p95"),
            )
            .where(*filters)
            .group_by(prompt_hash)
            .order_by(first_seen.desc())
            .limit(_MAX_PROMPT_VERSIONS + 1)
        )
    ).all()
    return PromptVersionPage(
        period=BillingPeriodView(start=start_at, end=end_at),
        items=[
            PromptVersionView(
                system_prompt_hash=row.system_prompt_hash,
                first_seen=row.first_seen,
                last_seen=row.last_seen,
                requests=row.requests,
                api_keys=[key for key in row.api_keys if key is not None][:10],
                models=row.models[:10],
                outcomes=PromptVersionOutcomes(
                    **{name: getattr(row, name) for name in _COMPLETION_OUTCOMES}
                ),
                failed=row.failed,
                p95_shim_latency_ms=round(row.p95) if row.p95 is not None else None,
            )
            for row in rows[:_MAX_PROMPT_VERSIONS]
        ],
        truncated=len(rows) > _MAX_PROMPT_VERSIONS,
    )


def _finding_filters(
    user: User,
    status_filter: FindingStatus | None,
    rule_id: str | None,
    severity_id: int | None,
) -> list[Any]:
    filters = [Finding.organization_id == _tenant_id(user)]
    if status_filter is not None:
        filters.append(Finding.status_id == STATUS_IDS[status_filter])
    if rule_id is not None:
        filters.append(Finding.rule_id == rule_id)
    if severity_id is not None:
        filters.append(Finding.severity_id == severity_id)
    return filters


@router.get("/findings", response_model=FindingPage)
async def list_findings(
    status_filter: FindingStatus | None = Query(default=None, alias="status"),
    rule_id: str | None = Query(default=None, min_length=1, max_length=64),
    severity_id: int | None = Query(default=None, ge=1, le=5),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(get_org_reader),
    session: AsyncSession = Depends(get_db),
) -> FindingPage:
    filters = _finding_filters(user, status_filter, rule_id, severity_id)
    total = await session.scalar(select(func.count(Finding.id)).where(*filters))
    rows = await session.scalars(
        select(Finding)
        .where(*filters)
        .order_by(Finding.last_seen_at.desc(), Finding.id)
        .limit(limit)
        .offset(offset)
    )
    return FindingPage(
        items=[FindingView.model_validate(row) for row in rows],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/findings/export",
    response_class=StreamingResponse,
    responses={
        200: {
            "content": {"application/x-ndjson": {}},
            "description": "One OCSF Detection Finding per line.",
        }
    },
)
async def export_findings(
    status_filter: FindingStatus | None = Query(default=None, alias="status"),
    rule_id: str | None = Query(default=None, min_length=1, max_length=64),
    severity_id: int | None = Query(default=None, ge=1, le=5),
    user: User = Depends(get_org_reader),
    session: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    rows = (
        await session.scalars(
            select(Finding)
            .where(*_finding_filters(user, status_filter, rule_id, severity_id))
            .order_by(Finding.last_seen_at.desc(), Finding.id)
            .limit(_MAX_SYNC_REQUEST_EXPORT_ROWS + 1)
        )
    ).all()
    if len(rows) > _MAX_SYNC_REQUEST_EXPORT_ROWS:
        raise HTTPException(
            status_code=422,
            detail=(
                "synchronous finding exports are limited to "
                f"{_MAX_SYNC_REQUEST_EXPORT_ROWS} rows"
            ),
        )
    body = "".join(
        json.dumps(ocsf_detection_finding(row), separators=(",", ":")) + "\n"
        for row in rows
    )
    return StreamingResponse(iter([body]), media_type="application/x-ndjson")


@router.get("/findings/{finding_id}", response_model=FindingView)
async def get_finding(
    finding_id: UUID,
    user: User = Depends(get_org_reader),
    session: AsyncSession = Depends(get_db),
) -> FindingView:
    return FindingView.model_validate(
        await _owned_finding(session, user, finding_id, lock=False)
    )


@router.patch("/findings/{finding_id}", response_model=FindingView)
async def update_finding(
    finding_id: UUID,
    patch: FindingPatch,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> FindingView:
    finding = await _owned_finding(session, user, finding_id, lock=True)
    before = _FINDING_STATUSES[finding.status_id]
    target = STATUS_IDS[patch.status]
    if finding.status_id == STATUS_RESOLVED and target != STATUS_RESOLVED:
        if await session.scalar(
            select(Finding.id).where(
                Finding.organization_id == finding.organization_id,
                Finding.rule_id == finding.rule_id,
                Finding.subject_key == finding.subject_key,
                Finding.status_id != STATUS_RESOLVED,
            )
        ):
            raise HTTPException(
                status_code=409,
                detail="Another open finding exists for this subject",
            )
    if target != finding.status_id:
        finding.status_id = target
        resolved = target == STATUS_RESOLVED
        finding.resolved_at = datetime.now(timezone.utc) if resolved else None
        finding.resolved_by = str(user.id) if resolved else None
        await _audit(
            session,
            user,
            "tenant.finding_status_changed",
            str(finding.id),
            details={
                "rule_id": finding.rule_id,
                **change_details({"status": before}, {"status": patch.status}),
            },
        )
        await session.commit()
        await session.refresh(finding)
    return FindingView.model_validate(finding)


async def _owned_finding(
    session: AsyncSession, user: User, finding_id: UUID, *, lock: bool
) -> Finding:
    statement = select(Finding).where(
        Finding.id == finding_id, Finding.organization_id == _tenant_id(user)
    )
    finding = await session.scalar(
        statement.with_for_update(of=Finding) if lock else statement
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


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
    warning: Annotated[
        ResponseWarning | None,
        Query(description="Only requests that carried this warning code."),
    ] = None,
    system_prompt_hash: Annotated[
        str | None, Query(pattern=_SYSTEM_PROMPT_HASH_PATTERN)
    ] = None,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    tenant_id = _tenant_id(user)
    end_at = _aware(end or datetime.now(timezone.utc))
    start_at = _aware(start or end_at - timedelta(days=30))
    _validate_sync_window(start_at, end_at)
    filters = _request_filters(
        user,
        start=start_at,
        end=end_at,
        status_filter=status_filter,
        model=model,
        request_id=request_id,
        pii_detected=pii_detected,
        tag=tag,
        cost_center=cost_center,
        warning=warning,
        system_prompt_hash=system_prompt_hash,
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

    # Buffered, not session.stream(): server-side cursors break on the
    # statement_cache_size=0 engine (core/database.py). The cap bounds memory.
    rows = (
        await session.execute(rows_statement.limit(_MAX_SYNC_REQUEST_EXPORT_ROWS))
    ).all()
    # Recorded after the rows are read, so the export never contains its own event.
    await _audit(
        session,
        user,
        "tenant.requests_exported",
        str(tenant_id),
        details=export_details(start_at, end_at, rows=len(rows)),
    )
    await session.commit()

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
                "shim_latency_ms",
                "pii_detected",
                "tags",
                "cost_center",
                "team",
                "provider_finish_reasons",
                "completion_outcome",
                "repeat_chain_length",
                "ttft_ms",
                "cached_input_tokens",
                "warnings",
                "system_prompt_hash",
                "deployment_kind",
                "cost_complete",
                "pii_entities",
                "monitored_entities",
                "blocked_entities",
                "bulk_disclosure",
                "response_entities",
            )
        )
        yield output.getvalue().encode("utf-8-sig")
        for row, cost_usd, response_entities in rows:
            details = row.details or {}
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
                    Decimal(str(cost_usd)) if cost_usd is not None else None,
                    details.get("shim_latency_ms"),
                    row.pii_detected,
                    ",".join(row.tags or []),
                    row.cost_center,
                    row.team,
                    (
                        json.dumps(details["provider_finish_reasons"], sort_keys=True)
                        if details.get("provider_finish_reasons") is not None
                        else None
                    ),
                    details.get("completion_outcome"),
                    details.get("repeat_chain_length"),
                    details.get("ttft_ms"),
                    details.get("cached_input_tokens"),
                    ",".join(details.get("warnings") or []),
                    details.get("system_prompt_hash"),
                    details.get("deployment_kind"),
                    cost_usd is not None,
                    *(
                        json.dumps(details[field], sort_keys=True)
                        if details.get(field) is not None
                        else None
                        for field in (
                            "pii_entities",
                            "monitored_entities",
                            "blocked_entities",
                            "bulk_disclosure",
                        )
                    ),
                    json.dumps(response_entities, sort_keys=True)
                    if response_entities is not None
                    else None,
                )
            )
            yield output.getvalue().encode("utf-8")

    return StreamingResponse(
        content(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="shim_requests.csv"'},
    )


@router.get("/usage/mine", response_model=MyUsageView)
async def my_usage(
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> MyUsageView:
    end_at = _aware(end or datetime.now(timezone.utc))
    start_at = _aware(
        start or end_at.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    )
    _validate_sync_window(start_at, end_at)
    keys = {
        key_id: (name, prefix)
        for key_id, name, prefix in await session.execute(
            select(ApiKey.id, ApiKey.name, ApiKey.prefix).where(
                ApiKey.organization_id == _tenant_id(user),
                _own_or_administered_key(user),
            )
        )
    }
    read_models = BillingReadModels()
    window = {
        "tenant_id": TenantId(_tenant_id(user)),
        "start_at": start_at,
        "end_at": end_at,
        "api_key_ids": list(keys),
    }
    daily = await read_models.daily_usage(session, **window)
    if len(daily) > MAX_BILLING_DAILY_ROWS:
        raise HTTPException(
            status_code=422,
            detail=f"synchronous usage is limited to {MAX_BILLING_DAILY_ROWS} rows",
        )
    by_model = await read_models.breakdown(
        session, **window, group_by="model", limit=None
    )
    by_key = await read_models.breakdown(
        session, **window, group_by="api_key_id", limit=None
    )
    return MyUsageView(
        period=BillingPeriodView(start=start_at, end=end_at),
        totals=UsageTotalsView(**_usage_totals(by_model)),
        daily=[
            UsageDayView(date=day, **_usage_totals(list(rows)))
            for day, rows in itertools.groupby(daily, key=lambda row: row.usage_date)
        ],
        by_model=[
            UsageModelView(model=row.key, **_usage_totals([row])) for row in by_model
        ],
        by_api_key=[
            UsageKeyView(
                api_key_id=UUID(row.key),
                name=keys[UUID(row.key)][0],
                prefix=keys[UUID(row.key)][1],
                **_usage_totals([row]),
            )
            for row in by_key
        ],
    )


def _usage_totals(rows: Sequence[BillingBreakdown | DailyUsage]) -> dict[str, Any]:
    unpriced = sum(row.unpriced_requests for row in rows)
    return {
        "requests": sum(row.request_count for row in rows),
        "input_tokens": sum(row.prompt_tokens for row in rows),
        "output_tokens": sum(row.completion_tokens for row in rows),
        "cost_usd": None
        if unpriced
        else sum((row.cost_usd for row in rows), Decimal()),
        "cost_complete": not unpriced,
        "unpriced_requests": unpriced,
    }


@router.get("/billing/usage", response_model=BillingUsageView)
async def billing_usage(
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    user: User = Depends(get_org_reader),
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
    unpriced_requests = sum(record.unpriced_requests for record in records)
    return BillingUsageView(
        period=BillingPeriodView(start=start, end=end),
        daily_usage=[DailyUsageView.model_validate(row) for row in rows],
        total_cost=None
        if unpriced_requests
        else sum(float(record.cost_usd) for record in records),
        unpriced_requests=unpriced_requests,
        cost_complete=not unpriced_requests,
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
    user: User = Depends(get_org_reader),
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
    labels = await _team_labels(session, user, group_by)
    return BillingBreakdownView(
        period=BillingPeriodView(start=start, end=end),
        group_by=group_by,
        rows=[
            BillingBreakdownRow.model_validate(
                record.as_public_record() | {"label": labels.get(record.key)}
            )
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
    user: User = Depends(get_org_reader),
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
    labels = await _team_labels(session, user, group_by)
    await _audit(
        session,
        user,
        "tenant.billing_exported",
        str(_tenant_id(user)),
        details=export_details(
            start, end, rows=len(records), group_by=group_by, format=format
        ),
    )
    await session.commit()
    content = (
        _billing_breakdown_csv(records, labels)
        if format == "csv"
        else await asyncio.to_thread(
            _billing_breakdown_pdf, records, labels, group_by, start, end
        )
    )
    return Response(
        content,
        media_type="text/csv" if format == "csv" else "application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="shim_billing_{group_by}.{format}"'
        },
    )


def _budget_facts(row: CostBudget) -> dict[str, Any]:
    return {
        "scope_type": row.scope_type,
        "scope_value": row.scope_value,
        "period": row.period,
        "limit_usd": row.limit_usd,
        "limit_tokens": row.limit_tokens,
        "alert_thresholds": list(row.alert_thresholds),
        "enabled": row.enabled,
        "notify_targets": [
            {"kind": target["kind"], "endpoint_origin": target["endpoint_origin"]}
            for target in row.notify_targets or []
        ],
    }


def _provider_secret_details(
    row: ProviderSecret, *, key_rotated: bool = False
) -> dict[str, object]:
    return {
        "provider": row.provider,
        "name": row.name,
        "monthly_limit_usd": (
            str(row.monthly_limit_usd) if row.monthly_limit_usd is not None else None
        ),
        "key_rotated": key_rotated,
    }


def _own_or_administered_key(user: User) -> Any:
    return or_(
        ApiKey.user_id == user.id,
        ApiKey.team_id.in_(member_team_ids(user, administer=True)),
    )


def _request_filters(
    user: User,
    *,
    start: datetime | None,
    end: datetime | None,
    status_filter: RequestActivityStatus | None,
    model: str | None,
    request_id: str | None,
    pii_detected: bool | None,
    tag: str | None,
    cost_center: str | None,
    warning: ResponseWarning | None = None,
    system_prompt_hash: str | None = None,
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
    tenant_id = _tenant_id(user)
    filters = [RequestLog.organization_id == tenant_id]
    if user.role not in ORGANIZATION_READERS:
        filters.append(
            RequestLog.api_key_id.in_(
                select(ApiKey.id).where(
                    ApiKey.organization_id == tenant_id,
                    _own_or_administered_key(user),
                )
            )
        )
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
    if system_prompt_hash is not None:
        filters.append(
            RequestLog.details["system_prompt_hash"].as_string() == system_prompt_hash
        )
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
    if warning is not None:
        filters.append(RequestLog.details.contains({"warnings": [warning]}))
    return filters


def _request_settled_spend(tenant_id: UUID):
    return (
        select(func.sum(UsageLedger.cost_usd))
        .where(
            UsageLedger.organization_id == tenant_id,
            UsageLedger.request_id == RequestLog.request_id,
            UsageLedger.event_type == "spend_settlement",
            UsageLedger.event_metadata["pricing"]["pricing_resolution"]
            .as_string()
            .is_distinct_from("unknown"),
        )
        .correlate(RequestLog)
        .scalar_subquery()
    )


def _request_unpriced_spend(tenant_id: UUID):
    return (
        select(UsageLedger.id)
        .where(
            UsageLedger.organization_id == tenant_id,
            UsageLedger.request_id == RequestLog.request_id,
            UsageLedger.event_type == "spend_settlement",
            UsageLedger.event_metadata["pricing"]["pricing_resolution"].as_string()
            == "unknown",
        )
        .correlate(RequestLog)
        .exists()
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
            AuditIntent.usage_summary["spend_denied"].as_integer() == 1,
        )
        .correlate(RequestLog)
        .exists()
    )
    return (
        select(
            func.count(RequestLog.id).label("requests"),
            func.count(RequestLog.id)
            .filter(_request_unpriced_spend(tenant_id))
            .label("unpriced_requests"),
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
            .within_group(RequestLog.details["shim_latency_ms"].as_integer())
            .filter(lifecycle_status == "completed")
            .label("p95_completed_shim_latency_ms"),
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
    p95 = row.p95_completed_shim_latency_ms
    return RequestActivitySummaryView(
        requests=int(row.requests or 0),
        technical_success_rate=(
            status_counts["completed"] / technical_requests
            if technical_requests
            else None
        ),
        p95_completed_shim_latency_ms=round(float(p95)) if p95 is not None else None,
        settled_spend_usd=Decimal(str(row.settled_spend_usd or 0)),
        cost_complete=not row.unpriced_requests,
        unpriced_requests=int(row.unpriced_requests or 0),
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
            case(
                (_request_unpriced_spend(tenant_id), None),
                else_=func.coalesce(spend, Decimal("0")),
            ).label("cost_usd"),
            # The response scan finishes after the analytics row is projected.
            RequestLifecycle.lifecycle_metadata["response_entities"].label(
                "response_entities"
            ),
        )
        .outerjoin(
            RequestLifecycle,
            (RequestLifecycle.organization_id == RequestLog.organization_id)
            & (RequestLifecycle.request_id == RequestLog.request_id),
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


async def _team_labels(
    session: AsyncSession, user: User, group_by: BillingBreakdownGroup
) -> dict[str, str]:
    if group_by != "team_id":
        return {}
    rows = await session.execute(
        select(Team.id, Team.name).where(Team.organization_id == _tenant_id(user))
    )
    return {str(team_id): name for team_id, name in rows}


def _billing_breakdown_csv(records: list[Any], labels: dict[str, str]) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        (
            "key",
            "request_count",
            "prompt_tokens",
            "completion_tokens",
            "cost_usd",
            "unpriced_requests",
            "cost_complete",
            "label",
        )
    )
    for record in records:
        writer.writerow(
            _safe_csv(value)
            for value in (
                record.key,
                record.request_count,
                record.prompt_tokens,
                record.completion_tokens,
                None if record.unpriced_requests else record.cost_usd,
                record.unpriced_requests,
                record.unpriced_requests == 0,
                labels.get(record.key),
            )
        )
    return output.getvalue().encode("utf-8-sig")


def _billing_breakdown_pdf(
    records: list[Any],
    labels: dict[str, str],
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
                        labels.get(record.key, record.key),
                        str(record.request_count),
                        str(record.prompt_tokens + record.completion_tokens),
                        str(record.cost_usd)
                        if record.unpriced_requests == 0
                        else f"Unknown ({record.unpriced_requests} unpriced)",
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
        role=cast(Literal["owner", "admin", "member", "auditor"], user.role),
        is_active=user.is_active,
        is_verified=user.is_verified,
        created_at=user.created_at,
    )


async def _owned_api_key(
    session: AsyncSession,
    user: User,
    api_key_id: UUID,
) -> ApiKey:
    _require_role(user, "owner", "admin", "member")
    await session.scalar(
        select(Organization.id)
        .where(Organization.id == _tenant_id(user))
        .with_for_update()
    )
    statement = (
        select(ApiKey)
        .where(
            ApiKey.id == api_key_id,
            ApiKey.organization_id == _tenant_id(user),
        )
        .with_for_update()
    )
    if user.role not in {"owner", "admin"}:
        statement = statement.where(
            or_(
                (ApiKey.user_id == user.id)
                & (
                    ApiKey.team_id.is_(None) | ApiKey.team_id.in_(member_team_ids(user))
                ),
                ApiKey.team_id.in_(member_team_ids(user, administer=True)),
            )
        )
    row = (await session.execute(statement)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="API key not found")
    return row


async def _owned_service_account(
    session: AsyncSession, user: User, account_id: UUID
) -> User:
    account = await session.scalar(
        select(User)
        .where(
            User.id == account_id,
            User.organization_id == _tenant_id(user),
            User.kind == "service",
            User.is_active.is_(True),
        )
        .with_for_update(of=User)
    )
    if account is None:
        raise HTTPException(status_code=404, detail="Service account not found")
    return account


async def _revoke_service_account_keys(session: AsyncSession, account: User) -> None:
    await session.execute(
        update(ServiceAccountCredential)
        .where(
            ServiceAccountCredential.user_id == account.id,
            ServiceAccountCredential.revoked_at.is_(None),
        )
        .values(revoked_at=datetime.now(timezone.utc))
    )


async def _created_service_account(
    session: AsyncSession,
    account: User,
    credential: ServiceAccountCredential,
    plaintext: str,
) -> CreatedServiceAccount:
    await session.refresh(credential)
    return CreatedServiceAccount(
        **_service_account_row(account, credential).model_dump(), plaintext=plaintext
    )


def _service_account_row(
    account: User, credential: ServiceAccountCredential
) -> ServiceAccountView:
    return ServiceAccountView(
        id=account.id,
        name=account.full_name,
        role=cast(Literal["admin", "auditor"], account.role),
        prefix=credential.prefix,
        expires_at=credential.expires_at,
        last_used_at=credential.last_used_at,
        created_by=credential.created_by,
        created_at=credential.created_at,
    )


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
                User.kind == "human",
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
    current_plan, features = (
        await session.execute(
            select(Organization.tier, TierDefinition.features)
            .outerjoin(TierDefinition, Organization.tier == TierDefinition.slug)
            .where(Organization.id == tenant_id)
        )
    ).one()
    if isinstance(features, dict) and features.get(feature) is True:
        return
    eligible_plans = await session.scalars(
        select(TierDefinition.slug)
        .where(TierDefinition.features.contains({feature: True}))
        .order_by(TierDefinition.slug)
    )
    raise HTTPException(
        status_code=403,
        detail={
            "code": "PLAN_UPGRADE_REQUIRED",
            "feature": feature,
            "current_plan": current_plan,
            "eligible_plans": list(eligible_plans),
            "message": "This feature needs one of the plans listed in eligible_plans.",
        },
    )


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


async def _budget_views(
    session: AsyncSession, budgets: list[CostBudget]
) -> list[BudgetView]:
    team_ids = {
        UUID(budget.scope_value)
        for budget in budgets
        if budget.scope_type == "team_id" and budget.scope_value
    }
    names = (
        {
            str(team_id): name
            for team_id, name in await session.execute(
                select(Team.id, Team.name).where(
                    Team.organization_id == budgets[0].organization_id,
                    Team.id.in_(team_ids),
                )
            )
        }
        if team_ids
        else {}
    )
    return [
        BudgetView.model_validate(budget).model_copy(
            update={
                "scope_label": names.get(budget.scope_value or "")
                if budget.scope_type == "team_id"
                else None
            }
        )
        for budget in budgets
    ]


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
            entry = {
                "kind": target.kind,
                "endpoint_origin": _endpoint_origin(target.endpoint),
                "secret_ref": str(reference),
            }
            stored.append(entry)
            if target.secret is not None:
                entry["signing_secret_ref"] = str(
                    await store.put_secret(
                        TenantId(tenant_id),
                        "budget-alert-signing",
                        target.secret,
                        {"kind": target.kind},
                    )
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
        for field, purpose in (
            ("secret_ref", "budget-alert-endpoint"),
            ("signing_secret_ref", "budget-alert-signing"),
        ):
            reference = target.get(field)
            if reference is not None:
                await _delete_secret_best_effort(
                    tenant_id, SecretRef(reference), purpose
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


class ModelDeploymentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alias: str = Field(
        min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$"
    )
    provider: Literal["openai", "anthropic"]
    upstream_model: str = Field(min_length=1, max_length=200)
    base_url: str = Field(min_length=1, max_length=2048)
    provider_secret_id: UUID
    timeout_seconds: int = Field(default=60, ge=1, le=300)
    deployment_kind: Literal["internal", "external"]
    declared_version: str = Field(min_length=1, max_length=200)
    owner: str = Field(min_length=1, max_length=200)
    enabled: bool = True
    input_price_per_million: Decimal | None = Field(
        default=None,
        ge=0,
        max_digits=18,
        decimal_places=8,
        description="USD per million input tokens; set both prices or neither.",
    )
    output_price_per_million: Decimal | None = Field(
        default=None,
        ge=0,
        max_digits=18,
        decimal_places=8,
        description="USD per million output tokens; set both prices or neither.",
    )
    context_window: int | None = Field(
        default=None,
        ge=1,
        description="Tokens the served model accepts; a request that certainly exceeds it is refused.",
    )

    @model_validator(mode="after")
    def price_pair(self) -> ModelDeploymentInput:
        if (self.input_price_per_million is None) != (
            self.output_price_per_million is None
        ):
            raise ValueError("Set both input and output prices, or neither")
        return self

    @field_validator("upstream_model", "declared_version", "owner")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("Value must be nonblank without surrounding whitespace")
        return value

    @field_validator("base_url")
    @classmethod
    def approved_destination(cls, value: str) -> str:
        return validate_deployment_url(value)


class ModelDeploymentView(ModelDeploymentInput):
    model_config = ConfigDict(from_attributes=True)

    @field_validator("base_url")
    @classmethod
    def approved_destination(cls, value: str) -> str:
        # Operators must still be able to inspect a now-disallowed deployment.
        return value

    id: UUID
    health: Literal["unknown", "healthy", "unhealthy"]
    health_checked_at: datetime | None
    created_at: datetime
    updated_at: datetime


@router.get("/model-deployments", response_model=list[ModelDeploymentView])
async def list_model_deployments(
    user: User = Depends(get_org_reader),
    session: AsyncSession = Depends(get_db),
):
    return (
        (
            await session.execute(
                select(ModelDeployment)
                .where(
                    ModelDeployment.organization_id == _tenant_id(user),
                )
                .order_by(ModelDeployment.alias)
            )
        )
        .scalars()
        .all()
    )


@router.post("/model-deployments", response_model=ModelDeploymentView, status_code=201)
async def create_model_deployment(
    payload: ModelDeploymentInput,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
):
    secret = await _owned_provider_secret(session, user, payload.provider_secret_id)
    if secret.provider != payload.provider:
        raise HTTPException(422, detail="Credential provider does not match deployment")
    row = ModelDeployment(organization_id=_tenant_id(user), **payload.model_dump())
    session.add(row)
    try:
        await session.flush()
        await _audit(
            session,
            user,
            "tenant.model_deployment_created",
            str(row.id),
            details={"configuration": payload.model_dump(mode="json")},
        )
        await session.commit()
    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            409, detail="Model alias already exists or credential is unavailable"
        ) from None
    await session.refresh(row)
    return row


@router.put("/model-deployments/{deployment_id}", response_model=ModelDeploymentView)
async def update_model_deployment(
    deployment_id: UUID,
    payload: ModelDeploymentInput,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
):
    # Locked, like the health result, so neither write can overwrite the other.
    row = await _owned_model_deployment(session, user, deployment_id, for_update=True)
    secret = await _owned_provider_secret(session, user, payload.provider_secret_id)
    if secret.provider != payload.provider:
        raise HTTPException(422, detail="Credential provider does not match deployment")
    configuration = payload.model_dump()
    before = {field: getattr(row, field) for field in configuration}
    for field, value in configuration.items():
        setattr(row, field, value)
    row.health, row.health_checked_at = "unknown", None
    try:
        await _audit(
            session,
            user,
            "tenant.model_deployment_updated",
            str(row.id),
            details=change_details(before, configuration),
        )
        await session.commit()
    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            409, detail="Model alias already exists or credential is unavailable"
        ) from None
    await session.refresh(row)
    return row


@router.post(
    "/model-deployments/{deployment_id}/health", response_model=ModelDeploymentView
)
async def check_model_deployment_health(
    deployment_id: UUID,
    request: Request,
    user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
):
    row = await _owned_model_deployment(session, user, deployment_id)
    secret = await _owned_provider_secret(session, user, row.provider_secret_id)
    try:
        base_url = validate_deployment_url(row.base_url)
    except ValueError:
        raise HTTPException(
            503, detail="Deployment origin is no longer approved"
        ) from None
    checked_version = row.updated_at
    secret_ref, provider, tenant_id = secret.secret_ref, row.provider, _tenant_id(user)
    # Finish the read transaction before secret-store or provider I/O.
    await session.commit()
    healthy = False
    try:
        async with asyncio.timeout(5):
            credential = await get_secret_store().get_secret(
                TenantId(tenant_id),
                SecretRef(secret_ref),
                expected_purpose=f"provider:{provider}:api-key",
            )
            headers = (
                {"Authorization": f"Bearer {credential}"}
                if provider == "openai"
                else {"x-api-key": credential, "anthropic-version": "2023-06-01"}
            )
            path = "/models" if provider == "openai" else "/v1/models"
            # Stream headers only: an unhealthy server cannot force an unbounded body read.
            async with request.app.state.http_client.stream(
                "GET",
                base_url + path,
                headers=headers,
                timeout=5,
                follow_redirects=False,
            ) as response:
                healthy = response.status_code == 200
    except (httpx.HTTPError, ValueError, TimeoutError):
        healthy = False
    # Locked, so an update committing now cannot be overwritten by a stale result.
    row = await _owned_model_deployment(session, user, deployment_id, for_update=True)
    if row.updated_at != checked_version:
        raise HTTPException(
            409, detail="Deployment changed during health check; check again"
        )
    row.health = "healthy" if healthy else "unhealthy"
    row.health_checked_at = datetime.now(timezone.utc)
    await _audit(
        session,
        user,
        "tenant.model_deployment_health_checked",
        str(row.id),
        details={"health": row.health, "declared_version": row.declared_version},
    )
    await session.commit()
    await session.refresh(row)
    return row


async def _owned_model_deployment(
    session: AsyncSession,
    user: User,
    deployment_id: UUID,
    *,
    for_update: bool = False,
) -> ModelDeployment:
    statement = (
        select(ModelDeployment)
        .where(
            ModelDeployment.id == deployment_id,
            ModelDeployment.organization_id == _tenant_id(user),
        )
        .execution_options(populate_existing=True)
    )
    if for_update:
        statement = statement.with_for_update()
    row = (await session.execute(statement)).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, detail="Model deployment not found")
    return row
