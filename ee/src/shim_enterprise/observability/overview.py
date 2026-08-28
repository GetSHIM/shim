"""Canonical tenant overview read model."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Literal
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.billing.models import (
    REQUEST_LIFECYCLE_TERMINAL_STATUSES,
    AuditIntent,
    RequestLifecycle,
    UsageLedger,
)
from shim_enterprise.tenants.models import ApiKey, OrganizationPIIConfig, ProviderSecret


TECHNICAL_STATUSES = frozenset(
    {"completed", "provider_error", "timeout", "internal_error", "failed"}
)
EXCEPTION_STATUSES = tuple(sorted(REQUEST_LIFECYCLE_TERMINAL_STATUSES - {"completed"}))
OverviewBucket = Literal["hour", "day"]
OverviewExceptionCategory = Literal[
    "technical_failure", "policy_rejection", "client_cancelled"
]


@dataclass(frozen=True, slots=True)
class OverviewSummaryRecord:
    requests: int
    technical_failures: int
    policy_rejections: int
    technical_success_rate: float | None
    p95_completed_latency_ms: int | None
    settled_spend_usd: Decimal
    status_counts: dict[str, int]


@dataclass(frozen=True, slots=True)
class OverviewTrendRecord:
    start: datetime
    requests: int
    settled_spend_usd: Decimal


@dataclass(frozen=True, slots=True)
class OverviewExceptionRecord:
    request_id: str
    occurred_at: datetime
    status: str
    category: OverviewExceptionCategory
    provider: str | None
    model: str | None
    error_code: str | None


@dataclass(frozen=True, slots=True)
class OverviewSetupRecord:
    verified_provider: bool
    active_gateway_key: bool
    protection_enabled: bool
    first_successful_request: bool

    @property
    def complete(self) -> bool:
        return all(
            (
                self.verified_provider,
                self.active_gateway_key,
                self.protection_enabled,
                self.first_successful_request,
            )
        )


@dataclass(frozen=True, slots=True)
class OverviewProjection:
    current: OverviewSummaryRecord
    previous: OverviewSummaryRecord
    trend: list[OverviewTrendRecord]
    recent_exceptions: list[OverviewExceptionRecord]
    setup: OverviewSetupRecord


class OverviewReadModel:
    """Read authoritative lifecycle and settlement facts for one tenant."""

    async def read(
        self,
        session: AsyncSession,
        *,
        tenant_id: UUID,
        start_at: datetime,
        end_at: datetime,
        previous_start_at: datetime,
        bucket: OverviewBucket,
        generated_at: datetime,
    ) -> OverviewProjection:
        current = _summary_from_row(
            (
                await session.execute(_summary_statement(tenant_id, start_at, end_at))
            ).one()
        )
        previous = _summary_from_row(
            (
                await session.execute(
                    _summary_statement(tenant_id, previous_start_at, start_at)
                )
            ).one()
        )
        trend_rows = (
            await session.execute(_trend_statement(tenant_id, start_at, end_at, bucket))
        ).all()
        exception_rows = (
            await session.execute(_exceptions_statement(tenant_id, start_at, end_at))
        ).all()
        setup_row = (
            await session.execute(_setup_statement(tenant_id, generated_at))
        ).one()
        return OverviewProjection(
            current=current,
            previous=previous,
            trend=_fill_trend(trend_rows, start_at, end_at, bucket),
            recent_exceptions=[
                OverviewExceptionRecord(
                    request_id=row.request_id,
                    occurred_at=row.reconciled_at,
                    status=row.status,
                    category=_exception_category(row.status, bool(row.spend_denied)),
                    provider=row.provider,
                    model=row.provider_model or row.requested_model,
                    error_code=row.terminal_error_code,
                )
                for row in exception_rows
            ],
            setup=OverviewSetupRecord(
                verified_provider=bool(setup_row.verified_provider),
                active_gateway_key=bool(setup_row.active_gateway_key),
                protection_enabled=bool(setup_row.protection_enabled),
                first_successful_request=bool(setup_row.first_successful_request),
            ),
        )


def _summary_statement(tenant_id: UUID, start_at: datetime, end_at: datetime):
    spend = _settled_spend(tenant_id)
    spend_denied = _spend_denied(tenant_id)
    latency_ms = (
        func.extract(
            "epoch", RequestLifecycle.completed_at - RequestLifecycle.started_at
        )
        * 1000
    )
    columns = [
        func.count(RequestLifecycle.id).label("requests"),
        *(
            func.count(RequestLifecycle.id)
            .filter(RequestLifecycle.status == lifecycle_status)
            .label(lifecycle_status)
            for lifecycle_status in sorted(REQUEST_LIFECYCLE_TERMINAL_STATUSES)
        ),
        func.count(RequestLifecycle.id)
        .filter(
            RequestLifecycle.status == "failed",
            spend_denied,
        )
        .label("policy_failed"),
        func.percentile_cont(0.95)
        .within_group(latency_ms)
        .filter(RequestLifecycle.status == "completed")
        .label("p95_completed_latency_ms"),
        func.coalesce(func.sum(func.coalesce(spend, Decimal("0"))), Decimal("0")).label(
            "settled_spend_usd"
        ),
    ]
    return (
        select(*columns)
        .select_from(RequestLifecycle)
        .where(*_terminal_window(tenant_id, start_at, end_at))
    )


def _trend_statement(
    tenant_id: UUID,
    start_at: datetime,
    end_at: datetime,
    bucket: OverviewBucket,
):
    spend = _settled_spend(tenant_id)
    bucket_start = func.date_trunc(
        bucket, func.timezone("UTC", RequestLifecycle.reconciled_at)
    )
    return (
        select(
            bucket_start.label("start"),
            func.count(RequestLifecycle.id).label("requests"),
            func.coalesce(
                func.sum(func.coalesce(spend, Decimal("0"))), Decimal("0")
            ).label("settled_spend_usd"),
        )
        .select_from(RequestLifecycle)
        .where(*_terminal_window(tenant_id, start_at, end_at))
        .group_by(bucket_start)
        .order_by(bucket_start)
    )


def _exceptions_statement(tenant_id: UUID, start_at: datetime, end_at: datetime):
    spend_denied = _spend_denied(tenant_id)
    return (
        select(
            RequestLifecycle.request_id,
            RequestLifecycle.reconciled_at,
            RequestLifecycle.status,
            RequestLifecycle.provider,
            RequestLifecycle.provider_model,
            RequestLifecycle.requested_model,
            RequestLifecycle.terminal_error_code,
            spend_denied.label("spend_denied"),
        )
        .select_from(RequestLifecycle)
        .where(
            *_terminal_window(tenant_id, start_at, end_at),
            RequestLifecycle.status.in_(EXCEPTION_STATUSES),
        )
        .order_by(RequestLifecycle.reconciled_at.desc(), RequestLifecycle.id.desc())
        .limit(5)
    )


def _setup_statement(tenant_id: UUID, generated_at: datetime):
    protection = or_(
        OrganizationPIIConfig.block_email,
        OrganizationPIIConfig.block_phone,
        OrganizationPIIConfig.block_credit_card,
        OrganizationPIIConfig.block_secrets,
        OrganizationPIIConfig.block_pii_tr,
    )
    return select(
        select(ProviderSecret.id)
        .where(
            ProviderSecret.organization_id == tenant_id,
            ProviderSecret.verified_at.is_not(None),
        )
        .exists()
        .label("verified_provider"),
        select(ApiKey.id)
        .where(
            ApiKey.organization_id == tenant_id,
            ApiKey.is_active.is_(True),
            or_(ApiKey.expires_at.is_(None), ApiKey.expires_at > generated_at),
        )
        .exists()
        .label("active_gateway_key"),
        select(OrganizationPIIConfig.id)
        .where(
            OrganizationPIIConfig.organization_id == tenant_id,
            protection,
        )
        .exists()
        .label("protection_enabled"),
        select(RequestLifecycle.id)
        .where(
            RequestLifecycle.organization_id == tenant_id,
            RequestLifecycle.source_endpoint != "scan",
            RequestLifecycle.status == "completed",
            RequestLifecycle.reconciled_at.is_not(None),
        )
        .exists()
        .label("first_successful_request"),
    )


def _settled_spend(tenant_id: UUID):
    return (
        select(func.sum(UsageLedger.cost_usd))
        .where(
            UsageLedger.organization_id == tenant_id,
            UsageLedger.request_id == RequestLifecycle.request_id,
            UsageLedger.event_type == "spend_settlement",
        )
        .correlate(RequestLifecycle)
        .scalar_subquery()
    )


def _spend_denied(tenant_id: UUID):
    return (
        select(AuditIntent.id)
        .where(
            AuditIntent.organization_id == tenant_id,
            AuditIntent.request_id == RequestLifecycle.request_id,
            AuditIntent.event_type == "preflight",
            AuditIntent.usage_summary["denial_reason"].as_string()
            == "spend_limit_exceeded",
        )
        .correlate(RequestLifecycle)
        .exists()
    )


def _terminal_window(tenant_id: UUID, start_at: datetime, end_at: datetime):
    return (
        RequestLifecycle.organization_id == tenant_id,
        RequestLifecycle.source_endpoint != "scan",
        RequestLifecycle.status.in_(tuple(REQUEST_LIFECYCLE_TERMINAL_STATUSES)),
        RequestLifecycle.reconciled_at >= start_at,
        RequestLifecycle.reconciled_at < end_at,
    )


def _summary_from_row(row) -> OverviewSummaryRecord:
    status_counts = {
        lifecycle_status: int(getattr(row, lifecycle_status) or 0)
        for lifecycle_status in sorted(REQUEST_LIFECYCLE_TERMINAL_STATUSES)
    }
    policy_failed = int(row.policy_failed or 0)
    technical_total = (
        sum(status_counts[status] for status in TECHNICAL_STATUSES) - policy_failed
    )
    p95 = row.p95_completed_latency_ms
    return OverviewSummaryRecord(
        requests=int(row.requests or 0),
        technical_failures=technical_total - status_counts["completed"],
        policy_rejections=status_counts["rejected"] + policy_failed,
        technical_success_rate=(
            status_counts["completed"] / technical_total if technical_total else None
        ),
        p95_completed_latency_ms=round(float(p95)) if p95 is not None else None,
        settled_spend_usd=Decimal(str(row.settled_spend_usd or 0)),
        status_counts=status_counts,
    )


def _exception_category(
    lifecycle_status: str, spend_denied: bool
) -> OverviewExceptionCategory:
    if lifecycle_status == "rejected" or spend_denied:
        return "policy_rejection"
    if lifecycle_status in {"cancelled", "client_disconnected"}:
        return "client_cancelled"
    return "technical_failure"


def _fill_trend(
    rows,
    start_at: datetime,
    end_at: datetime,
    bucket: OverviewBucket,
) -> list[OverviewTrendRecord]:
    values = {
        _utc(row.start): (
            int(row.requests or 0),
            Decimal(str(row.settled_spend_usd or 0)),
        )
        for row in rows
    }
    cursor = _floor_bucket(start_at, bucket)
    step = timedelta(hours=1) if bucket == "hour" else timedelta(days=1)
    trend = []
    while cursor < end_at:
        requests, spend = values.get(cursor, (0, Decimal("0")))
        trend.append(OverviewTrendRecord(max(cursor, start_at), requests, spend))
        cursor += step
    return trend


def _floor_bucket(value: datetime, bucket: OverviewBucket) -> datetime:
    utc = _utc(value)
    if bucket == "hour":
        return utc.replace(minute=0, second=0, microsecond=0)
    return utc.replace(hour=0, minute=0, second=0, microsecond=0)


def _utc(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )
