"""PostgreSQL records for durable gateway accounting."""

from __future__ import annotations

from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    Text,
    UniqueConstraint,
    false,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column

from shim_enterprise.core.database import Base, TimestampMixin


ZERO_NUMERIC = text("0")
EMPTY_OBJECT = text("'{}'::jsonb")
EMPTY_ARRAY = text("'[]'::jsonb")

REQUEST_LIFECYCLE_NONTERMINAL_STATUSES = frozenset(
    {
        "accepted",
        "routing_pending",
        "routing_rejected",
        "provider_pending",
        "provider_started",
        "streaming",
    }
)
REQUEST_LIFECYCLE_TERMINAL_STATUSES = frozenset(
    {
        "completed",
        "provider_error",
        "client_disconnected",
        "timeout",
        "cancelled",
        "internal_error",
        "rejected",
        "failed",
    }
)
REQUEST_LIFECYCLE_STATUSES = (
    REQUEST_LIFECYCLE_NONTERMINAL_STATUSES | REQUEST_LIFECYCLE_TERMINAL_STATUSES
)


class RequestLifecycle(Base):
    """Durable state machine record for one customer data-plane request."""

    __tablename__ = "request_lifecycle"
    __table_args__ = (
        UniqueConstraint("request_id", name="uq_request_lifecycle_request_id"),
        ForeignKeyConstraint(
            ("organization_id", "api_key_id"),
            ("api_keys.organization_id", "api_keys.id"),
            name="fk_request_lifecycle_org_api_key",
        ),
        ForeignKeyConstraint(
            ("organization_id", "user_id"),
            ("users.organization_id", "users.id"),
            name="fk_request_lifecycle_org_user",
        ),
        CheckConstraint(
            "actor_type IN ('api_key', 'user_jwt', 'internal')",
            name="ck_request_lifecycle_actor_type",
        ),
        CheckConstraint(
            "(actor_type = 'api_key' AND api_key_id IS NOT NULL) OR "
            "(actor_type = 'user_jwt' AND user_id IS NOT NULL "
            "AND api_key_id IS NULL) OR "
            "(actor_type = 'internal' AND api_key_id IS NULL "
            "AND user_id IS NULL)",
            name="ck_request_lifecycle_actor_identity",
        ),
        CheckConstraint(
            "status IN ("
            "'accepted', 'routing_pending', 'routing_rejected', "
            "'provider_pending', 'provider_started', 'streaming', "
            "'completed', 'provider_error', 'client_disconnected', "
            "'timeout', 'cancelled', 'internal_error', 'rejected', 'failed')",
            name="ck_request_lifecycle_status",
        ),
        Index(
            "ix_request_lifecycle_org_started_at",
            "organization_id",
            "started_at",
        ),
        Index(
            "ix_request_lifecycle_org_reconciled_at",
            "organization_id",
            "reconciled_at",
            postgresql_where=text("reconciled_at IS NOT NULL"),
        ),
        Index(
            "ix_request_lifecycle_api_key_started_at",
            "api_key_id",
            "started_at",
        ),
        Index("ix_request_lifecycle_user_started_at", "user_id", "started_at"),
        Index(
            "ix_request_lifecycle_org_status_started_at",
            "organization_id",
            "status",
            "started_at",
        ),
        Index(
            "ix_request_lifecycle_reconciliation_due",
            "reconciliation_due_at",
            "id",
            postgresql_where=text(
                "reconciliation_due_at IS NOT NULL AND reconciled_at IS NULL"
            ),
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    request_id: Mapped[str] = mapped_column(Text, nullable=False)
    organization_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False,
    )
    actor_type: Mapped[str] = mapped_column(Text, nullable=False)
    api_key_id: Mapped[UUID | None] = mapped_column(
        PostgreSQLUUID(as_uuid=True), ForeignKey("api_keys.id")
    )
    user_id: Mapped[UUID | None] = mapped_column(
        PostgreSQLUUID(as_uuid=True), ForeignKey("users.id")
    )
    source_endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str | None] = mapped_column(Text)
    provider_model: Mapped[str | None] = mapped_column(Text)
    requested_model: Mapped[str | None] = mapped_column(Text)
    route_decision: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    stream: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    cache_status: Mapped[str] = mapped_column(
        Text, nullable=False, default="not_checked", server_default="not_checked"
    )
    privacy_status: Mapped[str] = mapped_column(
        Text, nullable=False, default="not_checked", server_default="not_checked"
    )
    pii_detected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    provider_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    stream_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    client_disconnected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    reconciled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reconciliation_due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    terminal_error_code: Mapped[str | None] = mapped_column(Text)
    terminal_error_message: Mapped[str | None] = mapped_column(Text)
    lifecycle_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=EMPTY_OBJECT,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class UsageLedger(Base):
    """Immutable quota, spend, cache, and adjustment event."""

    __tablename__ = "usage_ledger"
    __table_args__ = (
        ForeignKeyConstraint(
            ("organization_id", "api_key_id"),
            ("api_keys.organization_id", "api_keys.id"),
            name="fk_usage_ledger_org_api_key",
        ),
        ForeignKeyConstraint(
            ("organization_id", "reservation_event_id"),
            ("usage_ledger.organization_id", "usage_ledger.id"),
            name="fk_usage_ledger_org_reservation_event",
        ),
        UniqueConstraint(
            "organization_id",
            "id",
            name="uq_usage_ledger_org_id",
        ),
        UniqueConstraint(
            "organization_id",
            "idempotency_key",
            name="uq_usage_ledger_org_idempotency",
        ),
        CheckConstraint("request_count >= 0", name="ck_usage_ledger_request_count"),
        CheckConstraint("prompt_tokens >= 0", name="ck_usage_ledger_prompt_tokens"),
        CheckConstraint(
            "completion_tokens >= 0", name="ck_usage_ledger_completion_tokens"
        ),
        CheckConstraint(
            "total_tokens = prompt_tokens + completion_tokens",
            name="ck_usage_ledger_total_tokens",
        ),
        CheckConstraint("cost_usd >= 0", name="ck_usage_ledger_cost_usd"),
        CheckConstraint(
            "event_type IN ("
            "'quota_reservation', 'quota_settlement', 'quota_refund', "
            "'spend_reservation', 'spend_settlement', 'spend_refund', "
            "'adjustment_debit', 'adjustment_credit', 'cache_hit', "
            "'provider_error')",
            name="ck_usage_ledger_event_type",
        ),
        CheckConstraint(
            "((event_type IN ("
            "'quota_reservation', 'quota_settlement', 'quota_refund') "
            "AND provider IS NULL AND provider_model IS NULL) OR "
            "(event_type IN ("
            "'spend_reservation', 'spend_settlement', 'spend_refund', "
            "'provider_error') AND provider IS NOT NULL "
            "AND provider_model IS NOT NULL) OR "
            "event_type IN ('cache_hit', 'adjustment_debit', 'adjustment_credit'))",
            name="ck_usage_ledger_provider_shape",
        ),
        CheckConstraint(
            "(provider IS NULL AND provider_model IS NULL) OR "
            "(provider IS NOT NULL AND provider_model IS NOT NULL)",
            name="ck_usage_ledger_provider_pair",
        ),
        CheckConstraint(
            "((event_type IN ("
            "'quota_settlement', 'quota_refund', 'spend_settlement', "
            "'spend_refund') AND reservation_event_id IS NOT NULL) OR "
            "(event_type NOT IN ("
            "'quota_settlement', 'quota_refund', 'spend_settlement', "
            "'spend_refund') AND reservation_event_id IS NULL))",
            name="ck_usage_ledger_reservation_reference",
        ),
        Index(
            "ux_usage_ledger_reservation_event_id",
            "reservation_event_id",
            unique=True,
            postgresql_where=text("reservation_event_id IS NOT NULL"),
        ),
        Index(
            "ix_usage_ledger_org_request_event",
            "organization_id",
            "request_id",
            "event_type",
        ),
        Index(
            "ix_usage_ledger_org_created_event",
            "organization_id",
            "created_at",
            "event_type",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    request_id: Mapped[str] = mapped_column(Text, nullable=False)
    organization_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False,
    )
    api_key_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), ForeignKey("api_keys.id"), nullable=False
    )
    requested_model: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str | None] = mapped_column(Text)
    provider_model: Mapped[str | None] = mapped_column(Text)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(Text, nullable=False)
    reservation_event_id: Mapped[UUID | None] = mapped_column(
        PostgreSQLUUID(as_uuid=True)
    )
    request_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=ZERO_NUMERIC
    )
    prompt_tokens: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=ZERO_NUMERIC
    )
    completion_tokens: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=ZERO_NUMERIC
    )
    total_tokens: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=ZERO_NUMERIC
    )
    estimated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    cost_usd: Mapped[Decimal] = mapped_column(
        Numeric(18, 8),
        nullable=False,
        default=Decimal("0"),
        server_default=ZERO_NUMERIC,
    )
    currency: Mapped[str] = mapped_column(
        Text, nullable=False, default="USD", server_default="USD"
    )
    period_allocations: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=EMPTY_ARRAY,
    )
    event_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=EMPTY_OBJECT,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class QuotaPeriodUsage(Base):
    """Authoritative daily or monthly API-key quota counters."""

    __tablename__ = "quota_period_usage"
    __table_args__ = (
        ForeignKeyConstraint(
            ("organization_id", "api_key_id"),
            ("api_keys.organization_id", "api_keys.id"),
            name="fk_quota_period_usage_org_api_key",
        ),
        UniqueConstraint(
            "organization_id",
            "api_key_id",
            "period_type",
            "period_start",
            name="uq_quota_period_usage_scope",
        ),
        CheckConstraint(
            "period_type IN ('daily', 'monthly')",
            name="ck_quota_period_usage_period_type",
        ),
        CheckConstraint(
            "reserved_requests >= 0",
            name="ck_quota_period_usage_reserved_requests",
        ),
        CheckConstraint(
            "settled_requests >= 0",
            name="ck_quota_period_usage_settled_requests",
        ),
        CheckConstraint(
            "reserved_tokens >= 0",
            name="ck_quota_period_usage_reserved_tokens",
        ),
        CheckConstraint(
            "settled_tokens >= 0",
            name="ck_quota_period_usage_settled_tokens",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False,
    )
    api_key_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), ForeignKey("api_keys.id"), nullable=False
    )
    period_type: Mapped[str] = mapped_column(Text, nullable=False)
    period_start: Mapped[date] = mapped_column(Date, nullable=False)
    period_end: Mapped[date] = mapped_column(Date, nullable=False)
    reserved_requests: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=ZERO_NUMERIC
    )
    settled_requests: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=ZERO_NUMERIC
    )
    reserved_tokens: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=ZERO_NUMERIC
    )
    settled_tokens: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=ZERO_NUMERIC
    )
    limit_requests: Mapped[int | None] = mapped_column(Integer)
    limit_tokens: Mapped[int | None] = mapped_column(Integer)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class SpendPeriodUsage(Base):
    """Authoritative monthly provider-spend counters."""

    __tablename__ = "spend_period_usage"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "provider",
            "period_start",
            name="uq_spend_period_usage_scope",
        ),
        CheckConstraint("reserved_usd >= 0", name="ck_spend_period_usage_reserved_usd"),
        CheckConstraint("settled_usd >= 0", name="ck_spend_period_usage_settled_usd"),
    )

    id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False,
    )
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    period_start: Mapped[date] = mapped_column(Date, nullable=False)
    period_end: Mapped[date] = mapped_column(Date, nullable=False)
    reserved_usd: Mapped[Decimal] = mapped_column(
        Numeric(18, 8),
        nullable=False,
        default=Decimal("0"),
        server_default=ZERO_NUMERIC,
    )
    settled_usd: Mapped[Decimal] = mapped_column(
        Numeric(18, 8),
        nullable=False,
        default=Decimal("0"),
        server_default=ZERO_NUMERIC,
    )
    limit_usd: Mapped[Decimal | None] = mapped_column(Numeric(18, 8))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class AuditIntent(Base):
    """Durable preflight or completion audit obligation."""

    __tablename__ = "audit_intent"
    __table_args__ = (
        ForeignKeyConstraint(
            ("organization_id", "api_key_id"),
            ("api_keys.organization_id", "api_keys.id"),
            name="fk_audit_intent_org_api_key",
        ),
        ForeignKeyConstraint(
            ("organization_id", "user_id"),
            ("users.organization_id", "users.id"),
            name="fk_audit_intent_org_user",
        ),
        ForeignKeyConstraint(
            ("organization_id", "outbox_event_id"),
            ("outbox_event.organization_id", "outbox_event.id"),
            name="fk_audit_intent_org_outbox_event",
        ),
        UniqueConstraint(
            "organization_id",
            "request_id",
            "event_type",
            name="uq_audit_intent_org_request_event",
        ),
        CheckConstraint(
            "event_type IN ('preflight', 'completion')",
            name="ck_audit_intent_event_type",
        ),
        CheckConstraint(
            "audit_policy_mode IN ('off', 'best_effort', 'strict')",
            name="ck_audit_intent_policy_mode",
        ),
        CheckConstraint(
            "actor_type IN ('api_key', 'user_jwt', 'internal')",
            name="ck_audit_intent_actor_type",
        ),
        CheckConstraint(
            "(actor_type = 'api_key' AND api_key_id IS NOT NULL) OR "
            "(actor_type = 'user_jwt' AND user_id IS NOT NULL "
            "AND api_key_id IS NULL) OR "
            "(actor_type = 'internal' AND api_key_id IS NULL "
            "AND user_id IS NULL)",
            name="ck_audit_intent_actor_identity",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    request_id: Mapped[str] = mapped_column(Text, nullable=False)
    organization_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False,
    )
    actor_type: Mapped[str] = mapped_column(Text, nullable=False)
    api_key_id: Mapped[UUID | None] = mapped_column(
        PostgreSQLUUID(as_uuid=True), ForeignKey("api_keys.id")
    )
    user_id: Mapped[UUID | None] = mapped_column(
        PostgreSQLUUID(as_uuid=True), ForeignKey("users.id")
    )
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    audit_policy_mode: Mapped[str] = mapped_column(Text, nullable=False)
    input_hash: Mapped[str | None] = mapped_column(Text)
    output_hash: Mapped[str | None] = mapped_column(Text)
    pii_entities: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=EMPTY_OBJECT,
    )
    provider: Mapped[str | None] = mapped_column(Text)
    model: Mapped[str | None] = mapped_column(Text)
    usage_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=EMPTY_OBJECT,
    )
    lifecycle_status: Mapped[str] = mapped_column(Text, nullable=False)
    outbox_event_id: Mapped[UUID | None] = mapped_column(PostgreSQLUUID(as_uuid=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class CostBudget(Base, TimestampMixin):
    """Tenant-owned monthly notification threshold definition."""

    __tablename__ = "cost_budget"
    __table_args__ = (
        CheckConstraint(
            "scope_type IN ('org', 'tag', 'team')",
            name="ck_cost_budget_scope_type",
        ),
        CheckConstraint("period = 'monthly'", name="ck_cost_budget_period"),
        CheckConstraint(
            "(scope_type = 'org' AND scope_value IS NULL) OR "
            "(scope_type <> 'org' AND scope_value IS NOT NULL)",
            name="ck_cost_budget_scope_value",
        ),
        CheckConstraint(
            "limit_usd IS NOT NULL OR limit_tokens IS NOT NULL",
            name="ck_cost_budget_has_limit",
        ),
        CheckConstraint(
            "limit_usd IS NULL OR limit_usd >= 0",
            name="ck_cost_budget_limit_usd",
        ),
        CheckConstraint(
            "limit_tokens IS NULL OR limit_tokens >= 0",
            name="ck_cost_budget_limit_tokens",
        ),
        Index("ix_cost_budget_org", "organization_id"),
    )

    id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False,
    )
    scope_type: Mapped[str] = mapped_column(Text, nullable=False)
    scope_value: Mapped[str | None] = mapped_column(Text)
    period: Mapped[str] = mapped_column(
        Text, nullable=False, default="monthly", server_default="monthly"
    )
    limit_usd: Mapped[Decimal | None] = mapped_column(Numeric(18, 8))
    limit_tokens: Mapped[int | None] = mapped_column(BigInteger)
    alert_thresholds: Mapped[list[float]] = mapped_column(
        JSONB,
        nullable=False,
        default=lambda: [0.8, 1.0],
        server_default=text("'[0.8, 1.0]'::jsonb"),
    )
    notify_targets: Mapped[list[dict[str, str]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=EMPTY_ARRAY,
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )


class CostBudgetAlertState(Base, TimestampMixin):
    """Idempotency marker for one budget threshold and UTC month."""

    __tablename__ = "cost_budget_alert_state"
    __table_args__ = (
        UniqueConstraint(
            "budget_id",
            "period_key",
            "threshold",
            name="uq_budget_period_threshold",
        ),
        CheckConstraint("threshold > 0", name="ck_budget_alert_threshold"),
    )

    id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    budget_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("cost_budget.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    period_key: Mapped[str] = mapped_column(Text, nullable=False)
    threshold: Mapped[Decimal] = mapped_column(Numeric(8, 6), nullable=False)
    fired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
