"""Tenant-owned identities, credentials, policies, and provider references."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    UUID as SqlUUID,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from shim_enterprise.core.database import Base, TimestampMixin


class Organization(Base, TimestampMixin):
    """Mandatory tenant boundary for every customer-owned record."""

    __tablename__ = "organizations"

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    tier: Mapped[str] = mapped_column(
        ForeignKey("tier_definitions.slug"),
        nullable=False,
        default="free",
        server_default="free",
    )
    billing_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="free", server_default="free"
    )
    billing_source: Mapped[str | None] = mapped_column(String(32))
    external_customer_id: Mapped[str | None] = mapped_column(String(128), unique=True)
    external_subscription_id: Mapped[str | None] = mapped_column(
        String(128), unique=True
    )
    billing_variant_id: Mapped[str | None] = mapped_column(String(128))
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_at_period_end: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    billing_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    customer_portal_url: Mapped[str | None] = mapped_column(Text)

    users: Mapped[list[User]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    api_keys: Mapped[list[ApiKey]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    pii_config: Mapped[OrganizationPIIConfig | None] = relationship(
        back_populates="organization", uselist=False, cascade="all, delete-orphan"
    )
    provider_secrets: Mapped[list[ProviderSecret]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    tier_definition: Mapped[TierDefinition] = relationship()
    invites: Mapped[list[OrganizationInvite]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )


class User(Base, TimestampMixin):
    """Supabase-authenticated user projected into one mandatory tenant."""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_users_tenant_id"),
        CheckConstraint("role IN ('owner', 'admin', 'member')", name="ck_users_role"),
        Index("ix_users_organization_id", "organization_id"),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    full_name: Mapped[str | None] = mapped_column(String(200))
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    is_verified: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    role: Mapped[str] = mapped_column(
        String(16), nullable=False, default="member", server_default="member"
    )

    organization: Mapped[Organization] = relationship(back_populates="users")
    api_keys: Mapped[list[ApiKey]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="[ApiKey.user_id]",
    )


class OrganizationInvite(Base, TimestampMixin):
    """Single-use invitation into an existing tenant."""

    __tablename__ = "organization_invites"
    __table_args__ = (
        CheckConstraint("role IN ('owner', 'admin', 'member')", name="ck_invites_role"),
        Index("ix_invites_organization_id", "organization_id"),
        Index("ix_invites_token_hash", "token_hash", unique=True),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    invited_by_user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    organization: Mapped[Organization] = relationship(back_populates="invites")


class BillingWebhookReceipt(Base, TimestampMixin):
    """Durable Lemon Squeezy delivery idempotency record."""

    __tablename__ = "billing_webhook_receipts"
    __table_args__ = (
        Index("ix_billing_receipts_organization_id", "organization_id"),
        Index("ix_billing_receipts_digest", "payload_digest", unique=True),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    event_name: Mapped[str] = mapped_column(String(64), nullable=False)
    external_subscription_id: Mapped[str | None] = mapped_column(String(128))
    event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TierDefinition(Base, TimestampMixin):
    """Bounded quota policy referenced by tenant API keys."""

    __tablename__ = "tier_definitions"
    __table_args__ = (
        CheckConstraint("rate_limit_rpm > 0", name="ck_tier_rate_limit_rpm"),
        CheckConstraint("rate_limit_tpm > 0", name="ck_tier_rate_limit_tpm"),
        CheckConstraint("monthly_request_limit >= 0", name="ck_tier_monthly_requests"),
        CheckConstraint("monthly_token_limit >= 0", name="ck_tier_monthly_tokens"),
        CheckConstraint(
            "daily_request_limit IS NULL OR daily_request_limit >= 0",
            name="ck_tier_daily_requests",
        ),
    )

    slug: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    rate_limit_rpm: Mapped[int] = mapped_column(Integer, nullable=False)
    rate_limit_tpm: Mapped[int] = mapped_column(Integer, nullable=False)
    monthly_request_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    monthly_token_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    daily_request_limit: Mapped[int | None] = mapped_column(Integer)
    features: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )


class ApiKey(Base, TimestampMixin):
    """One-way API-key verifier with enforced tenant/user ownership."""

    __tablename__ = "api_keys"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_api_keys_tenant_id"),
        ForeignKeyConstraint(
            ["organization_id", "user_id"],
            ["users.organization_id", "users.id"],
            name="fk_api_keys_tenant_user",
            ondelete="CASCADE",
        ),
        Index("ix_api_keys_organization_id", "organization_id"),
        Index("ix_api_keys_key_hash", "key_hash", unique=True),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prefix: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str | None] = mapped_column(String(100))
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cost_center: Mapped[str | None] = mapped_column(String(128))
    team: Mapped[str | None] = mapped_column(String(128))
    tier: Mapped[str] = mapped_column(
        ForeignKey("tier_definitions.slug"), nullable=False, default="free"
    )

    user: Mapped[User] = relationship(back_populates="api_keys", foreign_keys=[user_id])
    organization: Mapped[Organization] = relationship(back_populates="api_keys")
    tier_definition: Mapped[TierDefinition] = relationship()


class OrganizationPIIConfig(Base, TimestampMixin):
    """Tenant privacy policy consumed by the gateway privacy stage."""

    __tablename__ = "organization_pii_configs"

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    block_email: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    block_phone: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    block_credit_card: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    block_secrets: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    block_pii_tr: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    organization: Mapped[Organization] = relationship(back_populates="pii_config")


class ProviderSecret(Base, TimestampMixin):
    """Opaque tenant-bound reference to provider credentials in SecretStore."""

    __tablename__ = "provider_secrets"
    __table_args__ = (
        CheckConstraint(
            "monthly_limit_usd IS NULL OR monthly_limit_usd >= 0",
            name="ck_provider_secret_monthly_limit",
        ),
        Index(
            "ix_provider_secrets_tenant_provider",
            "organization_id",
            "provider",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str | None] = mapped_column(String(100))
    secret_ref: Mapped[str] = mapped_column(Text, nullable=False)
    secret_backend: Mapped[str] = mapped_column(String(32), nullable=False)
    secret_version: Mapped[str] = mapped_column(String(128), nullable=False)
    masked_key: Mapped[str] = mapped_column(String(64), nullable=False)
    monthly_limit_usd: Mapped[Decimal | None] = mapped_column(Numeric(18, 8))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    organization: Mapped[Organization] = relationship(back_populates="provider_secrets")
