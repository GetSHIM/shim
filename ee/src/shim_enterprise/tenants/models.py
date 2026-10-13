"""Tenant-owned identities, credentials, policies, and provider references."""

from __future__ import annotations

from datetime import datetime, timezone
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
    LargeBinary,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    UUID as SqlUUID,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from shim_enterprise.core.database import Base, TimestampMixin


class Organization(Base, TimestampMixin):
    """Mandatory tenant boundary for every customer-owned record."""

    __tablename__ = "organizations"
    __table_args__ = (
        CheckConstraint(
            "quota_monthly_request_limit IS NULL OR quota_monthly_request_limit >= 0",
            name="ck_organizations_quota_monthly_requests",
        ),
        CheckConstraint(
            "quota_monthly_token_limit IS NULL OR quota_monthly_token_limit >= 0",
            name="ck_organizations_quota_monthly_tokens",
        ),
        CheckConstraint(
            "(archived_at IS NULL) = (archived_reason IS NULL)",
            name="ck_organizations_archive_pair",
        ),
    )

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
    quota_monthly_request_limit: Mapped[int | None] = mapped_column(Integer)
    quota_monthly_token_limit: Mapped[int | None] = mapped_column(Integer)
    billing_revision: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    # False refuses x-provider-key on catalog routes; deployments ignore the header.
    allow_customer_provider_keys: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    # Set when the only user joined another organization; nobody belongs to it again.
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    archived_reason: Mapped[str | None] = mapped_column(String(32))

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
    """Authenticated identity projected into one mandatory tenant."""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_users_tenant_id"),
        CheckConstraint(
            "role IN ('owner', 'admin', 'member', 'auditor', 'recommender')",
            name="ck_users_role",
        ),
        UniqueConstraint("oidc_issuer", "oidc_subject", name="uq_users_oidc_identity"),
        Index("ix_users_organization_id", "organization_id"),
        CheckConstraint("kind IN ('human', 'service')", name="ck_users_kind"),
        CheckConstraint(
            "(kind = 'human' AND role <> 'recommender') OR "
            "(kind = 'service' AND role IN ('admin', 'auditor', 'recommender'))",
            name="ck_users_service_role",
        ),
        ForeignKeyConstraint(
            ["organization_id", "custom_role_id"],
            ["organization_roles.organization_id", "organization_roles.id"],
            name="fk_users_tenant_custom_role",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "custom_role_id IS NULL OR (role = 'member' AND kind = 'human')",
            name="ck_users_custom_role_member",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    oidc_issuer: Mapped[str | None] = mapped_column(String(512))
    oidc_subject: Mapped[str | None] = mapped_column(String(255))
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
    kind: Mapped[str] = mapped_column(
        String(16), nullable=False, default="human", server_default="human"
    )
    custom_role_id: Mapped[UUID | None] = mapped_column(SqlUUID(as_uuid=True))

    organization: Mapped[Organization] = relationship(back_populates="users")
    api_keys: Mapped[list[ApiKey]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="[ApiKey.user_id]",
    )


class OrganizationRole(Base, TimestampMixin):
    """A tenant-defined permission set held by organization members."""

    __tablename__ = "organization_roles"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "slug", name="uq_organization_roles_tenant_slug"
        ),
        UniqueConstraint(
            "organization_id", "id", name="uq_organization_roles_tenant_id"
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "organizations.id",
            name="fk_organization_roles_organization_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    slug: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    permissions: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    created_by: Mapped[str | None] = mapped_column(String(64))


class ServiceAccountCredential(Base):
    """One-way verifier of a service account's management key."""

    __tablename__ = "service_account_credentials"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "user_id"],
            ["users.organization_id", "users.id"],
            name="fk_service_account_credentials_tenant_user",
            ondelete="CASCADE",
        ),
        UniqueConstraint("key_hash", name="uq_service_account_credentials_key_hash"),
        Index("ix_service_account_credentials_user_id", "user_id"),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(SqlUUID(as_uuid=True), nullable=False)
    user_id: Mapped[UUID] = mapped_column(SqlUUID(as_uuid=True), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prefix: Mapped[str] = mapped_column(String(32), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[UUID] = mapped_column(SqlUUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )


class OrganizationInvite(Base, TimestampMixin):
    """Single-use invitation into an existing tenant."""

    __tablename__ = "organization_invites"
    __table_args__ = (
        CheckConstraint(
            "role IN ('owner', 'admin', 'member', 'auditor')", name="ck_invites_role"
        ),
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
    """Historical billing delivery receipt retained after integration retirement."""

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


class Team(Base, TimestampMixin):
    """Explicit tenant-owned delegation and quota boundary, not a billing label."""

    __tablename__ = "teams"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_teams_tenant_id"),
        UniqueConstraint("organization_id", "name", name="uq_teams_tenant_name"),
        CheckConstraint(
            "daily_request_limit IS NULL OR daily_request_limit >= 0",
            name="ck_teams_daily_requests",
        ),
        CheckConstraint(
            "monthly_request_limit IS NULL OR monthly_request_limit >= 0",
            name="ck_teams_monthly_requests",
        ),
        CheckConstraint(
            "monthly_token_limit IS NULL OR monthly_token_limit >= 0",
            name="ck_teams_monthly_tokens",
        ),
        CheckConstraint(
            "aws_cost_tag ~ '^[A-Za-z0-9 _.:/=+@-]+$'",
            name="ck_teams_aws_cost_tag",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    daily_request_limit: Mapped[int | None] = mapped_column(Integer)
    monthly_request_limit: Mapped[int | None] = mapped_column(Integer)
    monthly_token_limit: Mapped[int | None] = mapped_column(Integer)
    # The STS session tag value this team's Bedrock requests carry onto the AWS bill.
    aws_cost_tag: Mapped[str | None] = mapped_column(String(256))


class TeamMembership(Base, TimestampMixin):
    """Membership grants access only within the named tenant and team."""

    __tablename__ = "team_memberships"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "team_id"],
            ["teams.organization_id", "teams.id"],
            name="fk_team_memberships_tenant_team",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["organization_id", "user_id"],
            ["users.organization_id", "users.id"],
            name="fk_team_memberships_tenant_user",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "role IN ('member', 'team_admin')", name="ck_team_memberships_role"
        ),
        CheckConstraint(
            "source IN ('local', 'oidc')", name="ck_team_memberships_source"
        ),
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True
    )
    team_id: Mapped[UUID] = mapped_column(SqlUUID(as_uuid=True), primary_key=True)
    user_id: Mapped[UUID] = mapped_column(SqlUUID(as_uuid=True), primary_key=True)
    role: Mapped[str] = mapped_column(
        String(16), nullable=False, default="member", server_default="member"
    )
    source: Mapped[str] = mapped_column(
        String(16), nullable=False, default="local", server_default="local"
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
        ForeignKeyConstraint(
            ["organization_id", "team_id"],
            ["teams.organization_id", "teams.id"],
            name="fk_api_keys_tenant_team",
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
    team_id: Mapped[UUID | None] = mapped_column(SqlUUID(as_uuid=True))
    allowed_models: Mapped[list[str] | None] = mapped_column(JSONB)
    tier: Mapped[str] = mapped_column(
        ForeignKey("tier_definitions.slug"), nullable=False, default="free"
    )

    user: Mapped[User] = relationship(back_populates="api_keys", foreign_keys=[user_id])
    organization: Mapped[Organization] = relationship(back_populates="api_keys")
    tier_definition: Mapped[TierDefinition] = relationship()


class OrganizationPIIConfig(Base, TimestampMixin):
    """Tenant privacy policy consumed by the gateway privacy stage."""

    __tablename__ = "organization_pii_configs"
    __table_args__ = (
        CheckConstraint(
            "placeholder_mode IN ('random', 'stable')",
            name="ck_organization_pii_configs_placeholder_mode",
        ),
        CheckConstraint(
            "bulk_threshold IS NULL OR bulk_threshold >= 2",
            name="ck_organization_pii_configs_bulk_threshold",
        ),
        CheckConstraint(
            "response_scan IN ('off', 'count')",
            name="ck_organization_pii_configs_response_scan",
        ),
    )

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
    entity_actions: Mapped[dict[str, str]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    placeholder_mode: Mapped[str] = mapped_column(
        String(16), nullable=False, default="random", server_default="random"
    )
    bulk_threshold: Mapped[int | None] = mapped_column(
        Integer, default=50, server_default="50"
    )
    response_scan: Mapped[str] = mapped_column(
        String(16), nullable=False, default="off", server_default="off"
    )
    # Types an embeddings request only counts where chat masks or blocks them.
    embeddings_monitor_types: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )

    organization: Mapped[Organization] = relationship(back_populates="pii_config")


class OrganizationGatewaySettings(Base, TimestampMixin):
    """Tenant gateway switches; no row means every switch at its off default."""

    __tablename__ = "organization_gateway_settings"
    __table_args__ = (
        CheckConstraint(
            "revision >= 0", name="ck_organization_gateway_settings_revision"
        ),
    )

    organization_id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True),
        ForeignKey(
            "organizations.id",
            name="fk_organization_gateway_settings_organization_id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )
    settings: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    revision: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    updated_by: Mapped[UUID | None] = mapped_column(
        SqlUUID(as_uuid=True),
        ForeignKey(
            "users.id",
            name="fk_organization_gateway_settings_updated_by",
            ondelete="SET NULL",
        ),
    )


class ProviderSecret(Base, TimestampMixin):
    """Opaque tenant-bound reference to provider credentials in SecretStore."""

    __tablename__ = "provider_secrets"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_provider_secrets_tenant_id"),
        CheckConstraint(
            "monthly_limit_usd IS NULL OR monthly_limit_usd >= 0",
            name="ck_provider_secret_monthly_limit",
        ),
        CheckConstraint(
            "credential_kind IN "
            "('api_key', 'aws_access_key', 'aws_bedrock_api_key', 'aws_role')",
            name="ck_provider_secrets_credential_kind",
        ),
        # A role stores nothing secret: its ARN instead of a secret-store reference.
        CheckConstraint(
            "((credential_kind = 'aws_role') = (aws_role_arn IS NOT NULL)) AND "
            "((credential_kind = 'aws_role') = (secret_ref IS NULL)) AND "
            "((secret_ref IS NULL) = (secret_backend IS NULL)) AND "
            "((secret_ref IS NULL) = (secret_version IS NULL))",
            name="ck_provider_secrets_role_shape",
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
    # openai, anthropic, google, or azure_entra: an Entra client credential that calls
    # OpenAI on Azure for its deployments only, which a build without it never selects.
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str | None] = mapped_column(String(100))
    secret_ref: Mapped[str | None] = mapped_column(Text)
    secret_backend: Mapped[str | None] = mapped_column(String(32))
    secret_version: Mapped[str | None] = mapped_column(String(128))
    masked_key: Mapped[str] = mapped_column(String(64), nullable=False)
    monthly_limit_usd: Mapped[Decimal | None] = mapped_column(Numeric(18, 8))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # api_key, or an AWS kind that serves only Bedrock deployments: a long-term
    # access key pair the gateway mints Bedrock API keys from, or a Bedrock API key.
    credential_kind: Mapped[str] = mapped_column(
        String(32), nullable=False, default="api_key", server_default="api_key"
    )
    aws_role_arn: Mapped[str | None] = mapped_column(String(2048))

    organization: Mapped[Organization] = relationship(back_populates="provider_secrets")


class OrganizationAwsIdentity(Base):
    """The tenant's external id: what its AWS role's trust policy asks shim for."""

    __tablename__ = "organization_aws_identities"
    __table_args__ = (
        UniqueConstraint(
            "external_id", name="uq_organization_aws_identities_external_id"
        ),
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "organizations.id",
            name="fk_organization_aws_identities_organization_id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )
    external_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ModelDeployment(Base, TimestampMixin):
    """Tenant-owned alias bound to an administrator-approved serving endpoint."""

    __tablename__ = "model_deployments"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "alias", name="uq_model_deployments_tenant_alias"
        ),
        ForeignKeyConstraint(
            ["organization_id", "provider_secret_id"],
            ["provider_secrets.organization_id", "provider_secrets.id"],
            ondelete="RESTRICT",
            name="fk_model_deployments_tenant_secret",
        ),
        CheckConstraint(
            "provider IN ('openai', 'anthropic')", name="ck_model_deployments_provider"
        ),
        CheckConstraint(
            "deployment_kind IN ('internal', 'external')",
            name="ck_model_deployments_kind",
        ),
        CheckConstraint(
            "health IN ('unknown', 'healthy', 'unhealthy')",
            name="ck_model_deployments_health",
        ),
        CheckConstraint(
            "timeout_seconds BETWEEN 1 AND 300", name="ck_model_deployments_timeout"
        ),
        CheckConstraint(
            "(input_price_per_million IS NULL AND output_price_per_million IS NULL) "
            "OR (input_price_per_million IS NOT NULL AND output_price_per_million "
            "IS NOT NULL AND input_price_per_million >= 0 AND output_price_per_million >= 0)",
            name="ck_model_deployments_price_pair",
        ),
        CheckConstraint(
            "context_window IS NULL OR context_window > 0",
            name="ck_model_deployments_context_window",
        ),
        CheckConstraint(
            "(cache_read_price_per_million IS NULL OR (input_price_per_million "
            "IS NOT NULL AND cache_read_price_per_million >= 0)) AND "
            "(cache_write_price_per_million IS NULL OR (input_price_per_million "
            "IS NOT NULL AND cache_write_price_per_million >= 0))",
            name="ck_model_deployments_cache_prices",
        ),
        CheckConstraint(
            "upstream IN ('generic', 'azure_openai', 'aws_bedrock')",
            name="ck_model_deployments_upstream",
        ),
        CheckConstraint(
            "((upstream = 'aws_bedrock') = (aws_region IS NOT NULL)) AND "
            "(aws_region IS NULL OR aws_region ~ '^[a-z]{2}(-[a-z]+)+-[0-9]$')",
            name="ck_model_deployments_aws_region",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    alias: Mapped[str] = mapped_column(String(200), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    upstream_model: Mapped[str] = mapped_column(String(200), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    provider_secret_id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), nullable=False
    )
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    deployment_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    declared_version: Mapped[str] = mapped_column(String(200), nullable=False)
    owner: Mapped[str] = mapped_column(String(200), nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    health: Mapped[str] = mapped_column(
        String(16), nullable=False, default="unknown", server_default="unknown"
    )
    health_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    input_price_per_million: Mapped[Decimal | None] = mapped_column(Numeric(18, 8))
    output_price_per_million: Mapped[Decimal | None] = mapped_column(Numeric(18, 8))
    context_window: Mapped[int | None] = mapped_column(Integer)
    price_model: Mapped[str | None] = mapped_column(String(200))
    cache_read_price_per_million: Mapped[Decimal | None] = mapped_column(Numeric(18, 8))
    cache_write_price_per_million: Mapped[Decimal | None] = mapped_column(
        Numeric(18, 8)
    )
    upstream: Mapped[str] = mapped_column(
        String(32), nullable=False, default="generic", server_default="generic"
    )
    aws_region: Mapped[str | None] = mapped_column(String(32))
    # Where a Bedrock profile can route, from GetInferenceProfile; null when unknown.
    aws_destination_regions: Mapped[list[str] | None] = mapped_column(JSONB)
    aws_destinations_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )


class RecordSet(Base, TimestampMixin):
    """A tenant's hashed records or document fingerprints; never the records themselves."""

    __tablename__ = "record_sets"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('records', 'fingerprints')", name="ck_record_sets_kind"
        ),
        UniqueConstraint("organization_id", "name", name="uq_record_sets_org_name"),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True),
        ForeignKey(
            "organizations.id", name="fk_record_sets_organization", ondelete="CASCADE"
        ),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    label: Mapped[str] = mapped_column(
        String(32), nullable=False, default="RECORD", server_default="RECORD"
    )
    fields: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    fingerprint_version: Mapped[int | None] = mapped_column(SmallInteger)
    key_ref: Mapped[str] = mapped_column(Text, nullable=False)
    active_revision: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    # The revision active before the current one, kept for a one-step rollback.
    previous_revision: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    entry_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    created_by: Mapped[str | None] = mapped_column(String(64))


class RecordSetChunk(Base):
    """One uploaded slice of a revision: packed big-endian 8-byte hashes."""

    __tablename__ = "record_set_chunks"

    record_set_id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True),
        ForeignKey(
            "record_sets.id", name="fk_record_set_chunks_record_set", ondelete="CASCADE"
        ),
        primary_key=True,
    )
    revision: Mapped[int] = mapped_column(Integer, primary_key=True)
    chunk_index: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(SqlUUID(as_uuid=True), nullable=False)
    entry_count: Mapped[int] = mapped_column(Integer, nullable=False)
    data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
