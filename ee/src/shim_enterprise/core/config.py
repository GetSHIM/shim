"""Validated deployment configuration for the documented shim architecture."""

from __future__ import annotations

from typing import Literal, Self
from uuid import UUID
from urllib.parse import urlsplit

from pydantic import EmailStr, Field, RedisDsn, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

from shim.core.community_config import CommunitySettings


class Settings(CommunitySettings):
    API_PREFIX: Literal["/api/v1"] = "/api/v1"

    DATABASE_URL: str
    DATABASE_POOL_SIZE: int = Field(default=2, ge=1)
    DATABASE_MAX_OVERFLOW: int = Field(default=1, ge=0)
    REDIS_URL: RedisDsn
    SECRET_KEY: str = Field(min_length=16)
    SHIM_LICENSE_KEY: str | None = None
    ENCRYPTION_KEY: str | None = None
    SECRET_BACKEND: Literal[
        "fernet",
        "gcp_secret_manager",
        "aws_secrets_manager",
        "azure_key_vault",
        "vault",
    ] = "fernet"

    VAULT_ADDR: str | None = None
    VAULT_TOKEN_FILE: str | None = None
    VAULT_KV_MOUNT: str = Field(default="secret", pattern=r"^[A-Za-z0-9_-]+$")
    VAULT_NAMESPACE: str | None = None

    AUTH_MODE: Literal["supabase", "oidc"] = "supabase"
    SUPABASE_URL: str | None = None
    OIDC_ISSUER_URL: str | None = Field(default=None, max_length=512)
    OIDC_CLIENT_ID: str | None = None
    OIDC_CLIENT_SECRET: str | None = None
    OIDC_REDIRECT_URI: str | None = None
    OIDC_ORGANIZATION_ID: UUID | None = None
    OIDC_GROUPS_CLAIM: str = "groups"
    OIDC_GROUP_ROLE_MAP: dict[str, Literal["owner", "admin", "auditor", "member"]] = (
        Field(default_factory=dict)
    )
    OIDC_TEAM_GROUP_MAP: dict[str, dict[str, str]] = Field(default_factory=dict)
    OIDC_SESSION_SECONDS: int = Field(default=28_800, ge=60, le=86_400)
    OIDC_REVALIDATE_SECONDS: int = Field(default=60, ge=10, le=300)
    OIDC_API_AUDIENCE: str | None = None
    OIDC_API_MAX_TOKEN_SECONDS: int = Field(default=300, ge=60, le=900)
    DASHBOARD_ORIGIN: str | None = None
    SUPABASE_KEY: str | None = None

    MANUAL_TEST_DASHBOARD_ENABLED: bool = False
    SHIM_TEST_USER_EMAIL: str | None = None

    DEFAULT_MONTHLY_TOKEN_LIMIT: int = Field(default=1_000_000, ge=0)

    GATEWAY_RECONCILIATION_GRACE_SECONDS: int = Field(default=120, ge=30, le=3_600)
    GATEWAY_RECONCILIATION_INTERVAL_SECONDS: int = Field(default=30, ge=5, le=3_600)
    GATEWAY_RECONCILIATION_BATCH_SIZE: int = Field(default=100, ge=1, le=1_000)

    GATEWAY_OUTBOX_INTERVAL_SECONDS: int = Field(default=5, ge=1, le=3_600)
    GATEWAY_OUTBOX_BATCH_SIZE: int = Field(default=100, ge=1, le=1_000)
    GATEWAY_OUTBOX_LEASE_SECONDS: int = Field(default=60, ge=5, le=3_600)
    GATEWAY_OUTBOX_MAX_ATTEMPTS: int = Field(default=8, ge=1, le=100)

    COMPLIANCE_DEFAULT_INTERVAL_SECONDS: int = Field(default=300, ge=1)
    COMPLIANCE_DEFAULT_BACKFILL_HOURS: int = Field(default=24, ge=1)
    COMPLIANCE_ANTHROPIC_RPM: int = Field(default=600, ge=1)
    COMPLIANCE_OPENAI_RETENTION_DAYS: int = Field(default=30, ge=1)
    COMPLIANCE_RETENTION_RISK_DAYS: int = Field(default=7, ge=1)
    COMPLIANCE_SCAN_CONCURRENCY: int = Field(default=4, ge=1, le=64)
    COMPLIANCE_HASH_SALT: str | None = None
    RESEND_API_KEY: str | None = None
    COMPLIANCE_EMAIL_FROM: EmailStr | None = None

    AI_ACT_AUDIT_ENABLED: bool = True
    AI_ACT_AUDIT_RETENTION_DAYS: int = Field(default=180, ge=180)
    AI_ACT_AUDIT_ANCHOR_ENABLED: bool = True
    AI_ACT_AUDIT_WORKER_INTERVAL_SECONDS: int = Field(default=3_600, ge=1)
    OVERSIGHT_ENABLED: bool = False
    OVERSIGHT_DEFAULT_TTL_SECONDS: int = Field(default=3_600, ge=1)

    model_config = SettingsConfigDict(env_file="ee/.env")

    @field_validator("COMPLIANCE_EMAIL_FROM", mode="before")
    @classmethod
    def empty_email_is_unconfigured(cls, value: object) -> object:
        return None if value == "" else value

    @model_validator(mode="after")
    def validate_production_settings(self) -> Self:
        if (
            self.GATEWAY_RECONCILIATION_INTERVAL_SECONDS
            > self.GATEWAY_RECONCILIATION_GRACE_SECONDS
        ):
            raise ValueError(
                "gateway reconciliation interval cannot exceed its grace period"
            )
        if self.AUTH_MODE == "supabase" and not self.SUPABASE_URL:
            raise ValueError("supabase authentication requires SUPABASE_URL")
        if self.AUTH_MODE == "oidc":
            for name in (
                "OIDC_ISSUER_URL",
                "OIDC_CLIENT_ID",
                "OIDC_CLIENT_SECRET",
                "OIDC_REDIRECT_URI",
                "OIDC_ORGANIZATION_ID",
                "DASHBOARD_ORIGIN",
            ):
                if not getattr(self, name):
                    raise ValueError(f"oidc authentication requires {name}")
            if self.OIDC_API_AUDIENCE and self.OIDC_API_AUDIENCE == self.OIDC_CLIENT_ID:
                raise ValueError(
                    "OIDC_API_AUDIENCE must differ from the login client to reject ID tokens"
                )
            if not self.OIDC_GROUP_ROLE_MAP:
                raise ValueError(
                    "OIDC_GROUP_ROLE_MAP must grant at least one group access"
                )
            for name in ("OIDC_ISSUER_URL", "OIDC_REDIRECT_URI", "DASHBOARD_ORIGIN"):
                parsed = urlsplit(getattr(self, name))
                if (
                    parsed.scheme not in {"http", "https"}
                    or not parsed.hostname
                    or parsed.username
                    or parsed.password
                    or parsed.query
                    or parsed.fragment
                    or (self.ENVIRONMENT == "production" and parsed.scheme != "https")
                ):
                    raise ValueError(
                        f"{name} must be an absolute URL; production requires HTTPS"
                    )
            dashboard = urlsplit(self.DASHBOARD_ORIGIN)
            callback = urlsplit(self.OIDC_REDIRECT_URI)
            if dashboard.path not in {"", "/"} or (
                callback.scheme,
                callback.netloc,
                callback.path,
            ) != (dashboard.scheme, dashboard.netloc, "/api/v1/auth/callback"):
                raise ValueError(
                    "OIDC_REDIRECT_URI must use DASHBOARD_ORIGIN/api/v1/auth/callback"
                )
        if self.SECRET_BACKEND == "vault":
            if not self.VAULT_ADDR or not self.VAULT_TOKEN_FILE:
                raise ValueError("vault requires VAULT_ADDR and VAULT_TOKEN_FILE")
            parsed = urlsplit(self.VAULT_ADDR)
            if (
                parsed.scheme not in {"https", "http"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or parsed.path not in {"", "/"}
                or (self.ENVIRONMENT == "production" and parsed.scheme != "https")
            ):
                raise ValueError(
                    "VAULT_ADDR must be an origin; production requires HTTPS"
                )
        if self.ENVIRONMENT == "production" and self.SECRET_BACKEND == "fernet":
            raise ValueError("production requires a managed secret backend")
        if self.ENVIRONMENT == "production" and self.MANUAL_TEST_DASHBOARD_ENABLED:
            raise ValueError("manual test dashboard is unavailable in production")
        return self


settings = Settings()
