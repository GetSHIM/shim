"""Validated deployment configuration for the documented shim architecture."""

from __future__ import annotations

from typing import Literal, Self
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
    ] = "fernet"

    SUPABASE_URL: str
    SUPABASE_KEY: str | None = None

    LEMON_SQUEEZY_SIGNING_SECRET: str | None = None
    LEMON_SQUEEZY_SOLO_PRO_MONTHLY_VARIANT_ID: str | None = None
    LEMON_SQUEEZY_SOLO_PRO_YEARLY_VARIANT_ID: str | None = None
    LEMON_SQUEEZY_AGENCY_MONTHLY_VARIANT_ID: str | None = None
    LEMON_SQUEEZY_AGENCY_YEARLY_VARIANT_ID: str | None = None
    LEMON_SQUEEZY_SOLO_PRO_MONTHLY_CHECKOUT_URL: str | None = None
    LEMON_SQUEEZY_SOLO_PRO_YEARLY_CHECKOUT_URL: str | None = None
    LEMON_SQUEEZY_AGENCY_MONTHLY_CHECKOUT_URL: str | None = None
    LEMON_SQUEEZY_AGENCY_YEARLY_CHECKOUT_URL: str | None = None

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

    @field_validator(
        "LEMON_SQUEEZY_SOLO_PRO_MONTHLY_CHECKOUT_URL",
        "LEMON_SQUEEZY_SOLO_PRO_YEARLY_CHECKOUT_URL",
        "LEMON_SQUEEZY_AGENCY_MONTHLY_CHECKOUT_URL",
        "LEMON_SQUEEZY_AGENCY_YEARLY_CHECKOUT_URL",
        mode="before",
    )
    @classmethod
    def validate_checkout_url(cls, value: object) -> object:
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        if not isinstance(value, str):
            raise ValueError("checkout URL must be an absolute HTTPS URL")
        parsed = urlsplit(value)
        if parsed.scheme != "https" or parsed.hostname is None:
            raise ValueError("checkout URL must be an absolute HTTPS URL")
        return value

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
        if self.ENVIRONMENT == "production" and self.SECRET_BACKEND == "fernet":
            raise ValueError("production requires a managed secret backend")
        if self.ENVIRONMENT == "production" and self.MANUAL_TEST_DASHBOARD_ENABLED:
            raise ValueError("manual test dashboard is unavailable in production")
        return self


settings = Settings()
