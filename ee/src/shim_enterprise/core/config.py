"""Validated deployment configuration for the documented shim architecture."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal, Self
from uuid import UUID
from urllib.parse import urlsplit

from pydantic import (
    AliasChoices,
    EmailStr,
    Field,
    RedisDsn,
    field_validator,
    model_validator,
)
from pydantic_settings import SettingsConfigDict

from shim.core.community_config import CommunitySettings


class Settings(CommunitySettings):
    # The fallback for a tier without rate_limit_tpm keeps its enterprise value.
    DEFAULT_TPM_LIMIT: int = Field(default=10_000, ge=1)
    MODEL_DEPLOYMENT_REQUIRED: bool = False
    # Shadow copies of finished requests running at once per process; more are dropped.
    SHADOW_MAX_IN_FLIGHT: int = Field(default=4, ge=1, le=64)
    MODEL_DEPLOYMENT_ALLOWED_ORIGINS: list[str] = []
    # Host suffixes such as .openai.azure.com, approved for https on port 443 only.
    MODEL_DEPLOYMENT_ALLOWED_ORIGIN_SUFFIXES: list[str] = []
    # Empty: a deployment is internal when its tenant says so.
    MODEL_DEPLOYMENT_INTERNAL_ORIGINS: list[str] = []
    # Where AWS is reached; a VPC interface endpoint or a test double replaces them.
    AWS_BEDROCK_RUNTIME_URL_TEMPLATE: str = (
        "https://bedrock-runtime.{region}.amazonaws.com"
    )
    AWS_BEDROCK_CONTROL_URL_TEMPLATE: str = "https://bedrock.{region}.amazonaws.com"
    AWS_STS_URL_TEMPLATE: str = "https://sts.{region}.amazonaws.com"
    # The gateway's own AWS identity, the one that assumes tenants' roles. Chosen by
    # the operator; no metadata address is probed unless chosen here.
    AWS_GATEWAY_IDENTITY: Literal[
        "none", "env", "web_identity_file", "container", "imds", "gcp_metadata"
    ] = "none"
    AWS_GATEWAY_PRINCIPAL_ARN: str | None = None
    AWS_GCP_SERVICE_ACCOUNT_ID: str | None = Field(default=None, pattern=r"^\d{1,32}$")
    AWS_GCP_METADATA_URL: str = "http://metadata.google.internal"
    AWS_IMDS_URL: str = "http://169.254.169.254"
    AWS_ROLE_SESSION_SECONDS: int = Field(default=3_600, ge=900, le=3_600)
    ALERT_ALLOWED_ORIGINS: list[str] = []
    # The model-deployment name shipped in 0.1.4; existing installs still set it.
    OUTBOUND_CA_BUNDLE: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "OUTBOUND_CA_BUNDLE", "MODEL_DEPLOYMENT_CA_BUNDLE"
        ),
    )

    API_PREFIX: Literal["/api/v1"] = "/api/v1"

    DATABASE_URL: str
    DATABASE_POOL_SIZE: int = Field(default=2, ge=1)
    DATABASE_MAX_OVERFLOW: int = Field(default=1, ge=0)
    REDIS_URL: RedisDsn
    SECRET_KEY: str = Field(min_length=16)
    SHIM_LICENSE_KEY: str | None = None
    ENCRYPTION_KEY: str | None = None
    # Self-hosted only: lets tenants keep rule-matched requests, encrypted with
    # ENCRYPTION_KEY, for at most 90 days. The hosted cloud refuses to start with it.
    REQUEST_ARCHIVE_ENABLED: bool = False
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
    OIDC_GROUP_CUSTOM_ROLE_MAP: dict[str, str] = Field(default_factory=dict)
    OIDC_SESSION_SECONDS: int = Field(default=28_800, ge=60, le=86_400)
    OIDC_REVALIDATE_SECONDS: int = Field(default=60, ge=10, le=300)
    OIDC_API_AUDIENCE: str | None = None
    OIDC_API_MAX_TOKEN_SECONDS: int = Field(default=300, ge=60, le=900)
    DASHBOARD_ORIGIN: str | None = None
    SUPABASE_KEY: str | None = None

    MANUAL_TEST_DASHBOARD_ENABLED: bool = False
    SHIM_TEST_USER_EMAIL: str | None = None

    DEFAULT_MONTHLY_TOKEN_LIMIT: int = Field(default=1_000_000, ge=0)

    WORKER_HEARTBEAT_PATH: Path | None = None

    GATEWAY_RECONCILIATION_GRACE_SECONDS: int = Field(default=120, ge=30, le=3_600)
    GATEWAY_RECONCILIATION_INTERVAL_SECONDS: int = Field(default=30, ge=5, le=3_600)
    GATEWAY_RECONCILIATION_BATCH_SIZE: int = Field(default=100, ge=1, le=1_000)
    BUDGET_EVALUATION_INTERVAL_SECONDS: int = Field(default=300, ge=30, le=86_400)
    FINDINGS_EVALUATION_INTERVAL_SECONDS: int = Field(default=900, ge=60, le=86_400)
    # How often the reconciliation worker reads the metrics of the model servers
    # tenants listed in their inference_metrics setting.
    INFERENCE_METRICS_INTERVAL_SECONDS: int = Field(default=60, ge=15, le=3_600)
    # How long past a remediation's window to wait for refusals still in the outbox.
    REMEDIATION_WINDOW_GRACE_SECONDS: int = Field(default=900, ge=0, le=3_600)

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
    # Copies of the audit chain, anchors and monthly files in an S3 bucket with
    # Object Lock; the bucket's default retention decides, never shim.
    WORM_ARCHIVE_ENABLED: bool = False
    WORM_ARCHIVE_BUCKET: str | None = None
    WORM_ARCHIVE_PREFIX: str = Field(default="shim", pattern=r"^[a-z0-9-]{1,100}$")
    WORM_ARCHIVE_ENDPOINT_URL: str | None = None
    WORM_ARCHIVE_REGION: str | None = None
    OVERSIGHT_DEFAULT_TTL_SECONDS: int = Field(default=3_600, ge=1)

    model_config = SettingsConfigDict(env_file="ee/.env")

    @field_validator("OIDC_TEAM_GROUP_MAP")
    @classmethod
    def validate_oidc_team_mapping(
        cls, value: dict[str, dict[str, str]]
    ) -> dict[str, dict[str, str]]:
        for group, mapping in value.items():
            if (
                not group
                or set(mapping) != {"team_id", "role"}
                or mapping["role"] not in {"member", "team_admin"}
            ):
                raise ValueError(
                    "OIDC team mappings require group, team_id, and member/team_admin role"
                )
            UUID(mapping["team_id"])
        return value

    @field_validator("ALERT_ALLOWED_ORIGINS")
    @classmethod
    def validate_alert_origins(cls, value: list[str]) -> list[str]:
        error = (
            "ALERT_ALLOWED_ORIGINS entries must be exact https://host[:port] origins"
        )
        for origin in value:
            parsed = urlsplit(origin)
            try:
                parsed.port
            except ValueError:
                raise ValueError(error) from None
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(error)
        return value

    @field_validator(
        "AWS_BEDROCK_RUNTIME_URL_TEMPLATE",
        "AWS_BEDROCK_CONTROL_URL_TEMPLATE",
        "AWS_STS_URL_TEMPLATE",
    )
    @classmethod
    def validate_aws_url_template(cls, value: str) -> str:
        parsed = urlsplit(value.replace("{region}", "region"))
        if (
            value.count("{region}") > 1
            or value.replace("{region}", "").count("{")
            or value.replace("{region}", "").count("}")
            or parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "An AWS URL template is an absolute http(s) URL with no path, query "
                "or credentials and at most one {region}"
            )
        return value.rstrip("/")

    @model_validator(mode="after")
    def aws_identity_has_its_variables(self) -> Self:
        needed = {
            "env": [("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")],
            "web_identity_file": [("AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN")],
            "container": [
                ("AWS_CONTAINER_CREDENTIALS_FULL_URI",),
                ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",),
            ],
        }.get(self.AWS_GATEWAY_IDENTITY)
        if needed is not None and not any(
            all(os.environ.get(name) for name in group) for group in needed
        ):
            names = " or ".join(" and ".join(group) for group in needed)
            raise ValueError(
                f"AWS_GATEWAY_IDENTITY={self.AWS_GATEWAY_IDENTITY} needs {names}"
            )
        if (
            self.AWS_GATEWAY_IDENTITY == "gcp_metadata"
            and self.AWS_GCP_SERVICE_ACCOUNT_ID is None
        ):
            raise ValueError(
                "AWS_GATEWAY_IDENTITY=gcp_metadata needs AWS_GCP_SERVICE_ACCOUNT_ID"
            )
        return self

    @field_validator("MODEL_DEPLOYMENT_ALLOWED_ORIGIN_SUFFIXES")
    @classmethod
    def validate_origin_suffixes(cls, value: list[str]) -> list[str]:
        for suffix in value:
            labels = suffix.split(".")[1:]
            if (
                suffix != suffix.lower()
                or not suffix.startswith(".")
                or len(labels) < 2
                or not all(labels)
            ):
                raise ValueError(
                    "MODEL_DEPLOYMENT_ALLOWED_ORIGIN_SUFFIXES entries are lowercase, "
                    "start with a dot and have at least two labels"
                )
        return value

    @model_validator(mode="after")
    def azure_is_one_coherent_route(self) -> Self:
        # Enterprise reaches Azure through registry deployments, never these settings.
        return self

    @field_validator("WORKER_HEARTBEAT_PATH")
    @classmethod
    def validate_heartbeat_path(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_absolute():
            raise ValueError("worker heartbeat path must be absolute")
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
        if self.WORM_ARCHIVE_ENABLED and not self.WORM_ARCHIVE_BUCKET:
            raise ValueError("WORM_ARCHIVE_ENABLED requires WORM_ARCHIVE_BUCKET")
        if self.WORM_ARCHIVE_ENDPOINT_URL is not None:
            endpoint = urlsplit(self.WORM_ARCHIVE_ENDPOINT_URL)
            if (
                endpoint.scheme not in {"http", "https"}
                or not endpoint.hostname
                or endpoint.username
                or endpoint.password
                or (self.ENVIRONMENT == "production" and endpoint.scheme != "https")
            ):
                raise ValueError(
                    "WORM_ARCHIVE_ENDPOINT_URL must be an absolute URL without "
                    "credentials; production requires HTTPS"
                )
        if self.REQUEST_ARCHIVE_ENABLED and not self.ENCRYPTION_KEY:
            raise ValueError("REQUEST_ARCHIVE_ENABLED requires ENCRYPTION_KEY")
        if self.ENVIRONMENT == "production" and self.SECRET_BACKEND == "fernet":
            raise ValueError("production requires a managed secret backend")
        if self.ENVIRONMENT == "production" and self.MANUAL_TEST_DASHBOARD_ENABLED:
            raise ValueError("manual test dashboard is unavailable in production")
        return self


settings = Settings()
