"""Validated configuration required by the community gateway runtime."""

from __future__ import annotations

from decimal import Decimal
import json
from pathlib import Path
import re
from typing import Annotated, Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import (
    Field,
    SecretStr,
    StringConstraints,
    ValidationInfo,
    ValidatorFunctionWrapHandler,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from shim.billing.pricing import DEFAULT_PRICE_BOOK
from shim.gateway.analyzers import ANALYZER_NAMES, ANALYZERS
from shim.privacy.policies import EntityAction, effective_entity_actions


# An Azure OpenAI deployment name, in settings and in enterprise registry rows.
AZURE_DEPLOYMENT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class CommunitySettings(BaseSettings):
    PROJECT_NAME: str = "shim trust-boundary gateway"
    VERSION: str = "0.3.0"
    ENVIRONMENT: Literal["development", "test", "production"] = "development"
    IS_DEBUG: bool = False
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    SHIM_API_KEY: SecretStr | None = Field(default=None, min_length=16)

    MAX_REQUEST_BODY_SIZE: int = Field(default=32_000_000, ge=1_024)
    TRUSTED_PROXIES: Annotated[list[str], NoDecode] = Field(default_factory=list)
    BACKEND_CORS_ORIGINS: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            "https://getshim.tech",
            "https://www.getshim.tech",
            "https://app.getshim.tech",
        ]
    )
    CHROME_EXTENSION_ID: str | None = None

    OPENAI_BASE_URL: str | None = None
    OPENAI_CONNECT_TIMEOUT_SECONDS: float = Field(default=5, gt=0)
    OPENAI_READ_TIMEOUT_SECONDS: float = Field(default=600, gt=0)
    OPENAI_WRITE_TIMEOUT_SECONDS: float = Field(default=600, gt=0)
    OPENAI_POOL_TIMEOUT_SECONDS: float = Field(default=600, gt=0)
    ANTHROPIC_BASE_URL: str | None = None
    ANTHROPIC_CONNECT_TIMEOUT_SECONDS: float = Field(default=5, gt=0)
    ANTHROPIC_READ_TIMEOUT_SECONDS: float = Field(default=600, gt=0)
    ANTHROPIC_WRITE_TIMEOUT_SECONDS: float = Field(default=600, gt=0)
    ANTHROPIC_POOL_TIMEOUT_SECONDS: float = Field(default=600, gt=0)
    GOOGLE_BASE_URL: str = "https://generativelanguage.googleapis.com"
    GOOGLE_TIMEOUT_SECONDS: float = Field(default=60, gt=0)
    PII_ENTITY_ACTIONS: Annotated[dict[str, EntityAction], NoDecode] = Field(
        default_factory=dict
    )
    PII_PLACEHOLDER_MODE: Literal["random", "stable"] = "random"
    PII_PLACEHOLDER_KEY: SecretStr | None = Field(
        default=None, min_length=32, validate_default=True
    )
    SYSTEM_PROMPT_HASH_KEY: SecretStr | None = Field(default=None, min_length=32)
    PII_BULK_THRESHOLD: int = Field(default=50, ge=0)
    PII_RESPONSE_SCAN: Literal["off", "count"] = "off"
    SHIM_RESPONSE_ANALYSIS: Annotated[list[str], NoDecode] = Field(default_factory=list)
    PII_EMBEDDINGS_MONITOR: Annotated[list[str], NoDecode] = Field(default_factory=list)
    SHIM_INJECTION_MARKERS: Literal["off", "count", "warn"] = "off"
    SHIM_PRICE_TIER_WARNING: Literal["off", "on"] = "off"
    SHIM_TRACE_PARENT: Literal["ignore", "honor"] = "ignore"
    SHIM_TASK_MAX_CALLS: int | None = Field(default=None, ge=1, le=100_000)
    SHIM_TASK_MAX_COST_USD: Decimal | None = Field(default=None, gt=0, le=100_000)
    SHIM_TASK_WINDOW_SECONDS: int = Field(default=3600, ge=60, le=86_400)
    SHIM_AGENT_LOOP: Literal["off", "count", "block"] = "count"
    SHIM_AGENT_LOOP_REPEATS: int = Field(default=5, ge=3, le=100)
    SHIM_INFLIGHT_SHARING: Literal["off", "on"] = "off"
    SHIM_ANTHROPIC_AUTO_CACHE: Literal["off", "5m", "1h"] = "off"
    SHIM_OPENAI_PROMPT_CACHE_KEY: Literal["off", "key", "tenant"] = "off"
    SHIM_TOOL_SEARCH: Literal["off", "regex", "bm25"] = "off"
    SHIM_TOOL_SEARCH_MIN_TOOLS: int = Field(default=10, ge=2, le=10_000)
    SHIM_TOOL_SEARCH_KEEP_LOADED: Annotated[
        list[Annotated[str, StringConstraints(min_length=1, max_length=128)]],
        NoDecode,
    ] = Field(default_factory=list, max_length=64)
    SHIM_ANTHROPIC_KEEP_THINKING_TURNS: int = Field(default=0, ge=0, le=8)
    SHIM_OPENAI_REASONING_CONTEXT: Literal["off", "current_turn"] = "off"
    SHIM_JSON_COMPACTION: Literal["off", "on"] = "off"
    SHIM_MODEL_LIFECYCLE_FILE: Path | None = None
    SHIM_MODEL_RETIRING_WARNING: Literal["record", "header"] = "record"
    # Azure OpenAI v1 for catalog routes: an Azure key or an Entra app (S52).
    SHIM_AZURE_OPENAI_ENDPOINT: str | None = None
    SHIM_AZURE_OPENAI_API_KEY: SecretStr | None = None
    # The shapes EntraClientCredential takes, checked when the settings load.
    SHIM_AZURE_TENANT_ID: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9.-]{1,128}$"
    )
    SHIM_AZURE_CLIENT_ID: UUID | None = None
    SHIM_AZURE_CLIENT_SECRET: SecretStr | None = None
    SHIM_AZURE_TOKEN_SCOPE: str = Field(
        default="https://cognitiveservices.azure.com/.default",
        pattern=r"^https://\S{1,240}/\.default$",
    )
    SHIM_AZURE_AUTHORITY_HOST: str = "https://login.microsoftonline.com"
    SHIM_AZURE_OPENAI_DEPLOYMENTS: Annotated[dict[str, str], NoDecode] = Field(
        default_factory=dict
    )
    PRIVACY_CHAIN_TTL_SECONDS: int = Field(
        default=30 * 24 * 60 * 60,
        ge=60,
        le=30 * 24 * 60 * 60,
    )

    GLOBAL_RATE_LIMIT_PER_MINUTE: int = Field(default=1000, ge=1)
    DEFAULT_RPM_LIMIT: int = Field(default=60, ge=1)
    DEFAULT_TPM_LIMIT: int = Field(default=1_000_000, ge=1)
    COST_TAG_MAX_LENGTH: int = Field(default=64, ge=1, le=256)

    LOOP_REPEAT_LIMIT: int = Field(default=8, ge=2, le=100)
    LOOP_WINDOW_SECONDS: int = Field(default=300, ge=1, le=3_600)

    SENTRY_DSN: str | None = None
    OTEL_EXPORTER_OTLP_ENDPOINT: str | None = None
    OTEL_SERVICE_NAME: str = "shim"

    @field_validator(
        "TRUSTED_PROXIES",
        "BACKEND_CORS_ORIGINS",
        "SHIM_RESPONSE_ANALYSIS",
        "PII_EMBEDDINGS_MONITOR",
        "SHIM_TOOL_SEARCH_KEEP_LOADED",
        mode="before",
    )
    @classmethod
    def parse_csv_list(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith("["):
                return json.loads(stripped)
            return [item.strip() for item in stripped.split(",") if item.strip()]
        return value

    @field_validator("SHIM_RESPONSE_ANALYSIS")
    @classmethod
    def known_analyzers_in_registry_order(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - ANALYZER_NAMES)
        if unknown:
            raise ValueError(f"unknown analyzer: {', '.join(unknown)}")
        return [analyzer.name for analyzer in ANALYZERS if analyzer.name in value]

    @field_validator(
        "OPENAI_BASE_URL",
        "SHIM_AZURE_OPENAI_ENDPOINT",
        "SHIM_AZURE_OPENAI_API_KEY",
        "SHIM_AZURE_TENANT_ID",
        "SHIM_AZURE_CLIENT_ID",
        "SHIM_AZURE_CLIENT_SECRET",
        mode="before",
    )
    @classmethod
    def empty_is_unset(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("SHIM_AZURE_OPENAI_DEPLOYMENTS", mode="before")
    @classmethod
    def parse_deployments(cls, value: object) -> object:
        if isinstance(value, str):
            return json.loads(value) if value.strip() else {}
        return value

    @model_validator(mode="after")
    def azure_is_one_coherent_route(self) -> CommunitySettings:
        endpoint = self.SHIM_AZURE_OPENAI_ENDPOINT
        named = {
            "SHIM_AZURE_TENANT_ID": self.SHIM_AZURE_TENANT_ID,
            "SHIM_AZURE_CLIENT_ID": self.SHIM_AZURE_CLIENT_ID,
            "SHIM_AZURE_CLIENT_SECRET": self.SHIM_AZURE_CLIENT_SECRET,
        }
        entra = list(named.values())
        if endpoint is None:
            if given := [name for name, value in named.items() if value]:
                raise ValueError(f"{given[0]} needs SHIM_AZURE_OPENAI_ENDPOINT")
            if self.SHIM_AZURE_OPENAI_DEPLOYMENTS:
                raise ValueError(
                    "SHIM_AZURE_OPENAI_DEPLOYMENTS needs SHIM_AZURE_OPENAI_ENDPOINT"
                )
            return self
        if self.OPENAI_BASE_URL is not None:
            raise ValueError(
                "SHIM_AZURE_OPENAI_ENDPOINT and OPENAI_BASE_URL exclude each other"
            )
        endpoint = endpoint.strip().rstrip("/").removesuffix("/openai/v1")
        parts = urlsplit(endpoint)
        if not (
            parts.scheme == "https"
            or (
                parts.scheme == "http"
                and parts.hostname in {"127.0.0.1", "::1", "localhost"}
            )
        ):
            raise ValueError(
                "SHIM_AZURE_OPENAI_ENDPOINT must be https (http only on loopback)"
            )
        self.SHIM_AZURE_OPENAI_ENDPOINT = endpoint
        if (self.SHIM_AZURE_OPENAI_API_KEY is not None) == all(entra) or (
            any(entra) and not all(entra)
        ):
            raise ValueError(
                "SHIM_AZURE_OPENAI_ENDPOINT needs SHIM_AZURE_OPENAI_API_KEY or all three "
                "SHIM_AZURE_TENANT_ID, SHIM_AZURE_CLIENT_ID and SHIM_AZURE_CLIENT_SECRET"
            )
        deployments = self.SHIM_AZURE_OPENAI_DEPLOYMENTS
        catalog = set(DEFAULT_PRICE_BOOK.models("openai"))
        if (
            len(deployments) > 200
            or not set(deployments) <= catalog
            or not all(
                AZURE_DEPLOYMENT_NAME.fullmatch(name) for name in deployments.values()
            )
        ):
            raise ValueError(
                "SHIM_AZURE_OPENAI_DEPLOYMENTS maps at most 200 catalog OpenAI models to "
                "Azure deployment names"
            )
        return self

    @field_validator("PII_EMBEDDINGS_MONITOR")
    @classmethod
    def known_entity_types(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - set(effective_entity_actions()))
        if unknown:
            raise ValueError(f"unknown entity type: {', '.join(unknown)}")
        return sorted(set(value))

    @field_validator("PII_ENTITY_ACTIONS", mode="wrap")
    @classmethod
    def parse_entity_actions(
        cls, value: object, handler: ValidatorFunctionWrapHandler
    ) -> dict[str, EntityAction]:
        actions = handler(json.loads(value) if isinstance(value, str) else value)
        effective_entity_actions(None, actions)
        return actions

    @field_validator("PII_PLACEHOLDER_KEY")
    @classmethod
    def require_a_key_for_stable_placeholders(
        cls, value: SecretStr | None, info: ValidationInfo
    ) -> SecretStr | None:
        if value is None and info.data.get("PII_PLACEHOLDER_MODE") == "stable":
            raise ValueError("required when PII_PLACEHOLDER_MODE is stable")
        return value

    @field_validator("PII_BULK_THRESHOLD")
    @classmethod
    def reject_a_bulk_threshold_of_one(cls, value: int) -> int:
        if value == 1:
            raise ValueError("must be 0 (off) or at least 2")
        return value

    @field_validator("SHIM_API_KEY")
    @classmethod
    def reject_whitespace_in_shim_api_key(
        cls,
        value: SecretStr | None,
    ) -> SecretStr | None:
        if value is not None and any(
            character.isspace() for character in value.get_secret_value()
        ):
            raise ValueError("SHIM_API_KEY must not contain whitespace")
        return value

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
        hide_input_in_errors=True,
    )
