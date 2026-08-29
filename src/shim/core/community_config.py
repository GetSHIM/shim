"""Validated configuration required by the community gateway runtime."""

from __future__ import annotations

import json
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class CommunitySettings(BaseSettings):
    PROJECT_NAME: str = "shim trust-boundary gateway"
    VERSION: str = "0.1.0"
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
    PRIVACY_CHAIN_TTL_SECONDS: int = Field(
        default=30 * 24 * 60 * 60,
        ge=60,
        le=30 * 24 * 60 * 60,
    )

    DEFAULT_RPM_LIMIT: int = Field(default=60, ge=1)
    DEFAULT_TPM_LIMIT: int = Field(default=10_000, ge=1)
    COST_TAG_MAX_LENGTH: int = Field(default=64, ge=1, le=256)

    LOOP_REPEAT_LIMIT: int = Field(default=8, ge=2, le=100)
    LOOP_WINDOW_SECONDS: int = Field(default=300, ge=1, le=3_600)

    SENTRY_DSN: str | None = None
    OTEL_EXPORTER_OTLP_ENDPOINT: str | None = None
    OTEL_SERVICE_NAME: str = "ai-gateway-optimizer"

    @field_validator("TRUSTED_PROXIES", "BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def parse_csv_list(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith("["):
                return json.loads(stripped)
            return [item.strip() for item in stripped.split(",") if item.strip()]
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
