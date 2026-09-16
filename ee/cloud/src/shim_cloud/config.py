"""Validated cloud-only billing configuration."""

from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import Field, SecretStr, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


ProductKey = Literal[
    "managed:monthly", "managed:yearly", "agency:monthly", "agency:yearly"
]


class CloudSettings(BaseSettings):
    POLAR_ACCESS_TOKEN: SecretStr = Field(min_length=1)
    POLAR_WEBHOOK_SECRET: SecretStr = Field(min_length=1)
    POLAR_ORGANIZATION_ID: UUID
    POLAR_SERVER: Literal["sandbox", "production"] = "sandbox"
    POLAR_PRODUCTS: dict[ProductKey, UUID] = Field(min_length=1)
    CLOUD_DASHBOARD_URL: str
    CLOUD_BILLING_RECONCILE_SECONDS: int = Field(default=300, ge=30, le=3600)

    model_config = SettingsConfigDict(
        env_file="ee/cloud/.env", extra="ignore", hide_input_in_errors=True
    )

    @field_validator("POLAR_PRODUCTS")
    @classmethod
    def validate_products(cls, value: dict[ProductKey, UUID]) -> dict[ProductKey, UUID]:
        if len(set(value.values())) != len(value):
            raise ValueError(
                "Polar product IDs must identify exactly one plan/interval"
            )
        return value

    @field_validator("CLOUD_DASHBOARD_URL")
    @classmethod
    def validate_dashboard_url(cls, value: str, info: ValidationInfo) -> str:
        url = urlsplit(value)
        if (
            url.scheme not in {"https", "http"}
            or not url.hostname
            or url.username
            or url.password
            or url.path not in {"", "/"}
            or url.query
            or url.fragment
        ):
            raise ValueError("CLOUD_DASHBOARD_URL must be an HTTP(S) origin")
        if info.data.get("POLAR_SERVER") == "production" and url.scheme != "https":
            raise ValueError("production billing requires an HTTPS dashboard")
        return value.rstrip("/")

    @property
    def return_url(self) -> str:
        return f"{self.CLOUD_DASHBOARD_URL}/dashboard/workspace/subscription"
