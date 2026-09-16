"""Validated cloud-only billing configuration."""

from typing import Literal, Self
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


ProductKey = Literal[
    "managed:monthly", "managed:yearly", "agency:monthly", "agency:yearly"
]


class CloudSettings(BaseSettings):
    POLAR_ACCESS_TOKEN: SecretStr = Field(min_length=1)
    POLAR_WEBHOOK_SECRET: SecretStr = Field(min_length=1)
    POLAR_ORGANIZATION_ID: UUID
    POLAR_SERVER: Literal["sandbox", "production"] = "sandbox"
    POLAR_PRODUCTS: dict[ProductKey, UUID]
    CLOUD_DASHBOARD_URL: str
    CLOUD_BILLING_RECONCILE_SECONDS: int = Field(default=300, ge=30, le=3600)

    model_config = SettingsConfigDict(
        env_file="ee/cloud/.env", extra="ignore", hide_input_in_errors=True
    )

    @model_validator(mode="after")
    def validate_billing_configuration(self) -> Self:
        if not self.POLAR_PRODUCTS:
            raise ValueError("POLAR_PRODUCTS must map paid plan:interval choices")
        if len(set(self.POLAR_PRODUCTS.values())) != len(self.POLAR_PRODUCTS):
            raise ValueError(
                "Polar product IDs must identify exactly one plan/interval"
            )
        url = urlsplit(self.CLOUD_DASHBOARD_URL)
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
        if self.POLAR_SERVER == "production" and url.scheme != "https":
            raise ValueError("production billing requires an HTTPS dashboard")
        self.CLOUD_DASHBOARD_URL = self.CLOUD_DASHBOARD_URL.rstrip("/")
        return self

    @property
    def return_url(self) -> str:
        return f"{self.CLOUD_DASHBOARD_URL}/dashboard/workspace/subscription"
