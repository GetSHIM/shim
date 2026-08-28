"""Typed values passed between gateway-kernel stages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from shim.billing.pricing import (
    UNSPECIFIED_PROVIDER_MODEL as UNSPECIFIED_PROVIDER_MODEL,
)
from shim.gateway.contracts.context import GatewayContext
from shim.gateway.contracts.ids import ProviderId
from shim.gateway.request_policy import RequestPolicyContext as _RequestPolicyContext
from shim.privacy.policies import PrivacyOutcome


@dataclass(frozen=True)
class AdmissionState:
    estimated_input_tokens: int
    maximum_output_tokens: int
    cost_center: str
    tags: tuple[str, ...]


@dataclass(frozen=True)
class PreparedInference:
    """One validated native provider request plus trusted gateway state."""

    context: GatewayContext
    payload: dict[str, Any]
    provider: ProviderId
    protocol: Literal["chat", "responses", "messages", "generate_content"]
    model: str
    stream: bool
    policy: _RequestPolicyContext
    pii_config: dict[str, bool] | None
    admission: AdmissionState | None = None
    privacy: PrivacyOutcome | None = None

    @property
    def request_id(self):
        return self.context.request_id

    @property
    def tenant_id(self):
        return self.context.tenant_id

    @property
    def api_key_id(self):
        return self.context.api_key_id

    @property
    def source_endpoint(self) -> str:
        return {
            "chat": "chat.completions",
            "responses": "responses",
            "messages": "messages",
            "generate_content": "generateContent",
        }[self.protocol]
