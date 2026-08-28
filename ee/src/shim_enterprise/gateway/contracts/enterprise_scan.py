"""Enterprise scan accounting contracts."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import Field, model_validator

from shim.gateway.contracts import FrozenContractModel
from shim.gateway.contracts.ids import ApiKeyId, RequestId, TenantId, UserId
from shim.gateway.contracts.inference import ScanEntity, ScanPolicy, ScanVerdict
from shim.gateway.contracts.principal import ActorType, validate_actor_identity


class ScanRequest(FrozenContractModel):
    request_id: RequestId
    tenant_id: TenantId
    actor_type: ActorType
    api_key_id: ApiKeyId | None
    user_id: UserId | None
    text: str = Field(max_length=50_000)
    source: Literal["chatgpt", "gemini", "unknown"]

    @model_validator(mode="after")
    def validate_actor_shape(self) -> ScanRequest:
        validate_actor_identity(self.actor_type, self.api_key_id, self.user_id)
        return self


class ScanUsageStatus(FrozenContractModel):
    scan_count: int = Field(ge=0)
    scan_limit: int = Field(ge=-1)
    scans_remaining: int = Field(ge=-1)
    resets_at: str | None


class ScanExecutionResult(ScanUsageStatus):
    request_id: RequestId
    verdict: ScanVerdict
    entities_found: list[ScanEntity]
    entity_types: list[str]
    policy: ScanPolicy
    audit_preflight_intent_id: UUID | None = None
    audit_completion_intent_id: UUID | None = None
