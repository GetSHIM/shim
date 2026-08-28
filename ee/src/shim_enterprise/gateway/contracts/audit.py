from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import (
    AwareDatetime,
    Field,
    field_validator,
    model_validator,
)

from shim.gateway.contracts import FrozenContractModel
from shim.gateway.contracts.ids import (
    ApiKeyId,
    ModelId,
    ProviderId,
    RequestId,
    TenantId,
    UserId,
)
from shim.gateway.contracts.principal import ActorType, validate_actor_identity


AuditPolicyMode = Literal["off", "best_effort", "strict"]
UsageSummaryValue = int | Decimal
PiiEntityCount = Annotated[int, Field(ge=0)]
CompletionLifecycleStatus = Literal[
    "completed",
    "provider_error",
    "client_disconnected",
    "timeout",
    "cancelled",
    "internal_error",
    "rejected",
    "failed",
]
TERMINAL_LIFECYCLE_STATUSES = frozenset(
    {
        "completed",
        "provider_error",
        "client_disconnected",
        "timeout",
        "cancelled",
        "internal_error",
        "rejected",
        "failed",
    }
)


class _AuditRecord(FrozenContractModel):
    request_id: RequestId
    tenant_id: TenantId
    actor_type: ActorType
    api_key_id: ApiKeyId | None = None
    user_id: UserId | None = None
    audit_policy_mode: AuditPolicyMode
    input_hash: str | None = None
    output_hash: str | None = None
    pii_entities: dict[str, PiiEntityCount] = Field(default_factory=dict)
    provider: ProviderId | None = None
    model: ModelId | None = None
    usage_summary: dict[str, UsageSummaryValue] = Field(default_factory=dict)
    lifecycle_status: str = Field(min_length=1)
    outbox_event_id: UUID | None = None
    created_at: AwareDatetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @model_validator(mode="after")
    def validate_actor_shape(self) -> Self:
        validate_actor_identity(self.actor_type, self.api_key_id, self.user_id)
        return self


class AuditPreflightIntent(_AuditRecord):
    event_type: Literal["preflight"] = "preflight"

    @field_validator("lifecycle_status")
    @classmethod
    def validate_nonterminal_status(cls, lifecycle_status: str) -> str:
        if lifecycle_status in TERMINAL_LIFECYCLE_STATUSES:
            raise ValueError("preflight lifecycle_status must be nonterminal")
        return lifecycle_status


class AuditCompletion(_AuditRecord):
    event_type: Literal["completion"] = "completion"
    lifecycle_status: CompletionLifecycleStatus


def validate_audit_intent(
    tenant_id: TenantId,
    values: dict[str, object],
) -> AuditPreflightIntent | AuditCompletion:
    """Validate persistence input against the canonical audit contract."""

    payload = {**values, "tenant_id": tenant_id}
    event_type = payload.get("event_type")
    if event_type == "preflight":
        return AuditPreflightIntent.model_validate(payload)
    if event_type == "completion":
        return AuditCompletion.model_validate(payload)
    raise ValueError("audit event_type must be preflight or completion")
