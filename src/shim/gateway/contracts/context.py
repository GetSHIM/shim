from typing import Literal, Self

from pydantic import (
    AwareDatetime,
    Field,
    model_validator,
)

from .ids import ApiKeyId, ProviderId, RequestId, TenantId, UserId
from . import FrozenContractModel
from .principal import ActorType, validate_actor_identity


class TenantPolicy(FrozenContractModel):
    allowed_providers: tuple[ProviderId, ...] = ()
    allowed_regions: tuple[str, ...] = ()
    require_zero_retention: bool = False


class TierPolicy(FrozenContractModel):
    rate_limit_rpm: int | None = Field(default=None, ge=0)
    rate_limit_tpm: int | None = Field(default=None, ge=0)
    daily_request_limit: int | None = Field(default=None, ge=0)
    monthly_request_limit: int | None = Field(default=None, ge=0)
    monthly_token_limit: int | None = Field(default=None, ge=0)


class PrivacyPolicy(FrozenContractModel):
    pii_mode: Literal["disabled", "detect", "scrub"]


class AuditPolicy(FrozenContractModel):
    mode: Literal["off", "best_effort", "strict"]


class GatewayContext(FrozenContractModel):
    request_id: RequestId
    tenant_id: TenantId
    actor_type: ActorType
    api_key_id: ApiKeyId | None = None
    user_id: UserId | None = None
    endpoint: str
    started_at: AwareDatetime
    tier_policy: TierPolicy
    privacy_policy: PrivacyPolicy
    audit_policy: AuditPolicy

    @model_validator(mode="after")
    def validate_actor_shape(self) -> Self:
        validate_actor_identity(self.actor_type, self.api_key_id, self.user_id)
        return self
