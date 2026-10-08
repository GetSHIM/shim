"""Session-free request-policy contracts and local policy resolution."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol

from pydantic import SecretBytes

from shim.gateway.contracts import FrozenContractModel
from shim.gateway.contracts.context import AuditPolicy, TenantPolicy, TierPolicy
from shim.gateway.contracts.ids import TenantId
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.gateway.local_auth import LOCAL_API_KEY_ID, LOCAL_TENANT_ID
from shim.privacy.policies import EntityAction, effective_pii_config


@dataclass(frozen=True, slots=True)
class RequestPolicyContext:
    rate_limit_key_hash: str
    tier: str
    cost_center: str | None = None
    team: str | None = None


class ResolvedRequestPolicy(FrozenContractModel):
    tenant_id: TenantId
    tenant_policy: TenantPolicy
    tier_policy: TierPolicy
    audit_policy: AuditPolicy
    request_policy: RequestPolicyContext
    pii_config: dict[str, bool] | None
    entity_actions: Mapping[str, EntityAction] | None = None
    # Stable-placeholder root key; None keeps placeholders random.
    placeholder_key: SecretBytes | None = None


class RequestPolicyResolver(Protocol):
    async def resolve(
        self,
        principal: AuthenticatedPrincipal,
    ) -> ResolvedRequestPolicy: ...


class LocalRequestPolicyResolver:
    """Resolve the fixed single-user community policy."""

    __slots__ = (
        "_entity_actions",
        "_placeholder_key",
        "_rate_limit_rpm",
        "_rate_limit_tpm",
    )

    def __init__(
        self,
        *,
        rate_limit_rpm: int,
        rate_limit_tpm: int,
        entity_actions: Mapping[str, EntityAction] | None = None,
        placeholder_key: SecretBytes | None = None,
    ) -> None:
        self._rate_limit_rpm = rate_limit_rpm
        self._rate_limit_tpm = rate_limit_tpm
        self._entity_actions = entity_actions
        self._placeholder_key = placeholder_key

    async def resolve(
        self,
        principal: AuthenticatedPrincipal,
    ) -> ResolvedRequestPolicy:
        if (
            principal.actor_type != "api_key"
            or principal.api_key_id != LOCAL_API_KEY_ID
        ):
            raise ValueError("community gateway requires its local API-key principal")
        return ResolvedRequestPolicy(
            tenant_id=LOCAL_TENANT_ID,
            tenant_policy=TenantPolicy(),
            tier_policy=TierPolicy(
                rate_limit_rpm=self._rate_limit_rpm,
                rate_limit_tpm=self._rate_limit_tpm,
                daily_request_limit=None,
                monthly_request_limit=None,
                monthly_token_limit=None,
            ),
            audit_policy=AuditPolicy(mode="off"),
            request_policy=RequestPolicyContext(
                rate_limit_key_hash=sha256(str(LOCAL_API_KEY_ID).encode()).hexdigest(),
                tier="local",
            ),
            pii_config=effective_pii_config(),
            entity_actions=self._entity_actions,
            placeholder_key=self._placeholder_key,
        )
