"""Session-free request-policy contracts and local policy resolution."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
from typing import Literal, Protocol

from pydantic import Field, SecretBytes

from shim.gateway.contracts import FrozenContractModel
from shim.gateway.contracts.context import AuditPolicy, TenantPolicy, TierPolicy
from shim.gateway.contracts.ids import TenantId
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.gateway.local_auth import LOCAL_API_KEY_ID, LOCAL_TENANT_ID
from shim.privacy.policies import EntityAction, effective_pii_config
from shim.rules.model import RuleSet


@dataclass(frozen=True, slots=True)
class RequestPolicyContext:
    rate_limit_key_hash: str
    tier: str
    cost_center: str | None = None
    team: str | None = None
    team_id: str | None = None


class TaskCaps(FrozenContractModel):
    """Calls and settled cost one agent task may use; off until a cap is set."""

    max_calls: int | None = Field(default=None, ge=1, le=100_000)
    max_cost_usd: Decimal | None = Field(default=None, gt=0, le=100_000)
    window_seconds: int = Field(default=3600, ge=60, le=86_400)


class AgentLoop(FrozenContractModel):
    """What a tool call repeated in one task's history does: counted by default."""

    action: Literal["off", "count", "block"] = "count"
    repeats: int = Field(default=5, ge=3, le=100)


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
    bulk_threshold: int | None = None
    response_scan: Literal["off", "count"] = "off"
    response_analysis: tuple[str, ...] = ()
    injection_markers: Literal["off", "count", "warn"] = "off"
    price_tier_warning: bool = False
    model_retiring_warning: Literal["record", "header"] = "record"
    # Types an embeddings request only counts, where chat masks or blocks them.
    embeddings_monitor_types: frozenset[str] = frozenset()
    # Enterprise: entity types this caller's key and team may not see restored.
    restore_withheld: frozenset[str] = frozenset()
    task_caps: TaskCaps = TaskCaps()
    agent_loop: AgentLoop = AgentLoop()
    # The request's key may share an identical in-flight answer (S48).
    inflight_sharing: bool = False
    rules: RuleSet | None = None
    # Enterprise: the tenant's resolved gateway settings, read by its strategies; core never reads it.
    tenant_gateway_settings: object | None = None


class RequestPolicyResolver(Protocol):
    async def resolve(
        self,
        principal: AuthenticatedPrincipal,
    ) -> ResolvedRequestPolicy: ...


class LocalRequestPolicyResolver:
    """Resolve the fixed single-user community policy."""

    __slots__ = (
        "_agent_loop",
        "_bulk_threshold",
        "_embeddings_monitor_types",
        "_entity_actions",
        "_inflight_sharing",
        "_model_retiring_warning",
        "_injection_markers",
        "_placeholder_key",
        "_price_tier_warning",
        "_rate_limit_rpm",
        "_rate_limit_tpm",
        "_response_analysis",
        "_response_scan",
        "_task_caps",
    )

    def __init__(
        self,
        *,
        rate_limit_rpm: int,
        rate_limit_tpm: int,
        entity_actions: Mapping[str, EntityAction] | None = None,
        placeholder_key: SecretBytes | None = None,
        bulk_threshold: int | None = None,
        response_scan: Literal["off", "count"] = "off",
        response_analysis: tuple[str, ...] = (),
        injection_markers: Literal["off", "count", "warn"] = "off",
        price_tier_warning: bool = False,
        task_caps: TaskCaps = TaskCaps(),
        agent_loop: AgentLoop = AgentLoop(),
        inflight_sharing: bool = False,
        model_retiring_warning: Literal["record", "header"] = "record",
        embeddings_monitor_types: frozenset[str] = frozenset(),
    ) -> None:
        self._rate_limit_rpm = rate_limit_rpm
        self._rate_limit_tpm = rate_limit_tpm
        self._entity_actions = entity_actions
        self._placeholder_key = placeholder_key
        self._bulk_threshold = bulk_threshold
        self._response_scan: Literal["off", "count"] = response_scan
        self._response_analysis = response_analysis
        self._injection_markers: Literal["off", "count", "warn"] = injection_markers
        self._price_tier_warning = price_tier_warning
        self._task_caps = task_caps
        self._agent_loop = agent_loop
        self._inflight_sharing = inflight_sharing
        self._model_retiring_warning: Literal["record", "header"] = (
            model_retiring_warning
        )
        self._embeddings_monitor_types = embeddings_monitor_types

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
            bulk_threshold=self._bulk_threshold,
            response_scan=self._response_scan,
            response_analysis=self._response_analysis,
            injection_markers=self._injection_markers,
            price_tier_warning=self._price_tier_warning,
            task_caps=self._task_caps,
            agent_loop=self._agent_loop,
            inflight_sharing=self._inflight_sharing,
            model_retiring_warning=self._model_retiring_warning,
            embeddings_monitor_types=self._embeddings_monitor_types,
        )
