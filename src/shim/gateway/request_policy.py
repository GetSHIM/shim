"""Session-free request-policy contracts and local policy resolution."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
from typing import Annotated, Any, Literal, Protocol

from pydantic import Field, SecretBytes, StringConstraints

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


class BandSettings(FrozenContractModel):
    """The tenant's settings band switches, each off by default."""

    anthropic_auto_cache: Literal["off", "5m", "1h"] = "off"
    openai_prompt_cache_key: Literal["off", "key", "tenant"] = "off"
    # Enterprise: registry aliases the band's provider steps may touch.
    provider_cache_deployments: tuple[str, ...] = Field(default=(), max_length=100)
    tool_search: Literal["off", "regex", "bm25"] = "off"
    tool_search_min_tools: int = Field(default=10, ge=2, le=10_000)
    tool_search_keep_loaded: tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=128)], ...
    ] = Field(default=(), max_length=64)
    # Enterprise: the keys tool search applies to; empty is every key.
    tool_search_api_key_ids: tuple[str, ...] = Field(default=(), max_length=100)
    anthropic_keep_thinking_turns: int = Field(default=0, ge=0, le=8)
    openai_reasoning_context: Literal["off", "current_turn"] = "off"
    # The transform band's switch; it never starts the settings band.
    json_compaction: bool = False

    @property
    def on(self) -> bool:
        """A switch is on; the lists and the minimum alone start nothing."""
        return (
            self.anthropic_auto_cache != "off"
            or self.openai_prompt_cache_key != "off"
            or self.tool_search != "off"
            or self.anthropic_keep_thinking_turns > 0
            or self.openai_reasoning_context != "off"
        )


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
    media_inputs: Literal["block", "allow"] = "block"
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
    band: BandSettings = BandSettings()
    rules: RuleSet | None = None
    # Enterprise: the loaded record sets the rules reference, by set id.
    record_sets: Mapping[str, Any] | None = None
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
        "_band",
        "_bulk_threshold",
        "_embeddings_monitor_types",
        "_entity_actions",
        "_inflight_sharing",
        "_model_retiring_warning",
        "_injection_markers",
        "_media_inputs",
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
        media_inputs: Literal["block", "allow"] = "block",
        price_tier_warning: bool = False,
        task_caps: TaskCaps = TaskCaps(),
        agent_loop: AgentLoop = AgentLoop(),
        inflight_sharing: bool = False,
        model_retiring_warning: Literal["record", "header"] = "record",
        embeddings_monitor_types: frozenset[str] = frozenset(),
        band: BandSettings = BandSettings(),
    ) -> None:
        self._rate_limit_rpm = rate_limit_rpm
        self._rate_limit_tpm = rate_limit_tpm
        self._entity_actions = entity_actions
        self._placeholder_key = placeholder_key
        self._bulk_threshold = bulk_threshold
        self._response_scan: Literal["off", "count"] = response_scan
        self._response_analysis = response_analysis
        self._injection_markers: Literal["off", "count", "warn"] = injection_markers
        self._media_inputs: Literal["block", "allow"] = media_inputs
        self._price_tier_warning = price_tier_warning
        self._task_caps = task_caps
        self._agent_loop = agent_loop
        self._inflight_sharing = inflight_sharing
        self._model_retiring_warning: Literal["record", "header"] = (
            model_retiring_warning
        )
        self._embeddings_monitor_types = embeddings_monitor_types
        self._band = band

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
            media_inputs=self._media_inputs,
            price_tier_warning=self._price_tier_warning,
            task_caps=self._task_caps,
            agent_loop=self._agent_loop,
            inflight_sharing=self._inflight_sharing,
            model_retiring_warning=self._model_retiring_warning,
            embeddings_monitor_types=self._embeddings_monitor_types,
            band=self._band,
        )
