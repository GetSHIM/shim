"""Tenant gateway switches: one validated model, off by default, a direction per field."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import logging
import re
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from shim.gateway.analyzers import ANALYZER_NAMES, ANALYZERS
from shim.gateway.request_policy import AgentLoop, TaskCaps
from shim.privacy.policies import effective_entity_actions
from shim_enterprise.core.config import settings

logger = logging.getLogger(__name__)

Direction = Literal["tightening", "relaxing", "neutral"]
FourEyes = Literal["off", "relaxing"]
FindingMode = Literal["observe", "suggest", "auto"]
# Per field, the direction of a change from one value to another.
Directions = Mapping[str, Callable[[Any, Any], Direction]]
_logged_unknown: set[tuple[str, str]] = set()


def _known_analyzers(value: list[str]) -> list[str]:
    unknown = sorted(set(value) - ANALYZER_NAMES)
    if unknown:
        raise ValueError(f"unknown analyzer: {', '.join(unknown)}")
    if len(set(value)) != len(value):
        raise ValueError("analyzer names must be unique")
    return [analyzer.name for analyzer in ANALYZERS if analyzer.name in value]


# A tenant rule's placeholder label (shim.rules.content).
_RULE_LABEL = re.compile(r"[A-Z][A-Z0-9]{1,15}(?:_[A-Z0-9]{1,15})?")


class RestoreGrant(BaseModel):
    """Who gets a withheld type back: keys, and every key of the listed teams."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    team_ids: list[UUID] = Field(default=[], max_length=200)
    api_key_ids: list[UUID] = Field(default=[], max_length=200)


def _restorable_types[V](value: dict[str, V]) -> dict[str, V]:
    """Checked when written; a stored type this build does not know stays withheld."""
    if len(value) > 64:
        raise ValueError("at most 64 entity types")
    unknown = sorted(
        kind
        for kind in value
        if kind not in effective_entity_actions() and not _RULE_LABEL.fullmatch(kind)
    )
    if unknown:
        raise ValueError(f"unknown entity type or rule label: {', '.join(unknown)}")
    return value


def restore_relaxed(
    before: Mapping[str, RestoreGrant], after: Mapping[str, RestoreGrant]
) -> list[str]:
    """`restore_withheld.<TYPE>` for each type removed or granted to one more id."""
    return [
        f"restore_withheld.{kind}"
        for kind, grant in sorted(before.items())
        if kind not in after
        or not set(after[kind].team_ids) <= set(grant.team_ids)
        or not set(after[kind].api_key_ids) <= set(grant.api_key_ids)
    ]


class RequestArchiveSettings(BaseModel):
    """Keep rule-matched requests, encrypted, for at most 90 days (self-hosted only)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = False
    retention_days: int = Field(default=90, ge=1, le=90)


class RequestArchivePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    retention_days: int | None = Field(default=None, ge=1, le=90)


_Alias = Annotated[
    str,
    StringConstraints(
        min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$"
    ),
]


class ProviderCacheSettings(BaseModel):
    """The providers' own prompt-cache discount: two settings band steps (S54)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    anthropic_auto_cache: Literal["off", "5m", "1h"] = "off"
    openai_prompt_cache_key: Literal["off", "key", "tenant"] = "off"
    # Registry aliases the steps may touch; catalog routes always may.
    deployments: list[_Alias] = Field(default=[], max_length=100)


class ProviderCachePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    anthropic_auto_cache: Literal["off", "5m", "1h"] | None = None
    openai_prompt_cache_key: Literal["off", "key", "tenant"] | None = None
    deployments: list[_Alias] | None = Field(default=None, max_length=100)


_ToolName = Annotated[str, StringConstraints(min_length=1, max_length=128)]


class ToolSearchSettings(BaseModel):
    """Tools load on demand through the provider's tool search (S55)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: Literal["off", "regex", "bm25"] = "off"
    min_tools: int = Field(default=10, ge=2, le=10_000)
    keep_loaded: list[_ToolName] = Field(default=[], max_length=64)
    # Empty is every key.
    api_key_ids: list[UUID] = Field(default=[], max_length=100)


class ToolSearchPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["off", "regex", "bm25"] | None = None
    min_tools: int | None = Field(default=None, ge=2, le=10_000)
    keep_loaded: list[_ToolName] | None = Field(default=None, max_length=64)
    api_key_ids: list[UUID] | None = Field(default=None, max_length=100)


class ThinkingHistorySettings(BaseModel):
    """Earlier thinking stops being billed again (S55)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    anthropic_keep_turns: int = Field(default=0, ge=0, le=8)
    openai_reasoning_context: Literal["off", "current_turn"] = "off"


class ThinkingHistoryPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    anthropic_keep_turns: int | None = Field(default=None, ge=0, le=8)
    openai_reasoning_context: Literal["off", "current_turn"] | None = None


class TransformSettings(BaseModel):
    """Transform band steps: lossless content changes, each off by default (S56)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    json_compaction: Literal["off", "on"] = "off"


class TransformPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    json_compaction: Literal["off", "on"] | None = None


LockMode = Literal["off", "monitor", "enforce"]
# A profile prefix, or in_region (hence the underscore).
LockScope = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{1,15}$")]
# A region code or a geography prefix: eu-central-1, eu, us-gov.
LockRegion = Annotated[str, Field(pattern=r"^[a-z]{2}(-[a-z]+)*(-[0-9])?$")]
# A subset of AWS's tag value characters, without `|` (the credential reference's).
COST_TAG = r"^[A-Za-z0-9 _.:/=+@-]{1,256}$"
TagKey = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:/+@-]{1,128}$")]


def _unique(value: list[str]) -> list[str]:
    if len(set(value)) != len(value):
        raise ValueError("entries must be unique")
    return value


def _not_aws_prefix(value: str | None) -> str | None:
    if value is not None and value.lower().startswith("aws:"):
        raise ValueError("a tag key may not start with aws:")
    return value


class BedrockRegionLock(BaseModel):
    """Which Bedrock inference profiles a tenant's requests may use."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: LockMode = "off"
    # Profile prefixes (eu, us, apac, global) or in_region; empty allows any.
    scopes: list[LockScope] = Field(default=[], max_length=20)
    # Region codes or geography prefixes every destination must fall in; empty allows any.
    regions: list[LockRegion] = Field(default=[], max_length=50)

    @field_validator("scopes", "regions")
    @classmethod
    def unique(cls, value: list[str]) -> list[str]:
        return _unique(value)


class BedrockRegionLockPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: LockMode | None = None
    scopes: list[LockScope] | None = Field(default=None, max_length=20)
    regions: list[LockRegion] | None = Field(default=None, max_length=50)


class BedrockAttribution(BaseModel):
    """Session tags that carry each team onto the AWS bill (role credentials only)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: Literal["off", "session_tags"] = "off"
    tag_key: TagKey = "shim-team"
    unassigned_value: str = Field(default="unassigned", pattern=COST_TAG)

    @field_validator("tag_key")
    @classmethod
    def not_aws(cls, value: str | None) -> str | None:
        return _not_aws_prefix(value)


class BedrockAttributionPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["off", "session_tags"] | None = None
    tag_key: TagKey | None = None
    unassigned_value: str | None = Field(default=None, pattern=COST_TAG)

    @field_validator("tag_key")
    @classmethod
    def not_aws(cls, value: str | None) -> str | None:
        return _not_aws_prefix(value)


class InferenceMetricsSource(BaseModel):
    """An internal deployment whose model server shim reads the load of."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    deployment_id: UUID
    server: Literal["vllm", "tgi", "ollama"]
    # Send the deployment's stored credential; vLLM's /metrics needs none.
    send_credential: bool = False


def _one_per_deployment(
    value: list[InferenceMetricsSource] | None,
) -> list[InferenceMetricsSource] | None:
    if value is not None and len({source.deployment_id for source in value}) != len(
        value
    ):
        raise ValueError("at most one inference_metrics entry per deployment")
    return value


class GatewaySettings(BaseModel):
    """The effective settings; a later PRD adds a field here, never a column."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    response_analysis: list[str] = []
    injection_markers: Literal["off", "count", "warn"] = "off"
    price_tier_warning: bool = False
    model_retiring_warning: Literal["record", "header"] = "record"
    restore_withheld: dict[str, RestoreGrant] = {}
    task_caps: TaskCaps = TaskCaps()
    agent_loop: AgentLoop = AgentLoop()
    inflight_sharing_api_key_ids: list[UUID] = Field(default=[], max_length=1000)
    # A change that loosens protection needs a second administrator's approval.
    four_eyes: FourEyes = "off"
    # Per finding rule, how far shim may go; a rule left out observes.
    finding_modes: dict[str, FindingMode] = {}
    request_archive: RequestArchiveSettings = RequestArchiveSettings()
    provider_cache: ProviderCacheSettings = ProviderCacheSettings()
    tool_search: ToolSearchSettings = ToolSearchSettings()
    thinking_history: ThinkingHistorySettings = ThinkingHistorySettings()
    transforms: TransformSettings = TransformSettings()
    # Stops new automatic and agent applies; automatic undo keeps running.
    auto_remediation_paused: bool = False
    bedrock_region_lock: BedrockRegionLock = BedrockRegionLock()
    bedrock_attribution: BedrockAttribution = BedrockAttribution()
    inference_metrics: list[InferenceMetricsSource] = Field(default=[], max_length=64)

    @field_validator("inference_metrics")
    @classmethod
    def one_per_deployment(
        cls, value: list[InferenceMetricsSource]
    ) -> list[InferenceMetricsSource]:
        return _one_per_deployment(value) or []

    @field_validator("response_analysis")
    @classmethod
    def known_analyzers(cls, value: list[str]) -> list[str]:
        return _known_analyzers(value)


class GatewaySettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    response_analysis: list[str] | None = None
    injection_markers: Literal["off", "count", "warn"] | None = None
    price_tier_warning: bool | None = None
    model_retiring_warning: Literal["record", "header"] | None = None
    # Merged into the stored grants type by type; null gives a type back to everyone.
    restore_withheld: dict[str, RestoreGrant | None] | None = None
    # Merged into the stored values field by field; null removes a cap.
    task_caps: TaskCaps | None = None
    agent_loop: AgentLoop | None = None
    inflight_sharing_api_key_ids: list[UUID] | None = Field(
        default=None, max_length=1000
    )
    four_eyes: FourEyes | None = None
    finding_modes: dict[str, FindingMode] | None = None
    request_archive: RequestArchivePatch | None = None
    provider_cache: ProviderCachePatch | None = None
    tool_search: ToolSearchPatch | None = None
    thinking_history: ThinkingHistoryPatch | None = None
    transforms: TransformPatch | None = None
    auto_remediation_paused: bool | None = None
    bedrock_region_lock: BedrockRegionLockPatch | None = None
    bedrock_attribution: BedrockAttributionPatch | None = None
    # Replaces the whole list.
    inference_metrics: list[InferenceMetricsSource] | None = Field(
        default=None, max_length=64
    )

    @field_validator("inference_metrics")
    @classmethod
    def one_per_deployment(
        cls, value: list[InferenceMetricsSource] | None
    ) -> list[InferenceMetricsSource] | None:
        return _one_per_deployment(value)

    @model_validator(mode="before")
    @classmethod
    def no_nulls(cls, data: Any) -> Any:
        if isinstance(data, Mapping):
            nulls = sorted(key for key, value in data.items() if value is None)
            if nulls:
                raise ValueError(f"null is not a value for: {', '.join(nulls)}")
        return data

    @field_validator("response_analysis")
    @classmethod
    def known_analyzers(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _known_analyzers(value)

    @field_validator("restore_withheld")
    @classmethod
    def restorable_types(
        cls, value: dict[str, RestoreGrant | None] | None
    ) -> dict[str, RestoreGrant | None] | None:
        return None if value is None else _restorable_types(value)

    @field_validator("finding_modes")
    @classmethod
    def within_ladder(
        cls, value: dict[str, FindingMode] | None
    ) -> dict[str, FindingMode] | None:
        # Here, not at the top: the findings module reads these settings.
        from shim_enterprise.findings.service import MODES, RULES

        for rule_id, mode in (value or {}).items():
            if rule_id not in RULES:
                raise ValueError(f"unknown finding rule: {rule_id}")
            highest = RULES[rule_id].MAX_MODE
            if MODES.index(mode) > MODES.index(highest):
                raise ValueError(f"{rule_id} goes at most to {highest}")
        return value


def stored_settings(value: Mapping[str, Any]) -> GatewaySettings:
    """Read a stored row as this build knows it; a value of the wrong shape raises.

    A key, or an analyzer name, that only another build knows is left out and logged
    once, so rolling back to an older build keeps every tenant working.
    """

    unknown = {("key", key) for key in set(value) - set(GatewaySettings.model_fields)}
    # Here, not at the top: the findings module reads these settings.
    from shim_enterprise.findings.service import RULES

    modes = value.get("finding_modes")
    if isinstance(modes, dict):
        retired_rules = {rule for rule in modes if rule not in RULES}
        unknown |= {("finding rule", rule) for rule in retired_rules}
        value = {
            **value,
            "finding_modes": {
                rule: mode for rule, mode in modes.items() if rule in RULES
            },
        }
    names = value.get("response_analysis")
    if isinstance(names, list):
        retired = {
            name
            for name in names
            if isinstance(name, str) and name not in ANALYZER_NAMES
        }
        unknown |= {("analyzer", name) for name in retired}
        value = {
            **value,
            "response_analysis": [name for name in names if name not in retired],
        }
    for kind, name in sorted(unknown - _logged_unknown):
        _logged_unknown.add((kind, name))
        logger.warning("Unknown stored gateway %s ignored name=%s", kind, name)
    return GatewaySettings.model_validate(value)


def neutral(_before: Any, _after: Any) -> Direction:
    return "neutral"


def _relaxing(_before: Any, _after: Any) -> Direction:
    return "relaxing"


def toward(loosening: Any) -> Callable[[Any, Any], Direction]:
    """A switch: moving to `loosening` relaxes, any other move tightens."""
    return lambda _before, after: "relaxing" if after == loosening else "tightening"


def _finding_modes(
    before: dict[str, FindingMode], after: dict[str, FindingMode]
) -> Direction:
    # auto lets shim act without a person; every other move only shows more.
    raised = any(
        mode == "auto" and before.get(rule) != "auto" for rule, mode in after.items()
    )
    return "relaxing" if raised else "neutral"


def _request_archive(
    before: RequestArchiveSettings, after: RequestArchiveSettings
) -> Direction:
    # More content kept is relaxing: turning it on, or keeping it longer.
    if (after.enabled and not before.enabled) or (
        after.retention_days > before.retention_days
    ):
        return "relaxing"
    return "tightening"


_MARKER_LEVELS = ("off", "count", "warn")


def _marker_direction(before: str, after: str) -> Direction:
    return (
        "relaxing"
        if _MARKER_LEVELS.index(after) < _MARKER_LEVELS.index(before)
        else "tightening"
    )


def _restore_direction(
    before: Mapping[str, RestoreGrant], after: Mapping[str, RestoreGrant]
) -> Direction:
    return "relaxing" if restore_relaxed(before, after) else "tightening"


def _looser(before: Any, after: Any) -> bool:
    return before is not None and (after is None or after > before)


def _caps_direction(before: TaskCaps, after: TaskCaps) -> Direction:
    return (
        "relaxing"
        if _looser(before.max_calls, after.max_calls)
        or _looser(before.max_cost_usd, after.max_cost_usd)
        or after.window_seconds < before.window_seconds
        else "tightening"
    )


_LOOP_ACTIONS = ("off", "count", "block")


def _loop_direction(before: AgentLoop, after: AgentLoop) -> Direction:
    return (
        "relaxing"
        if _LOOP_ACTIONS.index(after.action) < _LOOP_ACTIONS.index(before.action)
        or after.repeats > before.repeats
        else "tightening"
    )


_LOCK_LEVELS = ("off", "monitor", "enforce")


def _list_direction(before: list[str], after: list[str]) -> Direction | None:
    if before == after:
        return None
    if (not before and after) or (set(after) < set(before) and after):
        return "tightening"
    return "relaxing"


def _region_lock_direction(
    before: BedrockRegionLock, after: BedrockRegionLock
) -> Direction:
    """A mode change alone decides (off < monitor < enforce): lists under `off`
    are inert, monitor refuses nothing, and enforce refuses at least what monitor
    did. With the mode kept and on, a list that narrows tightens and one that
    widens or empties relaxes."""
    if before.mode != after.mode:
        raised = _LOCK_LEVELS.index(after.mode) > _LOCK_LEVELS.index(before.mode)
        return "tightening" if raised else "relaxing"
    lists = [
        found
        for found in (
            _list_direction(before.scopes, after.scopes),
            _list_direction(before.regions, after.regions),
        )
        if found is not None
    ]
    if after.mode == "off" or not lists:
        return "neutral"
    return "relaxing" if "relaxing" in lists else "tightening"


# A field without a row here classifies as relaxing: a new switch fails closed.
SETTING_DIRECTIONS: dict[str, Callable[[Any, Any], Direction]] = {
    # Measurement only: what analyzers run changes no request.
    "response_analysis": neutral,
    "four_eyes": toward("off"),
    "finding_modes": _finding_modes,
    "request_archive": _request_archive,
    "injection_markers": _marker_direction,
    # A report, not a protection.
    "price_tier_warning": neutral,
    # Where a retirement warning is shown; it is always recorded.
    "model_retiring_warning": neutral,
    "restore_withheld": _restore_direction,
    "task_caps": _caps_direction,
    "agent_loop": _loop_direction,
    # A key's identical in-flight requests share one answer after each passes its own
    # limits and privacy; an answer never crosses keys.
    "inflight_sharing_api_key_ids": neutral,
    # A provider's own cache: what the request costs, not what it may carry.
    "provider_cache": neutral,
    # Cost settings: the same tools and history reach the model.
    "tool_search": neutral,
    "thinking_history": neutral,
    # Lossless: the model reads the same values in fewer characters.
    "transforms": neutral,
    # Pausing stops unattended changes; resuming lets them run again.
    "auto_remediation_paused": toward(False),
    "bedrock_region_lock": _region_lock_direction,
    # Measurement only: a tag on the session loosens no control.
    "bedrock_attribution": neutral,
    # Reads the tenant's own server; changes no request.
    "inference_metrics": neutral,
}

# Per field, "off, needs X" when an optional part is missing; None when available.
SETTING_AVAILABILITY: dict[str, Callable[[], str | None]] = {
    "bedrock_attribution": lambda: (
        None
        if settings.AWS_GATEWAY_IDENTITY != "none"
        else "off, needs AWS_GATEWAY_IDENTITY in this installation"
    ),
    "request_archive": lambda: (
        None
        if settings.REQUEST_ARCHIVE_ENABLED
        else "off, needs REQUEST_ARCHIVE_ENABLED in this installation (self-hosted only)"
    ),
}


def patched(before: Mapping[str, Any], changes: Mapping[str, Any]) -> dict[str, Any]:
    """A PATCH: a nested setting or a map changes only the entries named, and null
    removes one; a `finding_modes` rule set to `observe` is removed too."""
    after = {**before, **changes}
    for key, value in changes.items():
        if isinstance(value, dict):
            after[key] = {
                name: entry
                for name, entry in {**before.get(key, {}), **value}.items()
                if entry is not None and (key != "finding_modes" or entry != "observe")
            }
    return after


def classify_fields(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    directions: Directions,
) -> tuple[Direction, list[str]]:
    """The direction of a change and its relaxing fields; an unlisted field relaxes."""
    found = {
        field: directions.get(field, _relaxing)(before.get(field), after.get(field))
        for field in sorted(before.keys() | after.keys())
        if before.get(field) != after.get(field)
    }
    relaxed = [field for field, direction in found.items() if direction == "relaxing"]
    if relaxed:
        return "relaxing", relaxed
    if "tightening" in found.values():
        return "tightening", []
    return "neutral", []


def classify_change(
    before: GatewaySettings, after: GatewaySettings
) -> tuple[Direction, list[str]]:
    # Field values as they are, nested settings as models, for the direction functions.
    return classify_fields(dict(before), dict(after), SETTING_DIRECTIONS)
