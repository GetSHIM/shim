"""Tenant gateway switches: one validated model, off by default, a direction per field."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import logging
import re
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from shim.gateway.analyzers import ANALYZER_NAMES, ANALYZERS
from shim.privacy.policies import effective_entity_actions

logger = logging.getLogger(__name__)

Direction = Literal["tightening", "relaxing", "neutral"]
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


def _restorable_types(value: dict[str, RestoreGrant]) -> dict[str, RestoreGrant]:
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


class GatewaySettings(BaseModel):
    """The effective settings; a later PRD adds a field here, never a column."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    response_analysis: list[str] = []
    injection_markers: Literal["off", "count", "warn"] = "off"
    price_tier_warning: bool = False
    restore_withheld: dict[str, RestoreGrant] = {}

    @field_validator("response_analysis")
    @classmethod
    def known_analyzers(cls, value: list[str]) -> list[str]:
        return _known_analyzers(value)

    @field_validator("restore_withheld")
    @classmethod
    def restorable_types(
        cls, value: dict[str, RestoreGrant]
    ) -> dict[str, RestoreGrant]:
        return _restorable_types(value)


class GatewaySettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    response_analysis: list[str] | None = None
    injection_markers: Literal["off", "count", "warn"] | None = None
    price_tier_warning: bool | None = None
    # Replaces the stored grants whole; {} restores every type for everyone again.
    restore_withheld: dict[str, RestoreGrant] | None = None

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
        cls, value: dict[str, RestoreGrant] | None
    ) -> dict[str, RestoreGrant] | None:
        return None if value is None else _restorable_types(value)


def stored_settings(value: Mapping[str, Any]) -> GatewaySettings:
    """Read a stored row as this build knows it; a value of the wrong shape raises.

    A key, or an analyzer name, that only another build knows is left out and logged
    once, so rolling back to an older build keeps every tenant working.
    """

    unknown = {("key", key) for key in set(value) - set(GatewaySettings.model_fields)}
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


def _neutral(_before: Any, _after: Any) -> Direction:
    return "neutral"


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


SETTING_DIRECTIONS: dict[str, Callable[[Any, Any], Direction]] = {
    # Measurement only: what analyzers run changes no request.
    "response_analysis": _neutral,
    "injection_markers": _marker_direction,
    # A report, not a protection.
    "price_tier_warning": _neutral,
    "restore_withheld": _restore_direction,
}

# Per field, "off, needs X" when an optional part is missing; None when available.
SETTING_AVAILABILITY: dict[str, Callable[[], str | None]] = {}


def classify_change(
    before: GatewaySettings, after: GatewaySettings
) -> tuple[Direction, list[str]]:
    directions = {
        field: SETTING_DIRECTIONS[field](getattr(before, field), getattr(after, field))
        for field in GatewaySettings.model_fields
        if getattr(before, field) != getattr(after, field)
    }
    relaxed = [
        field for field, direction in directions.items() if direction == "relaxing"
    ]
    if relaxed:
        return "relaxing", relaxed
    if "tightening" in directions.values():
        return "tightening", []
    return "neutral", []
