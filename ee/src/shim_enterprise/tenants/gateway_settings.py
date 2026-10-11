"""Tenant gateway switches: one validated model, off by default, a direction per field."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import logging
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from shim.gateway.analyzers import ANALYZER_NAMES, ANALYZERS
from shim_enterprise.core.config import settings

logger = logging.getLogger(__name__)

Direction = Literal["tightening", "relaxing", "neutral"]
FourEyes = Literal["off", "relaxing"]
FindingMode = Literal["observe", "suggest", "auto"]
_logged_unknown: set[tuple[str, str]] = set()


def _known_analyzers(value: list[str]) -> list[str]:
    unknown = sorted(set(value) - ANALYZER_NAMES)
    if unknown:
        raise ValueError(f"unknown analyzer: {', '.join(unknown)}")
    if len(set(value)) != len(value):
        raise ValueError("analyzer names must be unique")
    return [analyzer.name for analyzer in ANALYZERS if analyzer.name in value]


class RequestArchiveSettings(BaseModel):
    """Keep rule-matched requests, encrypted, for at most 90 days (self-hosted only)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = False
    retention_days: int = Field(default=90, ge=1, le=90)


class RequestArchivePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    retention_days: int | None = Field(default=None, ge=1, le=90)


class GatewaySettings(BaseModel):
    """The effective settings; a later PRD adds a field here, never a column."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    response_analysis: list[str] = []
    # A change that loosens protection needs a second administrator's approval.
    four_eyes: FourEyes = "off"
    # Per finding rule, how far shim may go; a rule left out observes.
    finding_modes: dict[str, FindingMode] = {}
    request_archive: RequestArchiveSettings = RequestArchiveSettings()

    @field_validator("response_analysis")
    @classmethod
    def known_analyzers(cls, value: list[str]) -> list[str]:
        return _known_analyzers(value)


class GatewaySettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    response_analysis: list[str] | None = None
    four_eyes: FourEyes | None = None
    finding_modes: dict[str, FindingMode] | None = None
    request_archive: RequestArchivePatch | None = None

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

    @field_validator("finding_modes")
    @classmethod
    def within_ladder(
        cls, value: dict[str, FindingMode] | None
    ) -> dict[str, FindingMode] | None:
        # Here, not at the top: the findings module reads these settings.
        from shim_enterprise.findings.service import LADDER, MODES

        for rule_id, mode in (value or {}).items():
            if rule_id not in LADDER:
                raise ValueError(f"unknown finding rule: {rule_id}")
            highest = LADDER[rule_id].max_mode
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
    from shim_enterprise.findings.service import LADDER

    modes = value.get("finding_modes")
    if isinstance(modes, dict):
        retired_rules = {rule for rule in modes if rule not in LADDER}
        unknown |= {("finding rule", rule) for rule in retired_rules}
        value = {
            **value,
            "finding_modes": {
                rule: mode for rule, mode in modes.items() if rule in LADDER
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


def _neutral(_before: Any, _after: Any) -> Direction:
    return "neutral"


def _relaxing(_before: Any, _after: Any) -> Direction:
    return "relaxing"


def _four_eyes(_before: FourEyes, after: FourEyes) -> Direction:
    return "relaxing" if after == "off" else "tightening"


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


# A field without a row here classifies as relaxing: a new switch fails closed.
SETTING_DIRECTIONS: dict[str, Callable[[Any, Any], Direction]] = {
    # Measurement only: what analyzers run changes no request.
    "response_analysis": _neutral,
    "four_eyes": _four_eyes,
    "finding_modes": _finding_modes,
    "request_archive": _request_archive,
}

# Per field, "off, needs X" when an optional part is missing; None when available.
SETTING_AVAILABILITY: dict[str, Callable[[], str | None]] = {
    "request_archive": lambda: (
        None
        if settings.REQUEST_ARCHIVE_ENABLED
        else "off, needs REQUEST_ARCHIVE_ENABLED in this installation (self-hosted only)"
    ),
}


def patched(before: Mapping[str, Any], changes: Mapping[str, Any]) -> dict[str, Any]:
    """A PATCH: `finding_modes` merges per rule, and `observe` removes the rule;
    `request_archive` merges per field."""
    after = {**before, **changes}
    if "request_archive" in changes:
        after["request_archive"] = {
            **before.get("request_archive", {}),
            **changes["request_archive"],
        }
    if "finding_modes" in changes:
        modes = {**before.get("finding_modes", {}), **changes["finding_modes"]}
        after["finding_modes"] = {
            rule: mode for rule, mode in modes.items() if mode != "observe"
        }
    return after


def classify_change(
    before: GatewaySettings, after: GatewaySettings
) -> tuple[Direction, list[str]]:
    directions = {
        field: SETTING_DIRECTIONS.get(field, _relaxing)(
            getattr(before, field), getattr(after, field)
        )
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
