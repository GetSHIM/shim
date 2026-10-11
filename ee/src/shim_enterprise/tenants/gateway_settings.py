"""Tenant gateway switches: one validated model, off by default, a direction per field."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import logging
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from shim.gateway.analyzers import ANALYZER_NAMES, ANALYZERS

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


class GatewaySettings(BaseModel):
    """The effective settings; a later PRD adds a field here, never a column."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    response_analysis: list[str] = []
    injection_markers: Literal["off", "count", "warn"] = "off"

    @field_validator("response_analysis")
    @classmethod
    def known_analyzers(cls, value: list[str]) -> list[str]:
        return _known_analyzers(value)


class GatewaySettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    response_analysis: list[str] | None = None
    injection_markers: Literal["off", "count", "warn"] | None = None

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


SETTING_DIRECTIONS: dict[str, Callable[[Any, Any], Direction]] = {
    # Measurement only: what analyzers run changes no request.
    "response_analysis": _neutral,
    "injection_markers": _marker_direction,
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
