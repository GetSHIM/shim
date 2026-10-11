"""Tenant gateway switches: one validated model, off by default, a direction per field."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import logging
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from shim.gateway.analyzers import ANALYZER_NAMES, ANALYZERS

logger = logging.getLogger(__name__)

Direction = Literal["tightening", "relaxing", "neutral"]
_logged_unknown_keys: set[str] = set()


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

    @field_validator("response_analysis")
    @classmethod
    def known_analyzers(cls, value: list[str]) -> list[str]:
        return _known_analyzers(value)


class GatewaySettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    response_analysis: list[str] | None = None

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
    """Read a stored row; a key this build does not know is ignored, an invalid value raises."""

    for key in sorted(set(value) - set(GatewaySettings.model_fields)):
        if key not in _logged_unknown_keys:
            _logged_unknown_keys.add(key)
            logger.warning("Unknown stored gateway setting ignored name=%s", key)
    return GatewaySettings.model_validate(value)


def _neutral(_before: Any, _after: Any) -> Direction:
    return "neutral"


SETTING_DIRECTIONS: dict[str, Callable[[Any, Any], Direction]] = {
    # Measurement only: what analyzers run changes no request.
    "response_analysis": _neutral,
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
