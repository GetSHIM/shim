"""Tenant gateway switches: one validated model, off by default, a direction per field."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import logging
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from shim.gateway.analyzers import ANALYZER_NAMES, ANALYZERS

logger = logging.getLogger(__name__)

Direction = Literal["tightening", "relaxing", "neutral"]
FourEyes = Literal["off", "relaxing"]
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


class GatewaySettings(BaseModel):
    """The effective settings; a later PRD adds a field here, never a column."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    response_analysis: list[str] = []
    # A change that loosens protection needs a second administrator's approval.
    four_eyes: FourEyes = "off"

    @field_validator("response_analysis")
    @classmethod
    def known_analyzers(cls, value: list[str]) -> list[str]:
        return _known_analyzers(value)


class GatewaySettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    response_analysis: list[str] | None = None
    four_eyes: FourEyes | None = None

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


def neutral(_before: Any, _after: Any) -> Direction:
    return "neutral"


def _relaxing(_before: Any, _after: Any) -> Direction:
    return "relaxing"


def toward(loosening: Any) -> Callable[[Any, Any], Direction]:
    """A switch: moving to `loosening` relaxes, any other move tightens."""
    return lambda _before, after: "relaxing" if after == loosening else "tightening"


# A field without a row here classifies as relaxing: a new switch fails closed.
SETTING_DIRECTIONS: dict[str, Callable[[Any, Any], Direction]] = {
    # Measurement only: what analyzers run changes no request.
    "response_analysis": neutral,
    "four_eyes": toward("off"),
}

# Per field, "off, needs X" when an optional part is missing; None when available.
SETTING_AVAILABILITY: dict[str, Callable[[], str | None]] = {}


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
    return classify_fields(before.model_dump(), after.model_dump(), SETTING_DIRECTIONS)
