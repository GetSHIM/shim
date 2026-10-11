"""Destination rules: a data type that must not reach targets in the rule's scope."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import get_args

from pydantic import BaseModel, ConfigDict, Field, field_validator

from shim.privacy.policies import EntityAction, effective_entity_actions
from shim.rules.model import Rule


class DestinationMatch(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_types: tuple[str, ...] = Field(min_length=1, max_length=32)

    @field_validator("entity_types")
    @classmethod
    def known_and_distinct(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        unknown = sorted(set(value) - effective_entity_actions().keys())
        if unknown:
            raise ValueError(f"unknown entity type: {', '.join(unknown)}")
        if len(set(value)) != len(value):
            raise ValueError("entity types must be distinct")
        return value


def destination_actions(
    base: Mapping[str, EntityAction], rules: Sequence[Rule]
) -> Mapping[str, EntityAction]:
    """Per type, the strongest of the base action and every enforced `mask` rule naming it.

    A type any rule names is detected at least as `monitor`, which sends it unchanged;
    a rule never weakens the base action. `block` and `warn` act at the decision point.
    """

    if not rules:
        return base
    order = get_args(EntityAction)
    applied = dict(base)
    for rule in rules:
        wanted = (
            "mask" if (rule.state, rule.action) == ("enforced", "mask") else "monitor"
        )
        for entity_type in rule.match["entity_types"]:
            if order.index(wanted) > order.index(applied[entity_type]):
                applied[entity_type] = wanted
    return applied
