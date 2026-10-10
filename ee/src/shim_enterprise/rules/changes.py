"""Which rule changes weaken protection: the relaxation check plans and previews reuse."""

from __future__ import annotations

from typing import Any

from shim.rules import Rule, RuleAction, RuleSet

# Strength of an action; set and route rank with mask, the middle of the order.
_RANK: dict[RuleAction, int] = {
    "monitor": 0,
    "warn": 1,
    "mask": 2,
    "set": 2,
    "route": 2,
    "require_approval": 3,
    "block": 4,
}
_ADDITIVE_MATCH_KEYS = ("terms", "patterns")


def _match_only_grew(before: dict[str, Any], after: dict[str, Any]) -> bool:
    if before.keys() != after.keys():
        return False
    for key, value in before.items():
        if key in _ADDITIVE_MATCH_KEYS and isinstance(value, list):
            if not isinstance(after[key], list) or any(
                item not in after[key] for item in value
            ):
                return False
        elif after[key] != value:
            return False
    return True


def _relaxes(before: Rule, after: Rule | None) -> bool:
    if before.state != "enforced":
        return False
    if after is None or after.state == "monitor":
        return True
    if _RANK[after.action] < _RANK[before.action]:
        return True
    for field in type(before.scope).model_fields:
        old, new = getattr(before.scope, field), getattr(after.scope, field)
        # An empty list means everyone; naming some, or dropping one, protects fewer.
        if (not old and new) or (new and not set(old) <= set(new)):
            return True
    return before.match != after.match and not _match_only_grew(
        before.match, after.match
    )


def classify_rule_changes(before: RuleSet | None, after: RuleSet) -> list[str]:
    """`rules.<id>` for each rule whose protection weakens between two sets."""

    current = {rule.id: rule for rule in after.rules}
    return sorted(
        f"rules.{rule.id}"
        for rule in (before.rules if before is not None else ())
        if _relaxes(rule, current.get(rule.id))
    )
