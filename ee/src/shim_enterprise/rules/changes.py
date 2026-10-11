"""Which rule changes weaken protection: the relaxation check plans and previews reuse."""

from __future__ import annotations

from typing import Any, Literal

from shim.rules import ACTION_RANK, Rule, RuleSet

# Lists where another entry only finds more.
_ADDITIVE_MATCH_KEYS = frozenset({"terms", "templates", "regexes"})


def _match_only_grew(before: dict[str, Any], after: dict[str, Any]) -> bool:
    return before.keys() == after.keys() and all(
        set(value) <= set(after[key])
        if key in _ADDITIVE_MATCH_KEYS
        else after[key] == value
        for key, value in before.items()
    )


def _relaxes(before: Rule, after: Rule | None) -> bool:
    if before.state != "enforced":
        return False
    if after is None or after.state == "monitor":
        return True
    if ACTION_RANK[after.action] < ACTION_RANK[before.action]:
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


def rule_set_direction(
    before: list[dict[str, Any]], after: list[dict[str, Any]]
) -> Literal["relaxing", "tightening", "neutral"]:
    """A change that would relax if undone tightens."""
    old, new = (
        RuleSet(revision=1, rules=tuple(Rule.model_validate(rule) for rule in rules))
        for rules in (before, after)
    )
    if classify_rule_changes(old, new):
        return "relaxing"
    return "tightening" if classify_rule_changes(new, old) else "neutral"
