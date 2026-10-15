"""Which rule changes weaken protection: the relaxation check plans and previews reuse."""

from __future__ import annotations

from typing import Any, Literal

from shim.rules import ACTION_RANK, Rule, RuleSet
from shim_enterprise.rules.route_triggers import route_classifier

# Lists where another entry only finds more.
_ADDITIVE_MATCH_KEYS = frozenset({"terms", "templates", "regexes"})


def _match_only_grew(before: dict[str, Any], after: dict[str, Any]) -> bool:
    return before.keys() == after.keys() and all(
        set(value) <= set(after[key])
        if key in _ADDITIVE_MATCH_KEYS
        else after[key] == value
        for key, value in before.items()
    )


# Fields whose change protects no fewer requests; any other field is checked below,
# and one not checked (a field added later) relaxes.
_LABELS = frozenset({"id", "name"})
_CHECKED = frozenset({"state", "action", "scope", "match"})


def _relaxes(before: Rule | None, after: Rule | None) -> bool:
    if {rule.kind for rule in (before, after) if rule is not None} == {"route"}:
        # A route rule moves requests to another model: enforcing one, or changing
        # an enforced one, is what needs a second look; removing one protects.
        if after is None or after.state != "enforced" or before is None:
            return after is not None and after.state == "enforced"
        classify = route_classifier(before, after)
        if classify is not None and before.model_dump(
            exclude={"name", "match"}
        ) == after.model_dump(exclude={"name", "match"}):
            return classify(before.match, after.match) == "relaxing"
        return before.model_dump(exclude={"name"}) != after.model_dump(exclude={"name"})
    if before is None or before.state != "enforced":
        return False
    if after is None or after.state == "monitor":
        return True
    if any(
        getattr(before, field) != getattr(after, field)
        for field in Rule.model_fields.keys() - _LABELS - _CHECKED
    ):
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

    previous = {rule.id: rule for rule in (before.rules if before is not None else ())}
    current = {rule.id: rule for rule in after.rules}
    return sorted(
        f"rules.{rule_id}"
        for rule_id in previous.keys() | current.keys()
        if _relaxes(previous.get(rule_id), current.get(rule_id))
    )


def rule_direction(
    before: Rule | None, after: Rule | None
) -> Literal["relaxing", "tightening", "neutral"]:
    """Relaxing as above; a change that would relax if undone tightens."""
    old, new = (
        RuleSet(revision=1, rules=() if rule is None else (rule,))
        for rule in (before, after)
    )
    if classify_rule_changes(old, new):
        return "relaxing"
    return "tightening" if classify_rule_changes(new, old) else "neutral"
