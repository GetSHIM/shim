"""The kind table: where each rule kind is evaluated, its actions, and its match model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ValidationError

from shim.rules.content import PatternMatch, TermMatch
from shim.rules.model import LIMITS, RuleAction, RuleKind, RuleSet, RuleSetError

RulePoint = Literal["resolver", "admission", "privacy", "settings"]


@dataclass(frozen=True, slots=True)
class KindSpec:
    point: RulePoint
    actions: tuple[RuleAction, ...]
    # None until the kind's PRD adds it; a kind without one is unavailable.
    match: type[BaseModel] | None = None


KINDS: dict[RuleKind, KindSpec] = {
    "term": KindSpec(
        "privacy", ("monitor", "warn", "mask", "block", "require_approval"), TermMatch
    ),
    "pattern": KindSpec(
        "privacy",
        ("monitor", "warn", "mask", "block", "require_approval"),
        PatternMatch,
    ),
    "record_set": KindSpec("privacy", ("monitor", "warn", "mask", "block")),
    "destination": KindSpec("privacy", ("monitor", "warn", "mask", "block")),
    "request_limit": KindSpec("admission", ("monitor", "warn", "block")),
    "parameter_pin": KindSpec("settings", ("monitor", "warn", "set", "block")),
    "route": KindSpec("resolver", ("route",)),
}


# What a whole set may hold, per match key: (limit name, kind, key).
_SET_LIMITS = (
    ("terms_per_set", "term", "terms"),
    ("patterns_per_set", "pattern", "regexes"),
)


def _path(loc: tuple[int | str, ...]) -> str:
    return "".join(
        f"[{part}]" if isinstance(part, int) else f".{part}" for part in loc
    ).lstrip(".")


def validate_rule_set(
    payload: dict[str, Any], *, approval_available: bool = False
) -> RuleSet:
    try:
        rule_set = RuleSet.model_validate(payload)
    except ValidationError as error:
        first = error.errors()[0]
        raise RuleSetError(
            "RULE_SET_INVALID", _path(first["loc"]), first["msg"]
        ) from None
    seen: set[str] = set()
    totals = dict.fromkeys((name for name, _, _ in _SET_LIMITS), 0)
    rules = []
    for index, rule in enumerate(rule_set.rules):
        if rule.id in seen:
            raise RuleSetError(
                "RULE_ID_DUPLICATE", f"rules[{index}].id", f"rule id {rule.id} repeats"
            )
        seen.add(rule.id)
        spec = KINDS[rule.kind]
        if spec.match is None:
            raise RuleSetError(
                "RULE_KIND_UNAVAILABLE",
                f"rules[{index}].kind",
                f"rule kind {rule.kind} is not available yet",
            )
        if rule.action not in spec.actions or (
            rule.action == "require_approval" and not approval_available
        ):
            raise RuleSetError(
                "RULE_ACTION_UNAVAILABLE",
                f"rules[{index}].action",
                f"action {rule.action} is not available for kind {rule.kind}",
            )
        try:
            match = spec.match.model_validate(rule.match)
        except ValidationError as error:
            first = error.errors()[0]
            raise RuleSetError(
                "RULE_PATTERN_UNSAFE"
                if first["type"] == "rule_pattern_unsafe"
                else "RULE_MATCH_INVALID",
                f"rules[{index}].match.{_path(first['loc'])}".rstrip("."),
                first["msg"],
            ) from None
        stored = match.model_dump(mode="json")
        for name, kind, key in _SET_LIMITS:
            if rule.kind == kind:
                totals[name] += len(stored[key])
                if totals[name] > LIMITS[name]:
                    raise RuleSetError(
                        "RULE_SET_INVALID",
                        f"rules[{index}].match.{key}",
                        f"a rule set holds at most {LIMITS[name]:,} {key}",
                    )
        rules.append(rule.model_copy(update={"match": stored}))
    return rule_set.model_copy(update={"rules": tuple(rules)})
