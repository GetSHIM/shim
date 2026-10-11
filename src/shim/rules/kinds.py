"""The kind table: where each rule kind is evaluated, its actions, and its match model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ValidationError

from shim.rules.content import PatternMatch, TermMatch
from shim.rules.destination import DestinationMatch
from shim.rules.record_set import RecordSetMatch
from shim.rules.request_limit import RequestLimitMatch
from shim.rules.model import (
    LIMITS,
    Rule,
    RuleAction,
    RuleKind,
    RuleScope,
    RuleSet,
    RuleSetError,
    UnusableRule,
)

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
    "record_set": KindSpec(
        "privacy", ("monitor", "warn", "mask", "block"), RecordSetMatch
    ),
    "destination": KindSpec(
        "privacy", ("monitor", "warn", "mask", "block"), DestinationMatch
    ),
    "request_limit": KindSpec(
        "admission", ("monitor", "warn", "block"), RequestLimitMatch
    ),
    "parameter_pin": KindSpec("settings", ("monitor", "warn", "set", "block")),
    "route": KindSpec("resolver", ("route",)),
}


# What a whole set may hold, per match key: (limit name, kind, key).
_SET_LIMITS = (
    ("terms_per_set", "term", "terms"),
    ("patterns_per_set", "pattern", "regexes"),
    ("templates_per_set", "pattern", "templates"),
)


def _refusal(code: str, prefix: str, error: ValidationError) -> RuleSetError:
    first = error.errors()[0]
    path = "".join(
        f"[{part}]" if isinstance(part, int) else f".{part}" for part in first["loc"]
    )
    if first["type"] == "rule_pattern_unsafe":
        code = "RULE_PATTERN_UNSAFE"
    return RuleSetError(code, f"{prefix}{path}".lstrip("."), first["msg"])


def validate_rule_set(
    payload: dict[str, Any], *, approval_available: bool = False, stored: bool = False
) -> RuleSet:
    try:
        rule_set = RuleSet.model_validate(payload)
    except ValidationError as error:
        raise _refusal("RULE_SET_INVALID", "", error) from None
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
        # Unscoped, it would only repeat the tenant's base action for the type. A
        # block scoped only by what the caller sends (tags, endpoint) is one the
        # caller can step around.
        scope = rule.scope
        decided_by_server = (
            scope.api_key_ids
            or scope.team_ids
            or scope.models
            or scope.deployment_kinds
        )
        if rule.kind == "destination" and (
            scope == RuleScope() or (rule.action == "block" and not decided_by_server)
        ):
            raise RuleSetError(
                "RULE_SCOPE_REQUIRED",
                f"rules[{index}].scope",
                "a destination rule needs a scope list; a block needs a key, team, "
                "model or deployment kind",
            )
        try:
            match = spec.match.model_validate(rule.match, context={"stored": stored})
        except ValidationError as error:
            raise _refusal(
                "RULE_MATCH_INVALID", f"rules[{index}].match", error
            ) from None
        dumped = match.model_dump(mode="json")
        for name, kind, key in _SET_LIMITS:
            if rule.kind == kind:
                totals[name] += len(dumped[key])
                if totals[name] > LIMITS[name]:
                    raise RuleSetError(
                        "RULE_SET_INVALID",
                        f"rules[{index}].match.{key}",
                        f"a rule set holds at most {LIMITS[name]:,} {key}",
                    )
        rules.append(rule.model_copy(update={"match": dumped}))
    return RuleSet(revision=rule_set.revision, rules=tuple(rules))


def load_rule_set(revision: int, stored: list[dict[str, Any]]) -> RuleSet:
    """A stored set as this build runs it, for a build older than the one that wrote it.

    A rule this build cannot evaluate is kept aside as unusable, never dropped.
    """

    rules: list[Rule] = []
    unusable: list[UnusableRule] = []
    for index, raw in enumerate(stored):
        try:
            rules += validate_rule_set(
                {"revision": revision, "rules": [raw]},
                approval_available=True,
                stored=True,
            ).rules
            continue
        except RuleSetError:
            pass
        try:
            try:
                scope = RuleScope.model_validate(raw.get("scope", {}))
            except ValidationError:
                scope = RuleScope()
            unusable.append(
                UnusableRule(
                    id=raw["id"],
                    kind=str(raw.get("kind")),
                    action=raw["action"],
                    state=raw["state"],
                    scope=scope,
                    stored=raw,
                )
            )
        except (AttributeError, KeyError, ValidationError):
            raise RuleSetError(
                "RULE_SET_INVALID", f"rules[{index}]", "a stored rule cannot be read"
            ) from None
    return RuleSet(revision=revision, rules=tuple(rules), unusable=tuple(unusable))
