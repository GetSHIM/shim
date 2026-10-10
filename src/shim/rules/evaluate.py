"""Where rule matches become verdicts, warnings and refusals."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from hashlib import sha256
import json
from typing import TYPE_CHECKING, Literal

from shim.observability.metrics import RULE_MATCHES_TOTAL, bounded_label
from shim.privacy.policies import EntityAction
from shim.rules.model import Rule, RuleAction, RuleMatch

if TYPE_CHECKING:
    from shim.gateway.kernel.result import PreparedInference

# The strongest action wins when several enforced rules match; set and route stand alone.
ACTION_ORDER: tuple[RuleAction, ...] = (
    "monitor",
    "warn",
    "mask",
    "require_approval",
    "block",
)
_ENTITY_ORDER: tuple[EntityAction, ...] = (
    "off",
    "monitor",
    "mask_last4",
    "mask",
    "block",
)
_RULE_TO_ENTITY: dict[RuleAction, EntityAction] = {
    "monitor": "monitor",
    "warn": "monitor",
    "mask": "mask",
    "block": "block",
    "require_approval": "block",
}
MAX_RECORDED_MATCHES = 32


def in_scope(rule: Rule, prepared: PreparedInference, tags: Iterable[str]) -> bool:
    """Every non-empty scope list must hold the request's value."""

    scope = rule.scope
    # An unclassified target is treated as external.
    kind = (
        "external"
        if prepared.deployment_kind == "unknown"
        else prepared.deployment_kind
    )
    key_id = str(prepared.api_key_id) if prepared.api_key_id is not None else None
    checks: tuple[tuple[tuple[str, ...], str | None], ...] = (
        (scope.api_key_ids, key_id),
        (scope.team_ids, prepared.policy.team_id),
        (scope.models, prepared.model),
        (scope.deployment_kinds, kind),
        (scope.endpoints, prepared.protocol),
    )
    return all(not allowed or value in allowed for allowed, value in checks) and (
        not scope.tags or not set(scope.tags).isdisjoint(tags)
    )


def strongest(actions: Iterable[RuleAction]) -> RuleAction | None:
    ordered = [action for action in actions if action in ACTION_ORDER]
    return max(ordered, key=ACTION_ORDER.index) if ordered else None


def entity_action(
    base: EntityAction, rule_actions: Iterable[RuleAction]
) -> EntityAction:
    """A rule can only strengthen the tenant's base action for a built-in type, never weaken it."""

    candidates = [
        base,
        *(_RULE_TO_ENTITY[a] for a in rule_actions if a in _RULE_TO_ENTITY),
    ]
    return max(candidates, key=_ENTITY_ORDER.index)


def ordered_matches(matches: Sequence[RuleMatch]) -> list[RuleMatch]:
    """Block matches first, then by rule id."""

    return sorted(
        matches,
        key=lambda match: (
            not (match.state == "enforced" and match.action == "block"),
            match.rule_id,
        ),
    )


def match_records(prepared: PreparedInference) -> dict[str, object]:
    """A record's rule_matches (at most 32) and whether more matched.

    Absent without a rule set; [] when one was evaluated and nothing matched.
    """

    if prepared.rules is None or not prepared.rules.rules:
        return {}
    ordered = ordered_matches(prepared.rule_matches)
    return {
        "rule_matches": [
            match.model_dump(exclude={"error"} if not match.error else set())
            for match in ordered[:MAX_RECORDED_MATCHES]
        ],
        "rule_matches_truncated": len(ordered) > MAX_RECORDED_MATCHES,
    }


def _verdict(match: RuleMatch) -> tuple[Literal["allow", "mask", "deny", "error"], str]:
    if match.error:
        return "error", "RULE_EVALUATION_TIMEOUT"
    if match.action == "monitor":
        return "allow", "RULE_MONITORED"
    if match.state == "monitor":
        return "allow", f"RULE_WOULD_{match.action.upper()}"
    if match.action == "block":
        return "deny", "RULE_BLOCKED"
    if match.action == "mask":
        return "mask", "RULE_MASKED"
    return "allow", f"RULE_{match.action.upper()}"


def rule_version(prepared: PreparedInference, rule_id: str) -> str:
    assert prepared.rules is not None
    rule = next(rule for rule in prepared.rules.rules if rule.id == rule_id)
    canonical = json.dumps(
        {
            "id": rule.id,
            "revision": prepared.rules.revision,
            "rule": rule.model_dump(mode="json"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(canonical.encode()).hexdigest()


def settle_matches(prepared: PreparedInference) -> tuple[list[str], list[str]]:
    """Record the rule verdicts of a request; return the enforced block and approval rule ids.

    An evaluation error in an enforced mask or block rule is a block of that rule (fail closed);
    any other error is recorded and the request continues.
    """

    assert prepared.rules is not None
    matches = ordered_matches(prepared.rule_matches)
    for match in matches[:MAX_RECORDED_MATCHES]:
        outcome, reason = _verdict(match)
        prepared.record_verdict(
            f"rule.{match.rule_id}",
            stage="rules",
            outcome=outcome,
            reason_code=reason,
            policy_version=rule_version(prepared, match.rule_id),
        )
    prepared.record_verdict(
        "rules.evaluated",
        stage="rules",
        outcome="allow",
        reason_code="RULES_EVALUATED",
        policy_version=sha256(str(prepared.rules.revision).encode()).hexdigest(),
    )
    blocked: set[str] = set()
    approval: set[str] = set()
    for match in matches:
        RULE_MATCHES_TOTAL.labels(
            kind=bounded_label("rule_kind", match.kind),
            action=bounded_label("rule_action", match.action),
            state=bounded_label("rule_state", match.state),
        ).inc()
        if match.state != "enforced":
            continue
        if match.action == "block" or (match.error and match.action == "mask"):
            blocked.add(match.rule_id)
        elif match.error:
            continue
        elif match.action == "require_approval":
            approval.add(match.rule_id)
        elif match.action == "warn":
            prepared.warn("RULE_WARN")
    return sorted(blocked), sorted(approval)
