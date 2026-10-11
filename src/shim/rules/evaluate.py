"""Where rule matches become verdicts, warnings and refusals."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from hashlib import sha256
from itertools import islice
import json
import re
from typing import TYPE_CHECKING, Literal

from shim.observability.metrics import RULE_MATCHES_TOTAL, bounded_label
from shim.rules.model import Rule, RuleMatch, UnusableRule

if TYPE_CHECKING:
    from shim.gateway.kernel.result import PreparedInference

MAX_RECORDED_MATCHES = 32
# A dated snapshot id belongs to the model it is dated from.
_DATE_SUFFIX = re.compile(r"-(?:\d{8}|\d{4}-\d{2}-\d{2})$")
Outcome = Literal["allow", "mask", "deny", "error"]


def in_scope(
    rule: Rule | UnusableRule, prepared: PreparedInference, tags: Iterable[str]
) -> bool:
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
        (scope.deployment_kinds, kind),
        (scope.endpoints, prepared.protocol),
    )
    # The model the request reaches, never the alias the caller named.
    model = prepared.pricing_model.casefold()
    return (
        all(not allowed or value in allowed for allowed, value in checks)
        and (not scope.tags or not set(scope.tags).isdisjoint(tags))
        and (
            not scope.models
            or not {model, _DATE_SUFFIX.sub("", model)}.isdisjoint(
                entry.casefold() for entry in scope.models
            )
        )
    )


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

    Absent unless a matcher ran; [] when one ran and nothing matched.
    """

    # A match means a matcher ran, also when the request was refused before the
    # stage could say so.
    if not (prepared.rules_evaluated or prepared.rule_matches):
        return {}
    ordered = ordered_matches(prepared.rule_matches)
    return {
        "rule_matches": [
            match.model_dump(
                exclude={
                    key for key in ("error", "truncated") if not getattr(match, key)
                }
            )
            for match in ordered[:MAX_RECORDED_MATCHES]
        ],
        "rule_matches_truncated": len(ordered) > MAX_RECORDED_MATCHES,
    }


def _fails_closed(match: RuleMatch) -> bool:
    # The gateway cannot show the value stayed in, as with privacy fail-closed.
    return match.state == "enforced" and match.action in {
        "mask",
        "block",
        "require_approval",
    }


def _verdict(match: RuleMatch) -> tuple[Outcome, str]:
    if match.error:
        if _fails_closed(match):
            return "deny", "RULE_BLOCKED"
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


def record_rule_verdicts(
    prepared: PreparedInference, verdicts: Mapping[str, tuple[Outcome, str]]
) -> None:
    """One rule.<id> verdict per rule, the first 32 in the given order."""

    assert prepared.rules is not None
    stored = {
        rule.id: rule.stored
        if isinstance(rule, UnusableRule)
        else rule.model_dump(mode="json")
        for rule in (*prepared.rules.rules, *prepared.rules.unusable)
    }
    for rule_id, (outcome, reason) in islice(verdicts.items(), MAX_RECORDED_MATCHES):
        canonical = json.dumps(
            {
                "id": rule_id,
                "revision": prepared.rules.revision,
                "rule": stored[rule_id],
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        prepared.record_verdict(
            f"rule.{rule_id}",
            stage="rules",
            outcome=outcome,
            reason_code=reason,
            policy_version=sha256(canonical.encode()).hexdigest(),
        )


def settle_matches(prepared: PreparedInference) -> tuple[list[str], list[str]]:
    """Record the rule verdicts of a request; return the enforced block and approval rule ids.

    Fail closed: an evaluation error in an enforced mask, block or require_approval rule,
    and an enforced rule in scope that this build cannot evaluate, block the request.
    Any other error is recorded and the request continues.
    """

    assert prepared.rules is not None
    matches = ordered_matches(prepared.rule_matches)
    verdicts = {match.rule_id: _verdict(match) for match in matches}
    tags = prepared.admission.tags if prepared.admission is not None else ()
    unusable = sorted(
        rule.id
        for rule in prepared.rules.unusable
        if rule.enforced and in_scope(rule, prepared, tags)
    )
    blocks: dict[str, tuple[Outcome, str]] = dict.fromkeys(
        unusable, ("deny", "RULE_BLOCKED")
    )
    record_rule_verdicts(prepared, blocks | verdicts)
    if prepared.rules_evaluated or prepared.rule_matches:
        prepared.record_verdict(
            "rules.evaluated",
            stage="rules",
            outcome="allow",
            reason_code="RULES_EVALUATED",
            policy_version=sha256(str(prepared.rules.revision).encode()).hexdigest(),
        )
    blocked = [
        *unusable,
        *(rule_id for rule_id, (outcome, _) in verdicts.items() if outcome == "deny"),
    ]
    approval: list[str] = []
    for match in matches:
        RULE_MATCHES_TOTAL.labels(
            kind=bounded_label("rule_kind", match.kind),
            action=bounded_label("rule_action", match.action),
            state=bounded_label("rule_state", match.state),
        ).inc()
        if match.state == "enforced" and not match.error:
            if match.action == "require_approval":
                approval.append(match.rule_id)
            elif match.action == "warn":
                prepared.warn("RULE_WARN")
    return sorted(blocked), sorted(approval)
