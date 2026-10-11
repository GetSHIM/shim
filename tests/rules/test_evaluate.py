from __future__ import annotations

from types import MethodType, SimpleNamespace
from uuid import UUID

import pytest

from shim.gateway.kernel.result import PreparedInference
from shim.rules import Rule, RuleMatch, RuleSet, in_scope
from shim.rules.evaluate import (
    entity_action,
    match_records,
    ordered_matches,
    settle_matches,
    strongest,
)

KEY = UUID("11111111-1111-1111-1111-111111111111")
TEAM = "22222222-2222-2222-2222-222222222222"


def _prepared(**values) -> SimpleNamespace:
    prepared = SimpleNamespace(
        **{
            "api_key_id": KEY,
            "policy": SimpleNamespace(team_id=TEAM),
            "model": "gpt-5-mini",
            "deployment_kind": "unknown",
            "protocol": "chat",
            "rules": None,
            "rule_matches": [],
            "policy_verdicts": [],
            "warnings": [],
            **values,
        }
    )
    prepared.record_verdict = MethodType(PreparedInference.record_verdict, prepared)
    prepared.warn = MethodType(PreparedInference.warn, prepared)
    return prepared


def _rule(rule_id: str = "r", **values) -> Rule:
    return Rule.model_validate(
        {
            "id": rule_id,
            "name": "n",
            "kind": "term",
            "action": "block",
            "state": "enforced",
            **values,
        }
    )


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        ({}, True),
        ({"api_key_ids": [str(KEY)]}, True),
        ({"api_key_ids": ["33333333-3333-3333-3333-333333333333"]}, False),
        ({"team_ids": [TEAM]}, True),
        ({"team_ids": ["33333333-3333-3333-3333-333333333333"]}, False),
        ({"models": ["gpt-5-mini"]}, True),
        ({"models": ["gpt-5"]}, False),
        ({"tags": ["batch", "risk"]}, True),
        ({"tags": ["other"]}, False),
        ({"deployment_kinds": ["external"]}, True),
        ({"deployment_kinds": ["internal"]}, False),
        ({"endpoints": ["chat"]}, True),
        ({"endpoints": ["responses"]}, False),
        ({"models": ["gpt-5-mini"], "endpoints": ["responses"]}, False),
    ],
)
def test_every_non_empty_scope_list_must_hold_the_request(scope, expected) -> None:
    assert in_scope(_rule(scope=scope), _prepared(), ["risk"]) is expected


def test_an_unknown_deployment_kind_counts_as_external_only() -> None:
    internal = _prepared(deployment_kind="internal")

    assert in_scope(_rule(scope={"deployment_kinds": ["internal"]}), internal, [])
    assert not in_scope(_rule(scope={"deployment_kinds": ["external"]}), internal, [])
    assert not in_scope(
        _rule(scope={"team_ids": [TEAM]}),
        _prepared(policy=SimpleNamespace(team_id=None)),
        [],
    )


def test_the_strongest_action_wins_and_a_base_action_is_never_weakened() -> None:
    assert strongest(["warn", "block", "mask"]) == "block"
    assert strongest(["monitor", "require_approval", "mask"]) == "require_approval"
    assert strongest(["set"]) is None
    assert entity_action("block", ["monitor", "mask"]) == "block"
    assert entity_action("mask", ["warn"]) == "mask"
    assert entity_action("monitor", ["mask"]) == "mask"
    assert entity_action("off", ["monitor"]) == "monitor"
    assert entity_action("mask_last4", []) == "mask_last4"


def _match(
    rule_id: str, action: str = "block", state: str = "enforced", **values
) -> RuleMatch:
    return RuleMatch.model_validate(
        {
            "rule_id": rule_id,
            "kind": "term",
            "action": action,
            "state": state,
            "count": 1,
            **values,
        }
    )


def test_records_put_blocks_first_then_ids_and_cap_at_32() -> None:
    evaluated = RuleSet(revision=1, rules=(_rule("a"),))
    matches = [_match(f"r{index:02d}", action="mask") for index in range(40)] + [
        _match("z_block")
    ]

    records = match_records(_prepared(rules=evaluated, rule_matches=matches))

    assert [record["rule_id"] for record in records["rule_matches"][:3]] == [
        "z_block",
        "r00",
        "r01",
    ]
    assert len(records["rule_matches"]) == 32
    assert records["rule_matches_truncated"] is True
    assert match_records(_prepared(rules=evaluated, rule_matches=[_match("a")])) == {
        "rule_matches": [
            {
                "rule_id": "a",
                "kind": "term",
                "action": "block",
                "state": "enforced",
                "count": 1,
            }
        ],
        "rule_matches_truncated": False,
    }
    errored = [_match("a", error=True, count=0)]
    assert match_records(_prepared(rules=evaluated, rule_matches=errored))[
        "rule_matches"
    ][0]["error"]
    assert match_records(_prepared(rules=evaluated)) == {
        "rule_matches": [],
        "rule_matches_truncated": False,
    }
    assert match_records(_prepared()) == {}
    assert match_records(_prepared(rules=RuleSet(revision=1, rules=()))) == {}
    assert [
        m.rule_id
        for m in ordered_matches(
            [_match("b", action="warn"), _match("a", action="warn")]
        )
    ] == ["a", "b"]


def test_settling_records_verdicts_warnings_and_returns_refusals() -> None:
    rules = (
        "blocked",
        "masked",
        "warned",
        "would_block",
        "broken_mask",
        "broken_warn",
        "approval",
    )
    prepared = _prepared(
        rules=RuleSet(revision=3, rules=tuple(_rule(rule_id) for rule_id in rules))
    )
    prepared.rule_matches += [
        _match("blocked"),
        _match("masked", action="mask"),
        _match("warned", action="warn"),
        _match("would_block", state="monitor"),
        _match("broken_mask", action="mask", error=True, count=0),
        _match("broken_warn", action="warn", error=True, count=0),
        _match("approval", action="require_approval"),
    ]

    blocked, approval = settle_matches(prepared)

    assert (blocked, approval) == (["blocked", "broken_mask"], ["approval"])
    assert prepared.warnings == ["RULE_WARN"]
    verdicts = {
        verdict.rule_id: (verdict.outcome, verdict.reason_code)
        for verdict in prepared.policy_verdicts
    }
    assert verdicts == {
        "rule.blocked": ("deny", "RULE_BLOCKED"),
        "rule.masked": ("mask", "RULE_MASKED"),
        "rule.warned": ("allow", "RULE_WARN"),
        "rule.would_block": ("allow", "RULE_WOULD_BLOCK"),
        "rule.broken_mask": ("error", "RULE_EVALUATION_TIMEOUT"),
        "rule.broken_warn": ("error", "RULE_EVALUATION_TIMEOUT"),
        "rule.approval": ("allow", "RULE_REQUIRE_APPROVAL"),
        "rules.evaluated": ("allow", "RULES_EVALUATED"),
    }
    assert all(verdict.stage == "rules" for verdict in prepared.policy_verdicts)


def test_a_rule_version_follows_the_rule_and_the_revision() -> None:
    def version(revision: int, action: str) -> str:
        prepared = _prepared(
            rules=RuleSet(revision=revision, rules=(_rule("r", action=action),))
        )
        prepared.rule_matches.append(_match("r", action=action))
        settle_matches(prepared)
        return next(
            v.policy_version for v in prepared.policy_verdicts if v.rule_id == "rule.r"
        )

    assert version(1, "block") == version(1, "block")
    assert version(1, "block") != version(2, "block") != version(2, "mask")


def test_monitor_state_never_refuses_or_warns() -> None:
    prepared = _prepared(rules=RuleSet(revision=1, rules=(_rule("r"),)))
    prepared.rule_matches += [
        _match("r", state="monitor"),
        _match("r", action="warn", state="monitor"),
    ]

    assert settle_matches(prepared) == ([], [])
    assert prepared.warnings == []


def test_verdicts_are_capped_at_32_rules() -> None:
    ids = [f"r{index:02d}" for index in range(40)]
    prepared = _prepared(
        rules=RuleSet(
            revision=1, rules=tuple(_rule(rule_id, action="warn") for rule_id in ids)
        )
    )
    prepared.rule_matches += [_match(rule_id, action="warn") for rule_id in ids]

    settle_matches(prepared)

    assert (
        len([v for v in prepared.policy_verdicts if v.rule_id.startswith("rule.")])
        == 32
    )
