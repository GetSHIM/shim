from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID

import pytest

from shim.privacy.policies import effective_entity_actions
from shim.rules import RuleSetError, in_scope, validate_rule_set
from shim.rules.destination import destination_actions


def _rule(**values) -> dict:
    return {
        "id": "tckn_stays_inside",
        "name": "TCKN stays inside",
        "kind": "destination",
        "action": "mask",
        "state": "enforced",
        "scope": {"deployment_kinds": ["external"]},
        "match": {"entity_types": ["TR_NATIONAL_ID"]},
        **values,
    }


def _rules(*rules: dict):
    return validate_rule_set({"revision": 1, "rules": list(rules)}).rules


def test_a_destination_rule_stores_its_types() -> None:
    [rule] = _rules(_rule(match={"entity_types": ["TR_NATIONAL_ID", "IBAN_CODE"]}))

    assert rule.match == {"entity_types": ["TR_NATIONAL_ID", "IBAN_CODE"]}


@pytest.mark.parametrize(
    ("values", "code", "path"),
    [
        ({"scope": {}}, "RULE_SCOPE_REQUIRED", "rules[0].scope"),
        (
            {"match": {"entity_types": ["TERM"]}},
            "RULE_MATCH_INVALID",
            "rules[0].match.entity_types",
        ),
        (
            {"match": {"entity_types": ["PERSON"]}},
            "RULE_MATCH_INVALID",
            "rules[0].match.entity_types",
        ),
        (
            {"match": {"entity_types": []}},
            "RULE_MATCH_INVALID",
            "rules[0].match.entity_types",
        ),
        (
            {"match": {"entity_types": ["SECRET"] * 2}},
            "RULE_MATCH_INVALID",
            "rules[0].match.entity_types",
        ),
        (
            {"match": {"entity_types": ["SECRET"] * 33}},
            "RULE_MATCH_INVALID",
            "rules[0].match.entity_types",
        ),
        ({"match": {}}, "RULE_MATCH_INVALID", "rules[0].match.entity_types"),
        (
            {"match": {"entity_types": ["SECRET"], "label": "X"}},
            "RULE_MATCH_INVALID",
            "rules[0].match.label",
        ),
        ({"action": "require_approval"}, "RULE_ACTION_UNAVAILABLE", "rules[0].action"),
        # The caller chooses its tags and endpoint, so they alone cannot keep data in.
        (
            {"action": "block", "scope": {"tags": ["cloud"]}},
            "RULE_SCOPE_REQUIRED",
            "rules[0].scope",
        ),
        (
            {"action": "block", "scope": {"tags": ["x"], "endpoints": ["chat"]}},
            "RULE_SCOPE_REQUIRED",
            "rules[0].scope",
        ),
    ],
)
def test_a_destination_rule_is_refused_when_malformed(values, code, path) -> None:
    with pytest.raises(RuleSetError) as refused:
        _rules(_rule(**values))

    assert (refused.value.code, refused.value.path) == (code, path)


@pytest.mark.parametrize(
    "scope",
    [
        {"tags": ["cloud"], "deployment_kinds": ["external"]},
        {"models": ["gpt-5"]},
        {"team_ids": ["22222222-2222-2222-2222-222222222222"]},
        {"api_key_ids": ["11111111-1111-1111-1111-111111111111"]},
    ],
)
def test_a_destination_block_needs_a_scope_the_server_decides(scope) -> None:
    assert _rules(_rule(action="block", scope=scope))


def test_a_tag_scoped_destination_mask_stays_allowed() -> None:
    assert _rules(_rule(scope={"tags": ["cloud"]}))


def _rule_object(action: str, state: str = "enforced"):
    [rule] = _rules(
        _rule(action=action, state=state, match={"entity_types": ["IBAN_CODE"]})
    )
    return rule


@pytest.mark.parametrize(
    ("base", "action", "state", "applied"),
    [
        ("off", "mask", "enforced", "mask"),
        ("monitor", "mask", "enforced", "mask"),
        ("mask_last4", "mask", "enforced", "mask"),
        ("mask", "mask", "enforced", "mask"),
        ("block", "mask", "enforced", "block"),
        # Detected, never weakened; block and warn act at the decision point.
        ("off", "block", "enforced", "monitor"),
        ("off", "warn", "enforced", "monitor"),
        ("off", "monitor", "enforced", "monitor"),
        ("mask_last4", "block", "enforced", "mask_last4"),
        ("mask", "monitor", "enforced", "mask"),
        # A rule in monitor state changes nothing but detection.
        ("off", "mask", "monitor", "monitor"),
        ("monitor", "mask", "monitor", "monitor"),
        ("mask", "block", "monitor", "mask"),
    ],
)
def test_the_strongest_action_applies_and_the_base_is_never_weakened(
    base, action, state, applied
) -> None:
    actions = effective_entity_actions(None, {"IBAN_CODE": base})

    result = destination_actions(actions, [_rule_object(action, state)])

    assert result == actions | {"IBAN_CODE": applied}


def test_without_rules_the_base_actions_are_returned_as_they_are() -> None:
    actions = effective_entity_actions()

    assert destination_actions(actions, []) is actions


@pytest.mark.parametrize(
    ("kind", "matched"), [("internal", False), ("external", True), ("unknown", True)]
)
def test_an_external_scope_matches_unclassified_targets(kind, matched) -> None:
    prepared = SimpleNamespace(
        api_key_id=UUID("11111111-1111-1111-1111-111111111111"),
        policy=SimpleNamespace(team_id=None),
        model="gpt-5-nano",
        pricing_model="gpt-5-nano",
        deployment_kind=kind,
        protocol="chat",
    )

    assert in_scope(_rule_object("mask"), prepared, ()) is matched
