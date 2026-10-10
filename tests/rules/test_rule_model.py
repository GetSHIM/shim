from __future__ import annotations

from pydantic import BaseModel
import pytest

import shim.rules.kinds as kinds
from shim.rules import RuleSet, RuleSetError, validate_rule_set
from shim.rules.kinds import KindSpec


class _TermMatch(BaseModel):
    terms: list[str]


@pytest.fixture
def term_kind(monkeypatch):
    # A test-only match model stands in for the one S36 adds.
    monkeypatch.setitem(
        kinds.KINDS,
        "term",
        KindSpec(
            "privacy",
            ("monitor", "warn", "mask", "block", "require_approval"),
            _TermMatch,
        ),
    )


def _rule(**values) -> dict:
    return {
        "id": "project_names",
        "name": "Project names",
        "kind": "term",
        "action": "mask",
        "state": "monitor",
        "match": {"terms": ["aurora"]},
        **values,
    }


def _refused(payload: dict, **options) -> RuleSetError:
    with pytest.raises(RuleSetError) as error:
        validate_rule_set(payload, **options)
    return error.value


def test_an_empty_set_and_a_valid_rule_validate(term_kind) -> None:
    assert validate_rule_set({"revision": 1, "rules": []}) == RuleSet(
        revision=1, rules=()
    )
    rule_set = validate_rule_set({"revision": 2, "rules": [_rule()]})

    assert rule_set.rules[0].match == {"terms": ["aurora"]}
    assert rule_set.rules[0].scope.api_key_ids == ()


@pytest.mark.parametrize("rule_id", ["a", "a" * 48, "rule_2", "x_y_z"])
def test_rule_ids_on_the_bound(term_kind, rule_id) -> None:
    validate_rule_set({"revision": 1, "rules": [_rule(id=rule_id)]})


@pytest.mark.parametrize(
    "rule_id", ["", "a" * 49, "with-hyphen", "Upper", "1starts_with_digit", "has space"]
)
def test_rule_ids_past_the_bound(term_kind, rule_id) -> None:
    error = _refused({"revision": 1, "rules": [_rule(id=rule_id)]})

    assert (error.code, error.path) == ("RULE_SET_INVALID", "rules[0].id")


def test_a_set_holds_at_most_100_rules(term_kind) -> None:
    rules = [_rule(id=f"r{index}") for index in range(101)]

    validate_rule_set({"revision": 1, "rules": rules[:100]})
    assert _refused({"revision": 1, "rules": rules}).path == "rules"


def test_names_scope_lists_and_revisions_are_bounded(term_kind) -> None:
    uuid = "11111111-1111-1111-1111-111111111111"
    validate_rule_set(
        {
            "revision": 1,
            "rules": [
                _rule(
                    name="n" * 100,
                    scope={
                        "tags": ["t" * 200] * 100,
                        "api_key_ids": [uuid],
                        "deployment_kinds": ["internal"],
                        "endpoints": ["chat", "count_tokens"],
                    },
                )
            ],
        }
    )
    for rule, path in (
        (_rule(name=""), "rules[0].name"),
        (_rule(name="n" * 101), "rules[0].name"),
        (_rule(scope={"tags": ["t"] * 101}), "rules[0].scope.tags"),
        (_rule(scope={"tags": ["t" * 201]}), "rules[0].scope.tags[0]"),
        (_rule(scope={"api_key_ids": ["not-a-uuid"]}), "rules[0].scope.api_key_ids[0]"),
        (
            _rule(scope={"deployment_kinds": ["unknown"]}),
            "rules[0].scope.deployment_kinds[0]",
        ),
        (_rule(scope={"endpoints": ["embeddings"]}), "rules[0].scope.endpoints[0]"),
        (_rule(scope={"owners": ["x"]}), "rules[0].scope.owners"),
        (_rule(extra=1), "rules[0].extra"),
    ):
        assert _refused({"revision": 1, "rules": [rule]}).path == path
    assert _refused({"revision": 0, "rules": []}).path == "revision"


def test_kinds_actions_and_duplicates_are_checked(term_kind) -> None:
    assert (
        _refused({"revision": 1, "rules": [_rule(kind="weather")]}).path
        == "rules[0].kind"
    )
    unavailable = _refused({"revision": 1, "rules": [_rule(kind="pattern")]})
    assert (unavailable.code, unavailable.path) == (
        "RULE_KIND_UNAVAILABLE",
        "rules[0].kind",
    )
    for action in ("set", "route"):
        refused = _refused({"revision": 1, "rules": [_rule(action=action)]})
        assert (refused.code, refused.path) == (
            "RULE_ACTION_UNAVAILABLE",
            "rules[0].action",
        )
    duplicate = _refused({"revision": 1, "rules": [_rule(), _rule(name="again")]})
    assert (duplicate.code, duplicate.path) == ("RULE_ID_DUPLICATE", "rules[1].id")
    invalid = _refused({"revision": 1, "rules": [_rule(match={"terms": "aurora"})]})
    assert (invalid.code, invalid.path) == (
        "RULE_MATCH_INVALID",
        "rules[0].match.terms",
    )


def test_require_approval_needs_an_available_gate(term_kind) -> None:
    payload = {"revision": 1, "rules": [_rule(action="require_approval")]}

    refused = _refused(payload)
    assert (refused.code, refused.path) == (
        "RULE_ACTION_UNAVAILABLE",
        "rules[0].action",
    )
    assert validate_rule_set(payload, approval_available=True).rules[0].action == (
        "require_approval"
    )


def test_every_kind_is_unavailable_until_its_prd_adds_a_match_model() -> None:
    assert {kind: spec.match for kind, spec in kinds.KINDS.items()} == dict.fromkeys(
        kinds.KINDS
    )
    assert {kind: spec.point for kind, spec in kinds.KINDS.items()} == {
        "term": "privacy",
        "pattern": "privacy",
        "record_set": "privacy",
        "destination": "privacy",
        "request_limit": "admission",
        "parameter_pin": "settings",
        "route": "resolver",
    }
