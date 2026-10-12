from __future__ import annotations

import pytest

import shim.rules.kinds as kinds
import shim.rules.patterns as patterns
from shim.rules import RuleSet, RuleSetError, validate_rule_set
from shim.rules.content import PatternMatch, TermMatch
from shim.rules.destination import DestinationMatch
from shim.rules.parameter_pin import ParameterPinMatch
from shim.rules.record_set import RecordSetMatch
from shim.rules.request_limit import RequestLimitMatch


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


def test_an_empty_set_and_a_valid_rule_validate() -> None:
    assert validate_rule_set({"revision": 1, "rules": []}) == RuleSet(
        revision=1, rules=()
    )
    rule_set = validate_rule_set({"revision": 2, "rules": [_rule()]})

    assert rule_set.rules[0].match == {
        "terms": ["aurora"],
        "label": "TERM",
        "suffixes": "tr",
    }
    assert rule_set.rules[0].scope.api_key_ids == ()


@pytest.mark.parametrize("rule_id", ["a", "a" * 48, "rule_2", "x_y_z"])
def test_rule_ids_on_the_bound(rule_id) -> None:
    validate_rule_set({"revision": 1, "rules": [_rule(id=rule_id)]})


@pytest.mark.parametrize(
    "rule_id", ["", "a" * 49, "with-hyphen", "Upper", "1starts_with_digit", "has space"]
)
def test_rule_ids_past_the_bound(rule_id) -> None:
    error = _refused({"revision": 1, "rules": [_rule(id=rule_id)]})

    assert (error.code, error.path) == ("RULE_SET_INVALID", "rules[0].id")


def test_a_set_holds_at_most_100_rules() -> None:
    rules = [_rule(id=f"r{index}") for index in range(101)]

    validate_rule_set({"revision": 1, "rules": rules[:100]})
    assert _refused({"revision": 1, "rules": rules}).path == "rules"


def test_names_scope_lists_and_revisions_are_bounded() -> None:
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


def test_kinds_actions_and_duplicates_are_checked() -> None:
    assert (
        _refused({"revision": 1, "rules": [_rule(kind="weather")]}).path
        == "rules[0].kind"
    )
    unavailable = _refused({"revision": 1, "rules": [_rule(kind="route")]})
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


def test_require_approval_needs_an_available_gate() -> None:
    payload = {"revision": 1, "rules": [_rule(action="require_approval")]}

    refused = _refused(payload)
    assert (refused.code, refused.path) == (
        "RULE_ACTION_UNAVAILABLE",
        "rules[0].action",
    )
    assert validate_rule_set(payload, approval_available=True).rules[0].action == (
        "require_approval"
    )


def test_a_kind_is_unavailable_until_its_prd_adds_a_match_model() -> None:
    assert {kind: spec.match for kind, spec in kinds.KINDS.items()} == {
        **dict.fromkeys(kinds.KINDS),
        "term": TermMatch,
        "pattern": PatternMatch,
        "destination": DestinationMatch,
        "request_limit": RequestLimitMatch,
        "record_set": RecordSetMatch,
        "parameter_pin": ParameterPinMatch,
    }
    assert {kind: spec.point for kind, spec in kinds.KINDS.items()} == {
        "term": "privacy",
        "pattern": "privacy",
        "record_set": "privacy",
        "destination": "privacy",
        "request_limit": "admission",
        "parameter_pin": "settings",
        "route": "resolver",
    }


def test_a_stored_set_keeps_aside_every_rule_this_build_cannot_run() -> None:
    stored = [
        _rule(id="usable", state="enforced", match={"terms": ["Atlas"]}),
        _rule(id="new_kind", kind="geo_fence", action="block", state="enforced"),
        _rule(id="no_matcher", kind="destination", state="enforced"),
        _rule(id="new_field", match={"terms": ["Atlas"], "fuzzy": True}),
        _rule(id="new_action", action="redact", scope={"models": ["gpt-5"]}),
        _rule(id="new_scope", state="enforced", scope={"regions": ["eu"]}),
        _rule(id="held", action="require_approval"),
    ]

    loaded = kinds.load_rule_set(7, stored)

    assert loaded.revision == 7
    assert [rule.id for rule in loaded.rules] == ["usable", "held"]
    assert loaded.rules[0].match["suffixes"] == "tr"
    unusable = {rule.id: rule for rule in loaded.unusable}
    assert list(unusable) == [
        "new_kind",
        "no_matcher",
        "new_field",
        "new_action",
        "new_scope",
    ]
    assert unusable["new_kind"].stored == stored[1]
    assert [rule.id for rule in loaded.unusable if rule.enforced] == [
        "new_kind",
        "no_matcher",
        "new_scope",
    ]
    assert unusable["new_action"].scope.models == ("gpt-5",)
    # A scope this build cannot read applies to every request.
    assert unusable["new_scope"].scope == kinds.RuleScope()


@pytest.mark.parametrize(
    "stored", [{"kind": "term"}, {"id": "Bad-Id", "action": "x", "state": "y"}, []]
)
def test_a_stored_rule_without_a_readable_id_action_or_state_is_refused(
    stored,
) -> None:
    with pytest.raises(RuleSetError) as error:
        kinds.load_rule_set(1, [stored])

    assert (error.value.code, error.value.path) == ("RULE_SET_INVALID", "rules[0]")


def test_a_stored_pattern_is_not_probed_again(monkeypatch) -> None:
    # Every timed probe fails: a write is refused, a stored set still loads.
    monkeypatch.setattr(patterns, "PROBE_SECONDS", 0.0)
    rule = _rule(kind="pattern", match={"regexes": [r"INV\d{6}"]})

    assert _refused({"revision": 1, "rules": [rule]}).code == "RULE_PATTERN_UNSAFE"
    assert [rule.id for rule in kinds.load_rule_set(1, [rule]).rules] == [
        "project_names"
    ]


def test_every_written_pattern_rule_is_probed_not_only_the_first(monkeypatch) -> None:
    monkeypatch.setattr(patterns, "PROBE_SECONDS", 0.0)
    first = _rule(id="terms_first", kind="term", match={"terms": ["Apollo"]})
    second = _rule(kind="pattern", match={"regexes": [r"INV\d{6}"]})

    refused = _refused({"revision": 1, "rules": [first, second]})

    assert (refused.code, refused.path) == (
        "RULE_PATTERN_UNSAFE",
        "rules[1].match.regexes[0]",
    )
