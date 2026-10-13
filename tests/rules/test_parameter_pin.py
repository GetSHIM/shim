from __future__ import annotations

from typing import Any

import pytest

from shim.rules import RuleSetError, validate_rule_set


def _set(match: dict[str, Any], scope: dict[str, Any] | None = None):
    return validate_rule_set(
        {
            "revision": 1,
            "rules": [
                {
                    "id": "pin",
                    "name": "n",
                    "kind": "parameter_pin",
                    "action": "set",
                    "state": "monitor",
                    "scope": scope or {},
                    "match": match,
                }
            ],
        }
    )


@pytest.mark.parametrize(
    ("parameter", "value"),
    [
        ("temperature", 0),
        ("temperature", 1),
        ("temperature", 0.35),
        ("top_p", 0),
        ("top_p", 1.0),
        ("top_k", 1),
        ("top_k", 500),
        ("seed", 0),
        ("seed", 2_147_483_647),
        *(("reasoning_effort", effort) for effort in ("none", "minimal", "xhigh")),
    ],
)
def test_a_value_inside_its_bounds_is_stored(parameter, value) -> None:
    [rule] = _set({"parameter": parameter, "value": value}).rules

    assert rule.match == {"parameter": parameter, "value": value}


@pytest.mark.parametrize(
    "match",
    [
        {"parameter": "temperature", "value": -0.1},
        {"parameter": "temperature", "value": 2.01},
        {"parameter": "temperature", "value": "0"},
        {"parameter": "temperature", "value": True},
        {"parameter": "top_p", "value": 1.5},
        {"parameter": "top_k", "value": 0},
        {"parameter": "top_k", "value": 501},
        {"parameter": "top_k", "value": 5.0},
        {"parameter": "seed", "value": -1},
        {"parameter": "seed", "value": 2_147_483_648},
        {"parameter": "reasoning_effort", "value": "max"},
        {"parameter": "reasoning_effort", "value": 1},
        {"parameter": "max_tokens", "value": 100},
        {"parameter": "max_completion_tokens", "value": 100},
        {"parameter": "max_output_tokens", "value": 100},
        {"parameter": "maxOutputTokens", "value": 100},
        {"parameter": "temperature"},
        {"value": 0},
        {"parameter": "temperature", "value": 0, "extra": 1},
    ],
)
def test_a_value_out_of_bounds_an_output_field_or_a_missing_key_is_refused(
    match,
) -> None:
    with pytest.raises(RuleSetError) as refused:
        _set(match)

    assert refused.value.code == "RULE_MATCH_INVALID"
    assert refused.value.path.startswith("rules[0].match")


@pytest.mark.parametrize(
    ("scope", "allowed"),
    [
        ({}, False),
        ({"endpoints": ["chat", "messages"]}, False),
        ({"models": ["gpt-5-nano"]}, False),
        ({"endpoints": ["chat", "responses"]}, True),
        ({"endpoints": ["generate_content"]}, True),
    ],
)
def test_a_temperature_above_1_needs_a_scope_without_messages(scope, allowed) -> None:
    match = {"parameter": "temperature", "value": 1.5}
    if allowed:
        assert _set(match, scope).rules[0].match["value"] == 1.5
        return
    with pytest.raises(RuleSetError) as refused:
        _set(match, scope)

    assert (refused.value.code, refused.value.path) == (
        "RULE_PIN_OUT_OF_RANGE",
        "rules[0].match.value",
    )


def test_a_pin_takes_monitor_warn_set_and_block_only() -> None:
    for action in ("monitor", "warn", "set", "block"):
        assert validate_rule_set(
            {
                "revision": 1,
                "rules": [
                    {
                        "id": "pin",
                        "name": "n",
                        "kind": "parameter_pin",
                        "action": action,
                        "state": "monitor",
                        "match": {"parameter": "seed", "value": 1},
                    }
                ],
            }
        )
    with pytest.raises(RuleSetError) as refused:
        validate_rule_set(
            {
                "revision": 1,
                "rules": [
                    {
                        "id": "pin",
                        "name": "n",
                        "kind": "parameter_pin",
                        "action": "mask",
                        "state": "monitor",
                        "match": {"parameter": "seed", "value": 1},
                    }
                ],
            }
        )
    assert refused.value.code == "RULE_ACTION_UNAVAILABLE"
