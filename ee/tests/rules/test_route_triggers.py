from __future__ import annotations

import pytest
import pytest_asyncio

from ee.tests.rules.test_rules_resource import (
    MANAGEMENT,
    _aliases,
    _call,
    _organization,
    _put,
    _stored,
)


def _fallback(rule_id: str = "llama_a_yedek", **match) -> dict:
    return {
        "id": rule_id,
        "name": "Llama A down: use B",
        "kind": "route",
        "action": "route",
        "state": "monitor",
        "match": {
            "on": "unavailable",
            "from": "llama-a",
            "to": ["llama-b"],
            "triggers": ["health_flag", "circuit_open", "provider_error"],
            **match,
        },
    }


@pytest_asyncio.fixture
async def owner(db):
    owner = (await _organization(db))["owner"]
    await _aliases(
        db,
        owner.organization_id,
        {
            "llama-a": "openai",
            "llama-b": "openai",
            "llama-c": "openai",
            "llama-d": "openai",
            "sonnet": "anthropic",
        },
    )
    return owner


@pytest.mark.asyncio
async def test_the_predefined_rule_is_stored_as_sent(db, owner) -> None:
    stored = await _put(db, owner, [_fallback(to=["llama-b", "llama-c"])])

    assert stored.status_code == 200, stored.text
    assert (await _stored(db, owner.organization_id))[0]["match"] == {
        "on": "unavailable",
        "from": "llama-a",
        "to": ["llama-b", "llama-c"],
        "triggers": ["health_flag", "circuit_open", "provider_error"],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("rules", "path"),
    [
        ([_fallback(**{"from": "unregistered"})], "rules[0].match.from"),
        ([_fallback(to=["llama-b", "unregistered"])], "rules[0].match.to[1]"),
        # A catalog model has no registry target.
        ([_fallback(to=["gpt-5.6-luna"])], "rules[0].match.to[0]"),
        ([_fallback(to=["sonnet"])], "rules[0].match.to[0]"),
        ([_fallback(to=["llama-b", "llama-a"])], "rules[0].match"),
        ([_fallback(to=["llama-b", "llama-c", "llama-d"])], "rules[0].match.to"),
        ([_fallback(to=[])], "rules[0].match.to"),
        ([_fallback(triggers=[])], "rules[0].match.triggers"),
        ([_fallback(triggers=["health_flag", "slow"])], "rules[0].match.triggers[1]"),
        ([_fallback(extra=1)], "rules[0].match.extra"),
        (
            [_fallback(), _fallback("second", to=["llama-c"])],
            "rules[1].match.from",
        ),
        # Owned by a later release: nothing here would evaluate it.
        ([_fallback(on="capacity")], "rules[0].match.on"),
    ],
)
async def test_an_unusable_fallback_rule_is_refused_with_its_path(
    db, owner, rules, path
) -> None:
    refused = await _put(db, owner, rules)

    assert refused.status_code == 422, refused.text
    assert (refused.json()["detail"]["code"], refused.json()["detail"]["path"]) == (
        "RULE_MATCH_INVALID",
        path,
    )
    assert await _stored(db, owner.organization_id) == []


@pytest.mark.asyncio
async def test_two_sources_each_with_one_rule_are_kept(db, owner) -> None:
    stored = await _put(
        db,
        owner,
        [
            _fallback(),
            _fallback("c_down", **{"from": "llama-c"}, to=["llama-b", "llama-d"]),
        ],
    )

    assert stored.status_code == 200, stored.text


@pytest.mark.asyncio
async def test_a_preview_cannot_replay_health_and_says_start_in_monitor(
    db, owner
) -> None:
    previewed = await _call(
        db,
        owner,
        "POST",
        f"{MANAGEMENT}/rules/preview",
        json={"rule": _fallback()},
    )

    assert previewed.status_code == 200, previewed.text
    answer = previewed.json()
    assert (answer["basis"], answer["requests"], answer["enforce_on_create"]) == (
        "none",
        None,
        False,
    )
    assert answer["note"].endswith("start in monitor")
