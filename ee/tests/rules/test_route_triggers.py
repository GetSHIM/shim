from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import update

from ee.tests.rules.test_rules_resource import (
    MANAGEMENT,
    _aliases,
    _call,
    _organization,
    _put,
    _stored,
)
from shim_enterprise.tenants.models import ModelDeployment


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
@pytest.mark.parametrize("on", ["unavailable", "size"])
async def test_a_preview_cannot_replay_health_or_sizes_and_says_start_in_monitor(
    db, owner, on
) -> None:
    await _same_model(db, owner, "llama-a", "llama-b")
    previewed = await _call(
        db,
        owner,
        "POST",
        f"{MANAGEMENT}/rules/preview",
        json={"rule": _fallback() if on == "unavailable" else _size()},
    )

    assert previewed.status_code == 200, previewed.text
    answer = previewed.json()
    assert (answer["basis"], answer["requests"], answer["enforce_on_create"]) == (
        "none",
        None,
        False,
    )
    assert answer["note"].endswith("start in monitor")


def _split(rule_id: str = "llama4_kanarya", **match) -> dict:
    return {
        "id": rule_id,
        "name": "Llama 4 to 5 percent",
        "kind": "route",
        "action": "route",
        "state": "monitor",
        "match": {
            "on": "split",
            "from": "llama-a",
            "to": "llama-b",
            "share_percent": 5,
            "fallback_to_stable": False,
            **match,
        },
    }


@pytest.mark.asyncio
async def test_a_split_rule_is_stored_with_its_share(db, owner) -> None:
    stored = await _put(db, owner, [_split(share_percent=12.5)])

    assert stored.status_code == 200, stored.text
    assert (await _stored(db, owner.organization_id))[0]["match"][
        "share_percent"
    ] == 12.5


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("rules", "path"),
    [
        ([_split(**{"from": "unregistered"})], "rules[0].match.from"),
        ([_split(to="unregistered")], "rules[0].match.to"),
        ([_split(to="sonnet")], "rules[0].match.to"),
        ([_split(to="llama-a")], "rules[0].match"),
        ([_split(share_percent=-1)], "rules[0].match.share_percent"),
        ([_split(share_percent=100.5)], "rules[0].match.share_percent"),
        ([_split(share_percent=5.55)], "rules[0].match"),
        ([_split(), _split("second", to="llama-c")], "rules[1].match.from"),
        # No chains: llama-b is the first split's candidate.
        (
            [_split(), _split("chain", **{"from": "llama-b"}, to="llama-c")],
            "rules[1].match.from",
        ),
    ],
)
async def test_an_unusable_split_rule_is_refused_with_its_path(
    db, owner, rules, path
) -> None:
    refused = await _put(db, owner, rules)

    assert refused.status_code == 422, refused.text
    assert (refused.json()["detail"]["code"], refused.json()["detail"]["path"]) == (
        "RULE_MATCH_INVALID",
        path,
    )


@pytest.mark.asyncio
async def test_an_internal_alias_never_splits_to_an_external_one(db, owner) -> None:
    await db.execute(
        update(ModelDeployment)
        .where(
            ModelDeployment.organization_id == owner.organization_id,
            ModelDeployment.alias == "llama-b",
        )
        .values(deployment_kind="external")
    )

    refused = await _put(db, owner, [_split()])
    reversed_ = await _put(db, owner, [_split(**{"from": "llama-b"}, to="llama-a")])

    assert refused.status_code == 422, refused.text
    assert refused.json()["detail"]["path"] == "rules[0].match.to"
    assert reversed_.status_code == 200, reversed_.text


def _size(rule_id: str = "uzun_serit", **match) -> dict:
    return {
        "id": rule_id,
        "name": "Long requests to replica 2",
        "kind": "route",
        "action": "route",
        "state": "monitor",
        "match": {
            "on": "size",
            "from": "llama-a",
            "to": "llama-b",
            "min_input_tokens": 8_000,
            **match,
        },
    }


async def _same_model(db, owner, *aliases: str) -> None:
    await db.execute(
        update(ModelDeployment)
        .where(
            ModelDeployment.organization_id == owner.organization_id,
            ModelDeployment.alias.in_(aliases),
        )
        .values(upstream_model="llama-shared")
    )


@pytest.mark.asyncio
async def test_a_lane_on_a_replica_is_stored(db, owner) -> None:
    await _same_model(db, owner, "llama-a", "llama-b")

    stored = await _put(db, owner, [_size()])

    assert stored.status_code == 200, stored.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("rules", "path"),
    [
        ([_size(to="llama-c")], "rules[0].match.to"),
        ([_size(to="sonnet")], "rules[0].match.to"),
        ([_size(to="unregistered")], "rules[0].match.to"),
        ([_size(min_input_tokens=255)], "rules[0].match.min_input_tokens"),
        ([_size(min_input_tokens=10_000_001)], "rules[0].match.min_input_tokens"),
        ([_size(to="llama-a")], "rules[0].match"),
        ([_size(), _size("second")], "rules[1].match.from"),
    ],
)
async def test_an_unusable_lane_is_refused_with_its_path(
    db, owner, rules, path
) -> None:
    await _same_model(db, owner, "llama-a", "llama-b")

    refused = await _put(db, owner, rules)

    assert refused.status_code == 422, refused.text
    assert (refused.json()["detail"]["code"], refused.json()["detail"]["path"]) == (
        "RULE_MATCH_INVALID",
        path,
    )


@pytest.mark.asyncio
async def test_a_lane_of_another_kind_is_refused(db, owner) -> None:
    await _same_model(db, owner, "llama-a", "llama-b")
    await db.execute(
        update(ModelDeployment)
        .where(
            ModelDeployment.organization_id == owner.organization_id,
            ModelDeployment.alias == "llama-b",
        )
        .values(deployment_kind="external")
    )

    refused = await _put(db, owner, [_size()])

    assert refused.status_code == 422, refused.text
    assert "kind" in refused.json()["detail"]["message"]
