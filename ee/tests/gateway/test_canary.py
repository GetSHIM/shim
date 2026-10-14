"""Split and change-test rules through the real resolver, kernel and ledger."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ee.tests.gateway.test_fallback import (  # noqa: F401
    CHAT,
    _body,
    _fallback_gateway,
    _hosts,
    _rows,
    _rules,
    _unhealthy,
)
from ee.tests.tenants.test_deployments import (  # noqa: F401
    _deployments,
    db,
    origins,
    test_org,
)
from shim_enterprise.tenants.deployments import canary_bucket

pytestmark = pytest.mark.usefixtures("origins")
TENANT = "00000000-0000-4000-8000-000000000001"


def _split(
    share: float = 100,
    state: str = "enforced",
    fallback: bool = False,
    rule_id: str = "llama4_kanarya",
) -> dict:
    return {
        "id": rule_id,
        "name": "Llama 4 to a share",
        "kind": "route",
        "action": "route",
        "state": state,
        "match": {
            "on": "split",
            "from": "internal-a",
            "to": "internal-b",
            "share_percent": share,
            "fallback_to_stable": fallback,
        },
    }


def test_the_bucket_formula_is_pinned() -> None:
    assert canary_bucket(TENANT, "llama4_kanarya", "conv-1") == 6879
    assert canary_bucket(TENANT, "llama4_kanarya", "key:abc") == 4593
    assert canary_bucket(TENANT, "other_rule", "conv-1") == 5310


def test_raising_the_share_keeps_every_candidate_and_the_ends_are_exact() -> None:
    buckets = [canary_bucket(TENANT, "r", f"conv-{index}") for index in range(1_000)]

    def candidates(share: float) -> set[int]:
        return {index for index, bucket in enumerate(buckets) if bucket < share * 100}

    assert candidates(0) == set()
    assert candidates(100) == set(range(1_000))
    assert candidates(5) <= candidates(5.5) <= candidates(10)
    assert 20 <= len(candidates(5)) <= 80
    assert buckets == [canary_bucket(TENANT, "r", f"conv-{i}") for i in range(1_000)]


async def _send(db, key, rules, *conversations, failures=None, **body):  # noqa: F811
    calls: list[str] = []
    responses = []
    async with _fallback_gateway(db, key, _hosts(calls, failures or {}), rules) as (
        client,
        _,
    ):
        for index, conversation in enumerate(conversations):
            headers = (
                {} if conversation is None else {"x-shim-conversation-id": conversation}
            )
            responses.append(
                # Distinct text, so the repeat detector never answers.
                await client.post(
                    CHAT, json={**_body(f"hello {index}"), **body}, headers=headers
                )
            )
    return calls, responses


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("share", "state", "host", "side"),
    [
        (100, "enforced", "b", "candidate"),
        (0, "enforced", "a", "stable"),
        (100, "monitor", "a", "candidate"),
    ],
)
async def test_the_bucket_picks_the_side_and_both_sides_are_recorded(
    db,  # noqa: F811
    test_api_key,
    share,
    state,
    host,
    side,
) -> None:
    a, b = await _deployments(db, test_api_key)

    calls, [answered] = await _send(
        db, test_api_key, _rules(_split(share, state)), "conv-1"
    )

    assert answered.status_code == 200, answered.text
    assert calls == [host]
    [row] = await _rows(db, test_api_key)
    decision = row.lifecycle_metadata["route_decision"]
    assert decision.pop("conversation_id")
    assert decision == {
        "rule_id": "llama4_kanarya",
        "state": state,
        "from": "internal-a",
        "to": "internal-b" if host == "b" else "internal-a",
        "reason": "canary",
        "canary_side": side,
    }
    assert row.provider_model == (b if host == "b" else a).upstream_model
    assert [
        (match["rule_id"], match["count"])
        for match in row.lifecycle_metadata["rule_matches"]
    ] == [("llama4_kanarya", 1)]


@pytest.mark.asyncio
async def test_a_conversation_stays_on_its_side_and_without_one_the_key_decides(
    db,  # noqa: F811
    test_api_key,
) -> None:
    await _deployments(db, test_api_key)
    conversations = [f"conv-{index}" for index in range(12)]
    expected = [
        "b"
        if canary_bucket(str(test_api_key.organization_id), "llama4_kanarya", c) < 5_000
        else "a"
        for c in conversations
    ]
    keyed = (
        "b"
        if canary_bucket(
            str(test_api_key.organization_id),
            "llama4_kanarya",
            f"key:{test_api_key.id}",
        )
        < 5_000
        else "a"
    )

    calls, responses = await _send(
        db,
        test_api_key,
        _rules(_split(50)),
        *conversations,
        *conversations,
        None,
        None,
        None,
    )

    assert [response.status_code for response in responses] == [200] * 27
    assert calls == expected + expected + [keyed] * 3
    assert {"a", "b"} <= set(expected)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "held", ["disabled", "unhealthy", "not_approved", "not_allowed_for_key"]
)
async def test_a_candidate_that_cannot_serve_keeps_the_request_on_stable(
    db,  # noqa: F811
    test_api_key,
    held,
) -> None:
    _, b = await _deployments(db, test_api_key)
    if held == "disabled":
        b.enabled = False
    elif held == "unhealthy":
        _unhealthy(b)
    elif held == "not_approved":
        b.base_url = "https://c.internal/v1"
    else:
        test_api_key.allowed_models = ["internal-a"]

    calls, [answered] = await _send(db, test_api_key, _rules(_split()), "conv-1")

    assert answered.status_code == 200, answered.text
    assert calls == ["a"]
    [row] = await _rows(db, test_api_key)
    assert (
        row.lifecycle_metadata["route_decision"]["canary_side"],
        row.lifecycle_metadata["route_decision"]["to"],
        row.lifecycle_metadata["route_decision"]["held"],
    ) == ("stable", "internal-a", held)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fallback", "failure", "status", "calls"),
    [
        (False, 503, 503, ["b"]),
        (True, 503, 200, ["b", "a"]),
        (True, 400, 400, ["b"]),
    ],
)
async def test_a_failed_candidate_falls_back_to_stable_only_when_the_rule_says_so(
    db,  # noqa: F811
    test_api_key,
    fallback,
    failure,
    status,
    calls,
) -> None:
    await _deployments(db, test_api_key)

    seen, [response] = await _send(
        db,
        test_api_key,
        _rules(_split(fallback=fallback)),
        "conv-1",
        failures={"b": failure},
    )

    assert response.status_code == status, response.text
    assert seen == calls
    rows = await _rows(db, test_api_key)
    assert len(rows) == len(calls)
    if status == 200:
        assert response.headers["x-shim-attempts"] == "2"
        assert rows[1].lifecycle_metadata["attempt_reason"] == "canary_fallback"
        assert rows[1].lifecycle_metadata["attempt_rule_id"] == "llama4_kanarya"
        assert rows[0].status == "failed"


@pytest.mark.asyncio
async def test_an_unhealthy_stable_alias_moved_to_its_candidate_is_not_moved_again(
    db,  # noqa: F811
    test_api_key,
) -> None:
    a, _ = await _deployments(db, test_api_key)
    a.health, a.health_checked_at = "unhealthy", datetime.now(timezone.utc)
    unavailable = {
        "id": "a_down",
        "name": "A down",
        "kind": "route",
        "action": "route",
        "state": "enforced",
        "match": {
            "on": "unavailable",
            "from": "internal-a",
            "to": ["internal-b"],
            "triggers": ["health_flag"],
        },
    }

    calls, [answered] = await _send(
        db, test_api_key, _rules(_split(), unavailable), "conv-1"
    )

    assert answered.status_code == 200, answered.text
    assert calls == ["b"]
    [row] = await _rows(db, test_api_key)
    assert row.lifecycle_metadata["route_decision"]["canary_side"] == "candidate"


@pytest.mark.asyncio
async def test_a_candidate_that_is_no_longer_internal_keeps_the_request_on_stable(
    db,  # noqa: F811
    test_api_key,
    monkeypatch,
) -> None:
    from shim_enterprise.core.config import settings

    await _deployments(db, test_api_key)
    # b is still labelled internal, but the operator's list now makes it external.
    monkeypatch.setattr(
        settings, "MODEL_DEPLOYMENT_INTERNAL_ORIGINS", ["https://a.internal"]
    )

    calls, [answered] = await _send(db, test_api_key, _rules(_split()), "conv-1")

    assert answered.status_code == 200, answered.text
    assert calls == ["a"]
    [row] = await _rows(db, test_api_key)
    decision = row.lifecycle_metadata["route_decision"]
    assert (decision["canary_side"], decision["held"]) == ("stable", "not_approved")


@pytest.mark.asyncio
async def test_a_copy_the_core_guard_refuses_takes_nothing_from_the_test_cap(
    db,  # noqa: F811
    test_api_key,
) -> None:
    from datetime import timedelta
    from types import SimpleNamespace

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from ee.tests.gateway.test_change_test import _Redis
    from ee.tests.gateway.test_fallback import _row
    from ee.tests.tenants.test_deployments import _gateway, _success
    from shim_enterprise.gateway.change_test import ChangeTestSender, counter_key

    await _row(db, test_api_key, "a")
    await _row(db, test_api_key, "b")
    starts = datetime.now(timezone.utc) - timedelta(hours=1)
    shadow = {
        "id": "degisiklik",
        "name": "Copy to b",
        "kind": "route",
        "action": "route",
        "state": "enforced",
        "match": {
            "on": "shadow",
            "from": "internal-a",
            "to": "internal-b",
            "share_percent": 100,
            "starts_at": starts.isoformat(),
            "ends_at": (starts + timedelta(days=2)).isoformat(),
            "max_requests": 5,
            "max_cost_usd": "5",
        },
    }
    # Acts at b only, so the copy would carry text privacy never masked.
    guard = {
        "id": "falcon",
        "name": "Falcon at b",
        "kind": "term",
        "action": "mask",
        "state": "enforced",
        "scope": {"models": ["model-b"]},
        "match": {"terms": ["Falcon"]},
    }
    calls = []
    redis = _Redis()

    def upstream(request):
        calls.append(request.url.host[0])
        return _success(request, False, "chat")

    async with _gateway(db, test_api_key, upstream, _rules(shadow, guard)) as (
        client,
        app,
        _,
    ):
        kernel = app.state.gateway_service.kernel
        kernel.shadow_sender = ChangeTestSender(
            async_sessionmaker(db.bind, expire_on_commit=False),
            SimpleNamespace(redis=redis),
        )
        answered = await client.post(CHAT, json=_body("Project Falcon"))
        await kernel.postprocessor.drain()

    assert answered.status_code == 200, answered.text
    assert calls == ["a"]
    key = counter_key(test_api_key.organization_id, "degisiklik", starts)
    assert int(redis.values.get(f"{key}:n", 0)) == 0
