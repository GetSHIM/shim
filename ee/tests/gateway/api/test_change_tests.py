from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ee.tests.observability.test_tasks import _request, _tenant
from shim_enterprise.observability.analytics_projection import RequestLog
from ee.tests.rules.test_rules_resource import (
    MANAGEMENT,
    POLICY,
    _aliases,
    _call,
    _put,
    _stored,
    _versions,
)

TESTS = f"{MANAGEMENT}/change-tests"
NOW = datetime.now(timezone.utc).replace(microsecond=0)
STARTS = NOW - timedelta(days=1)


def _shadow(state: str = "enforced", **match) -> dict:
    return {
        "id": "llama4_degisiklik",
        "name": "Llama 4 change test",
        "kind": "route",
        "action": "route",
        "state": state,
        "match": {
            "on": "shadow",
            "from": "llama-a",
            "to": "llama-b",
            "share_percent": 100,
            "starts_at": STARTS.isoformat(),
            "ends_at": (STARTS + timedelta(days=7)).isoformat(),
            "max_requests": 1000,
            "max_cost_usd": "50",
            **match,
        },
    }


def _side(
    outcome: str = "complete",
    valid: bool | None = True,
    chars: int | None = 100,
    latency: int = 800,
    cost: str | None = "0.001",
    language: str | None = None,
) -> dict:
    return {
        "status": "completed" if outcome != "failed" else "provider_error",
        "outcome": outcome,
        "schema_valid": valid,
        "language": language,
        "soft_refusal": None,
        "answer_chars": chars,
        "prompt_tokens": 300,
        "completion_tokens": 90,
        "provider_latency_ms": latency,
        "ttft_ms": None,
        "cost_usd": cost,
        "error_code": None,
    }


async def _seed(db, *, state: str = "enforced", **match):
    user, key, _ = await _tenant(db)
    await _aliases(db, user.organization_id, {"llama-a": "openai", "llama-b": "openai"})
    stored = await _put(db, user, [_shadow("monitor", **match)])
    assert stored.status_code == 200, stored.text
    if state == "enforced":
        assert (await _put(db, user, [_shadow(**match)])).status_code == 200

    def copy(primary: dict, candidate: dict, cost: str = "0.002", **values) -> str:
        return _request(
            db,
            key,
            None,
            cost=cost,
            started_at=values.pop("started_at", STARTS + timedelta(hours=1)),
            shadow_of="req_primary",
            shadow_rule_id="llama4_degisiklik",
            shadow_comparison={
                "rule_id": "llama4_degisiklik",
                "starts_at": STARTS.isoformat(),
                "version": 1,
                "schema_expected": "json_schema",
                "primary": primary,
                "candidate": candidate,
            },
            **values,
        )

    return user, key, copy


@pytest.mark.asyncio
async def test_the_detail_compares_both_sides_of_the_copies(db) -> None:
    user, _, copy = await _seed(db)
    copy(_side(chars=100, latency=800), _side(valid=False, chars=50, latency=1200))
    copy(_side(chars=100, latency=900), _side(valid=True, chars=150, latency=1400))
    copy(_side(), _side("failed", valid=None, chars=None, cost=None), cost="0")
    copy(_side(valid=False), _side(outcome="truncated", valid=None))
    # Before the test started: outside the default window.
    copy(_side(), _side(), started_at=STARTS - timedelta(hours=1))
    await db.flush()

    answered = await _call(db, user, "GET", f"{TESTS}/llama4_degisiklik")

    assert answered.status_code == 200, answered.text
    body = answered.json()
    assert (body["copies"], body["compared"], body["failed_copies"]) == (4, 4, 1)
    assert body["outcome_mix"]["candidate"] == {
        "complete": 2,
        "truncated": 1,
        "empty": 0,
        "refused": 0,
        "filtered": 0,
        "failed": 1,
    }
    assert body["same_outcome_share"] == 0.5
    assert body["schema"] == {
        "checked": 2,
        "primary_valid_rate": 1.0,
        "candidate_valid_rate": 0.5,
        "primary_only_valid": 1,
        "candidate_only_valid": 0,
    }
    assert body["length"]["pairs"] == 3
    assert body["length"]["ratio_of_sums"] == pytest.approx(300 / 300)
    assert body["length"]["median_ratio"] == pytest.approx(1.0)
    # 800, 800, 1200 and 1400 ms.
    assert body["latency_ms"]["candidate"]["p50"] == pytest.approx(1000)
    assert body["cost"]["comparable_pairs"] == 3
    assert body["cost"]["candidate_unpriced"] == 0
    assert body["cost"]["delta_usd"] == pytest.approx(0)
    assert "language" not in body and "refusal" not in body
    assert body["caveats"] == [
        "copy_after_primary",
        "masked_payload",
        "share_not_random_over_time",
        "no_human_review",
    ]


@pytest.mark.asyncio
async def test_language_is_shown_only_when_analysed(db) -> None:
    user, _, copy = await _seed(db)
    copy(_side(language="tr"), _side(language="en"))
    copy(_side(language="tr"), _side(language="tr"))
    await db.flush()

    body = (await _call(db, user, "GET", f"{TESTS}/llama4_degisiklik")).json()

    assert body["language"]["primary"]["tr"] == 2
    assert body["language"]["candidate"]["en"] == 1
    assert body["language"]["mismatched"] == 1


@pytest.mark.asyncio
async def test_the_detail_refuses_bad_windows_unknown_rules_and_other_kinds(
    db,
) -> None:
    user, _, _ = await _seed(db)
    term = {
        "id": "falcon",
        "name": "Project names",
        "kind": "term",
        "action": "block",
        "state": "monitor",
        "match": {"terms": ["Project Falcon"]},
    }
    await _put(db, user, [_shadow(), term])

    too_long = await _call(
        db,
        user,
        "GET",
        f"{TESTS}/llama4_degisiklik",
        params={
            "start": (NOW - timedelta(days=40)).isoformat(),
            "end": NOW.isoformat(),
        },
    )
    unknown = await _call(db, user, "GET", f"{TESTS}/nothing_here")
    other = await _call(db, user, "GET", f"{TESTS}/falcon")
    stopped_other = await _call(db, user, "POST", f"{TESTS}/falcon/stop")

    assert too_long.status_code == 422
    assert unknown.status_code == 404
    assert (other.status_code, stopped_other.status_code) == (409, 409)


@pytest.mark.asyncio
async def test_another_tenants_copies_are_never_counted(db) -> None:
    user, _, _ = await _seed(db)
    _, _, other_copy = await _seed(db)
    other_copy(_side(), _side())
    await db.flush()

    body = (await _call(db, user, "GET", f"{TESTS}/llama4_degisiklik")).json()

    assert body["copies"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("match", "copies", "status", "reason"),
    [
        ({}, 1, "running", None),
        ({"max_requests": 2}, 2, "ended", "max_requests"),
        ({"max_cost_usd": "0.01"}, 6, "ended", "max_cost"),
        (
            {"starts_at": (NOW + timedelta(days=1)).isoformat()},
            0,
            "scheduled",
            None,
        ),
    ],
)
async def test_the_list_derives_status_and_end_reason_from_rows(
    db, match, copies, status, reason
) -> None:
    user, _, copy = await _seed(db, **match)
    for _ in range(copies):
        copy(_side(), _side())
    await db.flush()

    [test] = (await _call(db, user, "GET", TESTS)).json()

    assert (test["status"], test["end_reason"], test["copies"]) == (
        status,
        reason,
        copies,
    )
    assert "estimate" not in test


@pytest.mark.asyncio
async def test_a_monitor_test_lists_its_estimate(db) -> None:
    user, key, _ = await _seed(db, state="monitor")
    for _ in range(4):
        _request(db, key, None, model="llama-a", started_at=NOW - timedelta(hours=2))
    await db.flush()

    [test] = (await _call(db, user, "GET", TESTS)).json()

    assert (test["status"], test["copies"]) == ("monitor", 0)
    assert test["estimate"]["requests"] == 4
    assert test["estimate"]["would_copy"] == 4
    assert test["estimate"]["window_days"] == 7


@pytest.mark.asyncio
async def test_stop_is_one_tightening_version_and_restore_starts_it_again(db) -> None:
    user, _, _ = await _seed(db)
    versions = len(await _versions(db, user.organization_id))

    stopped = await _call(db, user, "POST", f"{TESTS}/llama4_degisiklik/stop")

    assert stopped.status_code == 200, stopped.text
    newest = await _versions(db, user.organization_id)
    assert len(newest) == versions + 1
    assert (newest[-1].reason, newest[-1].risk) == ("change test stopped", "tightening")
    assert (await _stored(db, user.organization_id))[0]["state"] == "monitor"

    restored = await _call(
        db,
        user,
        "POST",
        f"{POLICY}/versions/{stopped.json()['policy_version'] - 1}/restore",
        json={"reason": "start it again"},
    )

    assert restored.status_code in (200, 201, 202), restored.text
    assert (await _stored(db, user.organization_id))[0]["state"] == "enforced"


@pytest.mark.asyncio
async def test_the_request_list_and_csv_carry_the_comparison(db) -> None:
    user, key, copy = await _seed(db)
    request_id = copy(_side(), _side(valid=False))
    # The analytics row the list reads; the comparison comes from the lifecycle row.
    db.add(
        RequestLog(
            request_id=request_id,
            api_key_id=key.id,
            organization_id=key.organization_id,
            prompt_tokens=300,
            completion_tokens=90,
            details={},
        )
    )
    await db.flush()

    listed = await _call(
        db, user, "GET", f"{MANAGEMENT}/requests", params={"request_id": request_id}
    )
    exported = await _call(
        db,
        user,
        "GET",
        f"{MANAGEMENT}/requests/export",
        params={"request_id": request_id},
    )

    assert listed.status_code == 200, listed.text
    [item] = listed.json()["items"]
    assert item["shadow_comparison"]["candidate"]["schema_valid"] is False
    assert exported.status_code == 200, exported.text
    header, row = exported.text.lstrip("﻿").splitlines()[:2]
    assert header.split(",")[-1] == "shadow_comparison"
    assert '""schema_valid"": false' in row
