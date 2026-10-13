"""Bedrock cost per day and session tag, and its comparison with AWS's numbers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import uuid4

import pytest

from ee.tests.aws.test_bedrock_management import _admin, _call
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.tenants.models import ApiKey

ATTRIBUTION = "/api/v1/management/aws/attribution"
TODAY = datetime.now(timezone.utc).date()


async def _key(db, user) -> ApiKey:
    key = ApiKey(
        id=uuid4(),
        user_id=user.id,
        organization_id=user.organization_id,
        key_hash=uuid4().hex * 2,
        prefix="sk-shim-test",
        name="bedrock",
        tier="enterprise",
        is_active=True,
    )
    db.add(key)
    await db.flush()
    return key


async def _bedrock_request(
    db,
    key: ApiKey,
    *,
    tag: str | None,
    cost: str,
    days_ago: int = 0,
    priced: bool = True,
    cache: tuple[int, int] = (0, 0),
) -> None:
    request_id = f"req_aws_{uuid4().hex}"
    started = datetime.now(timezone.utc) - timedelta(days=days_ago)
    db.add(
        RequestLifecycle(
            request_id=request_id,
            organization_id=key.organization_id,
            actor_type="api_key",
            api_key_id=key.id,
            source_endpoint="messages",
            status="completed",
            requested_model="claude-bedrock",
            stream=False,
            started_at=started,
            lifecycle_metadata={
                "aws_bedrock": {
                    "region": "eu-central-1",
                    "model": "eu.anthropic.fixture-v1:0",
                    "scope": "eu",
                    "lock": "off",
                    "session_tag": tag,
                }
            },
        )
    )
    await db.flush()
    ledger = {
        "request_id": request_id,
        "organization_id": key.organization_id,
        "api_key_id": key.id,
        "requested_model": "claude-bedrock",
        "provider": "anthropic",
        "provider_model": "eu.anthropic.fixture-v1:0",
        "cost_usd": Decimal(cost),
        "created_at": started,
    }
    quota = {
        key: ledger[key]
        for key in (
            "request_id",
            "organization_id",
            "api_key_id",
            "requested_model",
            "created_at",
        )
    }
    quota_reservation = uuid4()
    db.add_all(
        [
            UsageLedger(
                id=quota_reservation,
                event_type="quota_reservation",
                idempotency_key=f"request:{request_id}:quota:reservation",
                prompt_tokens=100,
                completion_tokens=0,
                total_tokens=100,
                **quota,
            ),
            UsageLedger(
                event_type="quota_settlement",
                idempotency_key=f"request:{request_id}:quota:settlement",
                reservation_event_id=quota_reservation,
                prompt_tokens=100,
                completion_tokens=20,
                total_tokens=120,
                **quota,
            ),
        ]
    )
    reservation = uuid4()
    db.add_all(
        [
            UsageLedger(
                id=reservation,
                event_type="spend_reservation",
                idempotency_key=f"{request_id}:spend:reservation",
                **ledger,
            ),
            UsageLedger(
                event_type="spend_settlement",
                idempotency_key=f"{request_id}:spend:settlement",
                reservation_event_id=reservation,
                event_metadata={
                    "pricing": {
                        "pricing_resolution": "deployment" if priced else "unknown",
                        "cache_read_tokens": cache[0],
                        "cache_write_tokens": cache[1],
                        "cache_write_1h_tokens": 0,
                    }
                },
                **ledger,
            ),
        ]
    )
    await db.flush()


@pytest.mark.asyncio
async def test_cost_per_day_and_tag_from_shims_own_records(db) -> None:
    user = await _admin(db)
    key = await _key(db, user)
    await _bedrock_request(db, key, tag="payments", cost="0.10", cache=(4000, 6000))
    await _bedrock_request(db, key, tag="payments", cost="0.20")
    await _bedrock_request(db, key, tag=None, cost="0.05")
    await _bedrock_request(db, key, tag="risk", cost="0", priced=False)
    await _bedrock_request(db, key, tag="payments", cost="9", days_ago=40)
    other = await _admin(db)
    await _bedrock_request(db, await _key(db, other), tag="payments", cost="7")

    read = await _call(
        db,
        user,
        "GET",
        ATTRIBUTION,
        params={"from": str(TODAY - timedelta(days=1)), "to": str(TODAY)},
    )
    csv = await _call(
        db,
        user,
        "GET",
        ATTRIBUTION,
        params={"from": str(TODAY), "to": str(TODAY), "format": "csv"},
    )
    too_long = await _call(
        db,
        user,
        "GET",
        ATTRIBUTION,
        params={"from": str(TODAY - timedelta(days=93)), "to": str(TODAY)},
    )

    body = read.json()
    rows = {row["session_tag"]: row for row in body["rows"]}
    assert (body["tag_key"], body["aws_column"]) == (
        "shim-team",
        "iamPrincipal/shim-team",
    )
    assert set(rows) == {"payments", "risk", "untagged"}
    assert rows["payments"] | {"day": None} == {
        "day": None,
        "session_tag": "payments",
        "region": "eu-central-1",
        "model": "eu.anthropic.fixture-v1:0",
        "requests": 2,
        "prompt_tokens": 200,
        "completion_tokens": 40,
        "cache_read_tokens": 4000,
        "cache_write_tokens": 6000,
        "cost_usd": "0.30000000",
        "unpriced_requests": 0,
    }
    assert (rows["risk"]["cost_usd"], rows["risk"]["unpriced_requests"]) == (None, 1)
    assert csv.text.splitlines()[0] == (
        "day,session_tag,region,model,requests,prompt_tokens,completion_tokens,"
        "cache_read_tokens,cache_write_tokens,cost_usd,unpriced_requests"
    )
    assert len(csv.text.splitlines()) == 4
    assert too_long.status_code == 422


@pytest.mark.asyncio
async def test_compare_puts_shims_cost_next_to_awss(db) -> None:
    user = await _admin(db)
    key = await _key(db, user)
    await _bedrock_request(db, key, tag="payments", cost="0.30")
    await _bedrock_request(db, key, tag="unassigned", cost="0.10")
    await _bedrock_request(db, key, tag="risk", cost="0.05")
    day = str(TODAY)

    compared = await _call(
        db,
        user,
        "POST",
        f"{ATTRIBUTION}/compare",
        json={
            "from": day,
            "to": day,
            "rows": [
                {"day": day, "tag": "payments", "usd": "0.30"},
                {"day": day, "tag": "unassigned", "usd": "0.12"},
                {"day": day, "tag": "legal", "usd": "1"},
            ],
        },
    )
    outside = await _call(
        db,
        user,
        "POST",
        f"{ATTRIBUTION}/compare",
        json={
            "from": day,
            "to": day,
            "rows": [{"day": "2020-01-01", "tag": "x", "usd": "1"}],
        },
    )
    too_many = await _call(
        db,
        user,
        "POST",
        f"{ATTRIBUTION}/compare",
        json={
            "from": day,
            "to": day,
            "rows": [{"day": day, "tag": "x", "usd": "1"}] * 5_001,
        },
    )

    body = compared.json()
    assert compared.status_code == 200, compared.text
    assert [
        (r["tag"], r["shim_usd"], r["aws_usd"], r["difference_usd"])
        for r in body["rows"]
    ] == [
        ("payments", "0.30000000", "0.30", "0E-8"),
        ("unassigned", "0.10000000", "0.12", "-0.02000000"),
    ]
    assert Decimal(body["rows"][0]["difference_usd"]) == 0
    assert Decimal(body["rows"][0]["ratio"]) == 1
    assert body["only_in_shim"] == [{"day": day, "tag": "risk"}]
    assert body["only_in_aws"] == [{"day": day, "tag": "legal"}]
    assert (outside.status_code, too_many.status_code) == (422, 422)


@pytest.mark.asyncio
async def test_a_team_keeps_its_cost_tag_when_a_put_leaves_it_out(db) -> None:
    user = await _admin(db)
    created = await _call(
        db,
        user,
        "POST",
        "/api/v1/management/teams",
        json={"name": "payments", "aws_cost_tag": "payments"},
    )
    team = created.json()
    kept = await _call(
        db,
        user,
        "PUT",
        f"/api/v1/management/teams/{team['id']}",
        json={"name": "payments-eu"},
    )
    cleared = await _call(
        db,
        user,
        "PUT",
        f"/api/v1/management/teams/{team['id']}",
        json={"name": "payments-eu", "aws_cost_tag": None},
    )
    refused = await _call(
        db,
        user,
        "POST",
        "/api/v1/management/teams",
        json={"name": "x", "aws_cost_tag": "a|b"},
    )

    assert created.status_code == 201, created.text
    assert (kept.json()["name"], kept.json()["aws_cost_tag"]) == (
        "payments-eu",
        "payments",
    )
    assert cleared.json()["aws_cost_tag"] is None
    assert refused.status_code == 422


@pytest.mark.asyncio
async def test_a_tag_a_spreadsheet_would_run_is_quoted_in_the_csv(db) -> None:
    user = await _admin(db)
    await _bedrock_request(db, await _key(db, user), tag="=HYPERLINK(1)", cost="0.10")

    csv = await _call(
        db,
        user,
        "GET",
        ATTRIBUTION,
        params={"from": str(TODAY), "to": str(TODAY), "format": "csv"},
    )

    [row] = csv.text.splitlines()[1:]
    assert ",'=HYPERLINK(1)," in row
