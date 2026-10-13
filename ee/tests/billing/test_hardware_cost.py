"""Monthly hardware cost per internal deployment, shared out by tokens."""

from __future__ import annotations

from datetime import date, datetime, timezone
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event

from ee.tests.aws.test_bedrock_management import _admin, _call
from shim_enterprise.api.v1.management.hardware import _shift, largest_remainder
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.core.config import settings
from shim_enterprise.tenants.models import ApiKey, ModelDeployment, ProviderSecret, Team

DEPLOYMENTS = "/api/v1/management/model-deployments"
MONTH = date.today().replace(day=1)
PERIOD = f"{MONTH:%Y-%m}"


async def _deployment(
    db, tenant: UUID, *, kind: str = "internal", alias: str | None = None
):
    secret = ProviderSecret(
        id=uuid4(),
        organization_id=tenant,
        provider="openai",
        secret_ref=f"fernet:v2:{uuid4().hex}",
        secret_backend="fernet",
        secret_version="v2",
        masked_key="sk-...",
    )
    db.add(secret)
    await db.flush()
    row = ModelDeployment(
        organization_id=tenant,
        alias=alias or f"gpu-{uuid4().hex[:6]}",
        provider="openai",
        upstream_model="llama",
        base_url="https://a.internal/v1",
        provider_secret_id=secret.id,
        timeout_seconds=30,
        deployment_kind=kind,
        declared_version="v1",
        owner="Platform",
    )
    db.add(row)
    await db.flush()
    return row


async def _key(db, user, team: Team | None = None) -> ApiKey:
    key = ApiKey(
        id=uuid4(),
        user_id=user.id,
        organization_id=user.organization_id,
        key_hash=uuid4().hex * 2,
        prefix="sk-shim-test",
        name=f"key-{uuid4().hex[:4]}",
        tier="enterprise",
        is_active=True,
        team_id=team.id if team else None,
    )
    db.add(key)
    await db.flush()
    return key


async def _served(
    db,
    key: ApiKey,
    deployment: ModelDeployment | None,
    tokens: int,
    *,
    estimated: bool = False,
    at: datetime | None = None,
) -> None:
    request_id = f"req_hw_{uuid4().hex}"
    started = at or datetime.now(timezone.utc)
    db.add(
        RequestLifecycle(
            request_id=request_id,
            organization_id=key.organization_id,
            actor_type="api_key",
            api_key_id=key.id,
            source_endpoint="chat.completions",
            status="completed",
            requested_model="gpu",
            stream=False,
            started_at=started,
            lifecycle_metadata={
                **({"deployment_id": str(deployment.id)} if deployment else {}),
                "team_id": str(key.team_id) if key.team_id else None,
            },
        )
    )
    await db.flush()
    # As the gateway records it: tokens on the quota settlement, cost on the spend one.
    reservation = uuid4()
    quota = {
        "request_id": request_id,
        "organization_id": key.organization_id,
        "api_key_id": key.id,
        "requested_model": "gpu",
        "created_at": started,
    }
    db.add_all(
        [
            UsageLedger(
                id=reservation,
                event_type="quota_reservation",
                idempotency_key=f"request:{request_id}:quota:reservation",
                prompt_tokens=tokens,
                completion_tokens=0,
                total_tokens=tokens,
                **quota,
            ),
            UsageLedger(
                event_type="quota_settlement",
                idempotency_key=f"request:{request_id}:quota:settlement",
                reservation_event_id=reservation,
                estimated=estimated,
                prompt_tokens=tokens - tokens // 3,
                completion_tokens=tokens // 3,
                total_tokens=tokens,
                **quota,
            ),
        ]
    )
    await db.flush()


def test_largest_remainder_sums_exactly_and_ties_go_to_the_smaller_key() -> None:
    three = largest_remainder(Decimal("100.00"), [("b", 1), ("a", 1), ("c", 1)])
    uneven = largest_remainder(Decimal("120000.00"), [("x", 900), ("y", 450)])

    assert three == {
        "a": Decimal("33.34"),
        "b": Decimal("33.33"),
        "c": Decimal("33.33"),
    }
    assert sum(three.values()) == Decimal("100.00")
    assert uneven == {"x": Decimal("80000.00"), "y": Decimal("40000.00")}


@pytest.mark.asyncio
async def test_cost_entries_are_set_replaced_deleted_and_audited(
    db, audit_events
) -> None:
    user = await _admin(db)
    internal = await _deployment(db, user.organization_id)
    external = await _deployment(db, user.organization_id, kind="external")
    other = await _admin(db)
    path = f"{DEPLOYMENTS}/{internal.id}/hardware-costs/{PERIOD}"

    created = await _call(
        db, user, "PUT", path, json={"amount": "120000.00", "currency": "TRY"}
    )
    replaced = await _call(
        db,
        user,
        "PUT",
        path,
        json={"amount": "125000.50", "currency": "TRY", "note": "rack"},
    )
    listed = await _call(db, user, "GET", f"{DEPLOYMENTS}/{internal.id}/hardware-costs")
    refused = {
        name: (await _call(db, user, "PUT", target, json=body)).status_code
        for name, (target, body) in {
            "external": (
                f"{DEPLOYMENTS}/{external.id}/hardware-costs/{PERIOD}",
                {"amount": "1", "currency": "USD"},
            ),
            "period": (
                f"{DEPLOYMENTS}/{internal.id}/hardware-costs/2026-13",
                {"amount": "1", "currency": "USD"},
            ),
            "currency": (path, {"amount": "1", "currency": "try"}),
            "zero": (path, {"amount": "0", "currency": "USD"}),
        }.items()
    }
    foreign = await _call(
        db, other, "PUT", path, json={"amount": "1", "currency": "USD"}
    )
    deleted = await _call(db, user, "DELETE", path)
    gone = await _call(db, user, "DELETE", path)

    assert (created.status_code, replaced.json()["amount"]) == (200, "125000.50")
    assert [(e["period"], e["note"]) for e in listed.json()] == [(PERIOD, "rack")]
    assert refused == {"external": 422, "period": 422, "currency": 422, "zero": 422}
    assert foreign.status_code == 404
    assert (deleted.status_code, gone.status_code) == (204, 404)
    events = [
        (e["endpoint"], e["extra"]["before"], e["extra"]["after"])
        for e in await audit_events(user.organization_id)
        if "hardware_cost" in e["endpoint"]
    ]
    assert events == [
        (
            "tenant.deployment_hardware_cost_set",
            None,
            {"amount": "120000.00", "currency": "TRY"},
        ),
        (
            "tenant.deployment_hardware_cost_set",
            {"amount": "120000.00", "currency": "TRY"},
            {"amount": "125000.50", "currency": "TRY"},
        ),
        (
            "tenant.deployment_hardware_cost_deleted",
            {"amount": "125000.50", "currency": "TRY"},
            None,
        ),
    ]


@pytest.mark.asyncio
async def test_the_allocation_shares_each_cost_by_tokens_per_key_and_team(db) -> None:
    user = await _admin(db)
    tenant = user.organization_id
    team = Team(id=uuid4(), organization_id=tenant, name="risk")
    db.add(team)
    await db.flush()
    gpu = await _deployment(db, tenant, alias="gpu-a")
    idle = await _deployment(db, tenant, alias="gpu-b")
    carried = await _deployment(db, tenant, alias="gpu-c")
    in_team, alone = await _key(db, user, team), await _key(db, user)
    for _ in range(6):
        await _served(db, in_team, gpu, 150)
    for _ in range(3):
        await _served(db, alone, gpu, 150, estimated=True)
    await _served(db, alone, None, 999)
    await _served(
        db,
        alone,
        gpu,
        999,
        at=datetime.combine(_shift(MONTH, -1), datetime.min.time(), timezone.utc),
    )
    await _served(db, alone, carried, 100)
    other = await _admin(db)
    await _served(db, await _key(db, other), gpu, 5_000)
    for deployment, amount, currency, period in (
        (gpu, "120000.00", "TRY", PERIOD),
        (idle, "1000.00", "USD", PERIOD),
        (carried, "50.00", "USD", f"{_shift(MONTH, -3):%Y-%m}"),
    ):
        await _call(
            db,
            user,
            "PUT",
            f"{DEPLOYMENTS}/{deployment.id}/hardware-costs/{period}",
            json={"amount": amount, "currency": currency},
        )
    statements: list[str] = []
    connection = await db.connection()

    def count(conn, cursor, statement, *args) -> None:
        if "request_lifecycle" in statement:
            statements.append(statement)

    event.listen(connection.sync_connection, "before_cursor_execute", count)
    try:
        report = await _call(
            db,
            user,
            "GET",
            "/api/v1/management/cost/hardware",
            params={"period": PERIOD},
        )
    finally:
        event.remove(connection.sync_connection, "before_cursor_execute", count)
    future = await _call(
        db,
        user,
        "GET",
        "/api/v1/management/cost/hardware",
        params={"period": f"{_shift(MONTH, 1):%Y-%m}"},
    )

    body = report.json()
    rows = {row["alias"]: row for row in body["deployments"]}
    a = rows["gpu-a"]
    assert report.status_code == 200, report.text
    assert len(statements) == 1
    assert (a["tokens"], a["estimated_share"], a["carried_from"]) == (
        1350,
        450 / 1350,
        None,
    )
    assert [(k["api_key_id"], k["tokens"], k["amount"]) for k in a["by_key"]] == [
        (str(in_team.id), 900, "80000.00"),
        (str(alone.id), 450, "40000.00"),
    ]
    assert [(t["name"], t["amount"]) for t in a["by_team"]] == [
        ("risk", "80000.00"),
        ("no team", "40000.00"),
    ]
    assert (rows["gpu-b"]["unattributed"], rows["gpu-b"]["by_key"]) == ("1000.00", [])
    assert rows["gpu-c"]["carried_from"] == f"{_shift(MONTH, -3):%Y-%m}"
    assert body["totals"] == [
        {"currency": "TRY", "amount": "120000.00"},
        {"currency": "USD", "amount": "1050.00"},
    ]
    assert body["attributed_since"] is not None
    assert future.status_code == 422


@pytest.mark.asyncio
async def test_a_put_without_capacity_keeps_it(db, monkeypatch) -> None:
    monkeypatch.setattr(
        settings, "MODEL_DEPLOYMENT_ALLOWED_ORIGINS", ["https://a.internal"]
    )
    user = await _admin(db)
    secret = (
        await _call(
            db,
            user,
            "POST",
            "/api/v1/management/providers",
            json={"provider": "openai", "key": "sk-" + "0" * 20},
        )
    ).json()
    body = {
        "alias": "gpu-capacity",
        "provider": "openai",
        "upstream_model": "llama",
        "base_url": "https://a.internal/v1",
        "provider_secret_id": secret["id"],
        "deployment_kind": "internal",
        "declared_version": "v1",
        "owner": "Platform",
    }

    created = await _call(
        db, user, "POST", DEPLOYMENTS, json={**body, "capacity_concurrent_requests": 4}
    )
    renamed = await _call(
        db,
        user,
        "PUT",
        f"{DEPLOYMENTS}/{created.json()['id']}",
        json={**body, "alias": "gpu-renamed"},
    )
    bounds = [
        (
            await _call(
                db,
                user,
                "POST",
                DEPLOYMENTS,
                json={**body, "alias": f"b{n}", "capacity_concurrent_requests": n},
            )
        ).status_code
        for n in (0, 100_001)
    ]

    assert created.status_code == 201, created.text
    assert (
        renamed.json()["alias"],
        renamed.json()["capacity_concurrent_requests"],
    ) == (
        "gpu-renamed",
        4,
    )
    assert bounds == [422, 422]
