from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import event

from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.core.database import get_db
from shim_enterprise.observability import outcomes
from shim_enterprise.observability.outcomes import OutcomeGroup, OutcomeRatesReadModel
from shim_enterprise.tenants.models import ApiKey, Organization, Team, User

NOW = datetime.now(timezone.utc)


async def _tenant(db, role: str = "owner") -> tuple[User, ApiKey, ApiKey, Team]:
    organization = Organization(
        id=uuid4(), name="Outcomes", slug=f"outcomes-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    user = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"outcomes-{uuid4().hex}@example.com",
        role=role,
        is_active=True,
        is_verified=True,
    )
    team = Team(id=uuid4(), organization_id=organization.id, name="support")
    db.add_all([user, team])
    await db.flush()
    keys = [
        ApiKey(
            id=uuid4(),
            organization_id=organization.id,
            user_id=user.id,
            key_hash=uuid4().hex,
            prefix=f"sk-shim-o{index}",
            name=f"app-{index}",
            tier="enterprise",
            is_active=True,
        )
        for index in range(2)
    ]
    db.add_all(keys)
    await db.flush()
    return user, keys[0], keys[1], team


def _row(
    db, key: ApiKey, outcome: str | None, *, model: str = "gpt-5-mini", **metadata
):
    db.add(
        RequestLifecycle(
            request_id=f"req_outcome_{uuid4().hex}",
            organization_id=key.organization_id,
            actor_type="api_key",
            api_key_id=key.id,
            source_endpoint="chat.completions",
            status="completed" if outcome else "provider_error",
            provider="openai",
            requested_model=model,
            stream=False,
            started_at=metadata.pop("started_at", NOW - timedelta(hours=1)),
            lifecycle_metadata={"completion_outcome": outcome, **metadata},
        )
    )


async def _seed(db):
    user, first, second, team = await _tenant(db)
    for outcome in (
        "complete",
        "complete",
        "truncated",
        "refused",
        "empty",
        "filtered",
    ):
        _row(db, first, outcome, team_id=str(team.id))
    _row(db, first, None)
    _row(db, second, "complete", model="claude-haiku-4-5")
    _row(
        db,
        second,
        "complete",
        model="claude-haiku-4-5",
        response_analysis={"refusal": {"soft_refusal": True, "marker": "tr-1"}},
    )
    _row(
        db,
        second,
        "complete",
        model="claude-haiku-4-5",
        response_analysis={"refusal": {"soft_refusal": False, "marker": None}},
    )
    _row(db, second, "truncated", started_at=NOW - timedelta(days=9))
    _, other, _, _ = await _tenant(db)
    _row(db, other, "truncated")
    await db.flush()
    return user, first, second, team


async def _read(db, user, group_by: OutcomeGroup):
    return await OutcomeRatesReadModel().read(
        db,
        tenant_id=user.organization_id,
        start_at=NOW - timedelta(days=7),
        end_at=NOW,
        group_by=group_by,
    )


@pytest.mark.asyncio
async def test_rates_group_by_model_key_and_team(db) -> None:
    user, first, second, team = await _seed(db)
    statements: list[str] = []
    connection = await db.connection()

    def count(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(connection.sync_connection, "before_cursor_execute", count)
    try:
        by_key = await _read(db, user, "api_key")
    finally:
        event.remove(connection.sync_connection, "before_cursor_execute", count)

    assert len(statements) <= 2
    assert [(group.group, group.name, group.settled) for group in by_key.groups] == [
        (str(first.id), "app-0", 6),
        (str(second.id), "app-1", 3),
    ]
    app = by_key.groups[0]
    assert (app.truncated, app.refused, app.empty, app.filtered) == (1, 1, 1, 1)
    assert app.truncation_rate == pytest.approx(1 / 6)
    assert app.refusal_rate == pytest.approx(3 / 6)
    assert (app.analysed, app.soft_refused, app.soft_refusal_rate) == (0, 0, None)
    other = by_key.groups[1]
    assert (other.analysed, other.soft_refused, other.soft_refusal_rate) == (2, 1, 0.5)
    assert (by_key.totals.settled, by_key.totals.truncated, by_key.truncated) == (
        9,
        1,
        False,
    )
    by_model = await _read(db, user, "model")
    assert [(g.group, g.settled) for g in by_model.groups] == [
        ("gpt-5-mini", 6),
        ("claude-haiku-4-5", 3),
    ]
    by_team = await _read(db, user, "team")
    assert [(g.group, g.name, g.settled) for g in by_team.groups] == [
        (str(team.id), "support", 6),
        (None, None, 3),
    ]


@pytest.mark.asyncio
async def test_a_window_without_answers_has_no_rates(db) -> None:
    user, *_ = await _tenant(db)

    report = await _read(db, user, "model")

    assert report.groups == []
    assert (report.totals.settled, report.totals.truncation_rate) == (0, None)


@pytest.mark.asyncio
async def test_the_rates_are_capped(db, monkeypatch) -> None:
    user, *_ = await _seed(db)
    monkeypatch.setattr(outcomes, "MAX_OUTCOME_GROUPS", 1)

    report = await _read(db, user, "model")

    assert (len(report.groups), report.truncated, report.totals.settled) == (1, True, 9)


def _app(db, user: User) -> FastAPI:
    app = FastAPI()
    app.include_router(management_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = lambda: db
    return app


@pytest.mark.asyncio
async def test_readers_read_the_rates_within_thirty_one_days(db) -> None:
    owner, *_ = await _seed(db)
    member, *_ = await _tenant(db, role="member")
    auditor, *_ = await _tenant(db, role="auditor")

    async def get(user, **params):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=_app(db, user)), base_url="http://test"
        ) as client:
            return await client.get("/api/v1/management/outcomes", params=params)

    read = await get(owner, group_by="api_key")
    too_long = await get(owner, start=(NOW - timedelta(days=40)).isoformat())
    wrong = await get(owner, group_by="provider")

    assert read.status_code == 200
    assert read.json()["totals"]["settled"] == 9
    assert (too_long.status_code, wrong.status_code) == (422, 422)
    assert (await get(auditor)).status_code == 200
    assert (await get(member)).status_code == 403
