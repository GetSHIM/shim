from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import event, func, select

from shim.gateway.request_policy import TaskCaps
from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.core.database import get_db
from shim_enterprise.observability import tasks
from shim_enterprise.observability.tasks import TaskReadModel, task_windows
from shim_enterprise.tenants.models import (
    ApiKey,
    Organization,
    OrganizationGatewaySettings,
    User,
)

NOW = datetime.now(timezone.utc).replace(microsecond=0)
T0 = NOW - timedelta(days=1)


async def _tenant(db, role: str = "owner") -> tuple[User, ApiKey, ApiKey]:
    organization = Organization(
        id=uuid4(), name="Tasks", slug=f"tasks-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    user = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"tasks-{uuid4().hex}@example.com",
        role=role,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await db.flush()
    keys = [
        ApiKey(
            id=uuid4(),
            organization_id=organization.id,
            user_id=user.id,
            key_hash=uuid4().hex,
            prefix=f"sk-shim-t{index}",
            name=f"agent-{index}",
            tier="enterprise",
            is_active=True,
        )
        for index in range(2)
    ]
    db.add_all(keys)
    await db.flush()
    return user, keys[0], keys[1]


def _request(
    db,
    key: ApiKey,
    task_id: str | None,
    seconds: float = 0,
    *,
    cost: str = "0.010",
    prompt_tokens: int = 100,
    completion_tokens: int = 20,
    estimated: bool = False,
    unpriced: bool = False,
    status: str = "completed",
    outcome: str | None = "complete",
    model: str = "gpt-5-mini",
    settled: bool = True,
    started_at: datetime | None = None,
    **metadata,
) -> str:
    request_id = f"req_task_{uuid4().hex}"
    db.add(
        RequestLifecycle(
            request_id=request_id,
            organization_id=key.organization_id,
            actor_type="api_key",
            api_key_id=key.id,
            source_endpoint="chat.completions",
            status=status,
            provider="openai",
            requested_model=model,
            stream=False,
            started_at=started_at or T0 + timedelta(seconds=seconds),
            lifecycle_metadata={
                "task_id": task_id,
                "completion_outcome": outcome,
                **metadata,
            },
        )
    )
    if not settled:
        return request_id
    ledger = {
        "request_id": request_id,
        "organization_id": key.organization_id,
        "api_key_id": key.id,
        "requested_model": model,
    }
    provider = {"provider": "openai", "provider_model": model}
    quota, spend = uuid4(), uuid4()
    db.add_all(
        [
            UsageLedger(
                id=quota,
                event_type="quota_reservation",
                idempotency_key=f"{request_id}:quota:reservation",
                estimated=True,
                **ledger,
            ),
            UsageLedger(
                event_type="quota_settlement",
                idempotency_key=f"{request_id}:quota:settlement",
                reservation_event_id=quota,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
                estimated=estimated,
                **ledger,
            ),
            UsageLedger(
                id=spend,
                event_type="spend_reservation",
                idempotency_key=f"{request_id}:spend:reservation",
                estimated=True,
                cost_usd=Decimal("0"),
                **ledger,
                **provider,
            ),
            UsageLedger(
                event_type="spend_settlement",
                idempotency_key=f"{request_id}:spend:settlement",
                reservation_event_id=spend,
                cost_usd=Decimal("0") if unpriced else Decimal(cost),
                event_metadata={
                    "pricing": {
                        "pricing_resolution": "unknown" if unpriced else "catalog"
                    }
                },
                **ledger,
                **provider,
            ),
        ]
    )
    return request_id


LOOP = [{"rule_id": "task.agent_loop", "reason_code": "AGENT_LOOP_SUSPECTED"}]


async def _seed(db):
    user, first, second = await _tenant(db)
    for index, model in enumerate(
        ("gpt-5-mini", "gpt-5", "gpt-4.1", "gpt-4o", "o3", "o4-mini")
    ):
        _request(db, first, "agent-a", index * 10, model=model)
    _request(db, second, "agent-a", 70, unpriced=True, outcome="truncated")
    _request(db, first, "agent-a", 80, attempt_number=2, cost="0.004")
    _request(db, first, "agent-a", 90, estimated=True, policy_verdicts=LOOP)
    _request(
        db, first, "agent-a", 95, status="provider_error", outcome=None, settled=False
    )
    trace = "0af7651916cd43dd8448eb211c80319c"
    _request(db, second, trace, 5, trace_id=trace, cost="0.050")
    _request(db, second, trace, 6, trace_id=trace, cost="0.050")
    for seconds in (1, 2, 3):
        _request(db, first, None, seconds)
    _request(db, first, "agent-a", 0, started_at=NOW - timedelta(days=9))
    _, other, _ = await _tenant(db)
    _request(db, other, "agent-a", 0)
    await db.flush()
    return user, first, second


async def _read(db, user, *, caps: TaskCaps = TaskCaps(), **params):
    return await TaskReadModel().read(
        db,
        tenant_id=user.organization_id,
        start_at=NOW - timedelta(days=7),
        end_at=NOW,
        caps=caps,
        **params,
    )


class _Statements:
    def __init__(self, connection) -> None:
        self.connection, self.seen = connection, []

    def _count(self, conn, cursor, statement, parameters, context, executemany):
        self.seen.append(statement)

    def __enter__(self):
        event.listen(self.connection, "before_cursor_execute", self._count)
        return self

    def __exit__(self, *_):
        event.remove(self.connection, "before_cursor_execute", self._count)


@pytest.mark.asyncio
async def test_tasks_group_calls_attempts_tokens_cost_and_signals(db) -> None:
    user, first, second = await _seed(db)
    connection = (await db.connection()).sync_connection

    with _Statements(connection) as statements:
        report = await _read(db, user)

    assert len(statements.seen) == 1
    traced, agent = report.items
    assert (agent.task_id, agent.calls, agent.attempts) == ("agent-a", 9, 10)
    # The estimated settlement adds no tokens; the unsettled failure adds nothing.
    assert (agent.prompt_tokens, agent.completion_tokens) == (800, 160)
    assert (agent.cost_usd, agent.cost_complete) == (Decimal("0.074"), False)
    assert agent.models == ["gpt-4.1", "gpt-4o", "gpt-5", "gpt-5-mini", "o3"]
    assert agent.api_keys == sorted([first.id, second.id])
    assert agent.outcomes == {
        "complete": 8,
        "truncated": 1,
        "empty": 0,
        "refused": 0,
        "filtered": 0,
    }
    assert (agent.failed, agent.loop_signals, agent.trace_id) == (1, 1, None)
    assert (agent.first_seen, agent.duration_seconds) == (T0, 95)
    assert agent.against_caps is None
    assert (traced.calls, traced.trace_id, traced.cost_usd, traced.cost_complete) == (
        2,
        "0af7651916cd43dd8448eb211c80319c",
        Decimal("0.100"),
        True,
    )
    assert (
        report.tasks,
        report.requests_with_task,
        report.requests_without_task,
        report.cost_usd,
        report.truncated,
    ) == (2, 12, 3, Decimal("0.174"), False)


@pytest.mark.asyncio
async def test_a_shadow_copy_is_never_part_of_the_callers_task(db) -> None:
    user, first, _ = await _tenant(db)
    primary = _request(db, first, "agent-s", 0)
    # S58: the copy carries the caller's admission, task id included.
    _request(db, first, "agent-s", 1, cost="0.500", shadow_of=primary)
    await db.flush()

    report = await _read(db, user)

    [task] = report.items
    assert (task.calls, task.attempts, task.cost_usd) == (1, 1, Decimal("0.010"))


@pytest.mark.asyncio
async def test_tasks_sort_and_cap_the_list(db, monkeypatch) -> None:
    user, *_ = await _seed(db)

    by_cost = await _read(db, user)
    by_calls = await _read(db, user, sort="calls")
    by_last_seen = await _read(db, user, sort="last_seen")
    monkeypatch.setattr(tasks, "MAX_TASKS", 1)
    capped = await _read(db, user, sort="calls")

    traced = "0af7651916cd43dd8448eb211c80319c"
    assert [item.task_id for item in by_cost.items] == [traced, "agent-a"]
    assert [item.task_id for item in by_calls.items] == ["agent-a", traced]
    assert [item.task_id for item in by_last_seen.items] == ["agent-a", traced]
    assert ([item.task_id for item in capped.items], capped.truncated) == (
        ["agent-a"],
        True,
    )
    assert (capped.tasks, capped.requests_without_task) == (2, 3)


@pytest.mark.asyncio
async def test_a_tenant_without_task_requests_reads_empty(db) -> None:
    user, first, _ = await _tenant(db)
    empty = await _read(db, user)
    _request(db, first, None, 1)
    await db.flush()
    untasked = await _read(db, user)

    assert (empty.items, empty.tasks, empty.requests_without_task) == ([], 0, 0)
    assert (untasked.items, untasked.tasks, untasked.requests_with_task) == ([], 0, 0)
    assert (untasked.requests_without_task, untasked.cost_usd) == (1, Decimal("0"))


@pytest.mark.asyncio
async def test_against_caps_uses_the_busiest_window(db) -> None:
    user, first, _ = await _tenant(db)
    for seconds in (0, 10, 20, 30, 4000, 4010):
        _request(db, first, "busy", seconds, cost="0.25")
    _request(db, first, "busy", 40, attempt_number=2, cost="0.25")
    await db.flush()
    connection = (await db.connection()).sync_connection

    with _Statements(connection) as statements:
        report = await _read(
            db, user, caps=TaskCaps(max_calls=2, max_cost_usd=Decimal("2"))
        )
    calls_only = await _read(db, user, caps=TaskCaps(max_calls=8))

    assert len(statements.seen) == 2
    # The first hour holds four calls and one extra attempt, 1.25 USD.
    assert report.items[0].against_caps == tasks.AgainstCaps(
        calls_share=2.0, cost_share=0.625
    )
    assert calls_only.items[0].against_caps == tasks.AgainstCaps(
        calls_share=0.5, cost_share=None
    )


def _windows(rows, **caps):
    return task_windows(
        [
            (T0 + timedelta(seconds=seconds), is_call, Decimal(cost))
            for seconds, is_call, cost in rows
        ],
        TaskCaps(**caps),
        enforce=True,
    )


def test_the_calls_cap_refuses_the_calls_after_it_until_the_window_ends() -> None:
    windows = _windows(
        [
            (0, True, "1"),
            (1, True, "1"),
            (2, True, "1"),
            (3, True, "1"),
            (3600, True, "1"),
        ],
        max_calls=2,
    )

    assert [(w.calls, w.refused, w.refused_cost) for w in windows] == [
        (2, 2, Decimal("2")),
        (1, 0, Decimal("0")),
    ]


def test_the_cost_cap_refuses_once_reached_and_refused_calls_add_nothing() -> None:
    windows = _windows(
        [(0, True, "0.6"), (1, True, "0.5"), (2, True, "0.1"), (3, True, "0.1")],
        max_cost_usd=Decimal("1"),
    )
    under = _windows(
        [(0, True, "0.4"), (1, True, "0.5"), (2, True, "5")], max_cost_usd=1
    )

    assert [(w.calls, w.cost, w.refused) for w in windows] == [(2, Decimal("1.1"), 2)]
    assert [(w.calls, w.cost, w.refused) for w in under] == [(3, Decimal("5.9"), 0)]


def test_windows_restart_after_window_seconds_and_take_both_caps() -> None:
    windows = _windows(
        [
            (0, True, "0.1"),
            (1, True, "2"),
            (2, True, "0.1"),
            (60, True, "0.1"),
            (61, True, "0.1"),
            (62, True, "0.1"),
            (63, True, "0.1"),
        ],
        max_calls=3,
        max_cost_usd=Decimal("1"),
        window_seconds=60,
    )

    # The cost cap refuses the third call of the first minute, the calls cap the
    # fourth of the second.
    assert [(w.calls, w.refused) for w in windows] == [(2, 1), (3, 1)]


def test_extra_attempts_are_never_calls() -> None:
    windows = _windows(
        [
            (0, False, "1"),
            (1, True, "1"),
            (2, False, "1"),
            (3, True, "1"),
            (4, True, "1"),
        ],
        max_calls=2,
    )

    # The attempt before the task's first call has no window to fall in.
    assert [(w.calls, w.cost, w.refused) for w in windows] == [(2, Decimal("3"), 1)]


def _app(db, user: User) -> FastAPI:
    app = FastAPI()
    app.include_router(management_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = lambda: db
    return app


async def _get(db, user, path: str, **params) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(db, user)), base_url="http://test"
    ) as client:
        return await client.get(f"/api/v1/management/{path}", params=params)


@pytest.mark.asyncio
async def test_members_read_their_keys_tasks_and_readers_read_all(db) -> None:
    owner, first, second = await _seed(db)
    member = User(
        id=uuid4(),
        organization_id=owner.organization_id,
        email=f"tasks-member-{uuid4().hex}@example.com",
        role="member",
        is_active=True,
        is_verified=True,
    )
    auditor = User(
        id=uuid4(),
        organization_id=owner.organization_id,
        email=f"tasks-auditor-{uuid4().hex}@example.com",
        role="auditor",
        is_active=True,
        is_verified=True,
    )
    db.add_all([member, auditor])
    await db.flush()
    second.user_id = member.id
    await db.flush()

    as_member = await _get(db, member, "tasks")
    as_auditor = await _get(db, auditor, "tasks", api_key_id=str(first.id))
    as_owner = await _get(db, owner, "tasks", sort="calls")
    too_long = await _get(
        db, owner, "tasks", start=(NOW - timedelta(days=40)).isoformat()
    )
    naive = await _get(db, owner, "tasks", start="2026-10-01T00:00:00")
    wrong_sort = await _get(db, owner, "tasks", sort="tokens")

    assert as_member.status_code == 200
    traced = "0af7651916cd43dd8448eb211c80319c"
    assert [(item["task_id"], item["calls"]) for item in as_member.json()["items"]] == [
        (traced, 2),
        ("agent-a", 1),
    ]
    assert as_member.json()["requests_without_task"] == 0
    assert [item["task_id"] for item in as_auditor.json()["items"]] == ["agent-a"]
    owner_items = as_owner.json()["items"]
    assert owner_items[0]["requests_url"] == (
        "/api/v1/management/requests?task_id=agent-a"
    )
    assert owner_items[0]["against_caps"] is None
    assert (too_long.status_code, naive.status_code, wrong_sort.status_code) == (
        422,
        422,
        422,
    )


@pytest.mark.asyncio
async def test_the_tasks_route_reads_the_tenants_caps(db) -> None:
    owner, first, _ = await _tenant(db)
    for seconds in (0, 1, 2):
        _request(db, first, "capped", seconds)
    db.add(
        OrganizationGatewaySettings(
            organization_id=owner.organization_id,
            settings={"task_caps": {"max_calls": 4, "window_seconds": 3600}},
        )
    )
    await db.flush()

    item = (await _get(db, owner, "tasks")).json()["items"][0]

    assert item["against_caps"] == {"calls_share": 0.75, "cost_share": None}


@pytest.mark.asyncio
async def test_the_cap_preview_replays_seven_days_for_readers(db) -> None:
    owner, first, second = await _tenant(db)
    for seconds in range(6):
        _request(db, first, "agent-a", seconds, cost="0.10")
    _request(db, first, "agent-a", 7, attempt_number=2)
    for seconds in range(2):
        _request(db, second, "agent-b", seconds)
    _request(db, first, None, 1)
    _request(db, first, "agent-old", 0, started_at=NOW - timedelta(days=8))
    _request(db, first, "agent-old", 1, started_at=NOW - timedelta(days=8))
    _request(db, first, "agent-old", 2, started_at=NOW - timedelta(days=8))
    member, *_ = await _tenant(db, role="member")
    await db.flush()
    counts = (
        select(func.count()).select_from(RequestLifecycle),
        select(func.count()).select_from(UsageLedger),
    )
    before = [await db.scalar(count) for count in counts]

    calls = await _get(db, owner, "tasks/cap-preview", max_calls=4)
    cost = await _get(db, owner, "tasks/cap-preview", max_cost_usd="0.25")
    one_key = await _get(
        db, owner, "tasks/cap-preview", max_calls=1, api_key_id=str(second.id)
    )

    assert calls.status_code == 200
    body = calls.json()
    assert (
        body["tasks_considered"],
        body["tasks_affected"],
        body["requests_considered"],
        body["requests_refused"],
        Decimal(body["refused_cost_usd"]),
        body["refused_share"],
    ) == (2, 1, 8, 2, Decimal("0.20"), 0.25)
    assert body["affected"] == [{"task_id": "agent-a", "requests_refused": 2}]
    assert body["caps"] == {
        "max_calls": 4,
        "max_cost_usd": None,
        "window_seconds": 3600,
    }
    assert len(body["caveats"]) == 2
    assert (cost.json()["requests_refused"], cost.json()["affected"]) == (
        3,
        [{"task_id": "agent-a", "requests_refused": 3}],
    )
    assert (one_key.json()["tasks_considered"], one_key.json()["requests_refused"]) == (
        1,
        1,
    )
    assert [await db.scalar(count) for count in counts] == before
    assert (await _get(db, member, "tasks/cap-preview", max_calls=4)).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "params",
    [
        {},
        {"window_seconds": 600},
        {"max_calls": 0},
        {"max_calls": 100_001},
        {"max_cost_usd": "0"},
        {"max_calls": 4, "window_seconds": 59},
        {"max_calls": 4, "window_seconds": 86_401},
        {"max_calls": "four"},
    ],
)
async def test_the_cap_preview_takes_s47s_bounds(db, params) -> None:
    owner, *_ = await _tenant(db)

    assert (await _get(db, owner, "tasks/cap-preview", **params)).status_code == 422


@pytest.mark.asyncio
async def test_the_cap_preview_refuses_too_many_rows(db, monkeypatch) -> None:
    owner, first, _ = await _tenant(db)
    for seconds in range(3):
        _request(db, first, "agent-a", seconds)
    await db.flush()
    monkeypatch.setattr(tasks, "TASK_CAP_PREVIEW_MAX_ROWS", 2)

    refused = await _get(db, owner, "tasks/cap-preview", max_calls=1)

    assert refused.status_code == 422
    assert "narrow with api_key_id" in refused.json()["detail"]
