"""Calls and cost per agent task, and what a task cap would have refused."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from itertools import groupby
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import and_, case, distinct, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from shim.gateway.request_policy import TaskCaps
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.observability.model_inventory import shown_model
from shim_enterprise.observability.outcomes import OUTCOMES

TaskSort = Literal["cost", "calls", "last_seen"]
MAX_TASKS = 200
MAX_LISTED = 5
TASK_CAP_PREVIEW_DAYS = 7
TASK_CAP_PREVIEW_MAX_ROWS = 200_000
MAX_AFFECTED_TASKS = 20
CAP_PREVIEW_CAVEATS = (
    "Calls of one task that run at the same time can pass a cost cap together, "
    "because a call's cost counts only once it is settled.",
    "Requests without a task id are never capped.",
)
_FAILED = ("provider_error", "timeout", "failed", "internal_error")


@dataclass(frozen=True, slots=True)
class AgainstCaps:
    calls_share: float | None
    cost_share: float | None


@dataclass(frozen=True, slots=True)
class TaskItem:
    task_id: str
    trace_id: str | None
    first_seen: datetime
    last_seen: datetime
    duration_seconds: float
    calls: int
    attempts: int
    prompt_tokens: int
    completion_tokens: int
    cost_usd: Decimal
    cost_complete: bool
    models: list[str]
    api_keys: list[UUID]
    outcomes: dict[str, int]
    failed: int
    loop_signals: int
    against_caps: AgainstCaps | None


@dataclass(frozen=True, slots=True)
class TaskReport:
    items: list[TaskItem]
    truncated: bool
    tasks: int
    requests_with_task: int
    requests_without_task: int
    cost_usd: Decimal


@dataclass(frozen=True, slots=True)
class AffectedTask:
    task_id: str
    requests_refused: int


@dataclass(frozen=True, slots=True)
class CapPreview:
    start: datetime
    end: datetime
    tasks_considered: int
    tasks_affected: int
    requests_considered: int
    requests_refused: int
    refused_cost_usd: Decimal
    refused_share: float | None
    affected: list[AffectedTask]
    caveats: tuple[str, ...]


@dataclass(slots=True)
class _Window:
    calls: int = 0
    cost: Decimal = Decimal("0")
    refused: int = 0
    refused_cost: Decimal = Decimal("0")


def task_windows(
    rows: Iterable[tuple[datetime, bool, Decimal]],
    caps: TaskCaps,
    *,
    enforce: bool,
) -> list[_Window]:
    """S47's windows over one task's (started_at, is_call, cost) rows in time order.

    A window opens at a call and lasts `window_seconds`; the first call after it opens
    the next one with fresh counters. With `enforce`, a call is refused when it would
    be number `max_calls + 1`, or when the earlier admitted calls' settled cost has
    reached `max_cost_usd`; a refused call adds no cost. Extra attempts are not calls
    and are never refused; their cost counts in the window they fall in.
    """

    span = timedelta(seconds=caps.window_seconds)
    windows: list[_Window] = []
    opened: datetime | None = None
    for started_at, is_call, cost in rows:
        if is_call and (opened is None or started_at >= opened + span):
            opened = started_at
            windows.append(_Window())
        if not windows:
            continue
        current = windows[-1]
        if (
            is_call
            and enforce
            and (
                (caps.max_calls is not None and current.calls >= caps.max_calls)
                or (caps.max_cost_usd is not None and current.cost >= caps.max_cost_usd)
            )
        ):
            current.refused += 1
            current.refused_cost += cost
            continue
        current.calls += is_call
        current.cost += cost
    return windows


def _against(windows: Sequence[_Window], caps: TaskCaps) -> AgainstCaps:
    return AgainstCaps(
        calls_share=max(window.calls for window in windows) / caps.max_calls
        if caps.max_calls is not None and windows
        else None,
        cost_share=float(max(window.cost for window in windows) / caps.max_cost_usd)
        if caps.max_cost_usd is not None and windows
        else None,
    )


def _task_rows(
    tenant_id: UUID, start_at: datetime, end_at: datetime, scope: Any | None
):
    """Lifecycle rows of the window with their settled tokens and priced cost."""
    metadata = RequestLifecycle.lifecycle_metadata
    attempt = metadata["attempt_number"].as_integer()
    quota, spend = aliased(UsageLedger), aliased(UsageLedger)
    unpriced = (
        spend.event_metadata["pricing"]["pricing_resolution"].as_string() == "unknown"
    )
    settled = quota.estimated.is_(False)
    return (
        select(
            metadata["task_id"].as_string().label("task_id"),
            metadata["trace_id"].as_string().label("trace_id"),
            RequestLifecycle.started_at,
            RequestLifecycle.api_key_id,
            shown_model(RequestLifecycle.requested_model).label("model"),
            RequestLifecycle.status,
            metadata["completion_outcome"].as_string().label("outcome"),
            # S57: the first attempt carries no attempt_number.
            or_(attempt.is_(None), attempt == 1).label("is_call"),
            case((settled, quota.prompt_tokens), else_=0).label("prompt_tokens"),
            case((settled, quota.completion_tokens), else_=0).label(
                "completion_tokens"
            ),
            case(
                (unpriced, Decimal("0")), else_=func.coalesce(spend.cost_usd, 0)
            ).label("cost"),
            func.coalesce(unpriced, False).label("unpriced"),
            func.coalesce(
                metadata["policy_verdicts"].contains([{"rule_id": "task.agent_loop"}]),
                False,
            ).label("loop"),
        )
        .select_from(RequestLifecycle)
        .outerjoin(
            quota,
            and_(
                quota.organization_id == RequestLifecycle.organization_id,
                quota.request_id == RequestLifecycle.request_id,
                quota.event_type == "quota_settlement",
            ),
        )
        .outerjoin(
            spend,
            and_(
                spend.organization_id == RequestLifecycle.organization_id,
                spend.request_id == RequestLifecycle.request_id,
                spend.event_type == "spend_settlement",
            ),
        )
        .where(
            RequestLifecycle.organization_id == tenant_id,
            RequestLifecycle.started_at >= start_at,
            RequestLifecycle.started_at < end_at,
            # S58: a copy keeps the caller's task id but is never one of its calls.
            metadata["shadow_of"].as_string().is_(None),
            *(() if scope is None else (scope,)),
        )
    )


class TaskReadModel:
    async def read(
        self,
        session: AsyncSession,
        *,
        tenant_id: UUID,
        start_at: datetime,
        end_at: datetime,
        caps: TaskCaps,
        sort: TaskSort = "cost",
        scope: Any | None = None,
    ) -> TaskReport:
        rows = _task_rows(tenant_id, start_at, end_at, scope).cte("task_rows")
        has_task = rows.c.task_id.is_not(None)
        attempts = func.count()
        calls = func.count().filter(rows.c.is_call)
        cost = func.sum(rows.c.cost)
        last_seen = func.max(rows.c.started_at)
        # Totals run over the groups, so the no-task group stays in the statement
        # and is dropped from the items below.
        grouped = (
            await session.execute(
                select(
                    rows.c.task_id,
                    func.max(rows.c.trace_id).label("trace_id"),
                    func.min(rows.c.started_at).label("first_seen"),
                    last_seen.label("last_seen"),
                    calls.label("calls"),
                    attempts.label("attempts"),
                    func.sum(rows.c.prompt_tokens).label("prompt_tokens"),
                    func.sum(rows.c.completion_tokens).label("completion_tokens"),
                    cost.label("cost"),
                    func.bool_or(rows.c.unpriced).label("unpriced"),
                    func.array_agg(distinct(rows.c.model)).label("models"),
                    func.array_agg(distinct(rows.c.api_key_id)).label("api_keys"),
                    *(
                        func.count().filter(rows.c.outcome == name).label(name)
                        for name in OUTCOMES
                    ),
                    func.count().filter(rows.c.status.in_(_FAILED)).label("failed"),
                    func.count().filter(rows.c.loop).label("loop_signals"),
                    func.count().filter(has_task).over().label("tasks"),
                    func.sum(attempts).filter(has_task).over().label("with_task"),
                    func.sum(attempts).filter(~has_task).over().label("without_task"),
                    func.sum(cost).filter(has_task).over().label("task_cost"),
                )
                .group_by(rows.c.task_id)
                .order_by(
                    has_task,
                    {"cost": cost, "calls": calls, "last_seen": last_seen}[sort].desc(),
                    rows.c.task_id,
                )
                .limit(MAX_TASKS + 2)
            )
        ).all()
        tasks = [row for row in grouped if row.task_id is not None]
        shown = tasks[:MAX_TASKS]
        windows = (
            await self._windows(
                session, tenant_id, start_at, end_at, scope, caps, shown
            )
            if shown and (caps.max_calls is not None or caps.max_cost_usd is not None)
            else None
        )
        totals = grouped[0] if grouped else None
        return TaskReport(
            items=[
                TaskItem(
                    task_id=row.task_id,
                    trace_id=row.trace_id,
                    first_seen=row.first_seen,
                    last_seen=row.last_seen,
                    duration_seconds=(row.last_seen - row.first_seen).total_seconds(),
                    calls=row.calls,
                    attempts=row.attempts,
                    prompt_tokens=int(row.prompt_tokens or 0),
                    completion_tokens=int(row.completion_tokens or 0),
                    cost_usd=Decimal(row.cost or 0),
                    cost_complete=not row.unpriced,
                    models=sorted(model for model in row.models if model)[:MAX_LISTED],
                    api_keys=sorted(key for key in row.api_keys if key)[:MAX_LISTED],
                    outcomes={name: getattr(row, name) for name in OUTCOMES},
                    failed=row.failed,
                    loop_signals=row.loop_signals,
                    against_caps=_against(windows[row.task_id], caps)
                    if windows is not None
                    else None,
                )
                for row in shown
            ],
            truncated=len(tasks) > MAX_TASKS,
            tasks=totals.tasks if totals else 0,
            requests_with_task=int(totals.with_task or 0) if totals else 0,
            requests_without_task=int(totals.without_task or 0) if totals else 0,
            cost_usd=Decimal(totals.task_cost or 0) if totals else Decimal("0"),
        )

    async def _windows(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        start_at: datetime,
        end_at: datetime,
        scope: Any | None,
        caps: TaskCaps,
        shown: Sequence[Any],
    ) -> dict[str, list[_Window]]:
        rows = _task_rows(tenant_id, start_at, end_at, scope).cte("task_rows")
        found = await session.execute(
            select(rows.c.task_id, rows.c.started_at, rows.c.is_call, rows.c.cost)
            .where(rows.c.task_id.in_([row.task_id for row in shown]))
            .order_by(rows.c.task_id, rows.c.started_at)
        )
        return {
            task_id: task_windows(
                ((row.started_at, row.is_call, Decimal(row.cost)) for row in group),
                caps,
                enforce=False,
            )
            for task_id, group in groupby(found.all(), key=lambda row: row.task_id)
        }


class TooManyTaskRequests(ValueError):
    pass


async def preview_task_caps(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    end_at: datetime,
    caps: TaskCaps,
    api_key_id: UUID | None = None,
) -> CapPreview:
    """Replay the last TASK_CAP_PREVIEW_DAYS of task requests under `caps`; reads only."""
    start_at = end_at - timedelta(days=TASK_CAP_PREVIEW_DAYS)
    rows = _task_rows(
        tenant_id,
        start_at,
        end_at,
        None if api_key_id is None else RequestLifecycle.api_key_id == api_key_id,
    ).cte("task_rows")
    found = (
        await session.execute(
            select(rows.c.task_id, rows.c.started_at, rows.c.is_call, rows.c.cost)
            .where(rows.c.task_id.is_not(None))
            .order_by(rows.c.task_id, rows.c.started_at)
            .limit(TASK_CAP_PREVIEW_MAX_ROWS + 1)
        )
    ).all()
    if len(found) > TASK_CAP_PREVIEW_MAX_ROWS:
        raise TooManyTaskRequests
    affected: list[AffectedTask] = []
    tasks = requests = refused = 0
    refused_cost = Decimal("0")
    for task_id, group in groupby(found, key=lambda row: row.task_id):
        windows = task_windows(
            ((row.started_at, row.is_call, Decimal(row.cost)) for row in group),
            caps,
            enforce=True,
        )
        tasks += 1
        requests += sum(window.calls + window.refused for window in windows)
        task_refused = sum(window.refused for window in windows)
        if task_refused:
            affected.append(AffectedTask(task_id, task_refused))
            refused += task_refused
            refused_cost += sum((window.refused_cost for window in windows), Decimal(0))
    affected.sort(key=lambda task: (-task.requests_refused, task.task_id))
    return CapPreview(
        start=start_at,
        end=end_at,
        tasks_considered=tasks,
        tasks_affected=len(affected),
        requests_considered=requests,
        requests_refused=refused,
        refused_cost_usd=refused_cost,
        refused_share=refused / requests if requests else None,
        affected=affected[:MAX_AFFECTED_TASKS],
        caveats=CAP_PREVIEW_CAVEATS,
    )
