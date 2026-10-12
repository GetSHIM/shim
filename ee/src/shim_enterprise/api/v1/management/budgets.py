"""Cost budgets and their alert targets."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Collection, Mapping
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import ADMIN_REQUIRED, READER_REQUIRED, require
from shim_enterprise.billing.models import CostBudget
from shim_enterprise.billing.spend import (
    MAX_BUDGET_ALERT_THRESHOLDS,
    MAX_BUDGET_NOTIFY_TARGETS,
    BudgetConfigurationError,
    BudgetEvaluator,
    validate_budget_notification_config,
)
from shim_enterprise.compliance.url_guard import (
    UnsafeForwardURL,
    assert_safe_forward_url,
)
from shim_enterprise.core.database import get_db
from shim.gateway.contracts.ids import TenantId
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.secrets.store import get_secret_store
from shim_enterprise.tenants.audit import (
    change_details,
    record_management_action as _audit,
)
from shim_enterprise.tenants.gateway_settings import Directions, classify_fields, toward
from shim_enterprise.tenants.models import Team, User
from shim_enterprise.policy.plans import (
    Impact,
    Risk,
    State,
    lock_tenant,
    no_impact,
    record_managed_write,
    version_detail,
)
from shim_enterprise.tenants.permissions import Permission
from shim_enterprise.api.v1.management._common import (
    _delete_budget_targets,
    _limit,
    _only,
    _plain,
    _tenant_id,
    _uuids,
    _validate_attribution,
    _validated,
)


router = APIRouter()


_MAX_SYNC_BUDGETS = 100
_MAX_SYNC_BUDGET_DELIVERIES = 100


class NotificationTargetInput(BaseModel):
    kind: Literal["slack", "webhook"]
    endpoint: str = Field(min_length=1, max_length=2_048)
    secret: str | None = Field(
        default=None,
        min_length=16,
        repr=False,
        description="Signs webhook deliveries with X-Shim-Signature.",
    )

    @model_validator(mode="after")
    def validate_signing(self) -> NotificationTargetInput:
        if self.secret is not None and self.kind != "webhook":
            raise ValueError("only webhook targets support signing secrets")
        return self


class NotificationTargetView(BaseModel):
    kind: Literal["slack", "webhook"]
    endpoint_origin: str
    signed: bool

    @model_validator(mode="before")
    @classmethod
    def signed_from_reference(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {**value, "signed": "signing_secret_ref" in value}
        return value


class BudgetInput(BaseModel):
    scope_type: Literal["tag", "team", "team_id", "org"]
    scope_value: str | None = None
    limit_usd: Decimal | None = Field(default=None, gt=0)
    limit_tokens: int | None = Field(default=None, gt=0)
    alert_thresholds: list[float] = Field(
        default_factory=lambda: [0.8, 1.0],
        min_length=1,
        max_length=MAX_BUDGET_ALERT_THRESHOLDS,
        description=(
            "Fractions of the budget limit, greater than 0 and at most 5. "
            "0.8 means 80 percent."
        ),
    )
    notify_targets: list[NotificationTargetInput] = Field(
        min_length=1,
        max_length=MAX_BUDGET_NOTIFY_TARGETS,
    )
    enabled: bool = True

    @field_validator("alert_thresholds")
    @classmethod
    def validate_alert_thresholds(cls, values: list[float] | None) -> list[float]:
        if values is None:
            raise ValueError("alert thresholds must be within (0, 5]")
        for value in values:
            if not 0 < value <= 5:
                raise ValueError(
                    f"{value:g} is outside (0, 5]; thresholds are fractions, "
                    "0.5 means 50 percent"
                )
        if len(values) != len(set(values)):
            raise ValueError("alert thresholds must be unique")
        return values

    @field_validator("notify_targets")
    @classmethod
    def validate_notify_targets(
        cls, values: list[NotificationTargetInput]
    ) -> list[NotificationTargetInput]:
        keys = [(target.kind, target.endpoint.strip()) for target in values]
        if len(keys) != len(set(keys)):
            raise ValueError("notification targets must be unique")
        return values

    @model_validator(mode="after")
    def validate_budget(self) -> BudgetInput:
        if self.scope_type != "org":
            if not self.scope_value:
                raise ValueError("scoped budgets require scope_value")
            self.scope_value = (
                str(UUID(self.scope_value))
                if self.scope_type == "team_id"
                else _validate_attribution(self.scope_value)
            )
        if self.limit_usd is None and self.limit_tokens is None:
            raise ValueError("a budget requires a cost or token limit")
        return self


class BudgetPatch(BaseModel):
    limit_usd: Decimal | None = Field(default=None, gt=0)
    limit_tokens: int | None = Field(default=None, gt=0)
    alert_thresholds: list[float] | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_BUDGET_ALERT_THRESHOLDS,
        description=(
            "Fractions of the budget limit, greater than 0 and at most 5. "
            "0.8 means 80 percent."
        ),
    )
    notify_targets: list[NotificationTargetInput] | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_BUDGET_NOTIFY_TARGETS,
    )
    enabled: bool | None = None

    @field_validator("alert_thresholds")
    @classmethod
    def validate_alert_thresholds(cls, values: list[float] | None) -> list[float]:
        return BudgetInput.validate_alert_thresholds(values)

    @field_validator("notify_targets")
    @classmethod
    def validate_notify_targets(
        cls, values: list[NotificationTargetInput] | None
    ) -> list[NotificationTargetInput] | None:
        if values is None:
            return values
        return BudgetInput.validate_notify_targets(values)

    @field_validator("notify_targets", "enabled")
    @classmethod
    def reject_null(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("field cannot be null")
        return value


class BudgetView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    scope_type: Literal["tag", "team", "team_id", "org"]
    scope_value: str | None
    scope_label: str | None = None
    period: str
    limit_usd: Decimal | None
    limit_tokens: int | None
    alert_thresholds: list[float]
    notify_targets: list[NotificationTargetView]
    enabled: bool
    created_at: datetime

    @computed_field
    @property
    def alert_thresholds_percent(self) -> list[float]:
        return [float(Decimal(str(value)) * 100) for value in self.alert_thresholds]


class BudgetEvaluationItem(BaseModel):
    budget_id: UUID
    fraction: float
    fired: list[float]
    enqueued: int


class BudgetEvaluationView(BaseModel):
    period: str
    results: list[BudgetEvaluationItem]


@router.get("/cost/budgets", response_model=list[BudgetView])
async def list_budgets(
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(require("usage.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> list[BudgetView]:
    statement = (
        select(CostBudget)
        .where(CostBudget.organization_id == _tenant_id(user))
        .order_by(CostBudget.created_at.desc(), CostBudget.id.desc())
        .limit(limit)
        .offset(offset)
    )
    budgets = list((await session.execute(statement)).scalars().all())
    try:
        for budget in budgets:
            validate_budget_notification_config(budget)
    except BudgetConfigurationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return await _budget_views(session, budgets)


@router.post("/cost/budgets", response_model=BudgetView)
async def create_budget(
    payload: BudgetInput,
    user: User = Depends(require("budgets.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> BudgetView:
    tenant_id, budget_id = _tenant_id(user), uuid4()
    await _require_budget_team(session, tenant_id, payload.model_dump())
    await _validate_targets(payload.notify_targets)
    stored_targets = await _store_budget_targets(tenant_id, payload.notify_targets)
    try:
        after = _budget_state(
            {**payload.model_dump(), "notify_targets": stored_targets}
        )
        async with record_managed_write(
            session,
            user,
            tenant_id,
            [(BUDGETS, str(budget_id), None, after)],
            source="api",
        ) as version:
            row = await _create_budget(
                session,
                user,
                tenant_id,
                budget_id,
                after,
                stored_targets,
                policy_version=version,
            )
        await session.commit()
    except BaseException:
        await session.rollback()
        await _delete_budget_targets(tenant_id, stored_targets)
        raise
    await session.refresh(row)
    return (await _budget_views(session, [row]))[0]


@router.patch("/cost/budgets/{budget_id}", response_model=BudgetView)
async def update_budget(
    budget_id: UUID,
    patch: BudgetPatch,
    user: User = Depends(require("budgets.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> BudgetView:
    tenant_id = _tenant_id(user)
    await lock_tenant(session, tenant_id)
    row = await _owned_budget(session, user, budget_id)
    fields_set = patch.model_fields_set
    limit_usd = patch.limit_usd if "limit_usd" in fields_set else row.limit_usd
    limit_tokens = (
        patch.limit_tokens if "limit_tokens" in fields_set else row.limit_tokens
    )
    if limit_usd is None and limit_tokens is None:
        raise HTTPException(
            status_code=422, detail="a budget requires a cost or token limit"
        )
    values = patch.model_dump(exclude_unset=True)
    replacement_targets: list[dict[str, str]] | None = None
    previous_targets = list(row.notify_targets or [])
    if patch.notify_targets is not None:
        _reject_oversized_legacy_targets(previous_targets)
        await _validate_targets(patch.notify_targets)
        replacement_targets = await _store_budget_targets(
            tenant_id, patch.notify_targets
        )
        values["notify_targets"] = replacement_targets
    current = {field: getattr(row, field) for field in _BUDGET_FIELDS}
    before, after = _budget_state(current), _budget_state({**current, **values})
    try:
        async with record_managed_write(
            session,
            user,
            tenant_id,
            [(BUDGETS, str(row.id), before, after)],
            source="api",
        ) as version:
            await _update_budget(session, user, row, values, policy_version=version)
        await session.commit()
    except BaseException:
        await session.rollback()
        if replacement_targets is not None:
            await _delete_budget_targets(tenant_id, replacement_targets)
        raise
    if replacement_targets is not None:
        await _delete_budget_targets(tenant_id, previous_targets)
    await session.refresh(row)
    return (await _budget_views(session, [row]))[0]


@router.delete(
    "/cost/budgets/{budget_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def delete_budget(
    budget_id: UUID,
    user: User = Depends(require("budgets.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> None:
    tenant_id = _tenant_id(user)
    await lock_tenant(session, tenant_id)
    row = await _owned_budget(session, user, budget_id)
    before = _budget_state({field: getattr(row, field) for field in _BUDGET_FIELDS})
    async with record_managed_write(
        session, user, tenant_id, [(BUDGETS, str(row.id), before, None)], source="api"
    ) as version:
        targets = await _delete_budget(session, user, row, policy_version=version)
    await session.commit()
    await _delete_budget_targets(tenant_id, targets)


async def _create_budget(
    session: AsyncSession,
    actor: User,
    organization_id: UUID,
    budget_id: UUID,
    state: State,
    targets: list[dict[str, str]],
    *,
    policy_version: int | None,
) -> CostBudget:
    row = CostBudget(
        id=budget_id,
        organization_id=organization_id,
        period="monthly",
        **{
            **state,
            "notify_targets": targets,
            "limit_usd": None
            if state["limit_usd"] is None
            else Decimal(state["limit_usd"]),
        },
    )
    session.add(row)
    await session.flush()
    await _audit(
        session,
        actor,
        "tenant.budget_created",
        str(row.id),
        details={
            **change_details(None, _budget_facts(row)),
            **version_detail(policy_version),
        },
    )
    return row


async def _require_budget_team(
    session: AsyncSession, organization_id: UUID, state: State
) -> None:
    if state["scope_type"] == "team_id" and not await session.scalar(
        select(Team.id).where(
            Team.id == UUID(state["scope_value"] or ""),
            Team.organization_id == organization_id,
        )
    ):
        raise HTTPException(status_code=422, detail="Unknown team")


async def _update_budget(
    session: AsyncSession,
    actor: User,
    row: CostBudget,
    values: Mapping[str, Any],
    *,
    policy_version: int | None,
) -> None:
    before = _budget_facts(row)
    for field, value in values.items():
        setattr(row, field, value)
    if "notify_targets" in values:
        await _cancel_budget_deliveries(session, row.organization_id, row.id)
    await _audit(
        session,
        actor,
        "tenant.budget_updated",
        str(row.id),
        details={
            **change_details(before, _budget_facts(row)),
            **version_detail(policy_version),
        },
    )


async def _delete_budget(
    session: AsyncSession,
    actor: User,
    row: CostBudget,
    *,
    policy_version: int | None,
) -> list[dict[str, str]]:
    targets = list(row.notify_targets or [])
    _reject_oversized_legacy_targets(targets)
    await _cancel_budget_deliveries(session, row.organization_id, row.id)
    details = change_details(_budget_facts(row), None)
    await session.delete(row)
    await _audit(
        session,
        actor,
        "tenant.budget_deleted",
        str(row.id),
        details={**details, **version_detail(policy_version)},
    )
    return targets


@router.post(
    "/cost/budgets/evaluate",
    response_model=BudgetEvaluationView,
    responses={
        422: {
            "description": "Budget configuration or synchronous evaluation limit rejected."
        }
    },
)
async def evaluate_budgets(
    user: User = Depends(require("budgets.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> BudgetEvaluationView:
    budgets = list(
        (
            await session.execute(
                select(CostBudget)
                .where(CostBudget.organization_id == _tenant_id(user))
                .with_for_update(read=True, of=CostBudget)
                .limit(_MAX_SYNC_BUDGETS + 1)
            )
        )
        .scalars()
        .all()
    )
    if len(budgets) > _MAX_SYNC_BUDGETS:
        await session.rollback()
        raise HTTPException(
            status_code=422,
            detail=f"synchronous evaluation is limited to {_MAX_SYNC_BUDGETS} budgets",
        )
    try:
        delivery_count = sum(
            len(validate_budget_notification_config(budget))
            * len(budget.notify_targets)
            for budget in budgets
            if budget.enabled
        )
    except BudgetConfigurationError as exc:
        await session.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if delivery_count > _MAX_SYNC_BUDGET_DELIVERIES:
        await session.rollback()
        raise HTTPException(
            status_code=422,
            detail=(
                "synchronous evaluation is limited to "
                f"{_MAX_SYNC_BUDGET_DELIVERIES} potential deliveries"
            ),
        )
    now = datetime.now(timezone.utc)
    evaluator = BudgetEvaluator()
    try:
        results = [
            await evaluator.evaluate(session, budget, now=now)
            for budget in budgets
            if budget.enabled
        ]
    except BudgetConfigurationError as exc:
        await session.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from None
    await _audit(
        session,
        user,
        "tenant.budgets_evaluated",
        str(_tenant_id(user)),
        details={"budgets_evaluated": len(results)},
    )
    await session.commit()
    return BudgetEvaluationView(
        period=now.strftime("%Y-%m"),
        results=[BudgetEvaluationItem.model_validate(result) for result in results],
    )


def _budget_facts(row: CostBudget) -> dict[str, Any]:
    return {
        "scope_type": row.scope_type,
        "scope_value": row.scope_value,
        "period": row.period,
        "limit_usd": row.limit_usd,
        "limit_tokens": row.limit_tokens,
        "alert_thresholds": list(row.alert_thresholds),
        "enabled": row.enabled,
        "notify_targets": [
            {"kind": target["kind"], "endpoint_origin": target["endpoint_origin"]}
            for target in row.notify_targets or []
        ],
    }


async def _owned_budget(
    session: AsyncSession,
    user: User,
    budget_id: UUID,
) -> CostBudget:
    statement = (
        select(CostBudget)
        .where(
            CostBudget.id == budget_id,
            CostBudget.organization_id == _tenant_id(user),
        )
        .with_for_update(of=CostBudget)
    )
    row = (await session.execute(statement)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Budget not found")
    return row


async def _budget_views(
    session: AsyncSession, budgets: list[CostBudget]
) -> list[BudgetView]:
    team_ids = {
        UUID(budget.scope_value)
        for budget in budgets
        if budget.scope_type == "team_id" and budget.scope_value
    }
    names = (
        {
            str(team_id): name
            for team_id, name in await session.execute(
                select(Team.id, Team.name).where(
                    Team.organization_id == budgets[0].organization_id,
                    Team.id.in_(team_ids),
                )
            )
        }
        if team_ids
        else {}
    )
    return [
        BudgetView.model_validate(budget).model_copy(
            update={
                "scope_label": names.get(budget.scope_value or "")
                if budget.scope_type == "team_id"
                else None
            }
        )
        for budget in budgets
    ]


async def _validate_targets(targets: list[NotificationTargetInput]) -> None:
    for target in targets:
        try:
            await assert_safe_forward_url(target.endpoint)
        except UnsafeForwardURL as exc:
            raise HTTPException(
                status_code=422, detail="Unsafe notification URL"
            ) from exc


async def _store_budget_targets(
    tenant_id: UUID,
    targets: list[NotificationTargetInput],
) -> list[dict[str, str]]:
    stored: list[dict[str, str]] = []
    store = get_secret_store()
    try:
        for target in targets:
            reference = await store.put_secret(
                TenantId(tenant_id),
                "budget-alert-endpoint",
                target.endpoint,
                {"kind": target.kind},
            )
            entry = {
                "kind": target.kind,
                "endpoint_origin": _endpoint_origin(target.endpoint),
                "secret_ref": str(reference),
            }
            stored.append(entry)
            if target.secret is not None:
                entry["signing_secret_ref"] = str(
                    await store.put_secret(
                        TenantId(tenant_id),
                        "budget-alert-signing",
                        target.secret,
                        {"kind": target.kind},
                    )
                )
    except BaseException:
        await _delete_budget_targets(tenant_id, stored)
        raise
    return stored


def _reject_oversized_legacy_targets(targets: list[dict[str, str]]) -> None:
    if len(targets) > MAX_BUDGET_NOTIFY_TARGETS:
        raise HTTPException(
            status_code=422,
            detail="legacy budget notification targets require migration",
        )


async def _cancel_budget_deliveries(
    session: AsyncSession,
    tenant_id: UUID,
    budget_id: UUID,
) -> None:
    statement = (
        select(OutboxEvent)
        .where(
            OutboxEvent.organization_id == tenant_id,
            OutboxEvent.event_type == "budget.threshold_crossed",
            OutboxEvent.aggregate_type == "budget",
            OutboxEvent.aggregate_id == str(budget_id),
            OutboxEvent.status.in_(("pending", "processing", "failed")),
        )
        .with_for_update(of=OutboxEvent)
    )
    now = datetime.now(timezone.utc)
    for event in (await session.execute(statement)).scalars():
        event.cancel(now=now)


def _endpoint_origin(endpoint: str) -> str:
    parts = urlsplit(endpoint)
    return f"{parts.scheme}://{parts.netloc}"


_BUDGET_FIELDS = (
    "scope_type",
    "scope_value",
    "limit_usd",
    "limit_tokens",
    "alert_thresholds",
    "enabled",
    "notify_targets",
)
_BUDGET_DIRECTIONS: Directions = {
    "limit_usd": _limit,
    "limit_tokens": _limit,
    "enabled": toward(False),
    "alert_thresholds": lambda before, after: (
        "relaxing" if set(before) - set(after) else "tightening"
    ),
}


class _ManagedBudget(BudgetInput):
    model_config = ConfigDict(extra="forbid")

    notify_targets: list[NotificationTargetInput] = Field(
        default_factory=list, max_length=0
    )


def _budget_state(values: Mapping[str, Any]) -> State:
    return {
        **{field: _plain(values[field]) for field in _BUDGET_FIELDS},
        # A digest of each secret reference shows a replacement, never the URL.
        "notify_targets": [
            {
                "kind": target["kind"],
                "endpoint_origin": target["endpoint_origin"],
                "id": hashlib.sha256(target["secret_ref"].encode()).hexdigest()[:16],
            }
            for target in values["notify_targets"] or []
        ],
    }


class _BudgetResource:
    name = "budgets"
    permission: Permission = "budgets.manage"
    creatable = True
    deletable = True

    async def snapshot(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_ids: Collection[str] | None,
    ) -> dict[str, State]:
        statement = select(CostBudget).where(
            CostBudget.organization_id == organization_id
        )
        if item_ids is not None:
            statement = statement.where(CostBudget.id.in_(_uuids(item_ids)))
        return {
            str(row.id): _budget_state(
                {field: getattr(row, field) for field in _BUDGET_FIELDS}
            )
            for row in await session.scalars(statement)
        }

    async def validate(
        self,
        session: AsyncSession,
        actor: User,
        item_id: str | None,
        before: State | None,
        proposed: State,
    ) -> State:
        if before is None:
            after = _budget_state(_validated(_ManagedBudget, proposed).model_dump())
            await _require_budget_team(session, _tenant_id(actor), after)
            return after
        _only(proposed, ("limit_usd", "limit_tokens", "alert_thresholds", "enabled"))
        patch = _validated(BudgetPatch, proposed).model_dump(exclude_unset=True)
        after = {**before, **{field: _plain(value) for field, value in patch.items()}}
        if after["limit_usd"] is None and after["limit_tokens"] is None:
            raise HTTPException(
                status_code=422, detail="a budget requires a cost or token limit"
            )
        return after

    async def apply(
        self,
        session: AsyncSession,
        actor: User,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        *,
        policy_version: int | None,
    ) -> Callable[[], Awaitable[None]] | None:
        if before is None:
            assert after is not None
            await _create_budget(
                session,
                actor,
                organization_id,
                UUID(item_id),
                after,
                [],
                policy_version=policy_version,
            )
            return None
        row = await _owned_budget(session, actor, UUID(item_id))
        if after is None:
            targets = await _delete_budget(
                session, actor, row, policy_version=policy_version
            )
            return lambda: _delete_budget_targets(organization_id, targets)
        await _update_budget(
            session,
            actor,
            row,
            {
                field: Decimal(value)
                if field == "limit_usd" and value is not None
                else value
                for field, value in after.items()
                if value != before[field]
            },
            policy_version=policy_version,
        )
        return None

    def classify(self, before: State | None, after: State | None) -> Risk:
        if after is None:
            return "relaxing"
        if before is None:
            return "tightening"
        return classify_fields(before, after, _BUDGET_DIRECTIONS)[0]

    async def impact(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        window_days: int,
    ) -> Impact:
        if after is None:
            return no_impact(window_days, "its alerts stop")
        budget = CostBudget(
            organization_id=organization_id,
            scope_type=after["scope_type"],
            scope_value=after["scope_value"],
            limit_usd=None
            if after["limit_usd"] is None
            else Decimal(after["limit_usd"]),
            limit_tokens=after["limit_tokens"],
        )
        now = datetime.now(timezone.utc)
        usage = await BudgetEvaluator().aggregate(
            session,
            budget,
            now.replace(day=1, hour=0, minute=0, second=0, microsecond=0),
        )
        share = int(usage.fraction_of(budget) * 100)
        return {
            "requests": None,
            "basis": "metadata",
            "window_days": window_days,
            "note": f"month-to-date use is {share} percent of the new limit",
        }


BUDGETS = _BudgetResource()
