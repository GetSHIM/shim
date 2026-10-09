import asyncio
import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from pydantic import ValidationError
from sqlalchemy import delete, select, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import shim_enterprise.api.enterprise_deps as enterprise_deps
from shim_enterprise.api.v1 import management
from shim_enterprise.api.v1.router import management_router
from shim.billing.attribution import CostAttribution, UNTAGGED, normalize_attribution
from shim_enterprise.billing.ledger import (
    DurableAccountingRepository,
    FinalizationCommand,
    QuotaPolicySnapshot,
    QuotaReservationCommand,
    TerminalAction,
)
from shim_enterprise.billing.models import (
    CostBudget,
    CostBudgetAlertState,
    QuotaPeriodUsage,
    RequestLifecycle,
    UsageLedger,
)
from shim_enterprise.billing.read_models import BillingReadModels
from shim_enterprise.billing.spend import (
    BudgetConfigurationError,
    BudgetEvaluator,
    BudgetUsage,
    evaluate_enabled_budgets,
    validate_budget_notification_config,
)
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim.gateway.contracts.ids import TenantId
from shim_enterprise.outbox.handlers import _budget_text
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.tenants.models import ApiKey, Organization, Team, User


_TARGET = {"kind": "webhook", "endpoint": "https://alerts.example/hook"}


def test_api_key_cost_center_wins_and_header_tags_stay_dimensions() -> None:
    attribution = CostAttribution.resolve(
        " Research ,experiment,research,not valid! ",
        api_key_cost_center="fallback",
        maximum_length=32,
    )

    assert attribution.cost_center == "fallback"
    assert attribution.tags == ("research", "experiment")


def test_first_header_tag_is_the_cost_center_without_a_key_center() -> None:
    attribution = CostAttribution.resolve(
        " Research ,experiment,research,not valid! ",
        api_key_cost_center=None,
        maximum_length=32,
    )

    assert attribution.cost_center == "research"
    assert attribution.tags == ("research", "experiment")


def test_api_key_cost_center_is_used_without_valid_header_tags() -> None:
    attribution = CostAttribution.resolve(
        None,
        api_key_cost_center="Team-A",
        maximum_length=32,
    )

    assert attribution.cost_center == "team-a"
    assert attribution.tags == ()


def test_missing_attribution_uses_public_untagged_value() -> None:
    attribution = CostAttribution.resolve(
        None,
        api_key_cost_center=None,
        maximum_length=32,
    )

    assert attribution == CostAttribution(cost_center=UNTAGGED, tags=())


def test_attribution_rejects_unsupported_characters() -> None:
    with pytest.raises(ValueError, match="cost attribution"):
        normalize_attribution("contains spaces", maximum_length=32)


def test_budget_usage_uses_the_stricter_configured_dimension() -> None:
    usage = BudgetUsage(
        cost_usd=Decimal("25"),
        tokens=80,
        top_contributors=(),
    )
    budget = SimpleNamespace(limit_usd=100, limit_tokens=100)

    assert usage.fraction_of(budget) == Decimal("0.8")


def test_billing_breakdown_index_matches_tenant_reconciliation_filter() -> None:
    index = next(
        index
        for index in RequestLifecycle.__table__.indexes
        if index.name == "ix_request_lifecycle_org_reconciled_at"
    )

    assert tuple(column.name for column in index.columns) == (
        "organization_id",
        "reconciled_at",
    )
    assert (
        str(index.dialect_options["postgresql"]["where"]) == "reconciled_at IS NOT NULL"
    )


def test_budget_patch_reuses_create_threshold_validation() -> None:
    for thresholds in ([0], [5.01], [float("nan")], None):
        with pytest.raises(ValidationError, match=r"\(0, 5\]"):
            management.BudgetPatch(alert_thresholds=thresholds)

    assert management.BudgetInput(
        scope_type="org", limit_tokens=1, notify_targets=[_TARGET]
    ).alert_thresholds == [0.8, 1.0]
    assert management.BudgetPatch(alert_thresholds=[5]).alert_thresholds == [5]


@pytest.mark.parametrize("model", [management.BudgetInput, management.BudgetPatch])
@pytest.mark.parametrize(
    "values",
    [
        {"alert_thresholds": [index / 10 for index in range(1, 12)]},
        {"alert_thresholds": [0.8, 0.8]},
        {
            "notify_targets": [
                {"kind": "webhook", "endpoint": f"https://alerts.example/{index}"}
                for index in range(11)
            ]
        },
        {
            "notify_targets": [
                {"kind": "webhook", "endpoint": " https://alerts.example/hook "},
                {"kind": "webhook", "endpoint": "https://alerts.example/hook"},
            ]
        },
    ],
)
def test_budget_notification_fanout_is_bounded(model, values) -> None:
    if model is management.BudgetInput:
        values = {"scope_type": "org", "limit_tokens": 1, **values}

    with pytest.raises(ValidationError):
        model.model_validate(values)


@pytest.mark.parametrize("model", [management.BudgetInput, management.BudgetPatch])
def test_budget_notification_fanout_accepts_ten_unique_entries(model) -> None:
    values = {
        "alert_thresholds": [index / 10 for index in range(1, 11)],
        "notify_targets": [
            {"kind": "webhook", "endpoint": f"https://alerts.example/{index}"}
            for index in range(10)
        ],
    }
    if model is management.BudgetInput:
        values = {"scope_type": "org", "limit_tokens": 1, **values}

    assert (
        model.model_validate(values).model_dump(
            include=set(values), exclude={"notify_targets": {"__all__": {"secret"}}}
        )
        == values
    )


@pytest.mark.parametrize(
    ("thresholds", "targets"),
    [
        ({}, []),
        ([], {}),
        ([0.1] * 11, []),
        (
            [],
            [
                {
                    "kind": "webhook",
                    "endpoint_origin": "https://alerts.example",
                    "secret_ref": "secret:1",
                }
            ]
            * 11,
        ),
        ([float("nan")], []),
        ([0], []),
        ([5.1], []),
        ([0.8, Decimal("0.80")], []),
        ([], [{}]),
        (
            [],
            [
                {
                    "kind": "email",
                    "endpoint_origin": "https://alerts.example",
                    "secret_ref": "secret:1",
                }
            ],
        ),
        (
            [],
            [
                {
                    "kind": "webhook",
                    "endpoint_origin": " ",
                    "secret_ref": "secret:1",
                }
            ],
        ),
        (
            [],
            [
                {
                    "kind": "slack",
                    "endpoint_origin": "https://alerts.example",
                    "secret_ref": "",
                }
            ],
        ),
    ],
)
def test_persisted_budget_notification_config_is_validated(
    thresholds: object,
    targets: object,
) -> None:
    with pytest.raises(
        BudgetConfigurationError,
        match="budget notification configuration is invalid",
    ):
        validate_budget_notification_config(
            SimpleNamespace(alert_thresholds=thresholds, notify_targets=targets)
        )


def test_persisted_budget_thresholds_are_normalized_to_decimals() -> None:
    budget = SimpleNamespace(
        alert_thresholds=[0.8, 1],
        notify_targets=[
            {
                "kind": "webhook",
                "endpoint_origin": "https://alerts.example",
                "secret_ref": "secret:1",
            }
        ],
    )

    assert validate_budget_notification_config(budget) == [
        Decimal("0.8"),
        Decimal("1"),
    ]


@pytest.mark.asyncio
async def test_budget_evaluator_validates_persisted_config_before_queries() -> None:
    session = SimpleNamespace(execute=AsyncMock())
    budget = SimpleNamespace(
        alert_thresholds=[0.8],
        notify_targets=[{}],
    )

    with pytest.raises(BudgetConfigurationError, match="notification configuration"):
        await BudgetEvaluator().evaluate(
            session,
            budget,
            now=datetime(2026, 8, 1, tzinfo=timezone.utc),
        )

    session.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_legacy_unbounded_targets_require_migration_before_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_targets = [{"secret_ref": f"secret:{index}"} for index in range(11)]
    row = SimpleNamespace(
        id=uuid4(),
        limit_usd=Decimal("10"),
        limit_tokens=None,
        notify_targets=old_targets,
        enabled=True,
    )
    user = SimpleNamespace(organization_id=uuid4())
    # execute takes the tenant lock every managed write holds.
    session = SimpleNamespace(delete=AsyncMock(), execute=AsyncMock())
    monkeypatch.setattr(management, "_owned_budget", AsyncMock(return_value=row))

    with pytest.raises(HTTPException, match="require migration"):
        await management.update_budget(
            row.id,
            management.BudgetPatch(notify_targets=[_TARGET]),
            user,
            session,
        )
    with pytest.raises(HTTPException, match="require migration"):
        await management.delete_budget(row.id, user, session)

    session.delete.assert_not_awaited()


@pytest.mark.asyncio
async def test_budget_evaluation_returns_422_for_oversized_persisted_config() -> None:
    budget = SimpleNamespace(
        enabled=True,
        alert_thresholds=[0.1] * 11,
        notify_targets=[],
    )
    session = SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(
                scalars=lambda: SimpleNamespace(all=lambda: [budget])
            )
        ),
        commit=AsyncMock(),
        rollback=AsyncMock(),
    )

    with pytest.raises(HTTPException, match="notification configuration") as error:
        await management.evaluate_budgets(
            SimpleNamespace(organization_id=uuid4()),
            session,
        )

    assert error.value.status_code == 422
    session.rollback.assert_awaited_once()
    session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_budget_evaluation_rejects_more_than_100_budgets() -> None:
    session = SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(
                scalars=lambda: SimpleNamespace(
                    all=lambda: [SimpleNamespace(enabled=False)] * 101
                )
            )
        ),
        commit=AsyncMock(),
        rollback=AsyncMock(),
    )

    with pytest.raises(HTTPException, match="100 budgets") as error:
        await management.evaluate_budgets(
            SimpleNamespace(organization_id=uuid4()),
            session,
        )

    statement = session.execute.await_args.args[0]
    compiled = statement.compile(dialect=postgresql.dialect())
    assert error.value.status_code == 422
    assert 101 in compiled.params.values()
    session.rollback.assert_awaited_once()
    session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_budget_evaluation_caps_total_delivery_fanout() -> None:
    budget = SimpleNamespace(
        enabled=True,
        alert_thresholds=[index / 10 for index in range(1, 11)],
        notify_targets=[
            {
                "kind": "webhook",
                "endpoint_origin": f"https://alerts.example/{index}",
                "secret_ref": f"secret:{index}",
            }
            for index in range(10)
        ],
    )
    session = SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(
                scalars=lambda: SimpleNamespace(all=lambda: [budget, budget])
            )
        ),
        commit=AsyncMock(),
        rollback=AsyncMock(),
    )

    with pytest.raises(HTTPException, match="100 potential deliveries") as error:
        await management.evaluate_budgets(
            SimpleNamespace(organization_id=uuid4()),
            session,
        )

    assert error.value.status_code == 422
    session.rollback.assert_awaited_once()
    session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_budget_list_is_stably_paginated() -> None:
    session = SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(
                scalars=lambda: SimpleNamespace(all=lambda: [])
            )
        )
    )

    assert (
        await management.list_budgets(
            limit=100,
            offset=200,
            user=SimpleNamespace(organization_id=uuid4()),
            session=session,
        )
        == []
    )

    compiled = session.execute.await_args.args[0].compile(dialect=postgresql.dialect())
    sql = str(compiled)
    assert "ORDER BY cost_budget.created_at DESC, cost_budget.id DESC" in sql
    assert 100 in compiled.params.values()
    assert 200 in compiled.params.values()


@pytest.mark.asyncio
async def test_budget_list_returns_422_for_invalid_persisted_config() -> None:
    budget = SimpleNamespace(alert_thresholds=[0.8], notify_targets=[{}])
    session = SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(
                scalars=lambda: SimpleNamespace(all=lambda: [budget])
            )
        )
    )

    with pytest.raises(HTTPException) as error:
        await management.list_budgets(
            limit=100,
            offset=0,
            user=SimpleNamespace(organization_id=uuid4()),
            session=session,
        )

    assert error.value.status_code == 422
    assert error.value.detail == "budget notification configuration is invalid"


@pytest.mark.asyncio
async def test_budget_patch_distinguishes_omitted_and_null_limits(
    db, test_user_with_org
) -> None:
    test_user_with_org.role = "admin"
    row = CostBudget(
        organization_id=test_user_with_org.organization_id,
        scope_type="org",
        scope_value=None,
        period="monthly",
        limit_usd=Decimal("10"),
        limit_tokens=100,
        alert_thresholds=[0.8, 1.0],
        notify_targets=[],
        enabled=True,
    )
    db.add(row)
    await db.flush()

    async def apply(**values):
        return await management.update_budget(
            row.id, management.BudgetPatch(**values), test_user_with_org, db
        )

    assert (await apply(enabled=False)).id == row.id
    assert (row.limit_usd, row.limit_tokens) == (Decimal("10"), 100)
    assert (await apply(limit_usd=None)).id == row.id
    assert (row.limit_usd, row.limit_tokens) == (None, 100)
    with pytest.raises(HTTPException) as exc_info:
        await apply(limit_tokens=None)

    assert exc_info.value.status_code == 422
    assert exc_info.value.detail == "a budget requires a cost or token limit"
    assert row.limit_tokens == 100


@pytest.mark.asyncio
async def test_daily_usage_groups_timestamps_in_utc() -> None:
    statements = []

    async def execute(statement):
        statements.append(statement)
        return SimpleNamespace(all=lambda: [])

    await BillingReadModels().daily_usage(
        SimpleNamespace(execute=execute),
        tenant_id=TenantId(uuid4()),
        start_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        end_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    compiled = statements[0].compile(dialect=postgresql.dialect())
    sql = str(compiled)
    assert "date(timezone(%(timezone_1)s, request_lifecycle.reconciled_at))" in sql
    assert compiled.params["timezone_1"] == "UTC"
    assert " LIMIT " in sql
    assert 501 in compiled.params.values()


@pytest.mark.parametrize(
    ("group_by", "group_sql"),
    [
        ("model", "coalesce(request_lifecycle.provider_model"),
        ("tag", "jsonb_array_elements_text"),
        ("cost_center", "request_lifecycle.metadata"),
        ("provider", "coalesce(request_lifecycle.provider"),
        ("team", "request_lifecycle.metadata"),
    ],
)
@pytest.mark.asyncio
async def test_billing_breakdown_is_tenant_scoped_and_exact(
    group_by: str,
    group_sql: str,
) -> None:
    tenant_id = uuid4()
    statements = []

    async def execute(statement):
        statements.append(statement)
        return SimpleNamespace(
            all=lambda: [
                SimpleNamespace(
                    key="research",
                    request_count=2,
                    prompt_tokens=20,
                    completion_tokens=5,
                    cost_usd=Decimal("0.12345678"),
                    unpriced_requests=0,
                )
            ]
        )

    records = await BillingReadModels().breakdown(
        SimpleNamespace(execute=execute),
        tenant_id=TenantId(tenant_id),
        start_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        end_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        group_by=group_by,
        limit=100,
    )

    assert records[0].cost_usd == Decimal("0.12345678")
    assert records[0].as_public_record()["cost_usd"] == Decimal("0.12345678")
    compiled = statements[0].compile(dialect=postgresql.dialect())
    sql = str(compiled)
    assert "request_logs" not in sql
    assert "request_lifecycle.organization_id =" in sql
    assert "usage_ledger.organization_id =" in sql
    assert sum(value == tenant_id for value in compiled.params.values()) == 2
    assert compiled.params["reconciled_at_1"] == datetime(
        2026, 1, 1, tzinfo=timezone.utc
    )
    assert compiled.params["reconciled_at_2"] == datetime(
        2026, 1, 2, tzinfo=timezone.utc
    )
    assert group_sql in sql
    if group_by in {"tag", "cost_center", "team"}:
        assert ("tags" if group_by == "tag" else group_by) in compiled.params.values()
    assert "quota_settlement" in compiled.params.values()
    assert "spend_settlement" in compiled.params.values()


@pytest.mark.asyncio
async def test_billing_breakdown_reads_settlements_without_request_log(
    db,
    test_api_key,
) -> None:
    request_id = f"req_billing_{uuid4().hex}"
    organization_id = test_api_key.organization_id
    ledger_at = datetime(2025, 12, 31, 23, 59, tzinfo=timezone.utc)
    reconciled_at = datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc)
    db.add(
        RequestLifecycle(
            request_id=request_id,
            organization_id=organization_id,
            actor_type="api_key",
            api_key_id=test_api_key.id,
            user_id=None,
            source_endpoint="chat.completions",
            status="completed",
            provider="openai",
            provider_model="gpt-5-mini",
            requested_model="fast-model",
            stream=False,
            started_at=ledger_at,
            completed_at=reconciled_at,
            reconciled_at=reconciled_at,
            lifecycle_metadata={
                "cost_center": "research",
                "tags": ["research", "batch"],
                "team": "platform",
            },
        )
    )
    spend_reservation = UsageLedger(
        request_id=request_id,
        organization_id=organization_id,
        api_key_id=test_api_key.id,
        requested_model="fast-model",
        provider="openai",
        provider_model="gpt-5-mini",
        event_type="spend_reservation",
        idempotency_key=f"{request_id}:spend:reservation",
        cost_usd=Decimal("0.12345678"),
        created_at=ledger_at,
    )
    db.add(spend_reservation)
    await db.flush()
    db.add(
        UsageLedger(
            request_id=request_id,
            organization_id=organization_id,
            api_key_id=test_api_key.id,
            requested_model="fast-model",
            provider="openai",
            provider_model="gpt-5-mini",
            event_type="spend_settlement",
            idempotency_key=f"{request_id}:spend:settlement",
            reservation_event_id=spend_reservation.id,
            cost_usd=Decimal("0.12345678"),
            created_at=ledger_at,
        )
    )
    await db.flush()

    records = await BillingReadModels().breakdown(
        db,
        tenant_id=TenantId(organization_id),
        start_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        end_at=datetime(2026, 1, 1, 1, tzinfo=timezone.utc),
        group_by="tag",
        limit=100,
    )

    assert {record.key for record in records} == {"research", "batch"}
    assert all(record.cost_usd == Decimal("0.12345678") for record in records)
    assert not await BillingReadModels().breakdown(
        db,
        tenant_id=TenantId(organization_id),
        start_at=datetime(2025, 12, 31, 23, tzinfo=timezone.utc),
        end_at=datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        group_by="tag",
        limit=100,
    )
    assert not await BillingReadModels().breakdown(
        db,
        tenant_id=TenantId(uuid4()),
        start_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        end_at=datetime(2026, 1, 1, 1, tzinfo=timezone.utc),
        group_by="tag",
        limit=100,
    )


@pytest.mark.asyncio
async def test_budget_alert_labels_incomplete_known_spend(monkeypatch) -> None:
    append = AsyncMock()
    monkeypatch.setattr("shim_enterprise.billing.spend.OutboxWriter.append", append)
    await BudgetEvaluator._enqueue_alert(
        AsyncMock(),
        SimpleNamespace(
            id=uuid4(),
            organization_id=uuid4(),
            scope_type="org",
            scope_value=None,
            limit_usd=10,
            limit_tokens=None,
            notify_targets=[{"kind": "webhook"}],
        ),
        BudgetUsage(Decimal("8"), 50, (), unpriced_requests=2),
        fraction=Decimal("0.8"),
        threshold=Decimal("0.8"),
        period_key="2026-09",
        now=datetime.now(timezone.utc),
    )
    payload = append.await_args.kwargs["values"]["payload"]
    assert payload["current_usd"] == 8
    assert payload["cost_basis"] == "known_settled_spend"
    assert payload["cost_complete"] is False
    assert payload["unpriced_requests"] == 2
    assert "known spend only; 2 unpriced requests" in _budget_text(payload)


@pytest.mark.asyncio
async def test_team_budget_alert_names_the_team_and_falls_back_to_the_id(
    db, test_org, monkeypatch
) -> None:
    append = AsyncMock()
    monkeypatch.setattr("shim_enterprise.billing.spend.OutboxWriter.append", append)
    elsewhere = Organization(id=uuid4(), name="Elsewhere", slug=f"else-{uuid4()}")
    db.add(elsewhere)
    await db.flush()
    team = Team(organization_id=test_org.id, name="credit-risk")
    foreign = Team(organization_id=elsewhere.id, name="not-yours")
    db.add_all([team, foreign])
    await db.flush()

    async def alert_text(team_id: UUID) -> str:
        await BudgetEvaluator._enqueue_alert(
            db,
            SimpleNamespace(
                id=uuid4(),
                organization_id=test_org.id,
                scope_type="team_id",
                scope_value=str(team_id),
                limit_usd=10,
                limit_tokens=None,
                notify_targets=[{"kind": "slack"}],
            ),
            BudgetUsage(Decimal("8"), 50, ()),
            fraction=Decimal("0.8"),
            threshold=Decimal("0.8"),
            period_key="2026-09",
            now=datetime.now(timezone.utc),
        )
        return _budget_text(append.await_args.kwargs["values"]["payload"])

    assert (await alert_text(team.id)).startswith("shim budget credit-risk: 80%")
    missing, foreign_id = uuid4(), foreign.id
    assert (await alert_text(missing)).startswith(f"shim budget {missing}: 80%")
    assert (await alert_text(foreign_id)).startswith(f"shim budget {foreign_id}: 80%")


async def _tenant_with_settled_tokens(session: AsyncSession, tokens: int) -> UUID:
    organization_id, user_id, api_key_id = uuid4(), uuid4(), uuid4()
    await session.execute(
        text(
            "INSERT INTO tier_definitions "
            "(slug, name, rate_limit_rpm, rate_limit_tpm, "
            "monthly_request_limit, monthly_token_limit, features) "
            "VALUES ('free', 'Free', 60, 15000, 1000, 1000000, '{}') "
            "ON CONFLICT (slug) DO NOTHING"
        )
    )
    session.add(
        Organization(
            id=organization_id,
            name="Budget cadence",
            slug=f"budget-cadence-{organization_id}",
        )
    )
    await session.flush()
    session.add(
        User(
            id=user_id, organization_id=organization_id, email=f"{user_id}@example.com"
        )
    )
    await session.flush()
    session.add(
        ApiKey(
            id=api_key_id,
            organization_id=organization_id,
            user_id=user_id,
            key_hash=uuid4().hex,
            prefix="sk-budget",
            tier="free",
            is_active=True,
        )
    )
    await session.flush()
    request_id = f"req_budget_{uuid4().hex}"
    now = datetime.now(timezone.utc)
    repository = DurableAccountingRepository()
    await repository.reserve_quota(
        session,
        QuotaReservationCommand(
            tenant_id=TenantId(organization_id),
            api_key_id=api_key_id,
            request_id=request_id,
            requested_model="gpt-5.6-luna",
            source_endpoint="chat.completions",
            started_at=now,
            reconciliation_due_at=now + timedelta(minutes=2),
            estimated_input_tokens=tokens,
            maximum_output_tokens=0,
            policy=QuotaPolicySnapshot("budget-cadence", None, None, None),
        ),
    )
    await repository.finalize(
        session,
        FinalizationCommand(
            tenant_id=TenantId(organization_id),
            request_id=request_id,
            quota_action=TerminalAction.SETTLE,
            prompt_tokens=tokens,
        ),
    )
    return organization_id


async def _drop_budget_tenants(factory, organization_ids: list[UUID]) -> None:
    async with factory.begin() as cleanup:
        for model in (
            CostBudget,
            OutboxEvent,
            UsageLedger,
            RequestLifecycle,
            QuotaPeriodUsage,
            ApiKey,
            User,
        ):
            await cleanup.execute(
                delete(model).where(model.organization_id.in_(organization_ids))
            )
        await cleanup.execute(
            delete(Organization).where(Organization.id.in_(organization_ids))
        )


async def _fired(factory, budgets: list[CostBudget]) -> set[tuple[UUID, float]]:
    async with factory() as session:
        rows = await session.execute(
            select(
                CostBudgetAlertState.budget_id, CostBudgetAlertState.threshold
            ).where(
                CostBudgetAlertState.budget_id.in_([budget.id for budget in budgets])
            )
        )
        return {(budget_id, float(threshold)) for budget_id, threshold in rows}


@pytest.mark.asyncio
async def test_scheduled_evaluation_covers_enabled_budgets_of_every_tenant(
    async_engine, caplog
) -> None:
    caplog.set_level(logging.WARNING, logger="shim_enterprise.billing.spend")
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    async with factory.begin() as setup:
        tenants = [await _tenant_with_settled_tokens(setup, 50) for _ in range(2)]
        first, second, disabled, invalid = budgets = [
            CostBudget(
                organization_id=tenants[0],
                scope_type="org",
                limit_tokens=10,
                alert_thresholds=[0.5, 1.0],
            ),
            CostBudget(
                organization_id=tenants[1],
                scope_type="org",
                limit_tokens=10,
                alert_thresholds=[1.0],
            ),
            CostBudget(
                organization_id=tenants[1],
                scope_type="org",
                limit_tokens=10,
                enabled=False,
            ),
            CostBudget(
                organization_id=tenants[0],
                scope_type="org",
                limit_tokens=10,
                alert_thresholds=[50],
            ),
        ]
        setup.add_all(budgets)

    try:
        await evaluate_enabled_budgets(factory, now=datetime.now(timezone.utc))

        assert await _fired(factory, budgets) == {
            (first.id, 0.5),
            (first.id, 1.0),
            (second.id, 1.0),
        }
        assert f"budget_id={invalid.id}" in caplog.text
        assert str(disabled.id) not in caplog.text
    finally:
        await _drop_budget_tenants(factory, tenants)


@pytest.mark.asyncio
async def test_concurrent_scheduled_evaluations_enqueue_each_alert_once(
    async_engine,
) -> None:
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    async with factory.begin() as setup:
        tenant = await _tenant_with_settled_tokens(setup, 50)
        budget = CostBudget(
            organization_id=tenant,
            scope_type="org",
            limit_tokens=10,
            alert_thresholds=[0.5, 1.0],
            notify_targets=[
                {
                    "kind": "webhook",
                    "endpoint_origin": "https://alerts.example",
                    "secret_ref": "secret:budget-cadence",
                }
            ],
        )
        setup.add(budget)

    try:
        now = datetime.now(timezone.utc)
        await asyncio.gather(
            evaluate_enabled_budgets(factory, now=now),
            evaluate_enabled_budgets(factory, now=now),
        )

        async with factory() as session:
            alerts = (
                await session.scalars(
                    select(OutboxEvent.idempotency_key).where(
                        OutboxEvent.organization_id == tenant,
                        OutboxEvent.event_type == "budget.threshold_crossed",
                    )
                )
            ).all()
        assert sorted(alerts) == sorted(
            f"budget:{budget.id}:{now:%Y-%m}:{threshold}:target:0"
            for threshold in ("0.5", "1.0")
        )
        assert await _fired(factory, [budget]) == {(budget.id, 0.5), (budget.id, 1.0)}
    finally:
        await _drop_budget_tenants(factory, [tenant])


@pytest.mark.parametrize("scope_type", ["tag", "team"])
def test_budget_scope_uses_the_ingest_label_normalization(scope_type: str) -> None:
    def budget(value: str) -> management.BudgetInput:
        return management.BudgetInput(
            scope_type=scope_type,
            scope_value=value,
            limit_usd=1,
            notify_targets=[_TARGET],
        )

    assert budget(" Payments ").scope_value == "payments"
    for invalid in ("bad tag", "café", "x" * (settings.COST_TAG_MAX_LENGTH + 1), " "):
        with pytest.raises(ValidationError):
            budget(invalid)


@pytest.mark.parametrize(
    "values",
    [
        {"limit_usd": 0},
        {"limit_tokens": 0},
        {"limit_usd": "-1"},
        {"alert_thresholds": []},
        {"notify_targets": []},
    ],
)
def test_budget_settings_that_could_never_alert_are_rejected(values) -> None:
    with pytest.raises(ValidationError):
        management.BudgetInput.model_validate(
            {"scope_type": "org", "limit_usd": 1, "notify_targets": [_TARGET]} | values
        )
    with pytest.raises(ValidationError):
        management.BudgetPatch.model_validate(values)


@pytest.mark.asyncio
async def test_budget_routes_answer_422_for_a_budget_without_targets(
    db, test_user_with_org
) -> None:
    test_user_with_org.role = "admin"
    legacy = CostBudget(
        organization_id=test_user_with_org.organization_id,
        scope_type="org",
        limit_usd=0,
        alert_thresholds=[],
        notify_targets=[],
    )
    db.add(legacy)
    await db.flush()
    application = FastAPI()
    application.include_router(management_router, prefix="/api/v1")
    application.dependency_overrides[enterprise_deps.get_current_user] = lambda: (
        test_user_with_org
    )
    application.dependency_overrides[get_db] = lambda: db

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        created = await client.post(
            "/api/v1/management/cost/budgets",
            json={"scope_type": "org", "limit_usd": 1, "notify_targets": []},
        )
        patched = await client.patch(
            f"/api/v1/management/cost/budgets/{legacy.id}",
            json={"notify_targets": []},
        )
        disabled = await client.patch(
            f"/api/v1/management/cost/budgets/{legacy.id}", json={"enabled": False}
        )

    assert (created.status_code, patched.status_code) == (422, 422)
    assert disabled.status_code == 200
    assert disabled.json()["alert_thresholds_percent"] == []


@pytest.mark.asyncio
async def test_mixed_case_scopes_match_normalized_request_labels(db) -> None:
    organization_id = await _tenant_with_settled_tokens(db, 50)
    await db.execute(
        text(
            "UPDATE request_lifecycle SET metadata = "
            "metadata || CAST(:labels AS jsonb) WHERE organization_id = :org"
        ),
        {
            "labels": '{"tags": ["payments"], "team": "payments"}',
            "org": organization_id,
        },
    )
    evaluator = BudgetEvaluator()
    now = datetime.now(timezone.utc)

    fired = []
    for scope_type in ("tag", "team"):
        payload = management.BudgetInput(
            scope_type=scope_type,
            scope_value="Payments",
            limit_tokens=10,
            alert_thresholds=[1.0],
            notify_targets=[_TARGET],
        )
        budget = CostBudget(
            organization_id=organization_id,
            scope_type=scope_type,
            scope_value=payload.scope_value,
            limit_tokens=payload.limit_tokens,
            alert_thresholds=payload.alert_thresholds,
            notify_targets=[
                {
                    "kind": "webhook",
                    "endpoint_origin": "https://alerts.example",
                    "secret_ref": "fernet:v2:target",
                }
            ],
        )
        db.add(budget)
        await db.flush()
        fired.append((await evaluator.evaluate(db, budget, now=now))["fired"])

    assert fired == [[1.0], [1.0]]


@pytest.mark.asyncio
async def test_legacy_budget_without_limits_or_thresholds_still_evaluates(db) -> None:
    organization_id = await _tenant_with_settled_tokens(db, 50)
    legacy = CostBudget(
        organization_id=organization_id,
        scope_type="org",
        limit_usd=0,
        limit_tokens=0,
        alert_thresholds=[],
        notify_targets=[],
    )
    db.add(legacy)
    await db.flush()

    result = await BudgetEvaluator().evaluate(
        db, legacy, now=datetime.now(timezone.utc)
    )

    assert (result["fraction"], result["fired"], result["enqueued"]) == (0.0, [], 0)


def test_budget_view_shows_thresholds_as_percent_and_signed_targets() -> None:
    view = management.BudgetView.model_validate(
        SimpleNamespace(
            id=uuid4(),
            organization_id=uuid4(),
            scope_type="org",
            scope_value=None,
            period="monthly",
            limit_usd=Decimal("1"),
            limit_tokens=None,
            alert_thresholds=[0.07, 0.8, 1.5],
            notify_targets=[
                {
                    "kind": "webhook",
                    "endpoint_origin": "https://alerts.example",
                    "secret_ref": "fernet:v2:endpoint",
                    "signing_secret_ref": "fernet:v2:signing",
                },
                {
                    "kind": "slack",
                    "endpoint_origin": "https://hooks.slack.com",
                    "secret_ref": "fernet:v2:slack",
                },
            ],
            enabled=True,
            created_at=datetime.now(timezone.utc),
        )
    ).model_dump()

    assert view["alert_thresholds_percent"] == [7.0, 80.0, 150.0]
    assert [target["signed"] for target in view["notify_targets"]] == [True, False]
    assert "signing_secret_ref" not in str(view)


@pytest.mark.asyncio
async def test_budget_signing_secrets_live_in_the_secret_store(monkeypatch) -> None:
    store = SimpleNamespace(
        put_secret=AsyncMock(side_effect=lambda *args: f"ref:{args[1]}:{args[2]}"),
        delete_secret=AsyncMock(),
    )
    monkeypatch.setattr(management, "get_secret_store", lambda: store)
    tenant_id = uuid4()
    secret = "s" * 32

    stored = await management._store_budget_targets(
        tenant_id,
        [
            management.NotificationTargetInput(**_TARGET, secret=secret),
            management.NotificationTargetInput(
                kind="slack", endpoint="https://hooks.slack.com/services/x"
            ),
        ],
    )
    await management._delete_budget_targets(tenant_id, stored)

    assert stored[0]["signing_secret_ref"] == f"ref:budget-alert-signing:{secret}"
    assert "signing_secret_ref" not in stored[1]
    assert sorted(
        call.kwargs["expected_purpose"] for call in store.delete_secret.await_args_list
    ) == ["budget-alert-endpoint", "budget-alert-endpoint", "budget-alert-signing"]
    with pytest.raises(ValidationError, match="webhook"):
        management.NotificationTargetInput(
            kind="slack", endpoint="https://hooks.slack.com/services/x", secret=secret
        )
    with pytest.raises(ValidationError):
        management.NotificationTargetInput(**_TARGET, secret="short")


_RISK = UUID("00000000-0000-4000-8000-0000000000a1")
_OTHER_TEAM = UUID("00000000-0000-4000-8000-0000000000a2")


@pytest.mark.parametrize(
    ("labels", "fractions"),
    [
        pytest.param(
            {"team_id": str(_RISK), "team": "risk"}, (1.0, 1.0), id="labelled"
        ),
        pytest.param({"team_id": str(_RISK)}, (1.0, 0.0), id="unlabelled-in-team"),
        pytest.param(
            {"team_id": str(_OTHER_TEAM), "team": "risk"}, (0.0, 1.0), id="other-team"
        ),
        pytest.param({"team": "risk"}, (0.0, 1.0), id="before-team-ids"),
    ],
)
@pytest.mark.asyncio
async def test_team_id_budgets_match_the_key_team_and_label_budgets_the_label(
    db, labels: dict[str, str], fractions: tuple[float, float]
) -> None:
    organization_id = await _tenant_with_settled_tokens(db, 50)
    await db.execute(
        text(
            "UPDATE request_lifecycle SET metadata = "
            "(metadata - 'team_id' - 'team') || CAST(:labels AS jsonb) "
            "WHERE organization_id = :org"
        ),
        {"labels": json.dumps(labels), "org": organization_id},
    )
    evaluator = BudgetEvaluator()
    now = datetime.now(timezone.utc)

    measured = []
    for scope_type, scope_value in (("team_id", str(_RISK)), ("team", "risk")):
        budget = CostBudget(
            organization_id=organization_id,
            scope_type=scope_type,
            scope_value=scope_value,
            limit_tokens=50,
            alert_thresholds=[1.0],
            notify_targets=[
                {
                    "kind": "webhook",
                    "endpoint_origin": "https://alerts.example",
                    "secret_ref": "fernet:v2:target",
                }
            ],
        )
        db.add(budget)
        await db.flush()
        measured.append((await evaluator.evaluate(db, budget, now=now))["fraction"])

    assert tuple(measured) == fractions


@pytest.mark.asyncio
async def test_team_id_budgets_name_their_team_and_refuse_other_teams(
    db, test_user_with_org, monkeypatch: pytest.MonkeyPatch
) -> None:
    test_user_with_org.role = "admin"
    monkeypatch.setattr(management, "assert_safe_forward_url", AsyncMock())
    elsewhere = Organization(id=uuid4(), name="Elsewhere", slug=f"else-{uuid4()}")
    db.add(elsewhere)
    await db.flush()
    team = Team(organization_id=test_user_with_org.organization_id, name="risk")
    foreign = Team(organization_id=elsewhere.id, name="risk")
    db.add_all([team, foreign])
    await db.flush()
    application = FastAPI()
    application.include_router(management_router, prefix="/api/v1")
    application.dependency_overrides[enterprise_deps.get_current_user] = lambda: (
        test_user_with_org
    )
    application.dependency_overrides[get_db] = lambda: db

    def budget(scope_value: str) -> dict:
        return {
            "scope_type": "team_id",
            "scope_value": scope_value,
            "limit_usd": "1",
            "notify_targets": [_TARGET],
        }

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        refused = [
            await client.post("/api/v1/management/cost/budgets", json=budget(value))
            for value in (str(foreign.id), str(uuid4()))
        ]
        malformed = await client.post(
            "/api/v1/management/cost/budgets", json=budget("not-a-uuid")
        )
        created = await client.post(
            "/api/v1/management/cost/budgets", json=budget(str(team.id).upper())
        )
        team.name = "credit-risk"
        await db.flush()
        renamed = await client.get("/api/v1/management/cost/budgets")
        await db.execute(delete(Team).where(Team.id == team.id))
        deleted = await client.get("/api/v1/management/cost/budgets")

    assert [(r.status_code, r.json()["detail"]) for r in refused] == [
        (422, "Unknown team")
    ] * 2
    assert malformed.status_code == 422
    assert created.status_code == 200
    assert (created.json()["scope_value"], created.json()["scope_label"]) == (
        str(team.id),
        "risk",
    )
    assert [row["scope_label"] for row in renamed.json()] == ["credit-risk"]
    assert [row["scope_label"] for row in deleted.json()] == [None]
    row = await db.get(CostBudget, UUID(created.json()["id"]))
    result = await BudgetEvaluator().evaluate(db, row, now=datetime.now(timezone.utc))
    assert (result["fraction"], result["fired"]) == (0.0, [])
