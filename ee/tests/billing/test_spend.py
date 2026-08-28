from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql

from shim_enterprise.api.v1 import management
from shim.billing.attribution import CostAttribution, UNTAGGED, normalize_attribution
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.billing.read_models import BillingReadModels
from shim_enterprise.billing.spend import (
    BudgetConfigurationError,
    BudgetEvaluator,
    BudgetUsage,
    validate_budget_notification_config,
)
from shim.gateway.contracts.ids import TenantId


def test_header_tags_define_primary_and_complete_attribution() -> None:
    attribution = CostAttribution.resolve(
        " Research ,experiment,research,not valid! ",
        api_key_cost_center="fallback",
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
        with pytest.raises(ValidationError, match="alert thresholds"):
            management.BudgetPatch(alert_thresholds=thresholds)

    assert management.BudgetInput(
        scope_type="org", limit_tokens=1
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

    assert model.model_validate(values).model_dump(include=values.keys()) == values


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
    session = SimpleNamespace(delete=AsyncMock())
    monkeypatch.setattr(management, "_owned_budget", AsyncMock(return_value=row))

    with pytest.raises(HTTPException, match="require migration"):
        await management.update_budget(
            row.id,
            management.BudgetPatch(notify_targets=[]),
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
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id = uuid4()
    row = SimpleNamespace(
        id=uuid4(),
        limit_usd=Decimal("10"),
        limit_tokens=100,
        notify_targets=[],
        enabled=True,
    )
    user = SimpleNamespace(organization_id=tenant_id)
    session = SimpleNamespace(
        commit=AsyncMock(), rollback=AsyncMock(), refresh=AsyncMock()
    )
    audit = AsyncMock()
    monkeypatch.setattr(management, "_owned_budget", AsyncMock(return_value=row))
    monkeypatch.setattr(management, "_audit", audit)

    async def apply(**values):
        return await management.update_budget(
            row.id, management.BudgetPatch(**values), user, session
        )

    assert await apply(enabled=False) is row
    assert row.limit_usd == Decimal("10")
    assert row.limit_tokens == 100
    session.commit.assert_awaited_once()

    session.commit.reset_mock()
    audit.reset_mock()
    assert await apply(limit_usd=None) is row
    assert row.limit_usd is None
    assert row.limit_tokens == 100
    session.commit.assert_awaited_once()

    session.commit.reset_mock()
    audit.reset_mock()
    with pytest.raises(HTTPException) as exc_info:
        await apply(limit_tokens=None)

    assert exc_info.value.status_code == 422
    assert exc_info.value.detail == "a budget requires a cost or token limit"
    assert row.limit_tokens == 100
    session.commit.assert_not_awaited()
    audit.assert_not_awaited()


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
    assert "date(timezone(%(timezone_1)s, usage_ledger.created_at))" in sql
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
