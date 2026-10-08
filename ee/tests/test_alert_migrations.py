import importlib.util
from pathlib import Path
from uuid import uuid4

from alembic.migration import MigrationContext
from alembic.operations import Operations
import pytest
from sqlalchemy import insert, select, text
from sqlalchemy.exc import IntegrityError

from shim_enterprise.billing.models import CostBudget
from shim_enterprise.compliance.models import ComplianceForwardTarget
from shim_enterprise.tenants.models import User


_VERSIONS = Path(__file__).resolve().parents[1] / "alembic" / "versions"


async def _run(db, name: str, step: str) -> None:
    spec = importlib.util.spec_from_file_location(name, _VERSIONS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def run(connection) -> None:
        with Operations.context(MigrationContext.configure(connection)):
            getattr(module, step)()

    await (await db.connection()).run_sync(run)


@pytest.mark.asyncio
async def test_forward_targets_take_their_tenant_from_their_connector(
    db, test_org
) -> None:
    await _run(db, "de7150dd2f7a_tenant_level_forward_targets", "downgrade")
    connector_id, target_id = uuid4(), uuid4()
    await db.execute(
        text(
            "INSERT INTO compliance_connector (id, organization_id, provider, "
            "secret_ref, secret_backend, secret_version, masked_key) VALUES "
            "(:id, :org, 'openai', 'fernet:v2:c', 'fernet', 'v2', 'masked')"
        ),
        {"id": connector_id, "org": test_org.id},
    )
    await db.execute(
        text(
            "INSERT INTO compliance_forward_target (id, connector_id, endpoint_origin, "
            "secret_ref, secret_backend, secret_version) VALUES "
            "(:id, :connector, 'https://siem.example', 'fernet:v2:t', 'fernet', 'v2')"
        ),
        {"id": target_id, "connector": connector_id},
    )

    await _run(db, "de7150dd2f7a_tenant_level_forward_targets", "upgrade")

    assert (
        await db.execute(
            select(
                ComplianceForwardTarget.organization_id,
                ComplianceForwardTarget.connector_id,
            ).where(ComplianceForwardTarget.id == target_id)
        )
    ).one() == (test_org.id, connector_id)
    tenant_level = ComplianceForwardTarget(
        organization_id=test_org.id,
        endpoint_origin="https://siem.example",
        secret_ref="fernet:v2:tenant",
        secret_backend="fernet",
        secret_version="v2",
    )
    db.add(tenant_level)
    await db.flush()
    assert tenant_level.connector_id is None


@pytest.mark.asyncio
async def test_budget_scopes_are_lowercased_only_where_ingest_could_match(
    db, test_org
) -> None:
    scopes = [
        ("tag", "Payments", "payments"),
        ("tag", "payments", "payments"),
        ("team", " Risk.Ops ", "risk.ops"),
        ("tag", "Bad Tag!", "Bad Tag!"),
        ("team", "Ünit", "Ünit"),
        ("org", None, None),
    ]
    budgets = [
        CostBudget(
            organization_id=test_org.id,
            scope_type=scope_type,
            scope_value=value,
            limit_usd=1,
        )
        for scope_type, value, _ in scopes
    ]
    db.add_all(budgets)
    await db.flush()

    await _run(db, "ea4e658a2648_normalize_budget_scope_values", "upgrade")

    stored = dict(
        (
            await db.execute(
                select(CostBudget.id, CostBudget.scope_value).where(
                    CostBudget.organization_id == test_org.id
                )
            )
        ).all()
    )
    assert [stored[budget.id] for budget in budgets] == [
        expected for _, _, expected in scopes
    ]


@pytest.mark.asyncio
async def test_budget_scope_check_takes_team_ids_and_still_refuses_unknown_scopes(
    db, test_org
) -> None:
    async def insert_budget(scope_type: str) -> None:
        async with db.begin_nested():
            await db.execute(
                insert(CostBudget).values(
                    organization_id=test_org.id,
                    scope_type=scope_type,
                    scope_value=str(uuid4()),
                    limit_usd=1,
                )
            )

    await _run(db, "1ad1ca2101a5_add_team_id_budget_scope", "downgrade")
    with pytest.raises(IntegrityError, match="ck_cost_budget_scope_type"):
        await insert_budget("team_id")

    await _run(db, "1ad1ca2101a5_add_team_id_budget_scope", "upgrade")
    await insert_budget("team_id")
    with pytest.raises(IntegrityError, match="ck_cost_budget_scope_type"):
        await insert_budget("cost_center")


@pytest.mark.asyncio
async def test_service_account_downgrade_survives_their_request_history(
    db, test_org, test_user_with_org
) -> None:
    from datetime import datetime, timezone

    from shim_enterprise.api.v1 import management
    from shim_enterprise.billing.models import RequestLifecycle

    test_user_with_org.role = "owner"
    created = await management.create_service_account(
        management.ServiceAccountInput(name="ci", role="admin", expires_in_days=30),
        test_user_with_org,
        db,
    )
    account = await db.get(User, created.id)
    key = await management.create_api_key(
        management.ApiKeyInput(name="pipeline"), account, db
    )
    now = datetime.now(timezone.utc)
    db.add(
        RequestLifecycle(
            request_id=f"req_downgrade_{uuid4().hex}",
            organization_id=test_org.id,
            actor_type="api_key",
            api_key_id=key.id,
            source_endpoint="chat.completions",
            status="completed",
            started_at=now,
            completed_at=now,
        )
    )
    await db.flush()

    await _run(db, "d94f7f0ba8a2_add_service_accounts", "downgrade")

    assert (
        await db.scalar(
            text("SELECT is_active FROM users WHERE id = :id"), {"id": created.id}
        )
        is False
    )
