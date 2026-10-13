from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import shim_enterprise.core.database as database

from shim_enterprise.ai_act.models import AIActAuditLog
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.compliance.models import ComplianceForwardTarget
from shim_enterprise.core.config import settings
from shim_enterprise.findings import service
from shim_enterprise.findings.models import Finding
from shim_enterprise.outbox.handlers import (
    COMPLIANCE_DELIVERY,
    REMEDIATION_CHANGED,
    _compliance_text,
    announce_remediation,
    build_publisher,
)
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.outbox.publisher import OutboxMessage
from shim_enterprise.policy import allowlist, remediation
from shim_enterprise.policy.models import PolicyRemediation, PolicyVersion
from shim_enterprise.tenants.gateway_settings import GatewaySettings, classify_change
from shim_enterprise.tenants.models import (
    ModelDeployment,
    Organization,
    OrganizationGatewaySettings,
    ProviderSecret,
)


@pytest.fixture(autouse=True)
def _approved_origin(monkeypatch) -> None:
    # A plan validates the whole deployment, origin included.
    monkeypatch.setattr(
        settings, "MODEL_DEPLOYMENT_ALLOWED_ORIGINS", ["https://a.internal"]
    )


def _sessions(connection):
    """The worker's session factory, each session a savepoint of the test's transaction."""
    return lambda: AsyncSession(
        bind=connection,
        join_transaction_mode="create_savepoint",
        expire_on_commit=False,
    )


async def _tenant(db, modes: dict | None = None, **gateway) -> UUID:
    organization = Organization(
        id=uuid4(), name="Fixes", slug=f"fixes-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    db.add(
        OrganizationGatewaySettings(
            organization_id=organization.id,
            settings={
                "finding_modes": modes or {service.UNUSED_DEPLOYMENT: "auto"},
                **gateway,
            },
        )
    )
    await db.flush()
    return organization.id


async def _deployment(db, tenant: UUID, *, days: int = 40) -> ModelDeployment:
    secret = ProviderSecret(
        id=uuid4(),
        organization_id=tenant,
        provider="openai",
        secret_ref=f"reference-{uuid4().hex}",
        secret_backend="fernet",
        secret_version="v2",
        masked_key="masked",
    )
    db.add(secret)
    await db.flush()
    deployment = ModelDeployment(
        organization_id=tenant,
        alias=f"quiet-{uuid4().hex[:8]}",
        provider="openai",
        upstream_model="custom-model",
        base_url="https://a.internal/v1",
        provider_secret_id=secret.id,
        timeout_seconds=5,
        deployment_kind="internal",
        declared_version="v1",
        owner="Platform",
        enabled=True,
        created_at=datetime.now(timezone.utc) - timedelta(days=days),
    )
    db.add(deployment)
    await db.flush()
    return deployment


async def _pass(db, tenant: UUID, *, now: datetime | None = None) -> None:
    """One worker interval: the findings pass, then the remediation pass."""
    now = now or datetime.now(timezone.utc)
    await service.evaluate_organization(db, tenant, now=now)
    await db.flush()
    await remediation.run_remediations(_sessions(await db.connection()), now=now)


async def _rows(db, tenant: UUID) -> list[PolicyRemediation]:
    return list(
        await db.scalars(
            select(PolicyRemediation)
            .where(PolicyRemediation.organization_id == tenant)
            .order_by(PolicyRemediation.created_at, PolicyRemediation.id)
            .execution_options(populate_existing=True)
        )
    )


async def _versions(db, tenant: UUID) -> list[PolicyVersion]:
    return list(
        await db.scalars(
            select(PolicyVersion)
            .where(PolicyVersion.organization_id == tenant)
            .order_by(PolicyVersion.version)
        )
    )


async def _refused(db, tenant: UUID, at: datetime, count: int, **values) -> None:
    """Rejected requests as the audit chain records them, with a deny verdict."""
    start = int(
        await db.scalar(
            select(func.coalesce(func.max(AIActAuditLog.seq), 0)).where(
                AIActAuditLog.organization_id == tenant
            )
        )
    )
    for index in range(count):
        db.add(
            AIActAuditLog(
                organization_id=tenant,
                seq=start + index + 1,
                event_type="ai_request",
                policy_verdicts=[
                    {"rule_id": "deployment.registry", "outcome": "deny"},
                    {"rule_id": "api_key.access", "outcome": "allow"},
                ],
                prev_hash="0" * 64,
                row_hash=uuid4().hex * 2,
                created_at=at,
                **values,
            )
        )
    await db.flush()


async def _watched(db, tenant: UUID, *, hours_ago: int = 24) -> PolicyRemediation:
    """A deployment fixed `hours_ago`, its window just closed."""
    await _deployment(db, tenant)
    await _pass(db, tenant)
    [row] = await _rows(db, tenant)
    row.window_start = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    row.window_end = row.window_start + timedelta(hours=24)
    await db.flush()
    return row


async def _deployment_enabled(db, row: PolicyRemediation) -> bool:
    return bool(
        await db.scalar(
            select(ModelDeployment.enabled)
            .where(ModelDeployment.id == UUID(row.items[0]["item"]))
            .execution_options(populate_existing=True)
        )
    )


async def _finding(db, finding_id: UUID | None) -> Finding:
    finding = await db.scalar(
        select(Finding)
        .where(Finding.id == finding_id)
        .execution_options(populate_existing=True)
    )
    assert finding is not None
    return finding


@pytest.mark.parametrize("mode", ["observe", "suggest"])
@pytest.mark.asyncio
async def test_rules_below_auto_are_left_alone(db, mode) -> None:
    tenant = await _tenant(db, {service.UNUSED_DEPLOYMENT: mode})
    await _deployment(db, tenant)

    await _pass(db, tenant)

    assert await _rows(db, tenant) == []
    assert await _versions(db, tenant) == []


@pytest.mark.asyncio
async def test_an_auto_finding_is_fixed_once_and_watched(db) -> None:
    tenant = await _tenant(db)
    deployment = await _deployment(db, tenant)

    await _pass(db, tenant)
    await _pass(db, tenant)

    [row] = await _rows(db, tenant)
    [version] = await _versions(db, tenant)
    finding = await _finding(db, row.finding_id)
    await db.refresh(deployment)
    assert deployment.enabled is False
    assert (version.source, version.actor_type, version.created_by) == (
        "auto",
        "system",
        None,
    )
    assert (row.status, row.actor_type, row.actor_id, row.applied_version) == (
        "watching",
        "system",
        None,
        version.version,
    )
    assert row.window_end - row.window_start == timedelta(hours=24)
    assert [(item["entry"], item["item"]) for item in row.items] == [
        ("deployment.disable", str(deployment.id))
    ]
    assert row.items[0]["proof"] == {
        "metric": "refusals",
        "verdict_ids": ["deployment.registry"],
        "scope": "tenant",
        "window_hours": 24,
    }
    assert finding.status_id == service.STATUS_IDS["in_progress"]
    assert finding.evidence["policy_versions"] == [version.version]
    assert {"kind": "policy_version", "id": str(version.version)} in [
        item.model_dump(include={"kind", "id"})
        for item in service.finding_from_row(finding).evidence
    ]
    intents = await db.scalars(
        select(OutboxEvent.payload).where(
            OutboxEvent.organization_id == tenant,
            OutboxEvent.event_type == "remediation.changed",
        )
    )
    assert [(p["phase"], p["entries"]) for p in intents] == [
        ("applied", ["deployment.disable"])
    ]


@pytest.mark.asyncio
async def test_one_pass_fixes_at_most_five_findings(db) -> None:
    tenant = await _tenant(db)
    for _ in range(6):
        await _deployment(db, tenant)

    await _pass(db, tenant)

    assert len(await _rows(db, tenant)) == 5


@pytest.mark.asyncio
async def test_the_twenty_first_change_in_a_day_waits_for_the_next_pass(db) -> None:
    tenant = await _tenant(db)
    earlier = [
        PolicyRemediation(
            organization_id=tenant, actor_type="system", items=[], status="kept"
        )
        for _ in range(20)
    ]
    # An agent's applies have a limit of their own.
    agents = [
        PolicyRemediation(
            organization_id=tenant, actor_type="service", items=[], status="kept"
        )
        for _ in range(20)
    ]
    db.add_all([*earlier, *agents])
    await _deployment(db, tenant)

    await _pass(db, tenant)
    limited = [row.status for row in await _rows(db, tenant)]
    for row in earlier:
        row.created_at = datetime.now(timezone.utc) - timedelta(days=2)
    await db.flush()
    await _pass(db, tenant)

    assert "skipped" not in limited
    assert [row.status for row in await _rows(db, tenant)].count("watching") == 1
    assert len(await _versions(db, tenant)) == 1


@pytest.mark.asyncio
async def test_paused_applies_nothing(db) -> None:
    tenant = await _tenant(db, auto_remediation_paused=True)
    await _deployment(db, tenant)

    await _pass(db, tenant)

    assert await _rows(db, tenant) == []
    assert await _versions(db, tenant) == []


@pytest.mark.asyncio
async def test_a_deployment_used_since_the_finding_is_skipped_and_never_retried(
    db,
) -> None:
    tenant = await _tenant(db)
    deployment = await _deployment(db, tenant)
    await service.evaluate_organization(db, tenant, now=datetime.now(timezone.utc))
    db.add(
        RequestLifecycle(
            request_id=f"req_fix_{uuid4().hex}",
            organization_id=tenant,
            actor_type="internal",
            source_endpoint="chat.completions",
            status="completed",
            provider="openai",
            provider_model=deployment.alias,
            requested_model=deployment.alias,
            stream=False,
            started_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
    )
    await db.flush()

    await remediation.run_remediations(
        _sessions(await db.connection()), now=datetime.now(timezone.utc)
    )
    await remediation.run_remediations(
        _sessions(await db.connection()), now=datetime.now(timezone.utc)
    )

    [row] = await _rows(db, tenant)
    assert (row.status, row.result["reasons"], row.plan_id) == (
        "skipped",
        ["impact_too_large"],
        None,
    )
    assert await _versions(db, tenant) == []
    await db.refresh(deployment)
    assert deployment.enabled is True


@pytest.mark.asyncio
async def test_an_apply_error_is_skipped_with_its_code(db) -> None:
    tenant = await _tenant(db)
    deployment = await _deployment(db, tenant)
    await service.evaluate_organization(db, tenant, now=datetime.now(timezone.utc))
    await db.delete(deployment)
    await db.flush()

    await remediation.run_remediations(
        _sessions(await db.connection()), now=datetime.now(timezone.utc)
    )

    [row] = await _rows(db, tenant)
    assert (row.status, row.result["reasons"]) == ("skipped", ["http_422"])


@pytest.mark.asyncio
async def test_audit_mode_off_leaves_nothing_to_measure_so_the_fix_waits(
    db, monkeypatch
) -> None:
    tenant = await _tenant(db)
    await _deployment(db, tenant)
    monkeypatch.setattr(settings, "AI_ACT_AUDIT_ENABLED", False)

    await _pass(db, tenant)

    # Nothing to measure yet: no row, so the fix runs once audit is on.
    assert await _rows(db, tenant) == []
    assert await _versions(db, tenant) == []
    monkeypatch.setattr(settings, "AI_ACT_AUDIT_ENABLED", True)
    await _pass(db, tenant)
    assert [row.status for row in await _rows(db, tenant)] == ["watching"]


@pytest.mark.asyncio
async def test_a_window_closes_only_after_its_grace(db) -> None:
    tenant = await _tenant(db)
    row = await _watched(db, tenant)
    window_end = row.window_end
    assert window_end is not None

    await remediation.run_remediations(
        _sessions(await db.connection()), now=window_end + timedelta(minutes=14)
    )
    early = [row.status for row in await _rows(db, tenant)]
    await remediation.run_remediations(
        _sessions(await db.connection()), now=window_end + timedelta(minutes=15)
    )
    due = [row.status for row in await _rows(db, tenant)]

    assert (early, due) == (["watching"], ["kept"])


@pytest.mark.asyncio
async def test_no_rise_in_refusals_keeps_the_fix_and_resolves_the_finding(db) -> None:
    tenant = await _tenant(db)
    row = await _watched(db, tenant, hours_ago=30)
    assert row.window_start is not None
    await _refused(db, tenant, row.window_start - timedelta(hours=1), 2)
    await _refused(db, tenant, row.window_start + timedelta(hours=1), 2)

    await remediation.run_remediations(
        _sessions(await db.connection()), now=datetime.now(timezone.utc)
    )

    [kept] = await _rows(db, tenant)
    finding = await _finding(db, kept.finding_id)
    assert (kept.status, kept.result["items"]) == (
        "kept",
        {"0": {"baseline": 2, "measured": 2}},
    )
    assert kept.closed_at is not None
    assert (finding.status_id, finding.resolved_by) == (
        service.STATUS_RESOLVED,
        "system",
    )
    assert await _deployment_enabled(db, kept) is False


@pytest.mark.asyncio
async def test_a_rise_in_refusals_sets_the_item_back_even_under_four_eyes(db) -> None:
    tenant = await _tenant(db)
    row = await _watched(db, tenant, hours_ago=30)
    assert row.window_start is not None
    gateway = await db.get(OrganizationGatewaySettings, tenant)
    assert gateway is not None
    gateway.settings = {**gateway.settings, "four_eyes": "relaxing"}
    await _refused(db, tenant, row.window_start + timedelta(hours=2), 3)
    # Another tenant's refusals are never counted.
    other = await _tenant(db)
    await _refused(db, other, row.window_start - timedelta(hours=2), 9)
    await db.flush()

    await remediation.run_remediations(
        _sessions(await db.connection()), now=datetime.now(timezone.utc)
    )

    [restored] = await _rows(db, tenant)
    versions = await _versions(db, tenant)
    finding = await _finding(db, restored.finding_id)
    assert (restored.status, restored.result["items"]) == (
        "restored",
        {"0": {"baseline": 0, "measured": 3}},
    )
    assert [(v.source, v.actor_type) for v in versions] == [
        ("auto", "system"),
        ("auto", "system"),
    ]
    assert restored.restored_version == versions[-1].version
    assert await _deployment_enabled(db, restored) is True
    assert finding.status_id == service.STATUS_IDS["new"]
    assert finding.evidence["policy_versions"] == [versions[0].version]
    # One remediation per finding: after an undo shim only suggests.
    await _pass(db, tenant)
    assert len(await _rows(db, tenant)) == 1
    assert (await _finding(db, restored.finding_id)).remediation["mode"] == "suggest"


@pytest.mark.asyncio
async def test_a_restore_after_someone_changed_the_item_writes_nothing(db) -> None:
    tenant = await _tenant(db)
    row = await _watched(db, tenant, hours_ago=30)
    assert row.window_start is not None
    await _refused(db, tenant, row.window_start + timedelta(hours=2), 1)
    deployment = await db.get(ModelDeployment, UUID(row.items[0]["item"]))
    assert deployment is not None
    deployment.owner = "Someone else"
    await db.flush()

    await remediation.run_remediations(
        _sessions(await db.connection()), now=datetime.now(timezone.utc)
    )

    [skipped] = await _rows(db, tenant)
    assert (skipped.status, skipped.result["reason"]) == (
        "restore_skipped",
        "item_changed",
    )
    assert len(await _versions(db, tenant)) == 1
    assert await _deployment_enabled(db, skipped) is False


@pytest.mark.asyncio
async def test_a_measurement_that_runs_out_of_time_keeps_watching(
    db, monkeypatch
) -> None:
    tenant = await _tenant(db)
    await _watched(db, tenant, hours_ago=30)

    async def short(session) -> None:
        await session.execute(text("SET LOCAL statement_timeout = '50ms'"))

    def slow(organization_id, item, start, end):
        return select(func.count()).select_from(func.pg_sleep(1).table_valued())

    monkeypatch.setattr(remediation, "bound_statements", short)
    monkeypatch.setattr(remediation, "_refusals", slow)

    await remediation.run_remediations(
        _sessions(await db.connection()), now=datetime.now(timezone.utc)
    )

    [row] = await _rows(db, tenant)
    assert (row.status, row.closed_at) == ("watching", None)


def test_the_pause_switch_tightens_one_way_and_relaxes_the_other() -> None:
    paused, running = (
        GatewaySettings(auto_remediation_paused=True),
        GatewaySettings(),
    )

    assert classify_change(running, paused) == ("tightening", [])
    assert classify_change(paused, running) == ("relaxing", ["auto_remediation_paused"])


@pytest.mark.parametrize("targets", [0, 2])
@pytest.mark.asyncio
async def test_each_phase_reaches_every_forward_target_without_values(
    db, monkeypatch, targets: int
) -> None:
    tenant = await _tenant(db)
    db.add_all(
        ComplianceForwardTarget(
            organization_id=tenant,
            kind="slack",
            endpoint_origin="https://hooks.slack.com",
            secret_ref=f"fernet:v2:{uuid4().hex}",
            secret_backend="fernet",
            secret_version="v2",
            enabled=True,
        )
        for _ in range(targets)
    )
    row = await _watched(db, tenant)
    monkeypatch.setattr(
        database,
        "AsyncSessionLocal",
        async_sessionmaker(
            await db.connection(),
            class_=AsyncSession,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        ),
    )
    [intent] = await db.scalars(
        select(OutboxEvent).where(
            OutboxEvent.organization_id == tenant,
            OutboxEvent.event_type == REMEDIATION_CHANGED,
        )
    )

    await build_publisher().publish(OutboxMessage.from_event(intent))
    await announce_remediation(OutboxMessage.from_event(intent))

    deliveries = list(
        await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == tenant,
                OutboxEvent.event_type == COMPLIANCE_DELIVERY,
            )
        )
    )
    body = {
        "source": "shim",
        "event_type": "tenant_policy",
        "kind": "remediation_changed",
        "remediation_id": str(row.id),
        "phase": "applied",
        "entries": ["deployment.disable"],
        "resources": ["deployments"],
        "policy_version": row.applied_version,
        "actor_type": "system",
        "review": f"/api/v1/management/remediations/{row.id}",
    }
    assert intent.idempotency_key == f"remediation:{row.id}:applied"
    assert set(intent.payload) == {
        "organization_id",
        "remediation_id",
        "phase",
        "entries",
        "resources",
        "policy_version",
        "actor_type",
    }
    assert len(deliveries) == targets
    assert all(delivery.payload["body"] == body for delivery in deliveries)
    assert _compliance_text(body) == (
        f"shim automatic change {row.id} (deployment.disable): applied, policy "
        f"version {row.applied_version}: /api/v1/management/remediations/{row.id}"
    )


@pytest.mark.asyncio
async def test_an_undo_the_item_refuses_closes_its_row_and_the_pass_commits(
    db, monkeypatch
) -> None:
    tenant = await _tenant(db)
    row = await _watched(db, tenant, hours_ago=30)
    assert row.window_start is not None
    await _refused(db, tenant, row.window_start + timedelta(hours=2), 3)
    # The deployment's origin is no longer approved: re-enabling it is a 422.
    monkeypatch.setattr(settings, "MODEL_DEPLOYMENT_ALLOWED_ORIGINS", [])

    await remediation.run_remediations(
        _sessions(await db.connection()), now=datetime.now(timezone.utc)
    )

    [skipped] = await _rows(db, tenant)
    assert (skipped.status, skipped.result["reason"]) == (
        "restore_skipped",
        "http_422",
    )
    assert skipped.result["items"] == {"0": {"baseline": 0, "measured": 3}}
    assert len(await _versions(db, tenant)) == 1


@pytest.mark.asyncio
async def test_a_pass_measures_and_plans_before_the_tenant_lock(
    db, monkeypatch, tenant_lock
) -> None:
    tenant = await _tenant(db)
    row = await _watched(db, tenant, hours_ago=30)
    assert row.window_start is not None
    await _refused(db, tenant, row.window_start + timedelta(hours=2), 3)
    await _deployment(db, tenant)
    await service.evaluate_organization(db, tenant, now=datetime.now(timezone.utc))
    locked: dict[str, list[bool]] = {}
    for module, name in (
        (remediation, "_measure"),
        (remediation, "_restore_changes"),
        (remediation, "finding_changes"),
        (allowlist, "check_plan"),
    ):

        async def step(*args, _name=name, _step=getattr(module, name), **kwargs):
            locked.setdefault(_name, []).append(tenant_lock())
            return await _step(*args, **kwargs)

        monkeypatch.setattr(module, name, step)

    await remediation.run_remediations(
        _sessions(await db.connection()), now=datetime.now(timezone.utc)
    )

    assert sorted(row.status for row in await _rows(db, tenant)) == [
        "restored",
        "watching",
    ]
    # A request's reservation waits on the tenant lock; none of these hold it.
    assert locked == {
        "_measure": [False],
        "_restore_changes": [False],
        "finding_changes": [False],
        "check_plan": [False],
    }
