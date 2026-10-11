from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, call
from uuid import uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from shim_enterprise.ai_act.audit_writer import write_audit_row
from shim_enterprise.ai_act.models import AIActAuditAnchor, AIActAuditLog
from shim_enterprise.api.v1 import management
from shim_enterprise.billing.models import CostBudget, RequestLifecycle
from shim_enterprise.compliance.models import (
    ComplianceActivity,
    ComplianceConnector,
    ComplianceFinding,
    ComplianceForwardTarget,
)
from shim_enterprise.core.database import Base
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.outbox.publisher import OutboxWriter
from shim_enterprise.tenants.audit import record_management_action
from shim_enterprise.tenants.models import (
    ApiKey,
    Organization,
    OrganizationPIIConfig,
    ProviderSecret,
    ServiceAccountCredential,
    User,
)
from shim_enterprise.tenants.plans import activate_organization_plan
from shim_enterprise.tenants.service import (
    _ARCHIVE_KEPT_TABLES,
    _REQUEST_HISTORY,
    authenticate_api_key,
    create_api_key,
    ensure_privacy_defaults,
    get_or_create_organization,
)
from shim_enterprise.workers.ai_act import AuditMaintenanceWorker

HISTORY_MESSAGE = "has request history and cannot be archived"


async def _destination(session) -> User:
    organization = Organization(
        id=uuid4(), name="Bank", slug=f"archive-bank-{uuid4().hex}"
    )
    owner = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"archive-owner-{uuid4().hex}@example.com",
        role="owner",
        is_active=True,
        is_verified=True,
    )
    session.add_all([organization, owner])
    await session.flush()
    await activate_organization_plan(session, organization.id, "agency")
    return owner


async def _personal(session) -> User:
    user_id = uuid4()
    email = f"archive-analyst-{user_id.hex}@example.com"
    organization = await get_or_create_organization(
        session, name=email, creator_user_id=user_id
    )
    await ensure_privacy_defaults(session, organization.id)
    user = User(
        id=user_id,
        organization_id=organization.id,
        email=email,
        role="owner",
        is_active=True,
        is_verified=True,
    )
    session.add(user)
    await session.flush()
    return user


async def _invite(session, owner: User, email: str) -> str:
    created = await management.create_team_invite(
        management.TeamInviteInput(email=email, role="member"), owner, session
    )
    return created.token


def _secret_store(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    store = SimpleNamespace(delete_secret=AsyncMock())
    monkeypatch.setattr(management, "get_secret_store", lambda: store)
    return store


async def _accept(session, token: str, user: User) -> User:
    return await management.accept_team_invite(
        management.AcceptTeamInvite(token=token), user, session
    )


async def _configure(session, user: User) -> str:
    tenant_id = user.organization_id
    plaintext, key = await create_api_key(session, user_id=user.id, name="laptop")
    session.add_all(
        [
            ProviderSecret(
                organization_id=tenant_id,
                provider="openai",
                secret_ref="ref-provider",
                secret_backend="local",
                secret_version="1",
                masked_key="sk-...0000",
            ),
            ComplianceForwardTarget(
                organization_id=tenant_id,
                kind="slack",
                endpoint_origin="https://hooks.example.com",
                secret_ref="ref-forward",
                secret_backend="local",
                secret_version="1",
            ),
        ]
    )
    await session.flush()
    await record_management_action(session, user, "tenant.api_key_revoked", str(key.id))
    await write_audit_row(
        {"organization_id": tenant_id, "request_id": f"management:{uuid4()}"}, session
    )
    return plaintext


async def _count(session, model, organization_id) -> int:
    rows = await session.scalars(
        select(model.organization_id).where(model.organization_id == organization_id)
    )
    return len(rows.all())


@pytest.mark.asyncio
async def test_unused_personal_workspace_is_archived_when_its_user_joins(
    db, monkeypatch: pytest.MonkeyPatch, audit_events
) -> None:
    store = _secret_store(monkeypatch)
    owner = await _destination(db)
    analyst = await _personal(db)
    workspace_id = analyst.organization_id
    plaintext = await _configure(db, analyst)
    token = await _invite(db, owner, analyst.email)

    accepted = await _accept(db, token, analyst)

    assert accepted.organization_id == owner.organization_id
    assert accepted.role == "member" and accepted.is_active
    workspace = await db.get(Organization, workspace_id)
    assert workspace is not None
    assert workspace.archived_at is not None
    assert workspace.archived_reason == "joined_organization"
    for model in (
        ApiKey,
        ProviderSecret,
        ComplianceForwardTarget,
        OrganizationPIIConfig,
    ):
        assert await _count(db, model, workspace_id) == 0
    assert await _count(db, User, workspace_id) == 0
    assert await _count(db, AIActAuditLog, workspace_id) == 1
    assert await authenticate_api_key(db, plaintext) is None
    events = await audit_events(workspace_id)
    assert [event["endpoint"] for event in events] == [
        "tenant.api_key_revoked",
        "tenant.personal_workspace_archived",
    ]
    assert events[1]["actor"] == str(analyst.id)
    assert events[1]["extra"] == {
        "subject_id": str(workspace_id),
        "actor_type": "user_jwt",
        "removed": {
            "api_keys": 1,
            "compliance_forward_target": 1,
            "organization_pii_configs": 1,
            "provider_secrets": 1,
        },
    }
    joined = await audit_events(owner.organization_id)
    assert joined[-1]["endpoint"] == "tenant.team_invite_accepted"
    assert store.delete_secret.await_args_list == [
        call(
            workspace_id,
            "ref-provider",
            expected_purpose="provider:openai:api-key",
        ),
        call(
            workspace_id,
            "ref-forward",
            expected_purpose="compliance-forward-target-delivery",
        ),
    ]


@pytest.mark.asyncio
async def test_archiving_deletes_the_workspace_service_accounts(
    db, monkeypatch: pytest.MonkeyPatch, audit_events
) -> None:
    _secret_store(monkeypatch)
    owner = await _destination(db)
    analyst = await _personal(db)
    workspace_id = analyst.organization_id
    service = await management.create_service_account(
        management.ServiceAccountInput(name="ci", role="admin", expires_in_days=30),
        analyst,
        db,
    )
    token = await _invite(db, owner, analyst.email)

    await _accept(db, token, analyst)

    assert await db.get(User, service.id) is None
    assert await _count(db, ServiceAccountCredential, workspace_id) == 0
    removed = (await audit_events(workspace_id))[-1]["extra"]["removed"]
    assert removed["service_accounts"] == 1
    assert removed["service_account_credentials"] == 1


@pytest.mark.asyncio
async def test_request_history_keeps_the_workspace_and_names_the_reason(
    db, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _secret_store(monkeypatch)
    owner = await _destination(db)
    analyst = await _personal(db)
    workspace_id = analyst.organization_id
    await _configure(db, analyst)
    key_id = await db.scalar(select(ApiKey.id).where(ApiKey.user_id == analyst.id))
    now = datetime.now(timezone.utc)
    db.add(
        RequestLifecycle(
            request_id=f"req_archive_{uuid4().hex}",
            organization_id=workspace_id,
            actor_type="api_key",
            api_key_id=key_id,
            source_endpoint="chat.completions",
            status="completed",
            started_at=now,
            completed_at=now,
        )
    )
    await db.flush()
    token = await _invite(db, owner, analyst.email)

    with pytest.raises(management.HTTPException) as refused:
        await _accept(db, token, analyst)

    assert refused.value.status_code == 409
    assert HISTORY_MESSAGE in str(refused.value.detail)
    workspace = await db.get(Organization, workspace_id)
    assert workspace is not None and workspace.archived_at is None
    assert (await db.get(User, analyst.id)).organization_id == workspace_id
    assert await _count(db, ApiKey, workspace_id) == 1
    store.delete_secret.assert_not_awaited()


@pytest.mark.parametrize("reason", ["second_user", "paid_tier", "billing_source"])
@pytest.mark.asyncio
async def test_a_workspace_that_is_not_personal_keeps_the_old_refusal(
    db, monkeypatch: pytest.MonkeyPatch, reason: str
) -> None:
    _secret_store(monkeypatch)
    owner = await _destination(db)
    analyst = await _personal(db)
    workspace_id = analyst.organization_id
    await create_api_key(db, user_id=analyst.id, name="laptop")
    if reason == "second_user":
        db.add(
            User(
                organization_id=workspace_id,
                email=f"archive-colleague-{uuid4().hex}@example.com",
                is_active=False,
            )
        )
        await db.flush()
    elif reason == "paid_tier":
        await activate_organization_plan(db, workspace_id, "managed")
    else:
        workspace = await db.get(Organization, workspace_id)
        workspace.billing_source = "polar"
        await db.flush()
    token = await _invite(db, owner, analyst.email)

    with pytest.raises(management.HTTPException, match="Leave or empty") as refused:
        await _accept(db, token, analyst)

    assert refused.value.status_code == 409
    assert (await db.get(Organization, workspace_id)).archived_at is None
    assert await _count(db, ApiKey, workspace_id) == 1


@pytest.mark.asyncio
async def test_secrets_survive_when_the_acceptance_rolls_back(
    db, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _secret_store(monkeypatch)
    owner = await _destination(db)
    analyst = await _personal(db)
    await _configure(db, analyst)
    token = await _invite(db, owner, analyst.email)
    monkeypatch.setattr(
        management, "_audit", AsyncMock(side_effect=RuntimeError("audit down"))
    )

    with pytest.raises(RuntimeError, match="audit down"):
        await _accept(db, token, analyst)

    store.delete_secret.assert_not_awaited()


@pytest.mark.asyncio
async def test_concurrent_invitations_move_the_user_once(
    async_engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    _secret_store(monkeypatch)
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    async with factory() as setup:
        first = await _destination(setup)
        second = await _destination(setup)
        analyst = await _personal(setup)
        await create_api_key(setup, user_id=analyst.id, name="laptop")
        tokens = [
            await _invite(setup, owner, analyst.email) for owner in (first, second)
        ]
        await setup.commit()
    organizations = [
        first.organization_id,
        second.organization_id,
        analyst.organization_id,
    ]

    async def accept(token: str) -> object:
        async with factory() as session:
            user = await session.get(User, analyst.id)
            try:
                return await _accept(session, token, user)
            except management.HTTPException as exc:
                return exc.status_code

    try:
        results = await asyncio.gather(*(accept(token) for token in tokens))
        winners = [result for result in results if isinstance(result, User)]
        assert len(winners) == 1
        assert [result for result in results if not isinstance(result, User)][0] in {
            400,
            409,
        }
        async with factory() as verification:
            user = await verification.get(User, analyst.id)
            assert user.organization_id == winners[0].organization_id
            workspace = await verification.get(Organization, analyst.organization_id)
            assert workspace.archived_at is not None
            assert await _count(verification, ApiKey, analyst.organization_id) == 0
    finally:
        async with factory.begin() as cleanup:
            await cleanup.execute(
                delete(OutboxEvent).where(
                    OutboxEvent.organization_id.in_(organizations)
                )
            )
            await cleanup.execute(
                delete(Organization).where(Organization.id.in_(organizations))
            )


@pytest.mark.asyncio
async def test_the_archive_day_is_anchored(db, monkeypatch: pytest.MonkeyPatch) -> None:
    _secret_store(monkeypatch)
    owner = await _destination(db)
    analyst = await _personal(db)
    workspace_id = analyst.organization_id
    await _configure(db, analyst)
    token = await _invite(db, owner, analyst.email)
    await _accept(db, token, analyst)
    # The delivered tenant.personal_workspace_archived append, written after archiving.
    await write_audit_row(
        {"organization_id": workspace_id, "request_id": f"management:{uuid4()}"}, db
    )

    await AuditMaintenanceWorker()._anchor_tenants(
        db, datetime.now(timezone.utc).date()
    )

    assert await _count(db, AIActAuditAnchor, workspace_id) == 1


async def _pending(
    session, tenant_id, event_type: str, aggregate_id: str
) -> OutboxEvent:
    return await OutboxWriter().append(
        session,
        organization_id=tenant_id,
        values={
            "event_type": event_type,
            "aggregate_type": "test",
            "aggregate_id": aggregate_id,
            "idempotency_key": f"{aggregate_id}:{event_type}",
            "payload": {"target_id": aggregate_id},
            "status": "pending",
            "next_attempt_at": datetime.now(timezone.utc),
        },
    )


@pytest.mark.asyncio
async def test_archiving_deletes_budget_secrets_and_cancels_their_deliveries(
    db, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _secret_store(monkeypatch)
    owner = await _destination(db)
    analyst = await _personal(db)
    workspace_id = analyst.organization_id
    budget = CostBudget(
        organization_id=workspace_id,
        scope_type="org",
        limit_tokens=10,
        notify_targets=[
            {
                "kind": "webhook",
                "endpoint_origin": "https://hooks.example.com",
                "secret_ref": "ref-budget",
                "signing_secret_ref": "ref-signing",
            }
        ],
    )
    db.add(budget)
    await db.flush()
    deliveries = [
        await _pending(db, workspace_id, "budget.threshold_crossed", str(budget.id)),
        await _pending(
            db, workspace_id, "compliance.connector_delivery_requested", "target"
        ),
    ]
    audit_append = await _pending(
        db, workspace_id, "audit.chain_append_requested", "append"
    )
    token = await _invite(db, owner, analyst.email)

    await _accept(db, token, analyst)

    for event in deliveries:
        await db.refresh(event)
        assert event.status == "processed"
    await db.refresh(audit_append)
    assert audit_append.status == "pending"
    assert store.delete_secret.await_args_list == [
        call(workspace_id, "ref-budget", expected_purpose="budget-alert-endpoint"),
        call(workspace_id, "ref-signing", expected_purpose="budget-alert-signing"),
    ]


async def _connector(session, tenant_id) -> ComplianceConnector:
    connector = ComplianceConnector(
        organization_id=tenant_id,
        provider="anthropic",
        secret_ref="ref-connector",
        secret_backend="local",
        secret_version="1",
        masked_key="sk-...0000",
    )
    session.add(connector)
    await session.flush()
    return connector


@pytest.mark.asyncio
async def test_a_connector_without_evidence_is_archived_and_counted(
    db, monkeypatch: pytest.MonkeyPatch, audit_events
) -> None:
    store = _secret_store(monkeypatch)
    owner = await _destination(db)
    analyst = await _personal(db)
    workspace_id = analyst.organization_id
    await _connector(db, workspace_id)
    token = await _invite(db, owner, analyst.email)

    await _accept(db, token, analyst)

    assert await _count(db, ComplianceConnector, workspace_id) == 0
    removed = (await audit_events(workspace_id))[-1]["extra"]["removed"]
    assert removed["compliance_connector"] == 1
    store.delete_secret.assert_awaited_once_with(
        workspace_id, "ref-connector", expected_purpose="compliance-connector-api-key"
    )


@pytest.mark.parametrize("evidence", ["finding", "activity"])
@pytest.mark.asyncio
async def test_compliance_evidence_keeps_the_workspace_like_request_history(
    db, monkeypatch: pytest.MonkeyPatch, evidence: str
) -> None:
    store = _secret_store(monkeypatch)
    owner = await _destination(db)
    analyst = await _personal(db)
    workspace_id = analyst.organization_id
    connector = await _connector(db, workspace_id)
    if evidence == "finding":
        db.add(
            ComplianceFinding(
                connector_id=connector.id,
                content_id="message-1",
                entity_type="EMAIL_ADDRESS",
                severity="medium",
                match_offset=0,
                match_length=5,
                value_hash="hash",
            )
        )
    else:
        db.add(
            ComplianceActivity(
                connector_id=connector.id,
                provider_event_id="event-1",
                event_type="message.created",
            )
        )
    await db.flush()
    token = await _invite(db, owner, analyst.email)

    with pytest.raises(management.HTTPException) as refused:
        await _accept(db, token, analyst)

    assert refused.value.status_code == 409
    assert HISTORY_MESSAGE in str(refused.value.detail)
    assert (await db.get(Organization, workspace_id)).archived_at is None
    assert await _count(db, ComplianceConnector, workspace_id) == 1
    store.delete_secret.assert_not_awaited()


# Foreign keys that archiving neither deletes through nor rules out by R1, and why.
_KEPT_ON_PURPOSE = {
    ("users", "organizations"): "the user moves; the workspace row stays",
    ("users", "organization_roles"): "the moving owner holds no custom role",
    ("ai_act_audit_log", "organizations"): "the audit chain stays with the kept row",
    ("ai_act_audit_anchor", "organizations"): "anchors stay with the kept row",
    ("outbox_event", "organizations"): "undelivered appends stay and are delivered",
    # Every gateway audit row pairs with an audit_intent row; management rows carry no key.
    ("ai_act_audit_log", "api_keys"): "audit_intent is request history",
    (
        "billing_webhook_receipts",
        "organizations",
    ): "a receipt makes the workspace not personal",
}


def test_every_foreign_key_into_an_archived_workspace_is_accounted_for() -> None:
    deleted = {
        table.name
        for table in Base.metadata.sorted_tables
        if "organization_id" in table.c and table.name not in _ARCHIVE_KEPT_TABLES
    }
    history = {model.__tablename__ for model in _REQUEST_HISTORY}
    unaccounted = []
    for table in Base.metadata.sorted_tables:
        for foreign_key in table.foreign_key_constraints:
            referred = foreign_key.referred_table.name
            if referred not in deleted | {"users", "organizations"}:
                continue
            if table.name in history:
                continue
            if table.name in deleted:
                continue
            if referred in deleted and foreign_key.ondelete in {"CASCADE", "SET NULL"}:
                continue
            if (table.name, referred) not in _KEPT_ON_PURPOSE:
                unaccounted.append(f"{table.name}.{foreign_key.name} -> {referred}")
    assert unaccounted == []
    assert history | {"service_account_credentials"} <= deleted
