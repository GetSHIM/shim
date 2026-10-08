import asyncio
import base64
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
from pathlib import Path
import re
import runpy
import zlib
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import shim_enterprise.api.enterprise_deps as enterprise_deps
import shim_enterprise.core.database as database
from shim_enterprise.ai_act.api import router as compliance_router
from shim_enterprise.ai_act.audit_writer import write_audit_row
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.compliance.models import (
    ComplianceForwardTarget,
    MonthlyEvidenceFile,
)
from shim_enterprise.compliance.services import monthly_evidence as evidence
from shim_enterprise.core.database import get_db
from shim_enterprise.findings.models import Finding
from shim_enterprise.outbox.handlers import (
    COMPLIANCE_DELIVERY,
    EVIDENCE_MONTHLY_READY,
    _compliance_text,
    announce_monthly_evidence,
    build_publisher,
)
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.outbox.publisher import OutboxMessage
from shim_enterprise.tenants.models import ApiKey, Organization, User
from shim_enterprise.workers.ai_act import AuditMaintenanceWorker

SCRIPT = runpy.run_path(
    str(Path(__file__).parents[2] / "scripts" / "generate_monthly_evidence.py")
)


def _pdf_text(pdf: bytes) -> str:
    strings = []
    for match in re.finditer(
        rb"/Filter \[ (/ASCII85Decode )?/FlateDecode \][^>]*>>\s*stream\r?\n(.*?)endstream",
        pdf,
        re.S,
    ):
        data = match.group(2).strip()
        if match.group(1):
            data = base64.a85decode(data.removesuffix(b"~>"))
        strings += [
            item.decode("latin-1")
            for item in re.findall(rb"\(((?:[^()\\]|\\.)*)\) Tj", zlib.decompress(data))
        ]
    return re.sub(r"\\([()\\])", r"\1", " ".join(strings))


def _savepoints(connection) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        connection,
        class_=AsyncSession,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )


def _lifecycle(
    db,
    key: ApiKey,
    started_at: datetime,
    metadata: dict,
    *,
    cost: str | None = None,
    unpriced: bool = False,
) -> None:
    request_id = f"req_evidence_{uuid4().hex}"
    db.add(
        RequestLifecycle(
            request_id=request_id,
            organization_id=key.organization_id,
            actor_type="api_key",
            api_key_id=key.id,
            source_endpoint="chat.completions",
            status="completed",
            provider="openai",
            provider_model="gpt-5-mini",
            requested_model="gpt-5-mini",
            stream=False,
            started_at=started_at,
            reconciled_at=started_at,
            lifecycle_metadata=metadata,
        )
    )
    if cost is None:
        return
    common = {
        "request_id": request_id,
        "organization_id": key.organization_id,
        "api_key_id": key.id,
        "requested_model": "gpt-5-mini",
        "created_at": started_at,
    }
    quota, spend = uuid4(), uuid4()
    db.add_all(
        [
            UsageLedger(
                id=quota,
                event_type="quota_reservation",
                idempotency_key=f"{request_id}:quota:reservation",
                **common,
            ),
            UsageLedger(
                event_type="quota_settlement",
                idempotency_key=f"{request_id}:quota:settlement",
                reservation_event_id=quota,
                request_count=1,
                **common,
            ),
            UsageLedger(
                id=spend,
                event_type="spend_reservation",
                idempotency_key=f"{request_id}:spend:reservation",
                provider="openai",
                provider_model="gpt-5-mini",
                cost_usd=Decimal(cost),
                **common,
            ),
            UsageLedger(
                event_type="spend_settlement",
                idempotency_key=f"{request_id}:spend:settlement",
                reservation_event_id=spend,
                provider="openai",
                provider_model="gpt-5-mini",
                cost_usd=Decimal(cost),
                event_metadata=(
                    {"pricing": {"pricing_resolution": "unknown"}} if unpriced else {}
                ),
                **common,
            ),
        ]
    )


def test_windows_are_closed_partial_or_refused() -> None:
    now = datetime(2026, 1, 5, 9, tzinfo=timezone.utc)

    closed = evidence.monthly_window("2025-12", now=now)
    partial = evidence.monthly_window("2026-01", now=now)

    assert (closed.kind, closed.start, closed.end) == (
        "monthly",
        datetime(2025, 12, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 1, tzinfo=timezone.utc) - timedelta(microseconds=1),
    )
    assert (partial.kind, partial.end) == ("monthly_partial", now)
    assert evidence.previous_period(now) == "2025-12"
    for period in ("2026-02", "2026-13", "26-01", ""):
        with pytest.raises(ValueError):
            evidence.monthly_window(period, now=now)


@pytest.mark.asyncio
async def test_sections_show_what_was_recorded_and_say_what_was_not(
    db, test_api_key
) -> None:
    now = datetime.now(timezone.utc)
    window = evidence.monthly_window(f"{now:%Y-%m}", now=now)
    middle = window.start + (now - window.start) / 2
    tenant_id = test_api_key.organization_id
    _lifecycle(
        db, test_api_key, middle, {"pii_entities": {"TR_NATIONAL_ID": 2}}, cost="0.5"
    )
    await db.flush()

    before = await evidence.collect_monthly_evidence(db, tenant_id, window, now=now)
    old_text = _pdf_text(evidence.render_monthly_pdf(before))

    assert before.entities == {
        "pii_entities": {("openai", "TR_NATIONAL_ID"): 2},
        "monitored_entities": None,
        "blocked_entities": None,
    }
    assert (before.bulk_disclosures, before.response_entities) == (None, None)
    assert old_text.count(evidence.NOT_RECORDED) == 4
    assert "not an audit" in old_text
    for title in (
        "1. Traffic",
        "2. What left",
        "3. What was stopped",
        "4. Who changed what",
        "5. Audit chain",
        "6. Findings",
    ):
        assert title in old_text
    assert old_text.count("Source:") == 6

    _lifecycle(
        db,
        test_api_key,
        middle,
        {
            "pii_entities": {},
            "monitored_entities": {"EMAIL_ADDRESS": 3},
            "blocked_entities": {},
            "bulk_disclosure": {"distinct_values": 60, "threshold": 50},
            "response_entities": {"EMAIL_ADDRESS": 1},
        },
    )
    _lifecycle(db, test_api_key, middle, {"bulk_disclosure": None}, cost="0.25")
    _lifecycle(
        db,
        test_api_key,
        window.start - timedelta(days=1),
        {"pii_entities": {"IBAN_CODE": 9}},
    )
    _lifecycle(db, test_api_key, middle, {}, cost="0", unpriced=True)
    deny = {
        "schema_version": 1,
        "rule_id": "privacy.input",
        "rule_version": 1,
        "policy_version": "v",
        "stage": "privacy",
        "outcome": "deny",
        "reason_code": "PII_BLOCKED",
        "effective_at": now.isoformat(),
    }
    await write_audit_row(
        {
            "organization_id": tenant_id,
            "request_id": "req-evidence-deny",
            "policy_verdicts": [deny, {**deny, "outcome": "allow"}],
        },
        db,
    )
    for extra in ({"actor_type": "service"}, {}):
        await write_audit_row(
            {
                "organization_id": tenant_id,
                "event_type": "management_action",
                "request_id": f"mgmt-{uuid4().hex}",
                "endpoint": "tenant.budget_created",
                "extra": extra,
            },
            db,
        )
    db.add_all(
        [
            Finding(
                organization_id=tenant_id,
                rule_id=rule_id,
                rule_version=1,
                subject_key=f"api_key:{uuid4()}",
                subject={},
                title="t",
                summary="s",
                severity_id=3,
                status_id=status_id,
                first_seen_at=first_seen,
                last_seen_at=first_seen,
                evidence={},
                remediation={},
                resolved_at=resolved_at,
            )
            for rule_id, status_id, first_seen, resolved_at in (
                ("gateway.retry_storm", 1, middle, None),
                ("gateway.retry_storm", 4, window.start - timedelta(days=3), middle),
                (
                    "gateway.answer_quality",
                    4,
                    window.start - timedelta(days=9),
                    window.start - timedelta(days=2),
                ),
            )
        ]
    )
    await db.flush()

    # The audit rows carry the time they were written, after the first window closed.
    later = datetime.now(timezone.utc)
    after = await evidence.collect_monthly_evidence(
        db, tenant_id, evidence.monthly_window(f"{now:%Y-%m}", now=later), now=later
    )
    text = _pdf_text(evidence.render_monthly_pdf(after))

    assert after.entities == {
        "pii_entities": {("openai", "TR_NATIONAL_ID"): 2},
        "monitored_entities": {("openai", "EMAIL_ADDRESS"): 3},
        "blocked_entities": {},
    }
    assert after.bulk_disclosures == 1
    assert after.response_entities == {"EMAIL_ADDRESS": 1}
    assert after.denials == (("privacy.input", "PII_BLOCKED", 1),)
    assert after.changes == (
        ("tenant.budget_created", evidence.NOT_RECORDED, 1),
        ("tenant.budget_created", "service", 1),
    )
    assert isinstance(after.chain, dict) and after.chain["ok"] is True
    assert after.findings == (("gateway.retry_storm", 1, 1, 1),)
    assert [
        (row.key, row.request_count, row.unpriced_requests) for row in after.by_model
    ] == [("gpt-5-mini", 3, 1)]
    assert "unknown (1 unpriced request(s))" in text
    assert evidence.NOT_RECORDED in text
    assert "IBAN_CODE" not in text
    for value in ("PII_BLOCKED", "tenant.budget_created", "EMAIL_ADDRESS 1"):
        assert value in text


@pytest.mark.asyncio
async def test_the_job_writes_the_previous_month_once_per_active_organization(
    db, test_tier
) -> None:
    now = datetime(2031, 2, 1, 0, 30, tzinfo=timezone.utc)
    january = datetime(2031, 1, 20, tzinfo=timezone.utc)
    organizations = {
        name: Organization(
            id=uuid4(),
            name=name,
            slug=f"{name}-{uuid4().hex}",
            **(
                {"archived_at": now, "archived_reason": "joined_organization"}
                if name == "archived"
                else {}
            ),
        )
        for name in ("active", "archived", "quiet", "done", "partial")
    }
    db.add_all(organizations.values())
    await db.flush()
    for name, organization in organizations.items():
        user = User(
            id=uuid4(),
            organization_id=organization.id,
            email=f"evidence-{uuid4().hex}@example.com",
        )
        db.add(user)
        await db.flush()
        key = ApiKey(
            id=uuid4(),
            organization_id=organization.id,
            user_id=user.id,
            key_hash=uuid4().hex,
            prefix="sk-shim-evid",
            tier=test_tier,
            is_active=True,
        )
        db.add(key)
        await db.flush()
        _lifecycle(db, key, now if name == "quiet" else january, {})
    for name, kind in (("done", "monthly"), ("partial", "monthly_partial")):
        db.add(
            MonthlyEvidenceFile(
                organization_id=organizations[name].id,
                kind=kind,
                period="2031-01",
                content=b"%PDF",
                sha256="0" * 64,
                size_bytes=4,
                generated_at=now,
                generator_version="test",
            )
        )
    await db.flush()
    factory = _savepoints(await db.connection())

    first = await evidence.generate_due_monthly_evidence(factory, now=now)
    second = await evidence.generate_due_monthly_evidence(factory, now=now)

    ids = {organization.id: name for name, organization in organizations.items()}
    stored = (
        await db.execute(
            select(MonthlyEvidenceFile.organization_id, MonthlyEvidenceFile.kind).where(
                MonthlyEvidenceFile.organization_id.in_(ids)
            )
        )
    ).all()
    notices = (
        await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.organization_id.in_(ids),
                OutboxEvent.event_type == EVIDENCE_MONTHLY_READY,
            )
        )
    ).all()
    assert (first, second) == ((2, 0), (0, 0))
    assert sorted((ids[org], kind) for org, kind in stored) == [
        ("active", "monthly"),
        ("done", "monthly"),
        ("partial", "monthly"),
        ("partial", "monthly_partial"),
    ]
    assert sorted((ids[n.organization_id], n.idempotency_key) for n in notices) == [
        ("active", "evidence:monthly:2031-01"),
        ("partial", "evidence:monthly:2031-01"),
    ]
    active = organizations["active"].id
    with pytest.raises(evidence.EvidenceFileExists):
        async with factory() as session:
            await evidence.generate_monthly_evidence(
                session, active, evidence.monthly_window("2031-01", now=now), now=now
            )


@pytest.mark.parametrize("targets", [0, 2])
@pytest.mark.asyncio
async def test_the_notice_reaches_every_enabled_forward_target(
    db, test_org, monkeypatch: pytest.MonkeyPatch, targets: int
) -> None:
    db.add_all(
        ComplianceForwardTarget(
            organization_id=test_org.id,
            kind="slack",
            endpoint_origin="https://hooks.slack.com",
            secret_ref=f"fernet:v2:{index}",
            secret_backend="fernet",
            secret_version="v2",
            enabled=True,
        )
        for index in range(targets)
    )
    await db.flush()
    monkeypatch.setattr(
        database, "AsyncSessionLocal", _savepoints(await db.connection())
    )
    message = OutboxMessage(
        id=uuid4(),
        organization_id=test_org.id,
        event_type=EVIDENCE_MONTHLY_READY,
        aggregate_type="organization",
        aggregate_id=str(test_org.id),
        idempotency_key="evidence:monthly:2026-09",
        payload={
            "organization_id": str(test_org.id),
            "kind": "monthly",
            "period": "2026-09",
            "sha256": "a" * 64,
            "generated_at": "2026-10-01T00:00:00+00:00",
        },
        attempt_count=0,
        created_at=datetime.now(timezone.utc),
    )

    await build_publisher().publish(message)
    # A retried handler appends nothing twice.
    await announce_monthly_evidence(message)

    deliveries = (
        await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == test_org.id,
                OutboxEvent.event_type == COMPLIANCE_DELIVERY,
            )
        )
    ).all()
    assert len(deliveries) == targets
    for delivery in deliveries:
        assert delivery.idempotency_key.endswith(":evidence_monthly:2026-09")
        assert delivery.payload["body"]["kind"] == "evidence_monthly_ready"
    assert _compliance_text(
        {
            "kind": "evidence_monthly_ready",
            "period": "2026-09",
            "download": "/api/v1/compliance/evidence/monthly/2026-09?kind=monthly",
        }
    ) == (
        "shim monthly evidence file for 2026-09 is ready: "
        "GET /api/v1/compliance/evidence/monthly/2026-09?kind=monthly"
    )


@pytest.mark.asyncio
async def test_script_writes_the_current_month_as_partial_and_refuses_a_second(
    db, test_api_key, test_user_with_org, audit_events, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime.now(timezone.utc)
    period = f"{now:%Y-%m}"
    tenant_id = test_api_key.organization_id
    window = evidence.monthly_window(period, now=now)
    _lifecycle(
        db,
        test_api_key,
        window.start + (now - window.start) / 2,
        {"pii_entities": {"TR_NATIONAL_ID": 1}},
    )
    await db.flush()
    monkeypatch.setitem(
        SCRIPT["main"].__globals__,
        "AsyncSessionLocal",
        _savepoints(await db.connection()),
    )

    printed = await SCRIPT["main"](tenant_id, period)
    with pytest.raises(evidence.EvidenceFileExists):
        await SCRIPT["main"](tenant_id, period)
    with pytest.raises(ValueError, match="future"):
        await SCRIPT["main"](tenant_id, "2999-01")

    stored = (
        await db.scalars(
            select(MonthlyEvidenceFile).where(
                MonthlyEvidenceFile.organization_id == tenant_id
            )
        )
    ).one()
    assert printed.startswith(f"monthly_partial {period} sha256={stored.sha256}")
    assert stored.sha256 == hashlib.sha256(stored.content).hexdigest()
    assert stored.size_bytes == len(stored.content)

    user = test_user_with_org
    application = FastAPI()
    application.include_router(compliance_router, prefix="/api/v1")
    application.dependency_overrides[enterprise_deps.get_current_user] = lambda: user
    application.dependency_overrides[get_db] = lambda: db
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        base = "/api/v1/compliance/evidence/monthly"
        user.role = "member"
        member = [
            (await client.get(path)).status_code
            for path in (base, f"{base}/{period}?kind=monthly_partial")
        ]
        user.role = "auditor"
        listed = (await client.get(base)).json()
        downloaded = await client.get(
            f"{base}/{period}", params={"kind": "monthly_partial"}
        )
        closed = await client.get(f"{base}/{period}")
        malformed = await client.get(f"{base}/2026-13")

    assert member == [403, 403]
    assert listed == [
        {
            "period": period,
            "kind": "monthly_partial",
            "format": "pdf",
            "size_bytes": stored.size_bytes,
            "sha256": stored.sha256,
            "generated_at": stored.generated_at.isoformat().replace("+00:00", "Z"),
        }
    ]
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"] == "application/pdf"
    assert downloaded.headers["x-content-sha256"] == stored.sha256
    assert hashlib.sha256(downloaded.content).hexdigest() == stored.sha256
    assert (
        f'filename="shim-evidence-monthly_partial-{period}.pdf"'
        in downloaded.headers["content-disposition"]
    )
    assert (closed.status_code, malformed.status_code) == (404, 422)
    events = [
        event
        for event in await audit_events(tenant_id)
        if event["endpoint"] == "tenant.evidence_downloaded"
    ]
    assert [event["extra"] for event in events] == [
        {
            "subject_id": str(stored.id),
            "actor_type": "user_jwt",
            "kind": "monthly_partial",
            "period": period,
            "sha256": stored.sha256,
        }
    ]


@pytest.mark.asyncio
async def test_a_failing_organization_turns_the_maintenance_pass_red(
    db, test_api_key, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime.now(timezone.utc)
    window = evidence.monthly_window(evidence.previous_period(now), now=now)
    _lifecycle(db, test_api_key, window.start + timedelta(days=1), {})
    await db.flush()

    def broken(_):
        raise RuntimeError("render failed")

    monkeypatch.setattr(evidence, "render_monthly_pdf", broken)
    worker = AuditMaintenanceWorker(session_factory=_savepoints(await db.connection()))

    summary = await worker.run_once()

    # The heartbeat is written only for a pass without errors.
    assert (summary.monthly_evidence, summary.errors) == (0, 1)


@pytest.mark.asyncio
async def test_two_workers_store_one_file_and_one_notice(async_engine) -> None:
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    now = datetime(2031, 2, 1, 0, 30, tzinfo=timezone.utc)
    window = evidence.monthly_window("2031-01", now=now)
    organization = Organization(
        id=uuid4(), name="concurrent", slug=f"concurrent-{uuid4().hex}"
    )
    async with factory.begin() as setup:
        setup.add(organization)
    try:
        async with factory() as first, factory() as second:
            await evidence.generate_monthly_evidence(
                first, organization.id, window, now=now
            )
            racing = asyncio.create_task(
                evidence.generate_monthly_evidence(
                    second, organization.id, window, now=now
                )
            )
            # The second insert waits on the first worker's uncommitted row.
            async with factory() as observer:
                for _ in range(200):
                    waiting = await observer.scalar(
                        text(
                            "SELECT count(*) FROM pg_stat_activity "
                            "WHERE wait_event_type = 'Lock' "
                            "AND datname = current_database()"
                        )
                    )
                    if waiting or racing.done():
                        break
                    await asyncio.sleep(0.05)
            assert waiting and not racing.done()
            await first.commit()
            with pytest.raises(evidence.EvidenceFileExists):
                await racing
            await second.rollback()

        async with factory() as session:
            files = await session.scalar(
                select(func.count()).where(
                    MonthlyEvidenceFile.organization_id == organization.id
                )
            )
            notices = await session.scalar(
                select(func.count()).where(
                    OutboxEvent.organization_id == organization.id,
                    OutboxEvent.event_type == EVIDENCE_MONTHLY_READY,
                )
            )
        assert (files, notices) == (1, 1)
    finally:
        async with factory.begin() as cleanup:
            for model in (OutboxEvent, MonthlyEvidenceFile):
                await cleanup.execute(
                    delete(model).where(model.organization_id == organization.id)
                )
            await cleanup.execute(
                delete(Organization).where(Organization.id == organization.id)
            )
