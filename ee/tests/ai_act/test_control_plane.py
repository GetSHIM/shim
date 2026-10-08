import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from sqlalchemy.dialects import postgresql

import shim_enterprise.ai_act.api as api_module
import shim_enterprise.ai_act.bundle as bundle_module
import shim_enterprise.api.enterprise_deps as enterprise_deps
import shim_enterprise.ai_act.oversight as oversight_module
import shim_enterprise.ai_act.report as report_module
import shim_enterprise.workers.ai_act as worker_module
from shim_enterprise.ai_act.overview import (
    OverviewProjector,
    OverviewWindow,
    empty_overview,
)
from shim_enterprise.ai_act.report import EvidenceSnapshot, assess, load_frameworks
from shim_enterprise.ai_act.retention import archive_expired
from shim_enterprise.ai_act.schemas import AuditReportRequest, OverviewResponse
from shim_enterprise.ai_act.verify import AuditVerificationLimitExceeded
from shim_enterprise.ai_act.audit_writer import write_audit_row
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.core.database import get_db


def test_empty_overview_satisfies_the_typed_public_contract() -> None:
    overview = OverviewResponse.model_validate(empty_overview())

    assert overview.detective.total_findings == 0
    assert overview.preventive.redaction_rate == 0
    assert overview.audit_log.retention_days >= 180
    assert overview.connectors.total == 0


def test_framework_assessment_reports_evidence_and_explicit_gaps() -> None:
    now = datetime.now(timezone.utc)
    snapshot = EvidenceSnapshot(
        tenant_id=uuid4(),
        start=now,
        end=now,
        audit_rows=10,
        pii_rows=2,
        anchors=1,
        chain_valid=True,
        chain_break=None,
        retention_days=180,
        oversight_policies=1,
        oversight_events=0,
        findings=3,
        connectors=1,
    )

    report = assess(["ai_act", "gdpr"], snapshot)

    assert set(load_frameworks()) == {"ai_act", "gdpr", "iso27001", "kvkk", "soc2"}
    assert [item.framework.identifier for item in report.frameworks] == [
        "ai_act",
        "gdpr",
    ]
    assert all(item.controls for item in report.frameworks)
    assert report.frameworks[0].gaps == 0


@pytest.mark.parametrize(
    "trigger",
    [
        {"models": 1},
        {"pii_detected": "false"},
        {"unknown": ["value"]},
    ],
)
def test_invalid_oversight_triggers_are_rejected_without_worker_errors(
    trigger: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        oversight_module.validate_trigger(trigger)
    with pytest.raises(HTTPException) as captured:
        api_module._validate_policy_trigger(trigger)

    assert captured.value.status_code == 422
    assert not oversight_module.matches_trigger(trigger, {})


@pytest.mark.asyncio
async def test_connector_overview_distinguishes_paused_and_errored_states() -> None:
    connectors = [
        SimpleNamespace(status="active", consecutive_errors=0, last_success_at=None),
        SimpleNamespace(status="paused", consecutive_errors=0, last_success_at=None),
        SimpleNamespace(status="error", consecutive_errors=0, last_success_at=None),
        SimpleNamespace(status="active", consecutive_errors=2, last_success_at=None),
    ]
    session = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(scalars=lambda: connectors))
    )

    projection = await OverviewProjector(
        session,
        uuid4(),
        OverviewWindow(),
    ).connectors()

    assert projection["total"] == 4
    assert projection["healthy"] == 1
    assert projection["errored"] == 2


@pytest.mark.asyncio
async def test_retention_count_does_not_materialize_audit_rows() -> None:
    session = SimpleNamespace(
        scalar=AsyncMock(return_value=7),
        execute=AsyncMock(),
    )

    result = await archive_expired(
        session,
        now=datetime(2026, 7, 25, tzinfo=timezone.utc),
        retention_days=180,
    )

    assert result["eligible"] == 7
    assert result["exported"] == 0
    session.scalar.assert_awaited_once()
    session.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_write_api_rejects_users_without_a_tenant() -> None:
    session = SimpleNamespace(
        get=AsyncMock(),
        commit=AsyncMock(),
        rollback=AsyncMock(),
    )

    with pytest.raises(HTTPException) as captured:
        await api_module._tenant_for_write(
            session,
            SimpleNamespace(organization_id=None),
        )

    assert captured.value.status_code == 403
    session.get.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation",
    [api_module.list_audit_logs, api_module.verify_audit_chain],
)
async def test_audit_ranges_reject_reversed_dates(operation) -> None:
    with pytest.raises(HTTPException) as captured:
        await operation(
            start=datetime(2026, 7, 26, tzinfo=timezone.utc),
            end=datetime(2026, 7, 25, tzinfo=timezone.utc),
            current_user=SimpleNamespace(organization_id=uuid4()),
            session=SimpleNamespace(),
        )

    assert captured.value.status_code == 422


@pytest.mark.asyncio
async def test_audit_endpoints_reject_more_than_31_days(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    end = datetime(2026, 7, 26, tzinfo=timezone.utc)
    start = end - timedelta(days=32)
    tenant_for_write = AsyncMock(return_value=uuid4())
    verify = AsyncMock()
    verify_anchors = AsyncMock(return_value={"ok": True})
    report = AsyncMock()
    monkeypatch.setattr(api_module, "_tenant_for_write", tenant_for_write)
    monkeypatch.setattr(api_module, "verify_chain", verify)
    monkeypatch.setattr(api_module, "verify_anchors", verify_anchors)
    monkeypatch.setattr(api_module, "generate_audit_report", report)

    with pytest.raises(HTTPException, match="31 days") as verify_error:
        await api_module.verify_audit_chain(
            start=start,
            end=end,
            current_user=SimpleNamespace(organization_id=uuid4()),
            session=SimpleNamespace(),
        )
    with pytest.raises(HTTPException, match="31 days") as report_error:
        await api_module.generate_audit_report_endpoint(
            AuditReportRequest(start=start, end=end),
            current_user=SimpleNamespace(organization_id=uuid4()),
            session=SimpleNamespace(),
        )

    assert verify_error.value.status_code == report_error.value.status_code == 422
    tenant_for_write.assert_not_awaited()
    verify.assert_not_awaited()
    verify_anchors.assert_not_awaited()
    report.assert_not_awaited()


@pytest.mark.asyncio
async def test_audit_report_converts_anchor_range_to_utc_dates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id = uuid4()
    offset = timezone(timedelta(hours=3))
    start = datetime(2026, 7, 5, 1, tzinfo=offset)
    end = datetime(2026, 7, 12, 1, tzinfo=offset)
    session = SimpleNamespace(scalar=AsyncMock(return_value=0))
    monkeypatch.setattr(
        report_module,
        "verify_chain",
        AsyncMock(return_value={"ok": True, "first_break": None}),
    )

    await report_module.collect_evidence(
        session,
        tenant_id=tenant_id,
        start=start,
        end=end,
        connector_id=None,
    )

    anchor_statement = next(
        call.args[0]
        for call in session.scalar.await_args_list
        if "ai_act_audit_anchor" in str(call.args[0])
    )
    compiled = anchor_statement.compile(dialect=postgresql.dialect())
    assert start.astimezone(timezone.utc).date() in compiled.params.values()
    assert end.astimezone(timezone.utc).date() in compiled.params.values()


@pytest.mark.asyncio
async def test_audit_verification_without_a_range_preserves_full_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id = uuid4()
    tenant_for_write = AsyncMock(return_value=tenant_id)
    verify = AsyncMock(
        return_value={
            "ok": True,
            "chain_start": {"from_seq": 1, "anchor_date": None},
            "rows_checked": 0,
            "first_break": None,
            "last_verified_seq": None,
        }
    )
    anchors = AsyncMock(
        return_value={"ok": True, "anchors_checked": 0, "mismatches": []}
    )
    session = SimpleNamespace(commit=AsyncMock())
    audit = AsyncMock()
    monkeypatch.setattr(api_module, "_tenant_for_write", tenant_for_write)
    monkeypatch.setattr(api_module, "verify_chain", verify)
    monkeypatch.setattr(api_module, "verify_anchors", anchors)
    monkeypatch.setattr(api_module, "_audit", audit)

    result = await api_module.verify_audit_chain(
        start=None,
        end=None,
        current_user=SimpleNamespace(organization_id=tenant_id),
        session=session,
    )

    assert result.ok is True
    verify.assert_awaited_once_with(session, tenant_id, start=None, end=None)
    anchors.assert_awaited_once_with(session, tenant_id, start=None, end=None)
    assert audit.await_args.args[2] == "compliance.audit_verified"
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_audit_limits_are_returned_as_validation_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id = uuid4()
    monkeypatch.setattr(
        api_module,
        "_tenant_for_write",
        AsyncMock(return_value=tenant_id),
    )
    monkeypatch.setattr(
        api_module,
        "verify_chain",
        AsyncMock(side_effect=AuditVerificationLimitExceeded("audit too large")),
    )
    verify_anchors = AsyncMock()
    monkeypatch.setattr(api_module, "verify_anchors", verify_anchors)

    with pytest.raises(HTTPException, match="audit too large") as error:
        await api_module.verify_audit_chain(
            start=None,
            end=None,
            current_user=SimpleNamespace(organization_id=tenant_id),
            session=SimpleNamespace(),
        )

    assert error.value.status_code == 422
    verify_anchors.assert_not_awaited()

    report = AsyncMock(side_effect=AuditVerificationLimitExceeded("report too large"))
    monkeypatch.setattr(api_module, "generate_audit_report", report)
    with pytest.raises(HTTPException, match="report too large") as error:
        await api_module.generate_audit_report_endpoint(
            AuditReportRequest(),
            current_user=SimpleNamespace(organization_id=tenant_id),
            session=SimpleNamespace(),
        )

    assert error.value.status_code == 422


@pytest.mark.asyncio
async def test_anchor_rejects_an_open_day_before_writing() -> None:
    session = SimpleNamespace()

    with pytest.raises(HTTPException) as captured:
        await api_module.trigger_anchor(
            anchor_date=datetime.now(timezone.utc).date(),
            current_user=SimpleNamespace(organization_id=uuid4()),
            session=session,
        )

    assert captured.value.status_code == 422


@pytest.mark.asyncio
async def test_decide_rejects_expired_pending_request_without_audit(
    monkeypatch,
) -> None:
    organization_id = uuid4()
    request = SimpleNamespace(
        id=uuid4(),
        request_ref="expired-request",
        status="pending",
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        approver=None,
        decision_note=None,
        decided_at=None,
    )
    original = vars(request).copy()
    session = SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(scalar_one_or_none=lambda: request)
        )
    )
    audit = AsyncMock()
    monkeypatch.setattr(oversight_module, "_append_audit_event", audit)

    with pytest.raises(oversight_module.OversightStateError, match="no longer pending"):
        await oversight_module.decide(
            session,
            request.id,
            organization_id,
            decision="approve",
            note="too late",
            approver="reviewer",
        )

    assert vars(request) == original
    audit.assert_not_awaited()


@pytest.mark.asyncio
async def test_worker_main_handles_shutdown_signals_and_cancellation(
    monkeypatch,
    worker_shutdown_probe,
) -> None:
    configure_logging = Mock()
    configure_error_reporting = Mock()
    configure_tracing = Mock()
    shutdown_tracing = Mock()
    engine = SimpleNamespace(dispose=AsyncMock())
    monkeypatch.setattr(
        worker_module.asyncio,
        "get_running_loop",
        lambda: worker_shutdown_probe.loop,
    )
    monkeypatch.setattr(worker_module, "configure_logging", configure_logging)
    monkeypatch.setattr(
        worker_module,
        "configure_error_reporting",
        configure_error_reporting,
    )
    monkeypatch.setattr(worker_module, "configure_tracing", configure_tracing)
    monkeypatch.setattr(worker_module, "shutdown_tracing", shutdown_tracing)
    monkeypatch.setattr(worker_module, "engine", engine)
    monkeypatch.setattr(
        worker_module,
        "AuditMaintenanceWorker",
        lambda: worker_shutdown_probe,
    )

    with pytest.raises(asyncio.CancelledError):
        await worker_module.main()

    worker_shutdown_probe.assert_cleaned_up()
    configure_logging.assert_called_once_with(worker_module.settings.LOG_LEVEL)
    configure_error_reporting.assert_called_once_with(
        sentry_dsn=worker_module.settings.SENTRY_DSN,
        environment=worker_module.settings.ENVIRONMENT,
    )
    configure_tracing.assert_called_once_with(
        endpoint=worker_module.settings.OTEL_EXPORTER_OTLP_ENDPOINT,
        service_name=worker_module.settings.OTEL_SERVICE_NAME,
    )
    engine.dispose.assert_awaited_once_with()
    shutdown_tracing.assert_called_once_with()


@pytest.mark.asyncio
async def test_bundle_window_validation_and_empty_windows(
    db, test_org, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = SimpleNamespace(organization_id=test_org.id)
    with pytest.raises(HTTPException) as reversed_window:
        await api_module.export_audit_bundle(
            start=datetime(2026, 7, 26, tzinfo=timezone.utc),
            end=datetime(2026, 7, 25, tzinfo=timezone.utc),
            current_user=user,
            session=db,
        )
    with pytest.raises(HTTPException) as empty:
        await api_module.export_audit_bundle(
            start=None, end=None, current_user=user, session=db
        )
    for index in range(2):
        await write_audit_row(
            {"organization_id": test_org.id, "request_id": f"req-limit-{index}"}, db
        )
    monkeypatch.setattr(bundle_module, "MAX_SYNC_AUDIT_ROWS", 1)
    with pytest.raises(
        HTTPException, match="limited to 1 rows; .* hour-sized windows"
    ) as over_limit:
        await api_module.export_audit_bundle(
            start=None, end=None, current_user=user, session=db
        )

    assert reversed_window.value.status_code == 422
    assert empty.value.status_code == 404
    assert over_limit.value.status_code == 422


@pytest.mark.asyncio
async def test_bundle_is_for_organization_readers_with_a_user_session(
    db, test_user_with_org, monkeypatch: pytest.MonkeyPatch
) -> None:
    await write_audit_row(
        {"organization_id": test_user_with_org.organization_id, "request_id": "req-1"},
        db,
    )
    application = FastAPI()
    application.include_router(management_router, prefix="/api/v1")
    application.dependency_overrides[get_db] = lambda: db
    path = "/api/v1/compliance/audit/bundle"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        monkeypatch.setattr(
            enterprise_deps,
            "jwt_verifier",
            SimpleNamespace(verify=AsyncMock(return_value=None)),
        )
        api_key = await client.get(
            path, headers={"authorization": "Bearer sk-shim-" + "0" * 32}
        )
        application.dependency_overrides[enterprise_deps.get_current_user] = lambda: (
            test_user_with_org
        )
        test_user_with_org.role = "member"
        member = await client.get(path)
        test_user_with_org.role = "auditor"
        auditor = await client.get(path)

    assert api_key.status_code == 401
    assert member.status_code == 403
    assert auditor.status_code == 200
    assert auditor.headers["content-disposition"] == (
        "attachment; filename="
        f'"shim-audit-bundle-{test_user_with_org.organization_id}.json"'
    )
    assert auditor.json()["row_count"] == 1


@pytest.mark.asyncio
async def test_oversight_changes_triggers_and_evidence_reads_are_audited(
    db, test_user_with_org, audit_events
) -> None:
    from shim_enterprise.ai_act.schemas import (
        OversightPolicyCreate,
        OversightPolicyUpdate,
    )

    user = test_user_with_org
    user.role = "admin"
    tenant_id = user.organization_id
    await write_audit_row({"organization_id": tenant_id, "request_id": "req-1"}, db)

    policy = await api_module.create_oversight_policy(
        OversightPolicyCreate(name="PII", trigger={"pii_detected": True}),
        current_user=user,
        session=db,
    )
    await api_module.update_oversight_policy(
        policy.id,
        OversightPolicyUpdate(enabled=False),
        current_user=user,
        session=db,
    )
    await api_module.delete_oversight_policy(policy.id, current_user=user, session=db)
    await api_module.trigger_oversight_evaluation(current_user=user, session=db)
    yesterday = datetime.now(timezone.utc).date() - timedelta(days=1)
    await api_module.trigger_anchor(
        anchor_date=yesterday, current_user=user, session=db
    )
    bundle = await api_module.export_audit_bundle(
        start=None, end=None, current_user=user, session=db
    )
    await api_module.verify_audit_chain(
        start=None, end=None, current_user=user, session=db
    )
    await api_module.generate_audit_report_endpoint(
        AuditReportRequest(format="csv"), current_user=user, session=db
    )

    events = await audit_events(tenant_id)
    extra = {event["endpoint"]: event["extra"] for event in events}
    assert sorted(event["endpoint"] for event in events) == [
        "compliance.audit_anchored",
        "compliance.audit_bundle_exported",
        "compliance.audit_report_generated",
        "compliance.audit_verified",
        "compliance.oversight_evaluated",
        "compliance.oversight_policy_created",
        "compliance.oversight_policy_deleted",
        "compliance.oversight_policy_updated",
    ]
    assert all(event["actor"] == str(user.id) for event in events)
    created = extra["compliance.oversight_policy_created"]
    assert set(created) == {"subject_id", "actor_type", "after"}
    assert created["after"]["trigger"] == {"pii_detected": True}
    updated = extra["compliance.oversight_policy_updated"]
    assert (updated["before"], updated["after"]) == (
        {"enabled": True},
        {"enabled": False},
    )
    assert extra["compliance.oversight_policy_deleted"]["before"]["enabled"] is False
    assert extra["compliance.audit_anchored"] == {
        "subject_id": str(tenant_id),
        "actor_type": "user_jwt",
        "anchor_date": yesterday.isoformat(),
        "row_count": 0,
    }
    # The bundle was selected before its own event was recorded.
    assert bytes(bundle.body).count(b'"request_id"') == 1
    assert extra["compliance.audit_bundle_exported"]["rows"] == 1
    assert extra["compliance.audit_verified"]["ok"] is True
    assert extra["compliance.audit_report_generated"]["frameworks"] == ["ai_act"]
