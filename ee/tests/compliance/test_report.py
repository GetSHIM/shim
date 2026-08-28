import asyncio
from datetime import datetime, timedelta, timezone
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

import pytest
from pydantic import ValidationError
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError

import shim_enterprise.workers.compliance as worker_module
import shim_enterprise.compliance.api as compliance_api
import shim_enterprise.compliance.services.report as report_module
from shim_enterprise.compliance.models import ComplianceForwardTarget
from shim_enterprise.compliance.schemas import (
    ForwardTargetCreate,
    ForwardTargetUpdate,
    ReportRequest,
)
from shim_enterprise.compliance.services.ingest import (
    LOCK_SECONDS,
    UNLOCK_LUA,
    ComplianceIngestService,
)
from shim_enterprise.compliance.services.forwarder import ComplianceForwarderService
from shim_enterprise.compliance.services.report import (
    ExposureEvidence,
    FindingEvidence,
    ReportLimitExceeded,
    _render_csv,
    collect_exposure_evidence,
)


def _lock_test_service(redis):
    session_factory = Mock()
    adapter = Mock()
    service = ComplianceIngestService(
        scan=Mock(),
        forwarder=Mock(),
        cache=SimpleNamespace(redis=redis),
        secret_store=Mock(),
        session_factory=session_factory,
    )
    service._adapter = adapter
    return service, session_factory, adapter


def test_forward_target_update_rejects_an_empty_endpoint() -> None:
    with pytest.raises(ValidationError):
        ForwardTargetUpdate(endpoint="")


def test_forward_target_validates_kind_specific_destinations() -> None:
    email = ForwardTargetCreate(kind="email", endpoint="Alerts@Example.com")
    assert email.endpoint == "Alerts@example.com"
    assert (
        compliance_api._endpoint_origin("email", email.endpoint) == "A***@example.com"
    )
    with pytest.raises(ValidationError):
        ForwardTargetCreate(kind="email", endpoint="not-an-email")
    with pytest.raises(ValidationError, match="only SIEM"):
        ForwardTargetCreate(
            kind="slack",
            endpoint="https://hooks.slack.com/services/test",
            secret="sixteen-characters",
        )


def test_report_request_rejects_more_than_31_days() -> None:
    end = datetime(2026, 8, 1, tzinfo=timezone.utc)

    with pytest.raises(ValidationError, match="31 days"):
        ReportRequest(start=end - timedelta(days=32), end=end)

    ReportRequest(start=end - timedelta(days=30), end=end)


def test_report_request_normalizes_naive_datetimes_to_utc() -> None:
    request = ReportRequest(
        start=datetime(2026, 8, 1),
        end=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )

    assert request.start == datetime(2026, 8, 1, tzinfo=timezone.utc)
    assert request.end == datetime(2026, 8, 1, tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_compliance_report_rejects_findings_over_its_fixed_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(report_module, "MAX_SYNC_REPORT_FINDINGS", 1)
    session = SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(scalars=lambda: (object(), object()))
        )
    )
    end = datetime(2026, 8, 1, tzinfo=timezone.utc)

    with pytest.raises(ReportLimitExceeded, match="limited to 1"):
        await collect_exposure_evidence(
            session,
            tenant_id=uuid4(),
            start=end - timedelta(days=1),
            end=end,
            connector_id=None,
        )

    session.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_compliance_report_query_is_stably_ordered_and_bounded() -> None:
    session = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(scalars=lambda: ()))
    )
    end = datetime(2026, 8, 1, tzinfo=timezone.utc)

    await collect_exposure_evidence(
        session,
        tenant_id=uuid4(),
        start=end - timedelta(days=1),
        end=end,
        connector_id=None,
    )

    statement = session.execute.await_args.args[0]
    compiled = statement.compile(dialect=postgresql.dialect())
    assert (
        "ORDER BY compliance_finding.occurred_at DESC, "
        "compliance_finding.id DESC" in str(compiled)
    )
    assert " LIMIT " in str(compiled)
    assert 10_001 in compiled.params.values()


@pytest.mark.asyncio
async def test_compliance_report_limit_is_returned_as_validation_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        report_module,
        "generate_report",
        AsyncMock(side_effect=ReportLimitExceeded("report too large")),
    )

    with pytest.raises(compliance_api.HTTPException, match="report too large") as error:
        await compliance_api.generate_kvkk_report(
            ReportRequest(),
            SimpleNamespace(organization_id=uuid4()),
            SimpleNamespace(),
        )

    assert error.value.status_code == 422


@pytest.mark.asyncio
async def test_enabled_email_target_requires_delivery_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(compliance_api.settings, "RESEND_API_KEY", None)
    monkeypatch.setattr(compliance_api.settings, "COMPLIANCE_EMAIL_FROM", None)

    with pytest.raises(compliance_api.HTTPException) as error:
        await compliance_api._validate_target_destination(
            "email", "alerts@example.com", enabled=True
        )

    assert error.value.status_code == 503


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_commit", [False, True])
async def test_forward_target_rotation_rebinds_queued_delivery_before_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    fail_commit: bool,
) -> None:
    tenant_id = uuid4()
    target = ComplianceForwardTarget(
        id=uuid4(),
        connector_id=uuid4(),
        kind="siem_webhook",
        endpoint_origin="https://old.example",
        secret_ref="fernet:v2:old",
        secret_backend="fernet",
        secret_version="v2",
        signed=False,
        min_severity="high",
        enabled=True,
    )
    store = SimpleNamespace(
        get_secret=AsyncMock(
            return_value=(
                '{"kind":"siem_webhook","endpoint":"https://old.example/hook",'
                '"signing_secret":null}'
            )
        ),
        rotate_secret=AsyncMock(return_value="fernet:v2:replacement"),
        delete_secret=AsyncMock(),
    )
    queued = SimpleNamespace(payload={"secret_ref": "fernet:v2:old"})
    session = SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(scalars=lambda: (queued,)),
        ),
        commit=AsyncMock(
            side_effect=RuntimeError("commit failed") if fail_commit else None
        ),
        rollback=AsyncMock(),
        refresh=AsyncMock(),
    )
    monkeypatch.setattr(
        compliance_api,
        "_load_target",
        AsyncMock(return_value=target),
    )
    monkeypatch.setattr(compliance_api, "_validate_forward_url", AsyncMock())
    monkeypatch.setattr(compliance_api, "get_secret_store", lambda: store)

    operation = compliance_api.update_forward_target(
        target.id,
        ForwardTargetUpdate(endpoint="https://new.example/hook"),
        SimpleNamespace(organization_id=tenant_id),
        session,
    )
    if fail_commit:
        with pytest.raises(RuntimeError, match="commit failed"):
            await operation
        session.rollback.assert_awaited_once_with()
        deleted_ref = "fernet:v2:replacement"
        session.refresh.assert_not_awaited()
    else:
        await operation
        session.rollback.assert_not_awaited()
        deleted_ref = "fernet:v2:old"
        session.refresh.assert_awaited_once_with(target)
        assert target.secret_ref == "fernet:v2:replacement"
        assert target.secret_backend == "fernet"
        assert target.secret_version == "v2"
        assert queued.payload["secret_ref"] == "fernet:v2:replacement"
    store.delete_secret.assert_awaited_once_with(
        tenant_id,
        deleted_ref,
        expected_purpose="compliance-forward-target-delivery",
    )


@pytest.mark.asyncio
async def test_connector_delete_cancels_target_deliveries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id = uuid4()
    connector = SimpleNamespace(id=uuid4(), secret_ref="fernet:v2:connector")
    target = SimpleNamespace(id=uuid4(), secret_ref="fernet:v2:target")
    session = SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(scalars=lambda: (target,)),
        ),
        delete=AsyncMock(),
        commit=AsyncMock(),
    )
    store = SimpleNamespace(delete_secret=AsyncMock())
    cancel_deliveries = AsyncMock()
    monkeypatch.setattr(
        compliance_api,
        "_load_connector",
        AsyncMock(return_value=connector),
    )
    monkeypatch.setattr(
        compliance_api,
        "_cancel_forward_deliveries",
        cancel_deliveries,
    )
    monkeypatch.setattr(compliance_api, "get_secret_store", lambda: store)

    await compliance_api.delete_connector(
        connector.id,
        SimpleNamespace(organization_id=tenant_id),
        session,
    )

    cancel_deliveries.assert_awaited_once_with(session, tenant_id, target.id)
    assert store.delete_secret.await_count == 2


@pytest.mark.asyncio
async def test_repeated_health_alerts_share_an_hourly_idempotency_key() -> None:
    connector = SimpleNamespace(id=uuid4(), organization_id=uuid4(), provider="openai")
    target = SimpleNamespace(id=uuid4())
    service = ComplianceForwarderService()
    service._targets = AsyncMock(return_value=(target,))
    service._append = AsyncMock()
    first = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)
    second = datetime(2026, 7, 19, 12, 5, tzinfo=timezone.utc)

    with patch("shim_enterprise.compliance.services.forwarder.datetime") as clock:
        clock.now.side_effect = (first, second)
        await service.send_operational_alert(
            object(), connector, kind="retention_risk", message="Provider lag"
        )
        await service.send_operational_alert(
            object(), connector, kind="retention_risk", message="Provider lag"
        )

    calls = service._append.await_args_list
    assert calls[0].kwargs["delivery_key"] == calls[1].kwargs["delivery_key"]
    assert calls[0].kwargs["body"] == calls[1].kwargs["body"]


@pytest.mark.asyncio
async def test_slack_and_email_group_findings_while_siem_keeps_each_event() -> None:
    connector = SimpleNamespace(id=uuid4(), organization_id=uuid4(), provider="openai")
    targets = (
        SimpleNamespace(id=uuid4(), kind="siem_webhook", min_severity="high"),
        SimpleNamespace(id=uuid4(), kind="slack", min_severity="high"),
        SimpleNamespace(id=uuid4(), kind="email", min_severity="high"),
    )
    findings = [
        {
            "severity": "high",
            "entity_type": "EMAIL",
            "content_id": f"content-{index}",
            "value_hash": f"hash-{index}",
            "match_offset": 0,
            "match_length": 4,
            "actor_email": "raw@example.com",
        }
        for index in range(2)
    ]
    service = ComplianceForwarderService()
    service._targets = AsyncMock(return_value=targets)
    service._append = AsyncMock()

    result = await service.handle_run(object(), connector, findings)

    assert result == {"deliveries_queued": 4}
    bodies = [call.kwargs["body"] for call in service._append.await_args_list]
    summaries = [body for body in bodies if body["event_type"].endswith("summary")]
    summary_keys = [
        call.kwargs["delivery_key"]
        for call in service._append.await_args_list
        if call.kwargs["body"]["event_type"].endswith("summary")
    ]
    assert len(summaries) == 2
    assert all(body["finding_count"] == 2 for body in summaries)
    assert summary_keys[0] == summary_keys[1]
    assert "raw@example.com" not in str(summaries)

    changed_findings = [
        {**finding, "content_id": f"new-{index}"}
        for index, finding in enumerate(findings)
    ]
    service._append.reset_mock()
    await service.handle_run(object(), connector, changed_findings)
    changed_key = next(
        call.kwargs["delivery_key"]
        for call in service._append.await_args_list
        if call.kwargs["body"]["event_type"].endswith("summary")
    )
    assert changed_key != summary_keys[0]


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
        "ComplianceSweepWorker",
        lambda: worker_shutdown_probe,
    )
    cache = SimpleNamespace(connect=AsyncMock(), close=AsyncMock())
    worker_shutdown_probe.service = SimpleNamespace(cache=cache)

    with pytest.raises(asyncio.CancelledError):
        await worker_module.main()

    worker_shutdown_probe.assert_cleaned_up()
    cache.connect.assert_awaited_once_with()
    cache.close.assert_awaited_once_with()
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
async def test_worker_main_closes_cache_when_redis_startup_fails(
    monkeypatch,
    worker_shutdown_probe,
) -> None:
    monkeypatch.setattr(
        worker_module.asyncio,
        "get_running_loop",
        lambda: worker_shutdown_probe.loop,
    )
    monkeypatch.setattr(worker_module, "configure_logging", lambda _level: None)
    monkeypatch.setattr(worker_module, "configure_error_reporting", lambda **_: None)
    monkeypatch.setattr(worker_module, "configure_tracing", lambda **_: None)
    monkeypatch.setattr(worker_module, "shutdown_tracing", lambda: None)
    monkeypatch.setattr(
        worker_module,
        "engine",
        SimpleNamespace(dispose=AsyncMock()),
    )
    cache = SimpleNamespace(
        connect=AsyncMock(side_effect=RedisError("unavailable")),
        close=AsyncMock(),
    )
    worker_shutdown_probe.service = SimpleNamespace(cache=cache)
    monkeypatch.setattr(
        worker_module,
        "ComplianceSweepWorker",
        lambda: worker_shutdown_probe,
    )

    with pytest.raises(RedisError, match="unavailable"):
        await worker_module.main()

    worker_shutdown_probe.assert_cleaned_up()
    cache.connect.assert_awaited_once_with()
    cache.close.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_worker_main_cleans_up_when_construction_fails(
    monkeypatch,
    worker_shutdown_probe,
) -> None:
    shutdown_tracing = Mock()
    engine = SimpleNamespace(dispose=AsyncMock())
    monkeypatch.setattr(
        worker_module.asyncio,
        "get_running_loop",
        lambda: worker_shutdown_probe.loop,
    )
    monkeypatch.setattr(worker_module, "configure_logging", lambda _level: None)
    monkeypatch.setattr(worker_module, "configure_error_reporting", lambda **_: None)
    monkeypatch.setattr(worker_module, "configure_tracing", lambda **_: None)
    monkeypatch.setattr(worker_module, "shutdown_tracing", shutdown_tracing)
    monkeypatch.setattr(worker_module, "engine", engine)
    monkeypatch.setattr(
        worker_module,
        "ComplianceSweepWorker",
        Mock(side_effect=RuntimeError("construction failed")),
    )

    with pytest.raises(RuntimeError, match="construction failed"):
        await worker_module.main()

    worker_shutdown_probe.assert_cleaned_up()
    engine.dispose.assert_awaited_once_with()
    shutdown_tracing.assert_called_once_with()


@pytest.mark.asyncio
async def test_ingest_skips_before_session_when_redis_is_missing(caplog) -> None:
    connector_id = uuid4()
    service, session_factory, adapter = _lock_test_service(None)

    with caplog.at_level(
        logging.WARNING, logger="shim_enterprise.compliance.services.ingest"
    ):
        outcome = await service.run_once(connector_id)

    assert outcome["status"] == "skipped_locked"
    session_factory.assert_not_called()
    adapter.assert_not_called()
    assert "reason=redis_missing" in caplog.text


@pytest.mark.asyncio
async def test_ingest_skips_before_session_when_redis_lock_errors(caplog) -> None:
    connector_id = uuid4()
    sensitive_error = "redis://user:secret@internal.example"
    redis = SimpleNamespace(
        set=AsyncMock(side_effect=RedisError(sensitive_error)),
        eval=AsyncMock(),
    )
    service, session_factory, adapter = _lock_test_service(redis)

    with caplog.at_level(
        logging.WARNING, logger="shim_enterprise.compliance.services.ingest"
    ):
        outcome = await service.run_once(connector_id)

    assert outcome["status"] == "skipped_locked"
    session_factory.assert_not_called()
    adapter.assert_not_called()
    redis.eval.assert_not_awaited()
    assert "reason=redis_error type=RedisError" in caplog.text
    assert sensitive_error not in caplog.text


@pytest.mark.asyncio
async def test_ingest_skips_before_session_when_lock_is_contended() -> None:
    connector_id = uuid4()
    redis = SimpleNamespace(
        set=AsyncMock(return_value=False),
        eval=AsyncMock(),
    )
    service, session_factory, adapter = _lock_test_service(redis)

    outcome = await service.run_once(connector_id)

    assert outcome["status"] == "skipped_locked"
    session_factory.assert_not_called()
    adapter.assert_not_called()
    redis.eval.assert_not_awaited()


@pytest.mark.asyncio
async def test_ingest_acquires_and_releases_lock_with_ownership_token() -> None:
    connector_id = uuid4()
    redis = SimpleNamespace(
        set=AsyncMock(return_value=True),
        eval=AsyncMock(return_value=1),
    )
    service, _, _ = _lock_test_service(redis)

    token = await service._acquire_lock(connector_id)

    assert token is not None
    redis.set.assert_awaited_once_with(
        f"compliance:lock:{connector_id}",
        token,
        nx=True,
        ex=LOCK_SECONDS,
    )

    await service._release_lock(connector_id, token)

    redis.eval.assert_awaited_once_with(
        UNLOCK_LUA,
        1,
        f"compliance:lock:{connector_id}",
        token,
    )


def test_csv_report_prevents_spreadsheet_formula_execution() -> None:
    now = datetime.now(timezone.utc)
    evidence = ExposureEvidence(
        tenant_id=uuid4(),
        connector_id=None,
        start=now,
        end=now,
        findings=(
            FindingEvidence(
                occurred_at=now,
                severity="high",
                entity_type="EMAIL",
                kvkk_category="contact",
                gdpr_category="personal_data",
                actor_email='=HYPERLINK("unsafe")',
                model="gpt-5.6-luna",
                content_id="content-ref",
                value_hash="value-hash",
            ),
        ),
    )

    rendered = _render_csv(evidence).decode("utf-8-sig")

    assert "'=HYPERLINK" in rendered
    assert evidence.counts("entity_type") == {"EMAIL": 1}


@pytest.mark.asyncio
async def test_finding_references_must_belong_to_its_connector(db, test_org) -> None:
    owner_connector_id = uuid4()
    other_connector_id = uuid4()
    owner_activity_id = uuid4()
    other_activity_id = uuid4()
    owner_log_file_id = uuid4()
    other_log_file_id = uuid4()
    finding_id = uuid4()

    for connector_id, provider in (
        (owner_connector_id, "openai"),
        (other_connector_id, "anthropic"),
    ):
        await db.execute(
            text(
                "INSERT INTO compliance_connector ("
                "id, organization_id, provider, secret_ref, secret_backend, "
                "secret_version, masked_key) VALUES ("
                ":id, :organization_id, :provider, :secret_ref, 'fernet', '1', "
                "'sk-...test')"
            ),
            {
                "id": connector_id,
                "organization_id": test_org.id,
                "provider": provider,
                "secret_ref": f"secret:{connector_id}",
            },
        )

    for activity_id, connector_id, provider_event_id in (
        (owner_activity_id, owner_connector_id, "owner-event"),
        (other_activity_id, other_connector_id, "other-event"),
    ):
        await db.execute(
            text(
                "INSERT INTO compliance_activity ("
                "id, connector_id, provider_event_id, event_type) VALUES ("
                ":id, :connector_id, :provider_event_id, 'request')"
            ),
            {
                "id": activity_id,
                "connector_id": connector_id,
                "provider_event_id": provider_event_id,
            },
        )

    for log_file_id, connector_id, provider_file_id in (
        (owner_log_file_id, owner_connector_id, "owner-file"),
        (other_log_file_id, other_connector_id, "other-file"),
    ):
        await db.execute(
            text(
                "INSERT INTO compliance_log_file ("
                "id, connector_id, event_type, provider_file_id) VALUES ("
                ":id, :connector_id, 'request', :provider_file_id)"
            ),
            {
                "id": log_file_id,
                "connector_id": connector_id,
                "provider_file_id": provider_file_id,
            },
        )

    insert_finding = text(
        "INSERT INTO compliance_finding ("
        "id, connector_id, activity_id, source_log_file_id, content_id, "
        "entity_type, severity, match_offset, match_length, value_hash) VALUES ("
        ":id, :connector_id, :activity_id, :source_log_file_id, :content_id, "
        "'EMAIL', 'high', 0, 4, :value_hash)"
    )
    await db.execute(
        insert_finding,
        {
            "id": finding_id,
            "connector_id": owner_connector_id,
            "activity_id": owner_activity_id,
            "source_log_file_id": owner_log_file_id,
            "content_id": "owner-content",
            "value_hash": uuid4().hex,
        },
    )

    cross_connector_references = (
        (
            "activity_id",
            other_activity_id,
            "activity belongs to another connector",
        ),
        (
            "source_log_file_id",
            other_log_file_id,
            "log file belongs to another connector",
        ),
    )
    for column, cross_connector_id, rejection_message in cross_connector_references:
        insert_values = {
            "id": uuid4(),
            "connector_id": owner_connector_id,
            "activity_id": owner_activity_id,
            "source_log_file_id": owner_log_file_id,
            "content_id": f"cross-insert-{column}",
            "value_hash": uuid4().hex,
        }
        insert_values[column] = cross_connector_id
        with pytest.raises(IntegrityError) as insert_error:
            async with db.begin_nested():
                await db.execute(insert_finding, insert_values)
        assert rejection_message in str(insert_error.value.orig)

        with pytest.raises(IntegrityError) as update_error:
            async with db.begin_nested():
                await db.execute(
                    text(
                        f"UPDATE compliance_finding SET {column} = :reference_id "
                        "WHERE id = :finding_id"
                    ),
                    {
                        "reference_id": cross_connector_id,
                        "finding_id": finding_id,
                    },
                )
        assert rejection_message in str(update_error.value.orig)

    await db.execute(
        text("DELETE FROM compliance_activity WHERE id = :id"),
        {"id": owner_activity_id},
    )
    await db.execute(
        text("DELETE FROM compliance_log_file WHERE id = :id"),
        {"id": owner_log_file_id},
    )
    references = (
        await db.execute(
            text(
                "SELECT activity_id, source_log_file_id "
                "FROM compliance_finding WHERE id = :id"
            ),
            {"id": finding_id},
        )
    ).one()
    assert references.activity_id is None
    assert references.source_log_file_id is None
