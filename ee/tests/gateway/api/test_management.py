from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql

from shim_enterprise.api.v1 import management
from shim_enterprise.billing.read_models import BillingReadModels
from shim.gateway.contracts.ids import TenantId


class AsyncRows:
    def __init__(self, rows) -> None:
        self.rows = rows
        self.close = AsyncMock()

    def __aiter__(self):
        async def iterate():
            for row in self.rows:
                yield row

        return iterate()


@pytest.mark.asyncio
async def test_profile_patch_can_clear_full_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = SimpleNamespace(
        id=uuid4(),
        organization_id=uuid4(),
        full_name="Previous name",
    )
    session = SimpleNamespace(commit=AsyncMock(), refresh=AsyncMock())
    expected = object()
    monkeypatch.setattr(management, "_audit", AsyncMock())
    monkeypatch.setattr(
        management,
        "_user_view",
        AsyncMock(return_value=expected),
    )

    result = await management.update_profile(
        management.UserPatch(full_name=None),
        user,
        session,
    )

    assert result is expected
    assert user.full_name is None
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_provider_patch_can_clear_nullable_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id = uuid4()
    row = SimpleNamespace(
        id=uuid4(),
        organization_id=tenant_id,
        provider="openai",
        name="Primary",
        monthly_limit_usd=10,
        verified_at=datetime.now(timezone.utc),
    )
    user = SimpleNamespace(organization_id=tenant_id)
    session = SimpleNamespace(commit=AsyncMock(), refresh=AsyncMock())
    monkeypatch.setattr(
        management,
        "_owned_provider_secret",
        AsyncMock(return_value=row),
    )
    monkeypatch.setattr(management, "_audit", AsyncMock())

    result = await management.update_provider_secret(
        row.id,
        management.ProviderSecretPatch(name=None, monthly_limit_usd=None),
        user,
        session,
    )

    assert result is row
    assert row.name is None
    assert row.monthly_limit_usd is None
    assert row.verified_at is not None
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["openai", "anthropic", "google"])
async def test_provider_key_rotation_clears_verification(
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
) -> None:
    tenant_id = uuid4()
    row = SimpleNamespace(
        id=uuid4(),
        organization_id=tenant_id,
        provider=provider,
        name="Primary",
        monthly_limit_usd=10,
        secret_ref="fernet:v2:old",
        secret_backend="fernet",
        secret_version="v2",
        masked_key="sk-old",
        verified_at=datetime.now(timezone.utc),
    )
    store = SimpleNamespace(
        rotate_secret=AsyncMock(return_value="fernet:v2:new"),
        delete_secret=AsyncMock(),
    )
    session = SimpleNamespace(commit=AsyncMock(), refresh=AsyncMock())
    monkeypatch.setattr(
        management, "_owned_provider_secret", AsyncMock(return_value=row)
    )
    monkeypatch.setattr(management, "_audit", AsyncMock())
    monkeypatch.setattr(management, "get_secret_store", lambda: store)

    await management.update_provider_secret(
        row.id,
        management.ProviderSecretPatch(key="sk-replacement-key"),
        SimpleNamespace(organization_id=tenant_id),
        session,
    )

    assert row.verified_at is None
    assert row.secret_ref == "fernet:v2:new"
    store.rotate_secret.assert_awaited_once_with(
        TenantId(tenant_id),
        "fernet:v2:old",
        "sk-replacement-key",
        expected_purpose=f"provider:{provider}:api-key",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["openai", "anthropic", "google"])
async def test_provider_secret_creation_uses_provider_purpose(
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
) -> None:
    tenant_id = uuid4()
    store = SimpleNamespace(put_secret=AsyncMock(return_value="fernet:v2:stored"))
    session = SimpleNamespace(
        add=lambda _row: None,
        flush=AsyncMock(),
        commit=AsyncMock(),
        refresh=AsyncMock(),
    )
    monkeypatch.setattr(management, "get_secret_store", lambda: store)
    monkeypatch.setattr(management, "_audit", AsyncMock())

    row = await management.create_provider_secret(
        management.ProviderSecretInput(provider=provider, key="provider-api-key"),
        SimpleNamespace(organization_id=tenant_id, is_verified=True),
        session,
    )

    assert row.organization_id == tenant_id
    assert row.provider == provider
    store.put_secret.assert_awaited_once_with(
        TenantId(tenant_id),
        f"provider:{provider}:api-key",
        "provider-api-key",
        {"provider": provider},
    )


@pytest.mark.asyncio
async def test_admin_can_revoke_a_pending_member_invite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id = uuid4()
    invite = SimpleNamespace(
        id=uuid4(),
        organization_id=tenant_id,
        role="member",
        accepted_at=None,
        revoked_at=None,
    )
    session = SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(scalar_one_or_none=lambda: invite)
        ),
        commit=AsyncMock(),
    )
    audit = AsyncMock()
    monkeypatch.setattr(management, "_audit", audit)

    await management.revoke_team_invite(
        invite.id,
        SimpleNamespace(organization_id=tenant_id, role="admin"),
        session,
    )

    assert invite.revoked_at is not None
    audit.assert_awaited_once()
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("user_role", "invite_role", "accepted", "status_code"),
    [("admin", "admin", False, 403), ("owner", "member", True, 409)],
)
async def test_invite_revocation_preserves_role_and_acceptance_boundaries(
    user_role: str,
    invite_role: str,
    accepted: bool,
    status_code: int,
) -> None:
    tenant_id = uuid4()
    invite = SimpleNamespace(
        id=uuid4(),
        organization_id=tenant_id,
        role=invite_role,
        accepted_at=datetime.now(timezone.utc) if accepted else None,
        revoked_at=None,
    )
    session = SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(scalar_one_or_none=lambda: invite)
        ),
        commit=AsyncMock(),
    )

    with pytest.raises(management.HTTPException) as error:
        await management.revoke_team_invite(
            invite.id,
            SimpleNamespace(organization_id=tenant_id, role=user_role),
            session,
        )

    assert error.value.status_code == status_code
    session.commit.assert_not_awaited()


@pytest.mark.parametrize("field", ["notify_targets", "enabled"])
def test_budget_patch_rejects_null_for_non_nullable_fields(field: str) -> None:
    with pytest.raises(ValidationError, match="field cannot be null"):
        management.BudgetPatch.model_validate({field: None})


@pytest.mark.parametrize("details", [{}, None, {"lifecycle_status": "legacy"}])
def test_request_activity_marks_missing_or_legacy_status_unknown(details) -> None:
    assert management._request_activity_status(details) == "unknown"


def test_request_activity_recognizes_estimated_usage() -> None:
    assert management._request_usage_estimated({"usage_estimated": True}) is True
    assert management._request_usage_estimated({"usage_estimated": False}) is False


@pytest.mark.asyncio
async def test_request_activity_is_tenant_scoped_filterable_and_safe() -> None:
    tenant_id = uuid4()
    summary_row = SimpleNamespace(
        requests=14,
        completed=6,
        provider_error=1,
        client_disconnected=1,
        timeout=1,
        cancelled=1,
        internal_error=0,
        rejected=2,
        failed=1,
        unknown=1,
        prompt_tokens=120,
        completion_tokens=40,
        pii_detected_requests=4,
        policy_failed=1,
        p95_completed_latency_ms=401.2,
        settled_spend_usd=Decimal("1.25000000"),
    )
    row = SimpleNamespace(
        id=uuid4(),
        request_id="req-safe",
        timestamp=datetime(2026, 7, 1, 12, tzinfo=timezone.utc),
        path="/v1/responses",
        model="gpt-5-nano",
        details={
            "lifecycle_status": "completed",
            "provider": "openai",
            "usage_estimated": False,
        },
        prompt_tokens=12,
        completion_tokens=4,
        cost_usd=0.125,
        latency_ms=350,
        pii_detected=True,
        tags=["research", "safe"],
        cost_center="research",
        team="platform",
    )
    session = SimpleNamespace(
        execute=AsyncMock(
            side_effect=(
                SimpleNamespace(one=lambda: summary_row),
                SimpleNamespace(all=lambda: [(row, Decimal("0.12500000"))]),
            )
        ),
    )
    start = datetime(2026, 7, 1, tzinfo=timezone.utc)
    end = datetime(2026, 7, 2, tzinfo=timezone.utc)

    page = await management.list_requests(
        start=start,
        end=end,
        status_filter="completed",
        model="gpt-5-nano",
        request_id="req-safe",
        pii_detected=True,
        tag=" Research ",
        cost_center=" Research ",
        limit=25,
        offset=5,
        user=SimpleNamespace(organization_id=tenant_id),
        session=session,
    )

    assert page.total == 14
    assert page.summary.requests == page.total
    assert page.limit == 25
    assert page.offset == 5
    assert page.generated_at.tzinfo is timezone.utc
    assert page.summary.technical_success_rate == pytest.approx(6 / 8)
    assert page.summary.technical_failures == 2
    assert page.summary.policy_rejections == 3
    assert page.summary.p95_completed_latency_ms == 401
    assert page.summary.settled_spend_usd == Decimal("1.25000000")
    assert page.summary.prompt_tokens == 120
    assert page.summary.completion_tokens == 40
    assert page.summary.pii_detected_requests == 4
    assert page.summary.status_counts.unknown == 1
    assert page.model_dump(mode="json")["summary"]["settled_spend_usd"] == (
        "1.25000000"
    )
    assert page.items[0].cost_usd == Decimal("0.12500000")
    assert page.items[0].model_dump(mode="json")["cost_usd"] == "0.12500000"
    assert set(management.RequestActivityView.model_fields) == {
        "request_id",
        "created_at",
        "endpoint",
        "model",
        "status",
        "prompt_tokens",
        "completion_tokens",
        "usage_estimated",
        "cost_usd",
        "latency_ms",
        "pii_detected",
        "tags",
        "cost_center",
        "provider",
        "team",
    }
    assert page.items[0].provider == "openai"
    assert page.items[0].usage_estimated is False
    assert page.items[0].team == "platform"

    summary_statement = session.execute.await_args_list[0].args[0]
    rows_statement = session.execute.await_args_list[1].args[0]
    for statement in (summary_statement, rows_statement):
        compiled = statement.compile(dialect=postgresql.dialect())
        sql = str(compiled)
        assert "request_logs.organization_id =" in sql
        assert "jsonb_array_elements_text" in sql
        assert "ILIKE" in sql
        assert "ESCAPE" in sql
        assert "request_logs.timestamp >=" in sql
        assert "request_logs.timestamp <=" in sql
        assert "request_logs.pii_detected = true" in sql
        assert tenant_id in compiled.params.values()
        assert "research" in compiled.params.values()
        assert "gpt-5-nano" in compiled.params.values()
    summary_compiled = summary_statement.compile(dialect=postgresql.dialect())
    summary_sql = str(summary_compiled)
    assert "percentile_cont" in summary_sql
    assert "IS NULL" in summary_sql
    assert "NOT IN" in summary_sql
    assert "spend_settlement" in summary_compiled.params.values()
    assert "usage_estimated" in summary_compiled.params.values()
    assert "LIMIT" not in summary_sql
    assert "OFFSET" not in summary_sql
    list_sql = str(rows_statement.compile(dialect=postgresql.dialect()))
    assert "request_logs.timestamp DESC, request_logs.id DESC" in list_sql
    assert "usage_ledger.event_type =" in list_sql


def test_request_activity_summary_has_null_technical_metrics_without_denominator() -> (
    None
):
    summary = management._request_activity_summary(
        SimpleNamespace(
            requests=2,
            completed=0,
            provider_error=0,
            client_disconnected=1,
            timeout=0,
            cancelled=0,
            internal_error=0,
            rejected=1,
            failed=0,
            unknown=0,
            prompt_tokens=0,
            completion_tokens=0,
            pii_detected_requests=0,
            policy_failed=0,
            p95_completed_latency_ms=None,
            settled_spend_usd=Decimal("0"),
        )
    )

    assert summary.technical_success_rate is None
    assert summary.p95_completed_latency_ms is None
    assert summary.policy_rejections == 1


@pytest.mark.asyncio
async def test_request_activity_rejects_an_inverted_period() -> None:
    with pytest.raises(management.HTTPException) as exc_info:
        await management.list_requests(
            start=datetime(2026, 7, 2, tzinfo=timezone.utc),
            end=datetime(2026, 7, 1, tzinfo=timezone.utc),
            status_filter=None,
            model=None,
            request_id=None,
            pii_detected=None,
            tag=None,
            cost_center=None,
            limit=50,
            offset=0,
            user=SimpleNamespace(organization_id=uuid4()),
            session=SimpleNamespace(),
        )

    assert exc_info.value.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "provider",
        "setting_name",
        "base_url",
        "verification_url",
        "expected_headers",
    ),
    [
        (
            "openai",
            "OPENAI_BASE_URL",
            "https://api.openai.com/v1/",
            "https://api.openai.com/v1/models",
            {"authorization": "Bearer sk-sensitive"},
        ),
        (
            "anthropic",
            "ANTHROPIC_BASE_URL",
            "https://api.anthropic.com/",
            "https://api.anthropic.com/v1/models",
            {
                "x-api-key": "sk-sensitive",
                "anthropic-version": "2023-06-01",
            },
        ),
        (
            "google",
            "GOOGLE_BASE_URL",
            "https://generativelanguage.googleapis.com/",
            "https://generativelanguage.googleapis.com/v1beta/models",
            {"x-goog-api-key": "sk-sensitive"},
        ),
    ],
)
async def test_provider_verification_updates_only_conclusive_results(
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
    setting_name: str,
    base_url: str,
    verification_url: str,
    expected_headers: dict[str, str],
) -> None:
    tenant_id = uuid4()
    row = SimpleNamespace(
        id=uuid4(),
        organization_id=tenant_id,
        provider=provider,
        secret_ref="fernet:v2:provider",
        verified_at=None,
    )
    user = SimpleNamespace(organization_id=tenant_id)
    session = SimpleNamespace(commit=AsyncMock(), refresh=AsyncMock())
    client = SimpleNamespace(
        get=AsyncMock(return_value=SimpleNamespace(status_code=200))
    )
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(http_client=client))
    )
    store = SimpleNamespace(get_secret=AsyncMock(return_value="sk-sensitive"))
    monkeypatch.setattr(
        management, "_owned_provider_secret", AsyncMock(return_value=row)
    )
    monkeypatch.setattr(management, "_audit", AsyncMock())
    monkeypatch.setattr(management, "get_secret_store", lambda: store)
    monkeypatch.setattr(management.settings, setting_name, base_url)

    await management.verify_provider_secret(row.id, request, user, session)

    assert row.verified_at is not None
    client.get.assert_awaited_once_with(
        verification_url,
        headers=expected_headers,
    )
    store.get_secret.assert_awaited_once_with(
        TenantId(tenant_id),
        "fernet:v2:provider",
        expected_purpose=f"provider:{provider}:api-key",
    )

    row.verified_at = datetime.now(timezone.utc)
    client.get.return_value = SimpleNamespace(status_code=429)
    with pytest.raises(management.HTTPException) as unavailable:
        await management.verify_provider_secret(row.id, request, user, session)
    assert unavailable.value.status_code == 503
    assert row.verified_at is not None

    client.get.return_value = SimpleNamespace(status_code=401)
    with pytest.raises(management.HTTPException) as rejected:
        await management.verify_provider_secret(row.id, request, user, session)
    assert rejected.value.status_code == 400
    assert row.verified_at is None


@pytest.mark.asyncio
async def test_request_export_streams_all_filtered_rows_and_neutralizes_formulas() -> (
    None
):
    tenant_id = uuid4()
    row = SimpleNamespace(
        id=uuid4(),
        request_id="=unsafe",
        timestamp=datetime(2026, 7, 1, tzinfo=timezone.utc),
        path="/v1/responses",
        model="gpt-5-nano",
        details={"provider": "openai", "lifecycle_status": "completed"},
        prompt_tokens=10,
        completion_tokens=2,
        latency_ms=100,
        pii_detected=False,
        tags=["+formula"],
        cost_center="platform",
        team="@ops",
    )
    rows = AsyncRows([(row, Decimal("0.000001"))])
    session = SimpleNamespace(
        scalar=AsyncMock(return_value=1),
        stream=AsyncMock(return_value=rows),
    )

    response = await management.export_requests(
        start=None,
        end=None,
        status_filter="completed",
        model=None,
        request_id=None,
        pii_detected=None,
        tag=None,
        cost_center=None,
        user=SimpleNamespace(organization_id=tenant_id),
        session=session,
    )
    content = b"".join([chunk async for chunk in response.body_iterator]).decode(
        "utf-8-sig"
    )

    assert "request_id,created_at" in content
    assert "'=unsafe" in content
    assert "'+formula" in content
    assert "'@ops" in content
    rows.close.assert_awaited_once()
    statement = session.stream.await_args.args[0]
    compiled = statement.compile(dialect=postgresql.dialect())
    count_compiled = session.scalar.await_args.args[0].compile(
        dialect=postgresql.dialect()
    )
    assert "request_logs.organization_id =" in str(compiled)
    assert tenant_id in compiled.params.values()
    assert "LIMIT" in str(compiled)
    assert 10_000 in compiled.params.values()
    assert "LIMIT" in str(count_compiled)
    assert 10_001 in count_compiled.params.values()
    assert "usage_ledger" not in str(count_compiled)


@pytest.mark.asyncio
async def test_request_export_rejects_oversized_window_before_query() -> None:
    end = datetime(2026, 8, 1, tzinfo=timezone.utc)
    session = SimpleNamespace(scalar=AsyncMock(), stream=AsyncMock())

    with pytest.raises(management.HTTPException, match="31 days") as error:
        await management.export_requests(
            start=end - timedelta(days=32),
            end=end,
            status_filter=None,
            model=None,
            request_id=None,
            pii_detected=None,
            tag=None,
            cost_center=None,
            user=SimpleNamespace(organization_id=uuid4()),
            session=session,
        )

    assert error.value.status_code == 422
    session.scalar.assert_not_awaited()
    session.stream.assert_not_awaited()


@pytest.mark.asyncio
async def test_request_export_rejects_more_than_10000_rows() -> None:
    session = SimpleNamespace(
        scalar=AsyncMock(return_value=10_001),
        stream=AsyncMock(),
    )

    with pytest.raises(management.HTTPException, match="10000 rows") as error:
        await management.export_requests(
            start=None,
            end=None,
            status_filter=None,
            model=None,
            request_id=None,
            pii_detected=None,
            tag=None,
            cost_center=None,
            user=SimpleNamespace(organization_id=uuid4()),
            session=session,
        )

    assert error.value.status_code == 422
    session.stream.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("group_by", "sql_fragment"),
    [
        ("provider", "request_lifecycle.provider"),
        ("team", "request_lifecycle.metadata"),
    ],
)
async def test_billing_breakdown_supports_request_time_provider_and_team(
    group_by: str,
    sql_fragment: str,
) -> None:
    session = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(all=lambda: []))
    )
    tenant_id = uuid4()

    await BillingReadModels().breakdown(
        session,
        tenant_id=TenantId(tenant_id),
        start_at=datetime(2026, 7, 1, tzinfo=timezone.utc),
        end_at=datetime(2026, 7, 2, tzinfo=timezone.utc),
        group_by=group_by,
        limit=10,
    )

    compiled = session.execute.await_args.args[0].compile(dialect=postgresql.dialect())
    sql = str(compiled)
    assert sql_fragment in sql
    assert "request_logs" not in sql
    assert "request_lifecycle.reconciled_at" in sql
    assert tenant_id in compiled.params.values()


def test_billing_exports_render_safe_csv_and_pdf() -> None:
    record = SimpleNamespace(
        key="=formula",
        request_count=2,
        prompt_tokens=20,
        completion_tokens=5,
        cost_usd=Decimal("0.12345678"),
    )
    start = datetime(2026, 7, 1, tzinfo=timezone.utc)
    end = datetime(2026, 7, 2, tzinfo=timezone.utc)

    assert "'=formula" in management._billing_breakdown_csv([record]).decode(
        "utf-8-sig"
    )
    assert management._billing_breakdown_pdf(
        [record], "provider", start, end
    ).startswith(b"%PDF")


@pytest.mark.asyncio
async def test_billing_export_rejects_more_than_31_days_before_query() -> None:
    end = datetime(2026, 8, 1, tzinfo=timezone.utc)
    session = SimpleNamespace(execute=AsyncMock())

    with pytest.raises(management.HTTPException, match="31 days") as error:
        await management.export_billing_breakdown(
            start_date=end - timedelta(days=32),
            end_date=end,
            group_by="model",
            format="csv",
            user=SimpleNamespace(organization_id=uuid4()),
            session=session,
        )

    assert error.value.status_code == 422
    session.execute.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation", "extra"),
    [
        (management.billing_usage, {}),
        (management.billing_breakdown, {"group_by": "model", "limit": 100}),
    ],
)
async def test_synchronous_billing_views_reject_more_than_31_days_before_query(
    operation,
    extra: dict[str, object],
) -> None:
    end = datetime(2026, 8, 1, tzinfo=timezone.utc)
    session = SimpleNamespace(execute=AsyncMock())

    with pytest.raises(management.HTTPException, match="31 days") as error:
        await operation(
            start_date=end - timedelta(days=32),
            end_date=end,
            user=SimpleNamespace(organization_id=uuid4()),
            session=session,
            **extra,
        )

    assert error.value.status_code == 422
    session.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_billing_usage_rejects_more_than_500_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daily_usage = AsyncMock(return_value=[object()] * 501)
    monkeypatch.setattr(BillingReadModels, "daily_usage", daily_usage)

    with pytest.raises(management.HTTPException, match="500 rows") as error:
        await management.billing_usage(
            start_date=None,
            end_date=None,
            user=SimpleNamespace(organization_id=uuid4()),
            session=SimpleNamespace(),
        )

    assert error.value.status_code == 422


@pytest.mark.asyncio
async def test_billing_export_caps_grouped_results() -> None:
    end = datetime(2026, 8, 1, tzinfo=timezone.utc)
    session = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(all=lambda: []))
    )

    response = await management.export_billing_breakdown(
        start_date=end - timedelta(days=30),
        end_date=end,
        group_by="model",
        format="csv",
        user=SimpleNamespace(organization_id=uuid4()),
        session=session,
    )

    statement = session.execute.await_args.args[0]
    compiled = statement.compile(dialect=postgresql.dialect())
    assert response.status_code == 200
    assert "LIMIT" in str(compiled)
    assert 501 in compiled.params.values()


@pytest.mark.asyncio
async def test_billing_export_rejects_more_than_500_groups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = SimpleNamespace(
        key="model",
        request_count=1,
        prompt_tokens=1,
        completion_tokens=1,
        cost_usd=Decimal("0.01"),
    )
    breakdown = AsyncMock(return_value=[record] * 501)
    monkeypatch.setattr(BillingReadModels, "breakdown", breakdown)

    with pytest.raises(management.HTTPException, match="500 groups") as error:
        await management.export_billing_breakdown(
            start_date=None,
            end_date=None,
            group_by="model",
            format="csv",
            user=SimpleNamespace(organization_id=uuid4()),
            session=SimpleNamespace(),
        )

    assert error.value.status_code == 422
