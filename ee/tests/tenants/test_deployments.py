"""Registered destinations reuse native transports, credentials and accounting."""

from contextlib import asynccontextmanager
import asyncio
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import io
import json
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4
from urllib.parse import urlsplit

import httpx
import pytest
import pytest_asyncio
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker

from shim.application import create_community_app
from shim.core.circuit_breaker import InMemoryCircuitBreaker
from shim.core.community_config import CommunitySettings
from shim.gateway.contracts.context import AuditPolicy, TenantPolicy, TierPolicy
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.gateway.request_policy import RequestPolicyContext, ResolvedRequestPolicy
from shim.rules import validate_rule_set
from shim_enterprise.api.enterprise_deps import DatabaseGatewayAuthenticator
from shim_enterprise.api.v1.management.deployments import (
    ModelDeploymentInput,
    ModelDeploymentView,
    create_model_deployment,
    check_model_deployment_health,
    update_model_deployment,
)
from shim_enterprise.billing.models import (
    UsageLedger,
    RequestLifecycle,
    QuotaPeriodUsage,
    SpendPeriodUsage,
    AuditIntent,
)
from shim_enterprise.billing.read_models import BillingReadModels
from shim_enterprise.core.config import settings
from shim_enterprise.gateway.pipeline.quota_reservation import (
    DurableAccountingCoordinator,
    DurableUsageLifecycle,
)
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.services.gateway.enterprise import EnterpriseGatewayService
from shim_enterprise.secrets.store import ManagedProviderCredentialResolver
from shim_enterprise.tenants.deployments import (
    DeploymentResolver,
    validate_deployment_url,
)
from shim_enterprise.tenants.models import (
    ModelDeployment,
    Organization,
    ProviderSecret,
    User,
    ApiKey,
)


# A request whose app has no HTTP client: only Bedrock deployments call out on write.
NO_HTTP = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(http_client=None)))


@pytest_asyncio.fixture
async def db(async_engine):
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    async with factory() as session:
        session.info["tenant_id"] = uuid4()
        yield session
        await session.rollback()
        for model in (
            ModelDeployment,
            AuditIntent,
            OutboxEvent,
            UsageLedger,
            RequestLifecycle,
            QuotaPeriodUsage,
            SpendPeriodUsage,
            ApiKey,
            ProviderSecret,
            User,
        ):
            await session.execute(
                delete(model).where(model.organization_id == session.info["tenant_id"])
            )
        await session.execute(
            delete(Organization).where(Organization.id == session.info["tenant_id"])
        )
        await session.commit()


@pytest_asyncio.fixture
async def test_org(db):
    row = Organization(
        id=db.info["tenant_id"], name="Registry test", slug=f"registry-{uuid4().hex}"
    )
    db.add(row)
    await db.flush()
    return row


@pytest.fixture
def origins(monkeypatch):
    monkeypatch.setattr(
        settings,
        "MODEL_DEPLOYMENT_ALLOWED_ORIGINS",
        ["https://a.internal", "https://b.internal"],
    )
    monkeypatch.setattr(settings, "MODEL_DEPLOYMENT_REQUIRED", True)


def test_destinations_only_use_operator_origins(origins, monkeypatch):
    assert validate_deployment_url("https://a.internal/v1/") == "https://a.internal/v1"
    for url in [
        "https://a.internal.evil/v1",
        "http://a.internal/v1",
        "https://key@a.internal/v1",
        "https://a.internal/v1?key=x",
        "https://a.internal/v1#x",
        "https://a.internal\\@evil/v1",
    ]:
        with pytest.raises(ValueError):
            validate_deployment_url(url)
    monkeypatch.setattr(
        settings, "MODEL_DEPLOYMENT_ALLOWED_ORIGINS", ["http://169.254.169.254"]
    )
    with pytest.raises(ValueError, match="forbidden"):
        validate_deployment_url("http://169.254.169.254/latest/meta-data")


async def _deployments(db, key):
    rows = []
    for host, model in [("a", "custom-model-v1"), ("b", "gpt-5.6-luna")]:
        secret = ProviderSecret(
            id=uuid4(),
            organization_id=key.organization_id,
            provider="openai",
            secret_ref=f"reference-{host}",
            secret_backend="fernet",
            secret_version="v2",
            masked_key="masked",
        )
        db.add(secret)
        await db.flush()
        row = ModelDeployment(
            organization_id=key.organization_id,
            alias=f"internal-{host}",
            provider="openai",
            upstream_model=model,
            base_url=f"https://{host}.internal/v1",
            provider_secret_id=secret.id,
            timeout_seconds=5,
            deployment_kind="internal",
            declared_version="sha256:operator-declared",
            owner="Platform",
            enabled=True,
        )
        db.add(row)
        rows.append(row)
    await db.flush()
    return rows


@asynccontextmanager
async def _gateway(db, key, handler, rules=None):
    await db.commit()
    factory = async_sessionmaker(db.bind, expire_on_commit=False)
    resolver = DeploymentResolver(factory)
    store = SimpleNamespace(
        get_secret=AsyncMock(
            side_effect=lambda tenant, ref, **kw: f"key-{str(ref)[-1]}"
        )
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as outbound:
        app = create_community_app(
            CommunitySettings(_env_file=None, SHIM_API_KEY="sk-shim-architecture-test"),
            http_client=outbound,
            event_stream=io.StringIO(),
        )
        async with app.router.lifespan_context(app):
            app.state.gateway_authenticator = DatabaseGatewayAuthenticator(factory)
            app.state.model_catalog = resolver.catalog
            kernel = app.state.gateway_service.kernel
            app.state.gateway_service = EnterpriseGatewayService(kernel, AsyncMock())
            kernel.policy_resolver = SimpleNamespace(
                resolve=AsyncMock(
                    return_value=ResolvedRequestPolicy(
                        tenant_id=key.organization_id,
                        tenant_policy=TenantPolicy(),
                        tier_policy=TierPolicy(),
                        audit_policy=AuditPolicy(mode="strict"),
                        request_policy=RequestPolicyContext(
                            rate_limit_key_hash=key.key_hash, tier="free"
                        ),
                        rules=rules,
                        pii_config={"email": True},
                    )
                )
            )
            kernel.prepare_inference = resolver.resolve
            lifecycle = DurableUsageLifecycle(DurableAccountingCoordinator(), factory)
            kernel.usage = kernel.postprocessor.usage = lifecycle
            circuits = {
                host + ".internal": InMemoryCircuitBreaker(failure_threshold=1)
                for host in ("a", "b")
            }
            for provider in ("openai", "anthropic"):
                execution = kernel.executions[provider]
                execution.credential_resolver = ManagedProviderCredentialResolver(
                    provider, store, factory
                )
                execution.circuit_for = lambda prepared: circuits.setdefault(
                    urlsplit(prepared.target.base_url).hostname,
                    InMemoryCircuitBreaker(failure_threshold=1),
                )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app),
                base_url="http://shim.test",
                headers={
                    "x-shim-key": "sk-shim-architecture-test",
                    "x-provider-key": "ignored-override",
                },
            ) as client:
                yield client, app, store


def _success(request, stream, protocol):
    body = json.loads(request.content)
    model = body["model"]
    assert "alice@example.com" not in request.content.decode()
    assert request.headers["authorization"] == f"Bearer key-{request.url.host[0]}"
    if protocol == "responses":
        payload = {
            "id": f"resp_{uuid4().hex}",
            "object": "response",
            "created_at": 1,
            "model": model,
            "status": "completed",
            "output": [],
            "usage": {"input_tokens": 4, "output_tokens": 2, "total_tokens": 6},
        }
        event = {
            "type": "response.completed",
            "sequence_number": 0,
            "response": payload,
        }
        content = f"event: response.completed\ndata: {json.dumps(event)}\n\n"
    else:
        payload = {
            "id": "chat-1",
            "object": "chat.completion",
            "created": 1,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "ok"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6},
        }
        content = f"data: {json.dumps(payload)}\n\ndata: [DONE]\n\n"
    return (
        httpx.Response(200, text=content, headers={"content-type": "text/event-stream"})
        if stream
        else httpx.Response(200, json=payload)
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["chat", "responses"])
@pytest.mark.parametrize("stream", [False, True])
async def test_two_endpoints_native_json_sse_credentials_and_unpriced_cost(
    db, test_api_key, origins, protocol, stream
):
    rows = await _deployments(db, test_api_key)
    calls = []

    def upstream(request):
        calls.append(request)
        return _success(request, stream, protocol)

    async with _gateway(db, test_api_key, upstream) as (client, _, _store):
        catalog = await client.get("/v1/models")
        assert [record["id"] for record in catalog.json()["data"]] == [
            "internal-a",
            "internal-b",
        ]
        for row in rows:
            payload = {"model": row.alias, "stream": stream}
            payload.update(
                {"input": "alice@example.com"}
                if protocol == "responses"
                else {"messages": [{"role": "user", "content": "alice@example.com"}]}
            )
            response = await client.post(
                "/v1/responses" if protocol == "responses" else "/v1/chat/completions",
                json=payload,
            )
            assert response.status_code == 200, response.text
            if stream:
                assert "text/event-stream" in response.headers["content-type"]
            else:
                assert response.json()["model"] == row.upstream_model
    assert [request.url.host for request in calls] == ["a.internal", "b.internal"]
    settlements = (
        (
            await db.execute(
                select(UsageLedger)
                .where(
                    UsageLedger.organization_id == test_api_key.organization_id,
                    UsageLedger.event_type == "spend_settlement",
                )
                .order_by(UsageLedger.requested_model)
            )
        )
        .scalars()
        .all()
    )
    assert len(settlements) == 2
    assert settlements[0].cost_usd == 0
    assert settlements[0].event_metadata["pricing"]["pricing_resolution"] == "unknown"
    assert "input_per_million" not in settlements[0].event_metadata["pricing"]
    assert (
        settlements[1].cost_usd > 0 and settlements[1].provider_model == "gpt-5.6-luna"
    )
    now = datetime.now(timezone.utc)
    daily = await BillingReadModels().daily_usage(
        db,
        tenant_id=test_api_key.organization_id,
        start_at=now - timedelta(days=1),
        end_at=now + timedelta(days=1),
    )
    assert sum(row.unpriced_requests for row in daily) == 1
    assert any(not row.as_public_record()["cost_complete"] for row in daily)


@pytest.mark.asyncio
async def test_registry_denials_are_audited_and_money_cap_cannot_be_bypassed(
    db, test_api_key, origins
):
    rows = await _deployments(db, test_api_key)
    secret = await db.get(ProviderSecret, rows[0].provider_secret_id)
    secret.monthly_limit_usd = Decimal("1")
    await db.flush()
    calls = []
    async with _gateway(db, test_api_key, lambda request: calls.append(request)) as (
        client,
        _,
        _,
    ):
        omitted = await client.post("/v1/responses", json={"input": "hello"})
        assert omitted.status_code == 403
        payload = {"model": "missing", "messages": []}
        assert (
            await client.post("/v1/chat/completions", json=payload)
        ).status_code == 403
        capped = await client.post(
            "/v1/chat/completions", json={**payload, "model": "internal-a"}
        )
        assert capped.status_code == 403, capped.text
        assert capped.json()["error"]["code"] == "MODEL_PRICE_UNKNOWN"
        test_api_key.allowed_models = []
        await db.commit()
        denied = await client.post(
            "/v1/chat/completions", json={**payload, "model": "internal-b"}
        )
        assert denied.status_code == 403
        assert (await client.get("/v1/models")).json()["data"] == []
    assert calls == []
    intents = (
        (
            await db.execute(
                select(OutboxEvent).where(
                    OutboxEvent.organization_id == test_api_key.organization_id
                )
            )
        )
        .scalars()
        .all()
    )
    reasons = {
        verdict["reason_code"]
        for event in intents
        for verdict in event.payload.get("policy_verdicts", [])
    }
    assert {
        "MODEL_NOT_REGISTERED",
        "MODEL_PRICE_UNKNOWN",
        "MODEL_NOT_ALLOWED",
    } <= reasons


@pytest.mark.asyncio
async def test_unhealthy_endpoint_does_not_retry_or_open_other_endpoint_circuit(
    db, test_api_key, origins
):
    await _deployments(db, test_api_key)
    calls = []

    def upstream(request):
        calls.append(request)
        if request.url.host == "b.internal":
            return httpx.Response(
                503, json={"error": {"message": "key-b private provider detail"}}
            )
        return _success(request, False, "chat")

    async with _gateway(db, test_api_key, upstream) as (client, _, _):
        for alias, expected in [
            ("internal-b", 503),
            ("internal-b", 503),
            ("internal-a", 200),
        ]:
            response = await client.post(
                "/v1/chat/completions",
                json={
                    "model": alias,
                    "messages": [{"role": "user", "content": "hello"}],
                },
            )
            assert response.status_code == expected, response.text
            assert "private provider detail" not in response.text
    assert [request.url.host for request in calls] == ["b.internal", "a.internal"]


@pytest.mark.asyncio
async def test_registry_tenant_isolation_and_credential_fk(db, test_api_key, origins):
    rows = await _deployments(db, test_api_key)
    other = Organization(name="Other", slug=f"other-{uuid4().hex}")
    db.add(other)
    await db.flush()
    owner = User(
        id=uuid4(),
        email=f"{uuid4().hex}@example.com",
        organization_id=other.id,
        is_active=True,
        role="owner",
    )
    db.add(owner)
    await db.flush()
    key = ApiKey(
        user_id=owner.id,
        organization_id=other.id,
        key_hash=hashlib.sha256(uuid4().bytes).hexdigest(),
        prefix="other",
        tier="free",
        is_active=True,
    )
    db.add(key)
    await db.flush()
    resolver = DeploymentResolver(
        async_sessionmaker(await db.connection(), expire_on_commit=False)
    )
    principal = AuthenticatedPrincipal(
        actor_type="api_key",
        api_key_id=key.id,
        authenticated_at=datetime.now(timezone.utc),
    )
    assert await resolver.catalog(principal, "openai") == []
    payload = ModelDeploymentInput(
        alias="other-alias",
        provider="openai",
        upstream_model="local",
        base_url="https://a.internal/v1",
        provider_secret_id=rows[0].provider_secret_id,
        deployment_kind="internal",
        declared_version="1",
        owner="Platform",
    )
    with pytest.raises(HTTPException) as error:
        await create_model_deployment(payload, NO_HTTP, owner, db)
    assert error.value.status_code == 404


@pytest.mark.asyncio
async def test_health_headers_are_bounded_and_output_view_survives_policy_change(
    db, test_api_key, test_user_with_org, origins, monkeypatch
):
    rows = await _deployments(db, test_api_key)
    store = SimpleNamespace(get_secret=AsyncMock(return_value="health-key"))
    monkeypatch.setattr(
        "shim_enterprise.api.v1.management._common.get_secret_store", lambda: store
    )

    def upstream(request):
        assert request.method == "GET" and request.url.path == "/v1/models"
        assert not db.in_transaction()
        return httpx.Response(503)

    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as client:
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(http_client=client))
        )
        result = await check_model_deployment_health(
            rows[0].id, request, test_user_with_org, db
        )
    assert result.health == "unhealthy" and result.health_checked_at is not None
    monkeypatch.setattr(settings, "MODEL_DEPLOYMENT_ALLOWED_ORIGINS", [])
    assert (
        ModelDeploymentView.model_validate(result).base_url == "https://a.internal/v1"
    )
    with pytest.raises(ValidationError):
        ModelDeploymentInput.model_validate(
            ModelDeploymentView.model_validate(result).model_dump(
                exclude={
                    "id",
                    "health",
                    "health_checked_at",
                    "created_at",
                    "updated_at",
                }
            )
        )


@pytest.mark.asyncio
async def test_deployment_writes_reread_the_row_under_a_lock(
    db, test_api_key, test_user_with_org, origins, monkeypatch
):
    from shim_enterprise.api.v1.management.deployments import (
        _owned_model_deployment as owned,
    )

    row = (await _deployments(db, test_api_key))[0]
    test_user_with_org.role = "admin"
    store = SimpleNamespace(get_secret=AsyncMock(return_value="health-key"))
    monkeypatch.setattr(
        "shim_enterprise.api.v1.management._common.get_secret_store", lambda: store
    )
    locks: list[bool] = []

    async def recording(*args, for_update=False):
        locks.append(for_update)
        return await owned(*args, for_update=for_update)

    monkeypatch.setattr(
        "shim_enterprise.api.v1.management.deployments._owned_model_deployment",
        recording,
    )
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200))
    ) as client:
        await check_model_deployment_health(
            row.id,
            SimpleNamespace(
                app=SimpleNamespace(state=SimpleNamespace(http_client=client))
            ),
            test_user_with_org,
            db,
        )
    await update_model_deployment(
        row.id,
        ModelDeploymentInput(
            alias=row.alias,
            provider=row.provider,
            upstream_model=row.upstream_model,
            base_url=row.base_url,
            provider_secret_id=row.provider_secret_id,
            deployment_kind="internal",
            declared_version="sha256:locked",
            owner="Platform",
        ),
        NO_HTTP,
        test_user_with_org,
        db,
    )

    # The probe runs unlocked; each read that leads to a write holds the row.
    assert locks == [False, True, True]


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["json", "sse", "count_tokens"])
async def test_registered_anthropic_native_messages_and_nonbillable_token_count(
    db, test_api_key, origins, operation
):
    rows = await _deployments(db, test_api_key)
    row = rows[0]
    secret = await db.get(ProviderSecret, row.provider_secret_id)
    secret.provider = row.provider = "anthropic"
    row.base_url = "https://a.internal"
    row.upstream_model = "private-claude"
    await db.flush()
    calls = []

    def upstream(request):
        calls.append(request)
        assert request.headers["x-api-key"] == "key-a"
        assert json.loads(request.content)["model"] == "private-claude"
        assert "alice@example.com" not in request.content.decode()
        if operation == "count_tokens":
            assert request.url.path == "/v1/messages/count_tokens"
            return httpx.Response(
                200, json={"input_tokens": 17}, headers={"request-id": "count-1"}
            )
        assert request.url.path == "/v1/messages"
        message = {
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "model": "private-claude",
            "content": [],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 4, "output_tokens": 2},
        }
        if operation == "json":
            return httpx.Response(200, json=message)
        events = [
            {
                "type": "message_start",
                "message": {
                    **message,
                    "stop_reason": None,
                    "usage": {"input_tokens": 4, "output_tokens": 0},
                },
            },
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": 2},
            },
            {"type": "message_stop"},
        ]
        return httpx.Response(
            200,
            text="".join(
                f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
                for event in events
            ),
            headers={"content-type": "text/event-stream"},
        )

    async with _gateway(db, test_api_key, upstream) as (client, _, _):
        payload = {
            "model": row.alias,
            "messages": [{"role": "user", "content": "alice@example.com"}],
        }
        if operation != "count_tokens":
            payload.update(max_tokens=10, stream=operation == "sse")
        response = await client.post(
            "/v1/messages/count_tokens"
            if operation == "count_tokens"
            else "/v1/messages",
            json=payload,
        )
        assert response.status_code == 200, response.text
        if operation == "sse":
            assert "event: message_stop" in response.text
        elif operation == "count_tokens":
            assert response.json() == {"input_tokens": 17}
            assert response.headers["request-id"] == "count-1"
        else:
            assert response.json()["model"] == "private-claude"
    assert len(calls) == 1
    ledger = (
        await db.scalars(
            select(UsageLedger).where(
                UsageLedger.organization_id == test_api_key.organization_id
            )
        )
    ).all()
    if operation == "count_tokens":
        assert ledger == []
        assert (
            await db.scalars(
                select(RequestLifecycle).where(
                    RequestLifecycle.organization_id == test_api_key.organization_id
                )
            )
        ).all() == []
        intent = (
            await db.scalars(
                select(AuditIntent).where(
                    AuditIntent.organization_id == test_api_key.organization_id,
                    AuditIntent.event_type == "completion",
                )
            )
        ).one()
        assert intent.usage_summary == {"input_tokens": 17, "billable_executions": 0}
        event = await db.get(OutboxEvent, intent.outbox_event_id)
        assert event.payload["event_type"] == "token_count"
        assert event.payload["extra"]["billable_execution"] is False
        assert event.payload["extra"]["deployment_id"] == str(row.id)
        assert event.payload["extra"]["deployment_kind"] == "internal"
        assert "alice@example.com" not in json.dumps(event.payload)
    else:
        assert (
            len([entry for entry in ledger if entry.event_type == "spend_settlement"])
            == 1
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["preflight", "completion"])
async def test_strict_token_count_audit_failure_never_creates_billable_usage(
    db, test_api_key, origins, monkeypatch, phase
):
    from shim_enterprise.gateway.pipeline.audit_intent import AuditIntentRepository

    rows = await _deployments(db, test_api_key)
    secret = await db.get(ProviderSecret, rows[0].provider_secret_id)
    secret.provider = rows[0].provider = "anthropic"
    rows[0].base_url = "https://a.internal"
    await db.flush()
    original_create = AuditIntentRepository.create

    async def create(session, *, organization_id, values):
        if values["event_type"] == phase:
            raise RuntimeError("audit storage unavailable")
        return await original_create(
            session, organization_id=organization_id, values=values
        )

    monkeypatch.setattr(AuditIntentRepository, "create", create)
    calls = []

    def upstream(request):
        calls.append(request)
        return httpx.Response(200, json={"input_tokens": 17})

    async with _gateway(db, test_api_key, upstream) as (client, _, _):
        response = await client.post(
            "/v1/messages/count_tokens", json={"model": rows[0].alias, "messages": []}
        )
    assert response.status_code == 503
    assert len(calls) == (0 if phase == "preflight" else 1)
    assert (
        await db.scalars(
            select(UsageLedger).where(
                UsageLedger.organization_id == test_api_key.organization_id
            )
        )
    ).all() == []
    assert (
        await db.scalars(
            select(RequestLifecycle).where(
                RequestLifecycle.organization_id == test_api_key.organization_id
            )
        )
    ).all() == []


@pytest.mark.asyncio
async def test_registry_management_requires_admin_and_audits_configuration(
    db, test_api_key, test_user_with_org, origins
):
    from fastapi import FastAPI
    from shim_enterprise.api.enterprise_deps import get_current_user
    from shim_enterprise.api.v1.management import router
    from shim_enterprise.core.database import get_db

    rows = await _deployments(db, test_api_key)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_current_user] = lambda: test_user_with_org
    app.dependency_overrides[get_db] = lambda: db
    payload = {
        "alias": "registered-model",
        "provider": "openai",
        "upstream_model": "custom-v1",
        "base_url": "https://a.internal/v1",
        "provider_secret_id": str(rows[0].provider_secret_id),
        "deployment_kind": "internal",
        "declared_version": "sha256:v1",
        "owner": "Platform",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="http://test"
    ) as client:
        assert (await client.get("/model-deployments")).status_code == 403
        assert (
            await client.post("/model-deployments", json=payload)
        ).status_code == 403
        test_user_with_org.role = "owner"
        created = await client.post("/model-deployments", json=payload)
        assert created.status_code == 201, created.text
        deployment_id = created.json()["id"]
        updated = await client.put(
            f"/model-deployments/{deployment_id}",
            json={**payload, "declared_version": "sha256:v2", "enabled": False},
        )
        assert updated.status_code == 200 and updated.json()["id"] == deployment_id
        invalid = await client.post(
            "/api-keys",
            json={"name": "unknown model", "allowed_models": ["missing-alias"]},
        )
        assert invalid.status_code == 422
        disabled = await client.post(
            "/api-keys",
            json={"name": "disabled model", "allowed_models": ["registered-model"]},
        )
        assert disabled.status_code == 422
        known = await client.post(
            "/api-keys", json={"name": "known model", "allowed_models": ["internal-a"]}
        )
        assert known.status_code == 200, known.text
        assert known.json()["allowed_models"] == ["internal-a"]
    events = (
        await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == test_api_key.organization_id
            )
        )
    ).all()
    extras = {event.payload["endpoint"]: event.payload["extra"] for event in events}
    created_config = extras["tenant.model_deployment_created"]["configuration"]
    assert created_config["declared_version"] == "sha256:v1"
    assert created_config["provider_secret_id"] == str(rows[0].provider_secret_id)
    assert "key" not in created_config
    updated = extras["tenant.model_deployment_updated"]
    assert (updated["before"], updated["after"]) == (
        {"declared_version": "sha256:v1", "enabled": True},
        {"declared_version": "sha256:v2", "enabled": False},
    )


@pytest.mark.asyncio
async def test_disabled_registry_alias_cannot_fall_back_to_public_catalog(
    db, test_api_key, origins, monkeypatch
):
    rows = await _deployments(db, test_api_key)
    rows[1].alias, rows[1].enabled = "gpt-5.6-luna", False
    await db.flush()
    monkeypatch.setattr(settings, "MODEL_DEPLOYMENT_REQUIRED", False)
    calls = []
    async with _gateway(db, test_api_key, lambda request: calls.append(request)) as (
        client,
        _,
        _,
    ):
        catalog = await client.get("/v1/models")
        assert "gpt-5.6-luna" not in {row["id"] for row in catalog.json()["data"]}
        denied = await client.post(
            "/v1/chat/completions", json={"model": "gpt-5.6-luna", "messages": []}
        )
        assert denied.status_code == 403
    assert calls == []


@pytest.mark.asyncio
async def test_a_model_id_that_is_not_id_shaped_is_refused_and_never_stored(
    db, test_api_key, origins, monkeypatch
):
    monkeypatch.setattr(settings, "MODEL_DEPLOYMENT_REQUIRED", False)
    models = [
        "gpt-5.6-luna-" + "x" * 13_000,
        "gpt-5.6-luna-john.doe@example.com",
        "gpt-5.6-luna-john doe",
        "gpt-5.6-luna-\nx",
    ]
    calls = []
    async with _gateway(db, test_api_key, lambda request: calls.append(request)) as (
        client,
        _,
        _,
    ):
        responses = [
            await client.post(
                "/v1/chat/completions",
                json={"model": model, "messages": [{"role": "user", "content": "hi"}]},
            )
            for model in models
        ]

    assert [response.status_code for response in responses] == [403] * len(models)
    assert {response.json()["error"]["code"] for response in responses} == {
        "MODEL_NOT_REGISTERED"
    }
    assert calls == []
    tenant = test_api_key.organization_id
    assert not (
        await db.scalars(
            select(RequestLifecycle.requested_model).where(
                RequestLifecycle.organization_id == tenant
            )
        )
    ).all()
    stored = [
        (event.payload["model"], intent.model)
        for event, intent in (
            await db.execute(
                select(OutboxEvent, AuditIntent)
                .join(AuditIntent, AuditIntent.outbox_event_id == OutboxEvent.id)
                .where(OutboxEvent.organization_id == tenant)
            )
        ).all()
    ]
    assert stored == [(None, None)] * len(models)


@pytest.mark.asyncio
async def test_health_probe_has_a_wall_clock_deadline(
    db, test_api_key, test_user_with_org, origins, monkeypatch
):
    rows = await _deployments(db, test_api_key)
    real_timeout = asyncio.timeout
    monkeypatch.setattr(
        "shim_enterprise.api.v1.management.deployments.asyncio.timeout",
        lambda seconds: real_timeout(0.01),
    )

    async def delayed_secret(*args, **kwargs):
        await asyncio.sleep(1)
        pytest.fail("health deadline was not enforced")

    monkeypatch.setattr(
        "shim_enterprise.api.v1.management._common.get_secret_store",
        lambda: SimpleNamespace(get_secret=delayed_secret),
    )
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(http_client=None))
    )
    result = await check_model_deployment_health(
        rows[0].id, request, test_user_with_org, db
    )
    assert result.health == "unhealthy"


@pytest.mark.asyncio
async def test_unhealthy_deployment_gets_no_traffic_until_healthy_or_updated(
    db, test_api_key, test_user_with_org, origins, monkeypatch
):
    rows = await _deployments(db, test_api_key)
    deployment = rows[1]
    deployment.alias = "gpt-5.6-luna"
    deployment.health, deployment.health_checked_at = (
        "unhealthy",
        datetime.now(timezone.utc),
    )
    await db.flush()
    monkeypatch.setattr(settings, "MODEL_DEPLOYMENT_REQUIRED", False)
    calls = []

    def upstream(request):
        calls.append(request.url.host)
        return _success(request, False, "chat")

    body = {"model": "gpt-5.6-luna", "messages": [{"role": "user", "content": "hello"}]}
    async with _gateway(db, test_api_key, upstream) as (client, _, _):
        refused = await client.post("/v1/chat/completions", json=body)
        listed = {row["id"] for row in (await client.get("/v1/models")).json()["data"]}
        deployment.health = "healthy"
        await db.commit()
        healthy = await client.post("/v1/chat/completions", json=body)
        deployment.health = "unhealthy"
        await db.commit()
        test_user_with_org.role = "admin"
        await update_model_deployment(
            deployment.id,
            ModelDeploymentInput(
                alias=deployment.alias,
                provider="openai",
                upstream_model=deployment.upstream_model,
                base_url=deployment.base_url,
                provider_secret_id=deployment.provider_secret_id,
                deployment_kind="internal",
                declared_version="sha256:updated",
                owner="Platform",
            ),
            NO_HTTP,
            test_user_with_org,
            db,
        )
        updated = await client.post("/v1/chat/completions", json=body)

    assert refused.status_code == 503, refused.text
    assert refused.json()["error"]["code"] == "DEPLOYMENT_UNHEALTHY"
    assert 295 <= int(refused.headers["retry-after"]) <= 300
    assert refused.headers["x-should-retry"] == "false"
    assert refused.headers["x-shim-request-id"].startswith("req_")
    assert "gpt-5.6-luna" not in listed
    assert (healthy.status_code, updated.status_code) == (200, 200)
    assert deployment.health == "unknown"
    assert calls == ["b.internal", "b.internal"]
    verdicts = [
        verdict
        for event in (
            await db.scalars(
                select(OutboxEvent).where(
                    OutboxEvent.organization_id == test_api_key.organization_id
                )
            )
        ).all()
        for verdict in event.payload.get("policy_verdicts", [])
    ]
    assert any(
        verdict["rule_id"] == "deployment.registry"
        and verdict["outcome"] == "deny"
        and verdict["reason_code"] == "DEPLOYMENT_UNHEALTHY"
        for verdict in verdicts
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("checked_ago", [timedelta(seconds=301), None])
async def test_an_unhealthy_mark_expires_and_the_deployment_serves_again(
    db, test_api_key, origins, checked_ago: timedelta | None
):
    deployment = (await _deployments(db, test_api_key))[1]
    deployment.health = "unhealthy"
    deployment.health_checked_at = (
        None if checked_ago is None else datetime.now(timezone.utc) - checked_ago
    )
    await db.flush()
    calls = []

    def upstream(request):
        calls.append(request.url.host)
        return _success(request, False, "chat")

    async with _gateway(db, test_api_key, upstream) as (client, _, _):
        served = await client.post(
            "/v1/chat/completions",
            json={
                "model": deployment.alias,
                "messages": [{"role": "user", "content": "hello"}],
            },
        )
        listed = {row["id"] for row in (await client.get("/v1/models")).json()["data"]}

    assert served.status_code == 200, served.text
    assert deployment.alias in listed
    assert calls == ["b.internal"]


_CATALOG_REQUESTS = {
    "openai": (
        "/v1/chat/completions",
        {"model": "gpt-5-nano", "messages": [{"role": "user", "content": "hi"}]},
    ),
    "anthropic": (
        "/v1/messages",
        {
            "model": "claude-sonnet-4-6",
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "hi"}],
        },
    ),
    "google": (
        "/v1beta/models/gemini-3.5-flash:generateContent",
        {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]},
    ),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", sorted(_CATALOG_REQUESTS))
async def test_tenant_can_refuse_customer_provider_keys_before_any_upstream_call(
    db, test_api_key, provider
):
    organization = await db.get(Organization, test_api_key.organization_id)
    organization.allow_customer_provider_keys = False
    calls = []
    async with _gateway(db, test_api_key, calls.append) as (client, _, store):
        path, payload = _CATALOG_REQUESTS[provider]
        refused = await client.post(path, json=payload)
    assert refused.status_code == 403, refused.text
    assert refused.headers["x-shim-error-code"] == "PROVIDER_KEY_NOT_ALLOWED"
    assert "Drop the x-provider-key header" in refused.text
    assert calls == []
    store.get_secret.assert_not_awaited()
    denial = await db.scalar(
        select(AuditIntent).where(
            AuditIntent.organization_id == test_api_key.organization_id,
            AuditIntent.event_type == "preflight",
        )
    )
    assert (denial.provider, denial.lifecycle_status) == (provider, "spend_denied")
    events = (
        await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == test_api_key.organization_id
            )
        )
    ).all()
    assert "PROVIDER_KEY_NOT_ALLOWED" in {
        verdict["reason_code"]
        for event in events
        for verdict in event.payload.get("policy_verdicts", [])
    }


@pytest.mark.asyncio
async def test_refusing_customer_keys_keeps_deployments_on_the_managed_key(
    db, test_api_key, origins
):
    rows = await _deployments(db, test_api_key)
    organization = await db.get(Organization, test_api_key.organization_id)
    organization.allow_customer_provider_keys = False
    calls = []

    def upstream(request):
        calls.append(request)
        return _success(request, False, "chat")

    async with _gateway(db, test_api_key, upstream) as (client, _, _store):
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": rows[0].alias,
                "messages": [{"role": "user", "content": "hi"}],
            },
        )
    assert response.status_code == 200, response.text
    assert [request.headers["authorization"] for request in calls] == ["Bearer key-a"]


@pytest.mark.asyncio
async def test_allowed_customer_key_still_wins_on_catalog_routes(db, test_api_key):
    organization = await db.get(Organization, test_api_key.organization_id)
    assert organization.allow_customer_provider_keys is True
    calls = []

    def upstream(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "id": "chat-1",
                "object": "chat.completion",
                "created": 1,
                "model": "gpt-5-nano",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 4, "completion_tokens": 2},
            },
        )

    async with _gateway(db, test_api_key, upstream) as (client, app, store):
        execution = app.state.gateway_service.kernel.executions["openai"]
        execution.circuit_for = lambda prepared: InMemoryCircuitBreaker()
        path, payload = _CATALOG_REQUESTS["openai"]
        response = await client.post(path, json=payload)
    assert response.status_code == 200, response.text
    assert [request.headers["authorization"] for request in calls] == [
        "Bearer ignored-override"
    ]
    store.get_secret.assert_not_awaited()


@pytest.mark.asyncio
async def test_customer_provider_keys_default_to_allowed_for_existing_rows(db):
    organization_id = db.info["tenant_id"]
    await db.execute(
        text("INSERT INTO organizations (id, name, slug) VALUES (:id, 'Old', :slug)"),
        {"id": organization_id, "slug": f"old-{organization_id}"},
    )
    assert await db.scalar(
        select(Organization.allow_customer_provider_keys).where(
            Organization.id == organization_id
        )
    )


@pytest.mark.asyncio
async def test_priced_deployments_settle_at_their_price_and_stop_hiding_totals(
    db, test_api_key, origins
):
    rows = await _deployments(db, test_api_key)
    for row in rows:
        row.input_price_per_million = Decimal("0.5")
        row.output_price_per_million = Decimal("1.5")
    rows[0].context_window = 50
    secret = await db.get(ProviderSecret, rows[0].provider_secret_id)
    secret.monthly_limit_usd = Decimal("1")
    await db.flush()
    calls = []

    def upstream(request):
        calls.append(request)
        return _success(request, False, "chat")

    async with _gateway(db, test_api_key, upstream) as (client, _, _):
        for row in rows:
            response = await client.post(
                "/v1/chat/completions",
                json={
                    "model": row.alias,
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )
            assert response.status_code == 200, response.text
        overflow = await client.post(
            "/v1/chat/completions",
            json={
                "model": "internal-a",
                "messages": [{"role": "user", "content": " ".join(["w"] * 51)}],
            },
        )
    assert overflow.status_code == 400
    assert overflow.json()["error"]["code"] == "MODEL_CONTEXT_EXCEEDED"
    assert len(calls) == 2
    settlements = (
        (
            await db.execute(
                select(UsageLedger).where(
                    UsageLedger.organization_id == test_api_key.organization_id,
                    UsageLedger.event_type == "spend_settlement",
                )
            )
        )
        .scalars()
        .all()
    )
    # 4 input tokens at $0.50 and 2 output tokens at $1.50, also for the catalog model.
    assert [settlement.cost_usd for settlement in settlements] == [
        Decimal("0.000005")
    ] * 2
    assert {
        settlement.event_metadata["pricing"]["pricing_resolution"]
        for settlement in settlements
    } == {"deployment"}
    now = datetime.now(timezone.utc)
    window = {
        "tenant_id": test_api_key.organization_id,
        "start_at": now - timedelta(days=1),
        "end_at": now + timedelta(days=1),
    }
    daily = await BillingReadModels().daily_usage(db, **window)
    providers = await BillingReadModels().breakdown(
        db, **window, group_by="provider", limit=None
    )
    assert all(row.as_public_record()["cost_complete"] for row in daily)
    assert [row.as_public_record()["cost_usd"] for row in providers] == [
        Decimal("0.00001")
    ]


@pytest.mark.parametrize(
    "fields",
    [
        {"input_price_per_million": "0.5"},
        {"output_price_per_million": "1.5"},
        {"input_price_per_million": "-1", "output_price_per_million": "1"},
        {"input_price_per_million": "0.123456789", "output_price_per_million": "1"},
        {"context_window": 0},
    ],
)
def test_deployment_input_refuses_a_lone_or_invalid_price_and_a_zero_window(fields):
    with pytest.raises(ValidationError):
        ModelDeploymentInput(
            alias="internal-x",
            provider="openai",
            upstream_model="custom-model-v1",
            base_url="https://a.internal/v1",
            provider_secret_id=uuid4(),
            deployment_kind="internal",
            declared_version="v1",
            owner="Platform",
            **fields,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fields",
    [
        {"input_price_per_million": Decimal("0.5")},
        {"output_price_per_million": Decimal("0.5")},
        {
            "input_price_per_million": Decimal("-1"),
            "output_price_per_million": Decimal("1"),
        },
        {"context_window": 0},
    ],
)
async def test_the_database_refuses_an_invalid_price_and_a_zero_window(
    db, test_api_key, origins, fields
):
    from sqlalchemy.exc import IntegrityError

    [row, _] = await _deployments(db, test_api_key)
    for field, value in fields.items():
        setattr(row, field, value)

    with pytest.raises(IntegrityError):
        await db.flush()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("internal_origins", "kinds"),
    [
        ([], {"internal-a": "internal", "internal-b": "internal"}),
        (["https://a.internal"], {"internal-a": "internal", "internal-b": "external"}),
    ],
)
async def test_an_internal_row_outside_the_operator_list_is_treated_as_external(
    db, test_api_key, origins, monkeypatch, internal_origins, kinds
):
    monkeypatch.setattr(settings, "MODEL_DEPLOYMENT_INTERNAL_ORIGINS", internal_origins)
    await _deployments(db, test_api_key)
    ids = {}
    async with _gateway(
        db, test_api_key, lambda request: _success(request, False, "chat")
    ) as (client, _, _):
        for alias in kinds:
            response = await client.post(
                "/v1/chat/completions",
                json={"model": alias, "messages": [{"role": "user", "content": "hi"}]},
            )
            assert response.status_code == 200, response.text
            ids[alias] = response.headers["x-shim-request-id"]

    for alias, kind in kinds.items():
        row = (
            await db.execute(
                select(RequestLifecycle).where(
                    RequestLifecycle.request_id == ids[alias]
                )
            )
        ).scalar_one()
        verdicts = {
            verdict["rule_id"]: verdict["reason_code"]
            for verdict in row.lifecycle_metadata["policy_verdicts"]
        }
        assert row.lifecycle_metadata["deployment_kind"] == kind
        assert verdicts.get("deployment.classification") == (
            None if kind == "internal" else "INTERNAL_ORIGIN_NOT_APPROVED"
        )


@pytest.mark.asyncio
async def test_relabelling_internal_relaxes_and_follows_the_operator_list(
    db, test_api_key, test_user_with_org, origins, monkeypatch
):
    from fastapi import FastAPI
    from shim_enterprise.api.enterprise_deps import get_current_user
    from shim_enterprise.api.v1.management import router
    from shim_enterprise.core.database import get_db

    rows = await _deployments(db, test_api_key)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_current_user] = lambda: test_user_with_org
    app.dependency_overrides[get_db] = lambda: db
    test_user_with_org.role = "owner"
    payload = {
        "alias": "relabelled",
        "provider": "openai",
        "upstream_model": "custom-v1",
        "base_url": "https://a.internal/v1",
        "provider_secret_id": str(rows[0].provider_secret_id),
        "deployment_kind": "internal",
        "declared_version": "sha256:v1",
        "owner": "Platform",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="http://test"
    ) as client:
        created = await client.post("/model-deployments", json=payload)
        assert created.status_code == 201, created.text
        url = f"/model-deployments/{created.json()['id']}"
        external = {**payload, "deployment_kind": "external"}
        assert (await client.put(url, json=external)).status_code == 200
        assert (await client.put(url, json=payload)).status_code == 200

        monkeypatch.setattr(
            settings, "MODEL_DEPLOYMENT_INTERNAL_ORIGINS", ["https://b.internal"]
        )
        refused = [
            await client.put(url, json=payload),
            await client.post("/model-deployments", json={**payload, "alias": "x"}),
        ]
        allowed = [
            await client.put(url, json=external),
            await client.post(
                "/model-deployments",
                json={**payload, "alias": "y", "base_url": "https://b.internal/v1"},
            ),
        ]
    assert [response.status_code for response in refused] == [422, 422]
    assert {response.json()["detail"] for response in refused} == {
        "Deployment origin is not an operator-approved internal origin"
    }
    assert [response.status_code for response in allowed] == [200, 201]
    events = (
        await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == test_api_key.organization_id
            )
        )
    ).all()
    extras = [
        (event.payload.get("endpoint"), event.payload.get("extra", {}))
        for event in events
    ]
    updates = [
        (extra["before"], extra["after"])
        for endpoint, extra in extras
        if endpoint == "tenant.model_deployment_updated"
    ]
    assert [
        extra["relaxed"]
        for endpoint, extra in extras
        if endpoint == "tenant.privacy_protection_relaxed"
    ] == [[f"deployment_kind.{created.json()['id']}"]]
    assert sorted(map(str, updates)) == sorted(
        map(
            str,
            [
                ({"deployment_kind": "internal"}, {"deployment_kind": "external"}),
                ({"deployment_kind": "external"}, {"deployment_kind": "internal"}),
                ({"deployment_kind": "internal"}, {"deployment_kind": "external"}),
            ],
        )
    )


@pytest.mark.asyncio
async def test_moving_an_internal_deployment_relaxes_without_an_operator_list(
    db, test_api_key, test_user_with_org, origins
):
    from fastapi import FastAPI
    from shim_enterprise.api.enterprise_deps import get_current_user
    from shim_enterprise.api.v1.management import router
    from shim_enterprise.core.database import get_db

    rows = await _deployments(db, test_api_key)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_current_user] = lambda: test_user_with_org
    app.dependency_overrides[get_db] = lambda: db
    test_user_with_org.role = "owner"
    payload = {
        "alias": "moved",
        "provider": "openai",
        "upstream_model": "custom-v1",
        "base_url": "https://a.internal/v1",
        "provider_secret_id": str(rows[0].provider_secret_id),
        "deployment_kind": "internal",
        "declared_version": "sha256:v1",
        "owner": "Platform",
    }
    moved = {**payload, "base_url": "https://b.internal/v1"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="http://test"
    ) as client:
        created = await client.post("/model-deployments", json=payload)
        url = f"/model-deployments/{created.json()['id']}"
        assert (await client.put(url, json=moved)).status_code == 200
        external = {**payload, "deployment_kind": "external"}
        assert (await client.put(url, json=external)).status_code == 200
    relaxed = [
        event.payload["extra"]["relaxed"]
        for event in await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == test_api_key.organization_id
            )
        )
        if event.payload.get("endpoint") == "tenant.privacy_protection_relaxed"
    ]
    # An internal target moved elsewhere sees what only an internal one may.
    assert relaxed == [[f"base_url.{created.json()['id']}"]]


_AZURE_BASE = "https://bank.openai.azure.com/openai/v1"


@pytest.fixture
def azure_suffix(monkeypatch):
    monkeypatch.setattr(
        settings, "MODEL_DEPLOYMENT_ALLOWED_ORIGIN_SUFFIXES", [".openai.azure.com"]
    )
    monkeypatch.setattr(settings, "MODEL_DEPLOYMENT_ALLOWED_ORIGINS", [])
    monkeypatch.setattr(settings, "MODEL_DEPLOYMENT_REQUIRED", True)


def test_an_origin_suffix_approves_https_hosts_under_it_on_443_only(
    azure_suffix, monkeypatch
):
    assert validate_deployment_url(_AZURE_BASE + "/") == _AZURE_BASE
    assert validate_deployment_url("https://bank.openai.azure.com:443/openai/v1")
    for url in [
        "http://bank.openai.azure.com/openai/v1",
        "https://bank.openai.azure.com:8443/openai/v1",
        "https://openai.azure.com/openai/v1",
        "https://evilopenai.azure.com/openai/v1",
        "https://bank.openai.azure.com.evil/openai/v1",
        "https://key@bank.openai.azure.com/openai/v1",
        "https://bank.openai.azure.com/openai/v1?api-version=1",
    ]:
        with pytest.raises(ValueError):
            validate_deployment_url(url)
    monkeypatch.setattr(
        settings, "MODEL_DEPLOYMENT_ALLOWED_ORIGIN_SUFFIXES", [".google.internal"]
    )
    with pytest.raises(ValueError, match="forbidden"):
        validate_deployment_url("https://metadata.google.internal/v1")


def _azure_input(**fields):
    return ModelDeploymentInput.model_validate(
        {
            "alias": "azure-mini",
            "provider": "openai",
            "upstream": "azure_openai",
            "upstream_model": "kurum-mini",
            "base_url": _AZURE_BASE,
            "provider_secret_id": str(uuid4()),
            "deployment_kind": "external",
            "declared_version": "v1",
            "owner": "Platform",
            **fields,
        }
    )


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"provider": "anthropic"}, "uses provider openai"),
        ({"deployment_kind": "internal"}, "is external"),
        ({"base_url": "https://bank.openai.azure.com/v1"}, "ends in /openai/v1"),
        ({"upstream_model": "kurum mini"}, "Azure deployment name"),
        ({"price_model": "kurum-mini"}, "not a catalog model for this provider"),
        ({"price_model": "claude-sonnet-4-5"}, "not a catalog model"),
        ({"cache_read_price_per_million": "0.1"}, "cache price needs"),
    ],
)
def test_an_azure_deployment_is_checked_rule_by_rule(azure_suffix, fields, message):
    assert _azure_input(price_model="gpt-5.6-luna").upstream == "azure_openai"
    with pytest.raises(ValidationError, match=message):
        _azure_input(**fields)


def test_a_view_survives_a_price_model_the_catalog_dropped(azure_suffix):
    view = ModelDeploymentView.model_validate(
        {
            **_azure_input().model_dump(),
            "price_model": "retired-model",
            "id": uuid4(),
            "health": "unknown",
            "health_checked_at": None,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
    )

    assert view.price_model == "retired-model"


async def _azure_row(db, key, *, provider="openai", **fields):
    secret = ProviderSecret(
        id=uuid4(),
        organization_id=key.organization_id,
        provider=provider,
        secret_ref="reference-z",
        secret_backend="fernet",
        secret_version="v2",
        masked_key="masked",
    )
    db.add(secret)
    await db.flush()
    row = ModelDeployment(
        organization_id=key.organization_id,
        alias="azure-mini",
        provider="openai",
        upstream_model="kurum-mini",
        base_url=_AZURE_BASE,
        provider_secret_id=secret.id,
        timeout_seconds=5,
        deployment_kind="external",
        declared_version="v1",
        owner="Platform",
        **fields,
    )
    db.add(row)
    await db.flush()
    return row, secret


@pytest.mark.asyncio
async def test_existing_rows_default_to_generic_api_keys_and_the_database_checks(
    db, test_api_key, origins
):
    from sqlalchemy.exc import IntegrityError

    [row, _] = await _deployments(db, test_api_key)
    await db.refresh(row)
    secret = await db.get(ProviderSecret, row.provider_secret_id)
    await db.refresh(secret)

    assert (row.upstream, row.price_model, row.cache_read_price_per_million) == (
        "generic",
        None,
        None,
    )
    for field, value in [
        ("cache_read_price_per_million", Decimal("0.1")),
        ("upstream", "bedrock"),
    ]:
        async with db.begin_nested():
            setattr(row, field, value)
            with pytest.raises(IntegrityError):
                await db.flush()
        await db.refresh(row)


@pytest.mark.asyncio
async def test_a_put_without_the_new_fields_keeps_them(
    db, test_api_key, test_user_with_org, azure_suffix
):
    from fastapi import FastAPI
    from shim_enterprise.api.enterprise_deps import get_current_user
    from shim_enterprise.api.v1.management import router
    from shim_enterprise.core.database import get_db

    row, secret = await _azure_row(db, test_api_key)
    entra = ProviderSecret(
        id=uuid4(),
        organization_id=test_api_key.organization_id,
        provider="azure_entra",
        secret_ref="reference-e",
        secret_backend="fernet",
        secret_version="v2",
        masked_key="entra:000...00a1",
    )
    db.add(entra)
    await db.flush()
    test_user_with_org.role = "owner"
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_current_user] = lambda: test_user_with_org
    app.dependency_overrides[get_db] = lambda: db
    payload = {
        "alias": "azure-mini",
        "provider": "openai",
        "upstream_model": "kurum-mini",
        "base_url": _AZURE_BASE,
        "provider_secret_id": str(secret.id),
        "deployment_kind": "external",
        "declared_version": "v1",
        "owner": "Platform",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="http://test"
    ) as client:
        set_up = await client.put(
            f"/model-deployments/{row.id}",
            json={
                **payload,
                "upstream": "azure_openai",
                "price_model": "gpt-5.6-luna",
                "input_price_per_million": "1",
                "output_price_per_million": "2",
                "cache_read_price_per_million": "0.1",
            },
        )
        prices = {"input_price_per_million": "1", "output_price_per_million": "2"}
        kept = await client.put(
            f"/model-deployments/{row.id}",
            json={**payload, **prices, "declared_version": "v2"},
        )
        # The kept cache price still needs the input price an old client drops.
        unpriced = await client.put(f"/model-deployments/{row.id}", json=payload)
        cleared = await client.put(
            f"/model-deployments/{row.id}",
            json={
                **payload,
                "upstream": "generic",
                "price_model": None,
                "cache_read_price_per_million": None,
            },
        )
        generic_entra = await client.put(
            f"/model-deployments/{row.id}",
            json={**payload, "provider_secret_id": str(entra.id)},
        )

    assert set_up.status_code == 200, set_up.text
    assert {
        key: kept.json()[key]
        for key in ("upstream", "price_model", "cache_read_price_per_million")
    } == {
        "upstream": "azure_openai",
        "price_model": "gpt-5.6-luna",
        "cache_read_price_per_million": "0.10000000",
    }
    assert unpriced.status_code == 422
    assert "A cache price needs" in unpriced.text
    assert cleared.status_code == 200, cleared.text
    assert (cleared.json()["upstream"], cleared.json()["price_model"]) == (
        "generic",
        None,
    )
    assert generic_entra.status_code == 422
    assert generic_entra.json()["detail"] == (
        "An Entra credential can only serve an Azure OpenAI deployment"
    )


@pytest.mark.asyncio
async def test_an_azure_deployment_is_called_at_its_deployment_and_priced_by_its_model(
    db, test_api_key, azure_suffix
):
    from shim.billing.pricing import compute_cost_usd

    await _azure_row(
        db, test_api_key, upstream="azure_openai", price_model="gpt-5.6-luna"
    )
    seen = []

    def upstream(request):
        body = json.loads(request.content)
        seen.append((str(request.url), body["model"], request.headers["authorization"]))
        return httpx.Response(
            200,
            json={
                "id": "chat-1",
                "object": "chat.completion",
                "created": 1,
                "model": body["model"],
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 1_000,
                    "completion_tokens": 100,
                    "total_tokens": 1_100,
                    "prompt_tokens_details": {"cached_tokens": 600},
                },
            },
        )

    async with _gateway(db, test_api_key, upstream) as (client, _, _):
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "azure-mini",
                "messages": [{"role": "user", "content": "hi"}],
            },
        )
    assert response.status_code == 200, response.text
    assert seen == [(f"{_AZURE_BASE}/chat/completions", "kurum-mini", "Bearer key-z")]
    [settlement] = (
        await db.scalars(
            select(UsageLedger).where(
                UsageLedger.organization_id == test_api_key.organization_id,
                UsageLedger.event_type == "spend_settlement",
            )
        )
    ).all()
    assert settlement.cost_usd == compute_cost_usd(
        "gpt-5.6-luna", 1_000, 100, cache=(600, 0, 0)
    )
    assert settlement.cost_usd < compute_cost_usd("gpt-5.6-luna", 1_000, 100)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("upstream", "status", "health"),
    [
        ("azure_openai", 200, "healthy"),
        ("azure_openai", 404, "healthy"),
        ("azure_openai", 401, "unhealthy"),
        ("generic", 404, "unhealthy"),
    ],
)
async def test_an_azure_health_check_counts_a_404_as_reachable(
    db,
    test_api_key,
    test_user_with_org,
    azure_suffix,
    monkeypatch,
    upstream,
    status,
    health,
):
    row, _ = await _azure_row(db, test_api_key, upstream=upstream)
    store = SimpleNamespace(get_secret=AsyncMock(return_value="azure-key"))
    monkeypatch.setattr(
        "shim_enterprise.api.v1.management._common.get_secret_store", lambda: store
    )
    seen = []

    def answer(request):
        seen.append((request.url.path, request.headers["authorization"]))
        return httpx.Response(status)

    async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as client:
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(http_client=client))
        )
        result = await check_model_deployment_health(
            row.id, request, test_user_with_org, db
        )

    assert result.health == health
    assert seen == [("/openai/v1/models", "Bearer azure-key")]


@pytest.mark.asyncio
async def test_an_entra_backed_health_check_sends_the_entra_token(
    db, test_api_key, test_user_with_org, azure_suffix, monkeypatch
):
    row, _ = await _azure_row(
        db, test_api_key, provider="azure_entra", upstream="azure_openai"
    )
    stored = json.dumps(
        {
            "tenant_id": "contoso.onmicrosoft.com",
            "client_id": "00000000-0000-0000-0000-0000000000a1",
            "client_secret": "entra-secret",
            "scope": "https://cognitiveservices.azure.com/.default",
        }
    )
    store = SimpleNamespace(get_secret=AsyncMock(return_value=stored))
    monkeypatch.setattr(
        "shim_enterprise.api.v1.management._common.get_secret_store", lambda: store
    )
    monkeypatch.setattr(settings, "SHIM_AZURE_AUTHORITY_HOST", "https://login.test")
    seen = []

    def answer(request):
        seen.append(request.url.path)
        if request.url.host == "login.test":
            return httpx.Response(
                200,
                json={
                    "access_token": "entra-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        assert request.headers["authorization"] == "Bearer entra-token"
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as client:
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(http_client=client))
        )
        result = await check_model_deployment_health(
            row.id, request, test_user_with_org, db
        )

    assert result.health == "healthy"
    assert seen == ["/contoso.onmicrosoft.com/oauth2/v2.0/token", "/openai/v1/models"]
    assert store.get_secret.await_args.kwargs == {
        "expected_purpose": "provider:openai:azure-entra-client"
    }


def _route(rule_id="cheap_start", state="monitor", scope=None, **match) -> dict:
    return {
        "id": rule_id,
        "name": "Short starts",
        "kind": "route",
        "action": "route",
        "state": state,
        "scope": scope or {},
        "match": {"from": ["internal-a"], "to": "internal-b", **match},
    }


def _rules(*rules: dict):
    return validate_rule_set({"revision": 3, "rules": list(rules)})


_FOREIGN = [
    {
        "id": f"foreign_{on}",
        "name": "Owned by another feature",
        "kind": "route",
        "action": "route",
        "state": "enforced",
        "match": {"on": on, "to": "internal-b"},
    }
    for on in ("shadow", "degrade", "unavailable", "capacity", "split", "size")
]


async def _routed(db, key, rules, *texts, headers=None):
    """Each text as a chat's first message; the hosts reached and lifecycle rows."""

    hosts = []

    def upstream(request):
        hosts.append(request.url.host)
        return _success(request, False, "chat")

    ids = []
    async with _gateway(db, key, upstream, rules) as (client, _, _):
        for text in texts:
            response = await client.post(
                "/v1/chat/completions",
                headers=headers or {},
                json={
                    "model": "internal-a",
                    "messages": [{"role": "user", "content": text}],
                },
            )
            assert response.status_code == 200, response.text
            ids.append(response.headers["x-shim-request-id"])
    rows = [
        (
            await db.execute(
                select(RequestLifecycle).where(RequestLifecycle.request_id == id_)
            )
        ).scalar_one()
        for id_ in ids
    ]
    return hosts, [row.lifecycle_metadata.get("route_decision") for row in rows], rows


@pytest.mark.asyncio
async def test_without_route_rules_the_resolver_decides_nothing(
    db, test_api_key, origins
):
    await _deployments(db, test_api_key)
    term = {
        "id": "falcon",
        "name": "Project names",
        "kind": "term",
        "action": "monitor",
        "state": "monitor",
        "match": {"terms": ["Project Falcon"]},
    }

    for rules in (None, _rules(term), _rules(*_FOREIGN)):
        hosts, decisions, rows = await _routed(db, test_api_key, rules, "hi")
        assert hosts == ["a.internal"]
        assert decisions == [None]
        assert "route_decision" not in rows[0].lifecycle_metadata


@pytest.mark.asyncio
async def test_a_monitor_rule_records_where_it_would_route_and_changes_nothing(
    db, test_api_key, origins
):
    await _deployments(db, test_api_key)

    hosts, decisions, rows = await _routed(
        db,
        test_api_key,
        _rules(_route(when={"max_start_chars": 400})),
        "short",
        "x" * 401,
        headers={"x-shim-conversation-id": "conv-1"},
    )

    assert hosts == ["a.internal", "a.internal"]
    conversation = decisions[0].pop("conversation_id")
    assert decisions == [
        {
            "rule_id": "cheap_start",
            "state": "monitor",
            "from": "internal-a",
            "to": "internal-b",
            "reason": "max_start_chars",
            "outcome": "would_route",
        },
        None,
    ]
    # The header is kept only as its keyed digest, the same one for every turn.
    assert re.fullmatch(r"[0-9a-f]{16}", conversation)
    _, [again], _ = await _routed(
        db,
        test_api_key,
        _rules(_route(when={"max_start_chars": 400})),
        "another short start",
        headers={"x-shim-conversation-id": "conv-1"},
    )
    assert again["conversation_id"] == conversation
    assert rows[0].lifecycle_metadata["rule_matches"] == [
        {
            "rule_id": "cheap_start",
            "kind": "route",
            "action": "route",
            "state": "monitor",
            "count": 1,
        }
    ]
    verdicts = {
        verdict["rule_id"]: verdict["reason_code"]
        for verdict in rows[0].lifecycle_metadata["policy_verdicts"]
    }
    assert verdicts["rule.cheap_start"] == "RULE_WOULD_ROUTE"


@pytest.mark.asyncio
async def test_an_enforced_rule_sends_the_conversation_to_its_target(
    db, test_api_key, origins
):
    await _deployments(db, test_api_key)
    rules = _rules(_route(state="enforced", when={"keywords_any": ["fatura"]}))
    models = []

    def upstream(request):
        models.append((request.url.host, json.loads(request.content)["model"]))
        return _success(request, False, "chat")

    history = [
        {"role": "user", "content": "Faturalarımı özetle"},
        {"role": "assistant", "content": "Tamam."},
    ]
    async with _gateway(db, test_api_key, upstream, rules) as (client, _, _):
        for messages in (
            history[:1],
            [*history, {"role": "user", "content": "Uzun bir ikinci soru " * 50}],
            [{"role": "user", "content": "Raporu özetle"}],
        ):
            response = await client.post(
                "/v1/chat/completions",
                json={"model": "internal-a", "messages": messages},
            )
            assert response.status_code == 200, response.text
        routed = response.headers["x-shim-request-id"]

    assert models == [
        ("b.internal", "gpt-5.6-luna"),
        ("b.internal", "gpt-5.6-luna"),
        ("a.internal", "custom-model-v1"),
    ]
    row = (
        await db.execute(
            select(RequestLifecycle).where(RequestLifecycle.request_id == routed)
        )
    ).scalar_one()
    assert row.requested_model == "internal-a"
    assert "route_decision" not in row.lifecycle_metadata


@pytest.mark.asyncio
async def test_a_routed_request_keeps_the_client_model_and_records_the_decision(
    db, test_api_key, origins
):
    rows = await _deployments(db, test_api_key)

    hosts, [decision], [row] = await _routed(
        db, test_api_key, _rules(_route(state="enforced")), "short"
    )

    assert hosts == ["b.internal"]
    assert decision["outcome"] == "routed"
    assert decision["reason"] == "always"
    assert len(decision["conversation_id"]) == 16
    assert row.requested_model == "internal-a"
    assert row.lifecycle_metadata["deployment_id"] == str(rows[1].id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "problem", ["allowlist", "disabled", "unhealthy", "provider", "bedrock"]
)
async def test_a_target_the_key_or_registry_refuses_leaves_the_request_alone(
    db, test_api_key, origins, problem
):
    rows = await _deployments(db, test_api_key)
    if problem == "allowlist":
        test_api_key.allowed_models = ["internal-a"]
    elif problem == "disabled":
        rows[1].enabled = False
    elif problem == "unhealthy":
        rows[1].health = "unhealthy"
        rows[1].health_checked_at = datetime.now(timezone.utc)
    elif problem == "provider":
        rows[1].provider = "anthropic"
    else:
        # The region lock runs only where a request starts, never on a move.
        rows[1].upstream, rows[1].aws_region = "aws_bedrock", "eu-central-1"
    await db.flush()

    hosts, [decision], _ = await _routed(
        db, test_api_key, _rules(_route(state="enforced")), "short"
    )

    assert hosts == ["a.internal"]
    assert decision["outcome"] == (
        "not_allowed_for_key" if problem == "allowlist" else "target_unavailable"
    )


@pytest.mark.asyncio
async def test_enforced_rules_decide_before_monitor_ones_and_the_first_match_wins(
    db, test_api_key, origins
):
    await _deployments(db, test_api_key)
    cases = [
        ([_route("watch"), _route("send", state="enforced")], "send"),
        (
            [
                _route("long_only", when={"min_start_chars": 400}),
                _route("first"),
                _route("second"),
            ],
            "first",
        ),
        ([_route("tagged", scope={"tags": ["app-x"]}), _route("any")], "tagged"),
        ([_route("other_tag", scope={"tags": ["app-y"]}), _route("any")], "any"),
        ([_route("other_model", **{"from": ["internal-b"], "to": "internal-a"})], None),
    ]

    for rules, decided in cases:
        _, [decision], _ = await _routed(
            db, test_api_key, _rules(*rules), "short", headers={"x-shim-tag": "app-x"}
        )
        assert (decision or {}).get("rule_id") == decided, rules


@pytest.mark.asyncio
async def test_foreign_on_values_route_exactly_like_the_set_without_them(
    db, test_api_key, origins
):
    await _deployments(db, test_api_key)
    own = [_route("watch"), _route("send", state="enforced", when={"tools": False})]

    without = await _routed(db, test_api_key, _rules(*own), "short")
    with_foreign = await _routed(db, test_api_key, _rules(*_FOREIGN, *own), "short")

    assert without[0] == with_foreign[0] == ["b.internal"]
    for decision in (without[1][0], with_foreign[1][0]):
        decision.pop("conversation_id")
    assert without[1] == with_foreign[1]


@pytest.mark.asyncio
async def test_a_destination_rule_still_refuses_a_routed_request(
    db, test_api_key, origins
):
    rows = await _deployments(db, test_api_key)
    rows[1].deployment_kind = "external"
    await db.flush()
    destination = {
        "id": "mail_stays_inside",
        "name": "Mail stays inside",
        "kind": "destination",
        "action": "block",
        "state": "enforced",
        "scope": {"deployment_kinds": ["external"]},
        "match": {"entity_types": ["EMAIL_ADDRESS"]},
    }
    hosts = []
    async with _gateway(
        db,
        test_api_key,
        lambda request: (
            hosts.append(request.url.host) or _success(request, False, "chat")
        ),
        _rules(destination, _route(state="enforced")),
    ) as (client, _, _):
        refused = await client.post(
            "/v1/chat/completions",
            json={
                "model": "internal-a",
                "messages": [{"role": "user", "content": "alice@example.com"}],
            },
        )
        served = await client.post(
            "/v1/chat/completions",
            json={
                "model": "internal-a",
                "messages": [{"role": "user", "content": "no address here"}],
            },
        )

    assert refused.status_code == 400, refused.text
    assert refused.json()["error"]["code"] == "RULE_BLOCKED"
    assert served.status_code == 200, served.text
    assert hosts == ["b.internal"]


def _lane(state: str = "enforced", min_input_tokens: int = 256) -> dict:
    return {
        "id": "uzun_serit",
        "name": "Long requests to replica 2",
        "kind": "route",
        "action": "route",
        "state": state,
        "match": {
            "on": "size",
            "from": "internal-a",
            "to": "internal-b",
            "min_input_tokens": min_input_tokens,
        },
    }


def _measure(text: str) -> int:
    from shim_enterprise.tenants.deployments import approximate_input_tokens

    # The payload the resolver measures: the client's, with the upstream model.
    return approximate_input_tokens(
        {"model": "custom-model-v1", "messages": [{"role": "user", "content": text}]}
    )


async def _replicas(db, key):
    rows = await _deployments(db, key)
    rows[1].upstream_model = rows[0].upstream_model
    await db.flush()
    return rows


@pytest.mark.asyncio
async def test_a_request_at_the_lane_threshold_goes_to_the_lane_and_one_below_stays(
    db, test_api_key, origins
):
    await _replicas(db, test_api_key)
    long = "ç" * 2_000
    threshold = _measure(long)
    short = "ç" * 1_995
    assert _measure(short) == threshold - 3

    hosts, decisions, _ = await _routed(
        db, test_api_key, _rules(_lane(min_input_tokens=threshold)), long, short
    )

    assert hosts == ["b.internal", "a.internal"]
    decision = decisions[0]
    assert decision.pop("conversation_id")
    assert decision == {
        "rule_id": "uzun_serit",
        "state": "enforced",
        "from": "internal-a",
        "to": "internal-b",
        "reason": "long_request",
        "input_tokens_approx": threshold,
    }
    assert decisions[1] is None


@pytest.mark.asyncio
async def test_a_monitor_lane_records_the_long_request_and_serves_it_from_the_alias(
    db, test_api_key, origins
):
    await _replicas(db, test_api_key)

    hosts, decisions, rows = await _routed(
        db, test_api_key, _rules(_lane("monitor")), "x" * 2_000
    )

    assert hosts == ["a.internal"]
    assert (decisions[0]["state"], decisions[0]["to"]) == ("monitor", "internal-b")
    assert decisions[0]["input_tokens_approx"] >= 256
    assert [
        (match["rule_id"], match["state"])
        for match in rows[0].lifecycle_metadata["rule_matches"]
    ] == [("uzun_serit", "monitor")]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "held", ["disabled", "unhealthy", "not_approved", "not_allowed_for_key"]
)
async def test_a_lane_that_cannot_serve_keeps_the_request_on_the_alias(
    db, test_api_key, origins, held
):
    _, lane = await _replicas(db, test_api_key)
    if held == "disabled":
        lane.enabled = False
    elif held == "unhealthy":
        lane.health, lane.health_checked_at = "unhealthy", datetime.now(timezone.utc)
    elif held == "not_approved":
        lane.base_url = "https://c.internal/v1"
    else:
        test_api_key.allowed_models = ["internal-a"]
    await db.flush()

    hosts, decisions, _ = await _routed(db, test_api_key, _rules(_lane()), "x" * 2_000)

    assert hosts == ["a.internal"]
    assert (decisions[0]["to"], decisions[0]["held"]) == ("internal-a", held)


@pytest.mark.asyncio
async def test_an_alias_without_a_lane_is_never_serialized_by_the_resolver(
    db, test_api_key, origins, monkeypatch
):
    import shim_enterprise.tenants.deployments as deployments

    await _replicas(db, test_api_key)
    dumps = []
    monkeypatch.setattr(
        deployments,
        "json",
        SimpleNamespace(dumps=lambda *args, **kwargs: dumps.append(1) or "{}"),
    )
    other = {**_lane(), "match": {**_lane()["match"], "from": "internal-b"}}
    other["match"]["to"] = "internal-a"

    hosts, decisions, _ = await _routed(db, test_api_key, _rules(other), "x" * 2_000)

    assert (hosts, decisions, dumps) == (["a.internal"], [None], [])
