"""Registered destinations reuse native transports, credentials and accounting."""

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import io
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4
from urllib.parse import urlsplit

import httpx
import pytest
import pytest_asyncio
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import async_sessionmaker

from shim.application import create_community_app
from shim.core.circuit_breaker import InMemoryCircuitBreaker
from shim.core.community_config import CommunitySettings
from shim.gateway.contracts.context import AuditPolicy, TenantPolicy, TierPolicy
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.gateway.request_policy import RequestPolicyContext, ResolvedRequestPolicy
from shim_enterprise.api.enterprise_deps import DatabaseGatewayAuthenticator
from shim_enterprise.api.v1.management import (
    ModelDeploymentInput,
    ModelDeploymentView,
    create_model_deployment,
    check_model_deployment_health,
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
async def _gateway(db, key, handler):
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
                execution.circuit_for_target = lambda url: circuits[
                    urlsplit(url).hostname
                ]
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
        await create_model_deployment(payload, owner, db)
    assert error.value.status_code == 404


@pytest.mark.asyncio
async def test_health_headers_are_bounded_and_output_view_survives_policy_change(
    db, test_api_key, test_user_with_org, origins, monkeypatch
):
    rows = await _deployments(db, test_api_key)
    store = SimpleNamespace(get_secret=AsyncMock(return_value="health-key"))
    monkeypatch.setattr(
        "shim_enterprise.api.v1.management.get_secret_store", lambda: store
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
