import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from inspect import signature
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from sqlalchemy import delete
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request
from supabase import AuthApiError

import shim.api.deps as deps
import shim_enterprise.api.enterprise_deps as enterprise_deps
from shim.api.v1.chat import chat_completions
from shim.api.v1.gemini import generate_content, stream_generate_content
from shim.api.v1.messages import messages
from shim.api.v1.responses import responses
from shim.gateway.api.errors import gateway_exception_handler
from shim.gateway.contracts.ids import ApiKeyId
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.gateway.pipeline.authenticate import GatewayRequestMetadata
from shim.secrets.credentials import EphemeralProviderCredential
from shim.services.gateway.service import GatewayService
from shim_enterprise.application import create_enterprise_app
from shim_enterprise.shared_results.api import authenticated_router
from shim_enterprise.tenants.deployments import DeploymentResolver
from shim_enterprise.tenants.models import Organization, User
from shim_enterprise.tenants.service import JwtIdentityVerifier, ensure_privacy_defaults


def _request(*headers: tuple[bytes, bytes]) -> Request:
    return Request({"type": "http", "headers": list(headers)})


def test_inference_http_and_service_boundaries_do_not_accept_sessions() -> None:
    callables = (
        deps.dispatch_gateway_inference,
        GatewayService.dispatch_inference,
        chat_completions,
        responses,
        messages,
        generate_content,
        stream_generate_content,
    )

    assert all("db" not in signature(callable_).parameters for callable_ in callables)
    assert "session" not in signature(enterprise_deps.get_current_api_key).parameters
    assert (
        "session"
        not in signature(
            enterprise_deps.DatabaseGatewayAuthenticator.resolve
        ).parameters
    )


@pytest.mark.asyncio
async def test_database_authenticator_closes_its_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = SimpleNamespace()
    api_key = SimpleNamespace(id=uuid4())
    authenticate = AsyncMock(return_value=api_key)
    monkeypatch.setattr(enterprise_deps, "authenticate_api_key", authenticate)
    events: list[str] = []

    @asynccontextmanager
    async def session_scope():
        events.append("open")
        try:
            yield session
        finally:
            events.append("closed")

    result = await enterprise_deps.DatabaseGatewayAuthenticator(
        session_scope  # type: ignore[arg-type]
    ).resolve("shim-key")

    assert result.api_key_id == api_key.id
    authenticate.assert_awaited_once_with(session, "shim-key")
    assert events == ["open", "closed"]


@pytest.mark.asyncio
async def test_inference_auth_uses_first_present_credential() -> None:
    principal = SimpleNamespace()
    authenticator = SimpleNamespace(resolve=AsyncMock(return_value=principal))
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/messages",
            "headers": [
                (b"x-shim-key", b"invalid-high-priority-key"),
                (b"authorization", b"Bearer valid-lower-priority-key"),
                (b"x-api-key", b"valid-anthropic-key"),
            ],
            "app": SimpleNamespace(
                state=SimpleNamespace(gateway_authenticator=authenticator)
            ),
        }
    )

    result = await deps.get_anthropic_authenticated_principal(
        request,
        None,
        None,
        None,
    )

    assert result is principal
    authenticator.resolve.assert_awaited_once_with("invalid-high-priority-key")


@pytest.mark.asyncio
async def test_dispatch_carries_query_metadata() -> None:
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/messages",
            "query_string": b"beta=true&beta=false",
            "headers": [(b"x-api-key", b"shim-key")],
        }
    )
    response = SimpleNamespace()
    gateway_service = SimpleNamespace(
        dispatch_inference=AsyncMock(return_value=response)
    )

    result = await deps.dispatch_gateway_inference(
        request=request,
        payload={},
        provider="anthropic",
        protocol="messages",
        model="claude-test",
        stream=False,
        gateway_service=gateway_service,
        principal=SimpleNamespace(),
    )

    assert result is response
    call = gateway_service.dispatch_inference.await_args.kwargs
    assert call["headers"] == {}
    assert call["provider_credential"] is None
    assert "db" not in call
    assert call["request_metadata"].query_params == (
        ("beta", "true"),
        ("beta", "false"),
    )


@pytest.mark.asyncio
async def test_dispatch_rejects_an_empty_high_priority_provider_key() -> None:
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [
                (b"x-provider-key", b""),
                (b"x-openai-api-key", b"lower-priority-secret"),
            ],
        }
    )
    gateway_service = SimpleNamespace(dispatch_inference=AsyncMock())

    with pytest.raises(HTTPException) as captured:
        await deps.dispatch_gateway_inference(
            request=request,
            payload={},
            provider="openai",
            protocol="chat",
            model="gpt-test",
            stream=False,
            gateway_service=gateway_service,
            principal=SimpleNamespace(),
        )

    assert captured.value.status_code == 400
    assert captured.value.detail["code"] == "INVALID_PROVIDER_CREDENTIAL"
    gateway_service.dispatch_inference.assert_not_awaited()


@pytest.mark.asyncio
async def test_service_clears_provider_credential_after_failure() -> None:
    failure = RuntimeError("kernel failed")
    credential = EphemeralProviderCredential("openai", "provider-secret")
    service = GatewayService(
        SimpleNamespace(execute=AsyncMock(side_effect=failure))  # type: ignore[arg-type]
    )

    with pytest.raises(RuntimeError) as captured:
        await service.dispatch_inference(
            payload={},
            provider="openai",
            protocol="chat",
            model="gpt-test",
            stream=False,
            headers={},
            provider_credential=credential,
            principal=SimpleNamespace(),  # type: ignore[arg-type]
            request_metadata=GatewayRequestMetadata(endpoint="/v1/chat/completions"),
        )

    assert captured.value is failure
    assert credential.available() is False


@pytest.mark.asyncio
async def test_existing_user_refreshes_verification_only() -> None:
    organization_id = uuid4()
    user = SimpleNamespace(
        id=uuid4(),
        organization_id=organization_id,
        email="local@example.com",
        full_name="Local Name",
        is_active=False,
        is_verified=False,
    )
    session = SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(scalar_one_or_none=lambda: user)
        ),
        commit=AsyncMock(),
    )
    identity = SimpleNamespace(
        id=user.id,
        email="remote@example.com",
        email_confirmed_at=object(),
        user_metadata={"full_name": "Remote Name", "organization": "Remote Org"},
    )

    result = await enterprise_deps._load_or_sync_supabase_user(session, identity)

    assert result is user
    assert user.is_verified is True
    assert user.email == "local@example.com"
    assert user.full_name == "Local Name"
    assert user.organization_id == organization_id
    assert user.is_active is False
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_concurrent_first_requests_create_one_local_identity(
    async_engine,
) -> None:
    user_id = uuid4()
    identity = SimpleNamespace(
        id=user_id,
        email=f"concurrent-{user_id}@example.com",
        email_confirmed_at=object(),
        user_metadata={"full_name": "Concurrent User"},
    )
    factory = sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)

    async def synchronize():
        async with factory() as session:
            return await enterprise_deps._load_or_sync_supabase_user(session, identity)

    users = await asyncio.gather(*(synchronize() for _ in range(4)))

    assert {user.id for user in users} == {user_id}
    organization_ids = {user.organization_id for user in users}
    assert len(organization_ids) == 1
    async with factory() as session:
        await session.execute(
            delete(Organization).where(Organization.id.in_(organization_ids))
        )
        await session.commit()


@pytest.mark.asyncio
async def test_recreated_confirmed_identity_replaces_empty_bootstrap(
    db,
) -> None:
    old_user_id = uuid4()
    new_user_id = uuid4()
    organization_id = uuid4()
    email = f"recreated-{new_user_id}@example.com"
    db.add_all(
        [
            Organization(
                id=organization_id,
                name="Recreated identity",
                slug=f"recreated-identity-{organization_id}",
            ),
            User(
                id=old_user_id,
                organization_id=organization_id,
                email=email,
                role="owner",
                is_active=True,
                is_verified=True,
            ),
        ]
    )
    await db.flush()
    await ensure_privacy_defaults(db, organization_id)

    user = await enterprise_deps._load_or_sync_supabase_user(
        db,
        SimpleNamespace(
            id=new_user_id,
            email=email,
            email_confirmed_at=object(),
            user_metadata={},
        ),
    )

    assert user.id == new_user_id
    assert await db.get(User, old_user_id) is None
    assert await db.get(Organization, organization_id) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("email_confirmed_at", "billing_source"),
    [(None, None), (object(), "lemonsqueezy")],
)
async def test_recreated_identity_does_not_claim_untrusted_tenant(
    db,
    email_confirmed_at: object | None,
    billing_source: str | None,
) -> None:
    old_user_id = uuid4()
    organization_id = uuid4()
    email = f"protected-{old_user_id}@example.com"
    db.add_all(
        [
            Organization(
                id=organization_id,
                name="Protected identity",
                slug=f"protected-identity-{organization_id}",
                billing_source=billing_source,
            ),
            User(
                id=old_user_id,
                organization_id=organization_id,
                email=email,
                role="owner",
                is_active=True,
                is_verified=True,
            ),
        ]
    )
    await db.flush()
    await ensure_privacy_defaults(db, organization_id)

    with pytest.raises(RuntimeError, match="identity conflicts"):
        await enterprise_deps._load_or_sync_supabase_user(
            db,
            SimpleNamespace(
                id=uuid4(),
                email=email,
                email_confirmed_at=email_confirmed_at,
                user_metadata={},
            ),
        )
    assert await db.get(User, old_user_id) is not None
    assert await db.get(Organization, organization_id) is not None


@pytest.mark.asyncio
async def test_verified_identity_sync_failure_is_service_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = SimpleNamespace()
    bearer = SimpleNamespace(credentials="verified-jwt")
    identity = SimpleNamespace(id=uuid4(), email="verified@example.com")
    monkeypatch.setattr(
        enterprise_deps.jwt_verifier,
        "verify",
        AsyncMock(return_value=identity),
    )
    monkeypatch.setattr(
        enterprise_deps,
        "_load_or_sync_supabase_user",
        AsyncMock(side_effect=RuntimeError("database unavailable")),
    )

    calls = (
        (enterprise_deps.get_current_user, (_request(), bearer, session)),
        (
            enterprise_deps.get_scan_principal,
            (
                _request((b"authorization", b"Bearer verified-jwt")),
                None,
                None,
                session,
            ),
        ),
    )
    for dependency, args in calls:
        with pytest.raises(HTTPException) as captured:
            await dependency(*args)
        assert captured.value.status_code == 503
        assert captured.value.headers is None


@pytest.mark.asyncio
async def test_identity_provider_failure_is_service_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = SimpleNamespace()
    bearer = SimpleNamespace(credentials="verified-jwt")
    monkeypatch.setattr(
        enterprise_deps.jwt_verifier,
        "verify",
        AsyncMock(side_effect=RuntimeError("auth service unavailable")),
    )

    calls = (
        (enterprise_deps.get_current_user, (_request(), bearer, session)),
        (
            enterprise_deps.get_scan_principal,
            (
                _request((b"authorization", b"Bearer verified-jwt")),
                None,
                None,
                session,
            ),
        ),
    )
    for dependency, args in calls:
        with pytest.raises(HTTPException) as captured:
            await dependency(*args)
        assert captured.value.status_code == 503
        assert captured.value.headers is None


@pytest.mark.asyncio
async def test_identity_verifier_rejects_bad_tokens_but_propagates_outages() -> None:
    def invalid_token(_token: str):
        raise AuthApiError("invalid token", 401, None)

    invalid = JwtIdentityVerifier(
        SimpleNamespace(auth=SimpleNamespace(get_user=invalid_token))
    )
    assert await invalid.verify("bad-token") is None

    def unavailable(_token: str):
        raise RuntimeError("auth service unavailable")

    unavailable_verifier = JwtIdentityVerifier(
        SimpleNamespace(auth=SimpleNamespace(get_user=unavailable))
    )
    with pytest.raises(RuntimeError, match="auth service unavailable"):
        await unavailable_verifier.verify("valid-looking-token")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path,allowed",
    [
        ("/api/v1/compliance/audit/verify", True),
        ("/api/v1/compliance/reports/audit", True),
        ("/api/v1/compliance/reports/kvkk", True),
        ("/api/v1/management/api-keys", False),
        ("/api/v1/compliance/reports/kvkk/anything", False),
    ],
)
async def test_auditor_only_allows_read_only_posts(monkeypatch, path, allowed):
    user = SimpleNamespace(role="auditor", is_active=True)
    monkeypatch.setattr(
        enterprise_deps, "get_invite_user", AsyncMock(return_value=user)
    )
    request = Request({"type": "http", "method": "POST", "path": path, "headers": []})
    if allowed:
        assert await enterprise_deps.get_current_user(request, None, None) is user
    else:
        with pytest.raises(HTTPException) as error:
            await enterprise_deps.get_current_user(request, None, None)
        assert error.value.status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("candidate", "code"),
    [
        (None, "MISSING_API_KEY"),
        ("", "INVALID_API_KEY"),
        ("sk-shim-unknown", "INVALID_API_KEY"),
    ],
)
async def test_gateway_key_failures_carry_their_code(
    monkeypatch: pytest.MonkeyPatch,
    candidate: str | None,
    code: str,
) -> None:
    monkeypatch.setattr(
        enterprise_deps, "authenticate_api_key", AsyncMock(return_value=None)
    )

    with pytest.raises(HTTPException) as error:
        await enterprise_deps._authenticate_gateway_key(
            SimpleNamespace(),  # type: ignore[arg-type]
            candidate,
        )

    assert error.value.status_code == 401
    assert error.value.headers == {
        "WWW-Authenticate": "Bearer",
        "X-Shim-Error-Code": code,
    }


@pytest.mark.asyncio
async def test_shared_results_401_keeps_its_detail_body_and_gains_the_code() -> None:
    application = FastAPI()
    application.add_exception_handler(
        StarletteHTTPException,
        gateway_exception_handler,
    )
    application.include_router(authenticated_router, prefix="/api/v1")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://shim.test",
    ) as client:
        response = await client.post(
            "/api/v1/shared-results",
            json={"prompt": "hello", "response": "world"},
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "Missing API Key"}
    assert response.headers["x-shim-error-code"] == "MISSING_API_KEY"


def _failing_sessions(error: Exception):
    @asynccontextmanager
    async def session_scope():
        yield SimpleNamespace(execute=AsyncMock(side_effect=error))

    return session_scope


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        OperationalError("SELECT 1", {}, ConnectionRefusedError()),
        ConnectionResetError(),
    ],
)
async def test_database_authenticator_answers_503_when_the_database_fails(
    error: Exception,
) -> None:
    authenticator = enterprise_deps.DatabaseGatewayAuthenticator(
        _failing_sessions(error)  # type: ignore[arg-type]
    )

    with pytest.raises(HTTPException) as raised:
        await authenticator.resolve("sk-shim-" + "0" * 32)

    assert raised.value.status_code == 503
    assert raised.value.detail["code"] == "INTERNAL_ERROR"


@pytest.mark.asyncio
async def test_database_authenticator_does_not_hide_programming_errors() -> None:
    authenticator = enterprise_deps.DatabaseGatewayAuthenticator(
        _failing_sessions(TypeError("bug"))  # type: ignore[arg-type]
    )

    with pytest.raises(TypeError):
        await authenticator.resolve("sk-shim-" + "0" * 32)


@pytest.mark.asyncio
async def test_database_outage_answers_every_provider_in_its_native_shape() -> None:
    unavailable = _failing_sessions(
        OperationalError("SELECT 1", {}, ConnectionRefusedError())
    )
    application = create_enterprise_app()
    application.state.gateway_service = SimpleNamespace()
    application.state.gateway_authenticator = (
        enterprise_deps.DatabaseGatewayAuthenticator(unavailable)  # type: ignore[arg-type]
    )
    user = [{"role": "user", "content": "hi"}]

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://shim.test",
        headers={"x-shim-key": "sk-shim-" + "0" * 32},
    ) as client:
        chat = await client.post(
            "/v1/chat/completions", json={"model": "gpt-5.6-luna", "messages": user}
        )
        message = await client.post(
            "/v1/messages",
            json={"model": "claude-haiku-4-5", "max_tokens": 8, "messages": user},
        )
        gemini = await client.post(
            "/v1beta/models/gemini-3.5-flash-lite:generateContent",
            json={"contents": [{"role": "user", "parts": [{"text": "hi"}]}]},
        )
        application.state.gateway_authenticator = SimpleNamespace(
            resolve=AsyncMock(
                return_value=AuthenticatedPrincipal(
                    actor_type="api_key",
                    api_key_id=ApiKeyId(uuid4()),
                    authenticated_at=datetime.now(timezone.utc),
                )
            )
        )
        application.state.model_catalog = DeploymentResolver(unavailable).catalog  # type: ignore[arg-type]
        models = await client.get("/v1/models")

    for response in (chat, message, gemini, models):
        assert response.status_code == 503
        assert response.headers["content-type"] == "application/json"
    assert chat.json()["error"]["code"] == "INTERNAL_ERROR"
    assert models.json()["error"]["code"] == "INTERNAL_ERROR"
    assert message.json()["type"] == "error"
    assert message.json()["error"]["type"] == "api_error"
    assert gemini.json()["error"]["status"] == "UNAVAILABLE"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("role", "allowed"),
    [("owner", True), ("admin", True), ("auditor", True), ("member", False)],
)
async def test_org_reader_admits_owner_admin_and_auditor(
    role: str, allowed: bool
) -> None:
    user = SimpleNamespace(role=role)

    if allowed:
        assert await enterprise_deps.get_org_reader(user) is user  # type: ignore[arg-type]
    else:
        with pytest.raises(HTTPException) as refused:
            await enterprise_deps.get_org_reader(user)  # type: ignore[arg-type]
        assert refused.value.status_code == 403
        assert refused.value.detail == "Organization reader required"
