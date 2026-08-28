import asyncio
from contextlib import asynccontextmanager
from inspect import signature
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request
from supabase import AuthApiError

import shim.api.deps as deps
import shim_enterprise.api.enterprise_deps as enterprise_deps
from shim.api.v1.chat import chat_completions
from shim.api.v1.gemini import generate_content, stream_generate_content
from shim.api.v1.messages import messages
from shim.api.v1.responses import responses
from shim.gateway.pipeline.authenticate import GatewayRequestMetadata
from shim.secrets.credentials import EphemeralProviderCredential
from shim.services.gateway.service import GatewayService
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
        (enterprise_deps.get_current_user, (bearer, session)),
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
        (enterprise_deps.get_current_user, (bearer, session)),
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
