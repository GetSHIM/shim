from datetime import datetime, timedelta, timezone
import hashlib
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Response
import httpx
import pytest
from sqlalchemy.dialects import postgresql

from shim_enterprise.api import enterprise_deps
from shim_enterprise.api.v1 import management
from shim_enterprise.cache.redis_index import CacheService
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim_enterprise.tenants import hosted_auth, oidc
from shim_enterprise.tenants.models import OrganizationInvite, Team, TeamMembership


@pytest.mark.asyncio
async def test_hosted_cookie_login_session_refresh_origin_and_logout(
    db, test_org, test_user_with_org, monkeypatch
):
    monkeypatch.setattr(settings, "AUTH_MODE", "supabase")
    monkeypatch.setattr(settings, "DASHBOARD_ORIGIN", "https://console.example")
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    test_user_with_org.role = "member"
    team = Team(id=uuid4(), organization_id=test_org.id, name="Delivery")
    db.add(team)
    await db.flush()
    db.add(
        TeamMembership(
            organization_id=test_org.id,
            team_id=team.id,
            user_id=test_user_with_org.id,
            role="team_admin",
            source="local",
        )
    )
    await db.flush()
    identity = SimpleNamespace(
        id=test_user_with_org.id,
        email=test_user_with_org.email,
        email_confirmed_at="confirmed",
    )
    verify = AsyncMock(return_value=identity)
    monkeypatch.setattr(hosted_auth.verifier, "verify", verify)
    monkeypatch.setattr(enterprise_deps.jwt_verifier, "verify", verify)
    provider = AsyncMock(
        return_value={
            "access_token": "private-access",
            "refresh_token": "private-refresh",
            "expires_in": 300,
        }
    )
    monkeypatch.setattr(hosted_auth, "provider_request", provider)
    app = FastAPI()
    oidc.install_oidc(app)
    app.include_router(oidc.router, prefix="/api/v1")
    app.include_router(hosted_auth.router, prefix="/api/v1")
    app.include_router(management.router, prefix="/api/v1/management")
    app.dependency_overrides[get_db] = lambda: db
    cache = CacheService()
    await cache.connect()
    app.state.cache = cache
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://console.example"
        ) as browser:
            payload = {"email": identity.email, "password": "local-password"}
            assert (
                await browser.post("/api/v1/auth/password/login", json=payload)
            ).status_code == 403
            result = await browser.post(
                "/api/v1/auth/password/login",
                json=payload,
                headers={"Origin": settings.DASHBOARD_ORIGIN},
            )
            assert result.status_code == 200, result.text
            assert result.json() == {"ok": True}
            cookie = browser.cookies[oidc.SESSION_COOKIE]
            assert (
                "HttpOnly" in result.headers["set-cookie"]
                and "Secure" in result.headers["set-cookie"]
            )
            key = oidc._session_key(cookie)
            encrypted = await cache.redis.get(key)
            assert (
                "private-access" not in encrypted and "private-refresh" not in encrypted
            )
            response = await browser.get("/api/v1/auth/session")
            assert response.status_code == 200, response.text
            safe = response.json()
            assert safe["workspace"] == {"id": str(test_org.id), "name": test_org.name}
            assert (
                safe["user"]["id"] == str(identity.id)
                and safe["user"]["email_verified"]
            )
            assert safe["team_grants"] == [
                {"team_id": str(team.id), "role": "team_admin"}
            ]
            assert (
                safe["auth_mode"] == "supabase"
                and not safe["capabilities"]["cloud_billing"]
            )
            assert not safe["capabilities"]["model_deployments"]
            assert (
                "private-" not in response.text
                and response.headers["cache-control"] == "no-store"
            )
            data = json.loads(oidc._cipher().decrypt(encrypted.encode()))
            data["checked_at"] = time.time() - 600
            await oidc._save_session(SimpleNamespace(app=app), key, data)
            assert (await browser.get("/api/v1/auth/session")).status_code == 200
            assert browser.cookies[oidc.SESSION_COOKIE] == cookie
            assert provider.await_args_list[-1].kwargs["params"] == {
                "grant_type": "refresh_token"
            }
            assert (
                await browser.post(
                    "/api/v1/auth/password/reset",
                    json={"password": "new-password"},
                    headers={"Origin": settings.DASHBOARD_ORIGIN},
                )
            ).status_code == 403
            assert (
                await browser.post(
                    "/api/v1/auth/logout",
                    headers={"Origin": "https://attacker.example"},
                )
            ).status_code == 403
            assert (
                await browser.post(
                    "/api/v1/auth/logout", headers={"Origin": settings.DASHBOARD_ORIGIN}
                )
            ).status_code == 200
            assert await cache.redis.get(key) is None
            assert (await browser.get("/api/v1/auth/session")).status_code == 401
            test_user_with_org.is_active = False
            await db.flush()
            assert (
                await browser.post(
                    "/api/v1/auth/password/login",
                    json=payload,
                    headers={"Origin": settings.DASHBOARD_ORIGIN},
                )
            ).status_code == 200
            inactive = (await browser.get("/api/v1/auth/session")).json()
            assert (
                not inactive["user"]["is_active"]
                and inactive["capabilities"]["hosted_invitations"]
            )
            assert not inactive["capabilities"]["provider_findings"]
            assert (await browser.get("/api/v1/management/auth/me")).status_code == 401
            token = "synthetic-reinvite-token-0123456789"
            db.add(
                OrganizationInvite(
                    organization_id=test_org.id,
                    invited_by_user_id=test_user_with_org.id,
                    email=test_user_with_org.email,
                    role="member",
                    token_hash=hashlib.sha256(token.encode()).hexdigest(),
                    expires_at=datetime.now(timezone.utc) + timedelta(days=1),
                )
            )
            await db.flush()
            monkeypatch.setattr(management, "_require_entitlement", AsyncMock())
            accepted = await browser.post(
                "/api/v1/management/team/invites/accept",
                json={"token": token},
                headers={"Origin": settings.DASHBOARD_ORIGIN},
            )
            assert accepted.status_code == 200, accepted.text
            assert (await browser.get("/api/v1/auth/session")).json()["user"][
                "is_active"
            ]
            assert (await browser.get("/api/v1/management/auth/me")).status_code == 200
            await browser.post(
                "/api/v1/auth/logout", headers={"Origin": settings.DASHBOARD_ORIGIN}
            )
    finally:
        await cache.close()


@pytest.mark.asyncio
async def test_keycloak_mapping_preserves_local_identity_and_permissions(
    db, test_user_with_org, monkeypatch
):
    monkeypatch.setattr(settings, "AUTH_MODE", "keycloak")
    monkeypatch.setattr(
        settings, "OIDC_ISSUER_URL", "https://identity.example/realms/shim"
    )
    user = test_user_with_org
    user.oidc_issuer = settings.OIDC_ISSUER_URL
    user.oidc_subject = "linked-subject"
    user.role = "auditor"
    await db.flush()
    claims = {
        "iss": user.oidc_issuer,
        "sub": user.oidc_subject,
        "email_verified": True,
        "email": "other@example.com",
        "groups": ["owners"],
    }
    mapped = await oidc.synchronize_user(db, claims)
    assert (mapped.id, mapped.organization_id, mapped.role, mapped.email) == (
        user.id,
        user.organization_id,
        "auditor",
        user.email,
    )
    for invalid in (
        {"sub": "unlinked", "email": user.email},
        {"email_verified": False},
        {"iss": "https://attacker.example"},
    ):
        with pytest.raises(HTTPException):
            await oidc.synchronize_user(db, claims | invalid)
    user.is_active = False
    await db.flush()
    with pytest.raises(HTTPException):
        await oidc.synchronize_user(db, claims)


@pytest.mark.parametrize("exclusive", [False, True])
def test_request_interval_preserves_legacy_and_supports_exclusive_end(exclusive):
    bound = datetime(2026, 9, 1, tzinfo=timezone.utc)
    tenant_id = uuid4()
    filters = management._request_filters(
        tenant_id,
        start=bound,
        end=bound,
        status_filter=None,
        model=None,
        request_id="request-one",
        pii_detected=None,
        tag=None,
        cost_center=None,
        end_exclusive=exclusive,
    )
    sql = str(
        management._request_rows_statement(tenant_id, filters).compile(
            dialect=postgresql.dialect()
        )
    )
    assert "request_logs.timestamp >=" in sql
    assert ("request_logs.timestamp <=" in sql) is (not exclusive)
    assert (
        "request_logs.organization_id =" in sql and "request_logs.request_id =" in sql
    )
    assert management.list_requests.__annotations__["end_exclusive"]


@pytest.mark.asyncio
async def test_exclusive_interval_is_forwarded_to_full_request_export(monkeypatch):
    tenant_id = uuid4()
    end = datetime(2026, 9, 1, tzinfo=timezone.utc)
    session = SimpleNamespace(scalar=AsyncMock(return_value=0))
    response = await management.export_requests(
        start=end,
        end=end,
        status_filter=None,
        model=None,
        request_id="exact",
        pii_detected=None,
        tag=None,
        cost_center=None,
        end_exclusive=True,
        user=SimpleNamespace(organization_id=tenant_id),
        session=session,
    )
    assert response.media_type == "text/csv"
    sql = str(session.scalar.await_args.args[0].compile(dialect=postgresql.dialect()))
    assert "request_logs.timestamp < " in sql and "request_logs.timestamp <=" not in sql
    assert "request_logs.request_id =" in sql


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [401, 429, 503])
async def test_hosted_refresh_outage_preserves_session_but_denies_the_request(
    monkeypatch, failure
):
    monkeypatch.setattr(settings, "AUTH_MODE", "supabase")
    data = {
        "expires_at": time.time() + 300,
        "checked_at": 0,
        "provider": "supabase",
        "claims": {"sub": "local-user", "exp": time.time() + 60},
        "token": {"access_token": "synthetic", "refresh_token": "synthetic"},
    }
    encrypted = oidc._cipher().encrypt(json.dumps(data).encode()).decode()
    lock = SimpleNamespace(acquire=AsyncMock(return_value=True), release=AsyncMock())
    redis = SimpleNamespace(
        get=AsyncMock(return_value=encrypted),
        delete=AsyncMock(),
        lock=lambda *args, **kwargs: lock,
    )
    request = SimpleNamespace(
        method="GET",
        cookies={oidc.SESSION_COOKIE: "opaque-session"},
        app=SimpleNamespace(state=SimpleNamespace(cache=SimpleNamespace(redis=redis))),
    )
    monkeypatch.setattr(
        hosted_auth,
        "refresh_session",
        AsyncMock(side_effect=HTTPException(failure, "Unavailable")),
    )
    with pytest.raises(HTTPException) as rejected:
        await oidc.session_data(request)
    assert rejected.value.status_code == failure
    if failure == 401:
        redis.delete.assert_awaited_once()
    else:
        redis.delete.assert_not_awaited()
    lock.release.assert_awaited_once()


@pytest.mark.asyncio
async def test_resend_uses_server_pkce_callback_without_browser_tokens(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "supabase")
    monkeypatch.setattr(settings, "DASHBOARD_ORIGIN", "https://console.example")
    redis = SimpleNamespace(set=AsyncMock(return_value=True))
    request = SimpleNamespace(
        headers={"origin": settings.DASHBOARD_ORIGIN},
        session={},
        app=SimpleNamespace(state=SimpleNamespace(cache=SimpleNamespace(redis=redis))),
    )
    provider = AsyncMock(return_value={})
    monkeypatch.setattr(hosted_auth, "provider_request", provider)
    response = Response()
    await hosted_auth.resend(
        hosted_auth.EmailInput(
            email="member@example.com", next="/invite/accept?invite=synthetic"
        ),
        request,
        response,
    )
    arguments = provider.await_args.kwargs
    assert (
        arguments["params"]["redirect_to"]
        == "https://console.example/api/v1/auth/callback"
    )
    assert arguments["body"]["code_challenge_method"] == "s256"
    assert len(arguments["body"]["code_challenge"]) == 43
    encrypted = redis.set.await_args.args[1]
    flow = json.loads(oidc._cipher().decrypt(encrypted.encode()))
    assert flow["next"] == "/invite/accept?invite=synthetic"
    assert "verifier" not in request.session and "access_token" not in str(arguments)


@pytest.mark.asyncio
async def test_email_confirmation_preserves_supabase_type(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "supabase")
    monkeypatch.setattr(settings, "DASHBOARD_ORIGIN", "https://console.example")
    provider = AsyncMock(return_value={"opaque": "server-only"})
    monkeypatch.setattr(hosted_auth, "provider_request", provider)
    monkeypatch.setattr(hosted_auth, "create_session", AsyncMock())
    result = await hosted_auth.confirm(
        SimpleNamespace(), "synthetic-hash", "email", "/dashboard", SimpleNamespace()
    )
    assert result.status_code == 303
    assert provider.await_args.kwargs["body"]["type"] == "email"
    assert result.headers["location"] == "https://console.example/dashboard"


@pytest.mark.asyncio
async def test_auth_validation_excludes_secret_input(monkeypatch):
    from shim_enterprise.application import create_enterprise_app

    monkeypatch.setattr(settings, "AUTH_MODE", "supabase")
    monkeypatch.setattr(settings, "DASHBOARD_ORIGIN", "https://console.example")
    app = create_enterprise_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://console.example"
    ) as browser:
        result = await browser.post(
            "/api/v1/auth/register",
            json={"email": "member@example.com", "password": "private"},
            headers={"Origin": settings.DASHBOARD_ORIGIN},
        )
    assert result.status_code == 422
    assert "private" not in result.text and "input" not in result.text
    assert result.headers["cache-control"] == "private, no-store"


@pytest.mark.asyncio
async def test_request_end_equality_matches_list_and_complete_export(
    db, test_api_key, test_user_with_org
):
    from shim_enterprise.observability.analytics_projection import RequestLog

    bound = datetime(2026, 9, 1, tzinfo=timezone.utc)
    request_id = "boundary-" + uuid4().hex
    db.add(
        RequestLog(
            request_id=request_id,
            api_key_id=test_api_key.id,
            organization_id=test_user_with_org.organization_id,
            timestamp=bound,
            details={"lifecycle_status": "completed"},
        )
    )
    await db.flush()
    predicates = dict(
        start=bound,
        end=bound,
        status_filter=None,
        model=None,
        request_id=request_id,
        pii_detected=None,
        tag=None,
        cost_center=None,
        user=test_user_with_org,
        session=db,
    )
    inclusive = await management.list_requests(**predicates, limit=50, offset=0)
    exclusive = await management.list_requests(
        **predicates, limit=50, offset=0, end_exclusive=True
    )
    assert inclusive.total == 1 and exclusive.total == 0
    for excludes, expected in ((False, True), (True, False)):
        response = await management.export_requests(
            **predicates, end_exclusive=excludes
        )
        content = b"".join([chunk async for chunk in response.body_iterator])
        assert (request_id.encode() in content) is expected
