from __future__ import annotations

import base64
import hashlib
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException, Request
import httpx
import jwt
import pytest
from pydantic import ValidationError

from shim_enterprise.cache.redis_index import CacheService
from shim_enterprise.core.config import Settings, settings
from shim_enterprise.core.database import get_db
from shim_enterprise.tenants import oidc


@pytest.fixture
def oidc_config(monkeypatch):
    values = dict(
        AUTH_MODE="oidc",
        OIDC_ISSUER_URL="https://identity.internal/realm",
        OIDC_CLIENT_ID="dashboard",
        OIDC_CLIENT_SECRET="customer-secret",
        OIDC_API_AUDIENCE="shim-api",
        OIDC_REDIRECT_URI="https://shim.internal/api/v1/auth/callback",
        DASHBOARD_ORIGIN="https://shim.internal",
        OIDC_ORGANIZATION_ID=uuid4(),
        OIDC_GROUP_ROLE_MAP={"/shim/owners": "owner", "/shim/members": "member"},
        OIDC_REVALIDATE_SECONDS=60,
    )
    for name, value in values.items():
        monkeypatch.setattr(settings, name, value)
    return values


def test_oidc_configuration_needs_no_supabase(oidc_config):
    values = dict(
        oidc_config,
        DATABASE_URL="postgresql+asyncpg://test:test@localhost/test",
        REDIS_URL="redis://localhost/0",
        SECRET_KEY="test-secret-key-value",
        SUPABASE_URL=None,
        SUPABASE_KEY=None,
        _env_file=None,
    )
    assert Settings(**values).SUPABASE_URL is None
    for invalid in (
        {"OIDC_GROUP_ROLE_MAP": {}},
        {"OIDC_API_AUDIENCE": "dashboard"},
        {"OIDC_REDIRECT_URI": "https://other.internal/api/v1/auth/callback"},
        {"AUTH_MODE": "supabase"},
    ):
        with pytest.raises(ValidationError):
            Settings(**(values | invalid))


@pytest.mark.asyncio
async def test_identity_binding_role_removal_and_email_collision(
    db, test_org, test_user_with_org, monkeypatch, oidc_config
):
    monkeypatch.setattr(settings, "OIDC_ORGANIZATION_ID", test_org.id)
    claims = dict(
        iss=settings.OIDC_ISSUER_URL,
        sub="subject",
        email=f"{uuid4()}@example.com",
        email_verified=True,
        groups=["/shim/owners"],
    )
    user = await oidc.synchronize_user(db, claims)
    assert user.organization_id == test_org.id
    assert user.role == "owner"
    assert (user.oidc_issuer, user.oidc_subject) == (claims["iss"], "subject")
    same_user = await oidc.synchronize_user(
        db, claims | {"groups": ["/shim/members"], "email": "changed@example.com"}
    )
    assert same_user.id == user.id and same_user.role == "member"
    for changed in (
        {"groups": []},
        {"groups": "/shim/owners"},
        {"iss": "https://other.internal"},
        {"sub": "collision", "email": test_user_with_org.email},
        {"sub": "new", "email_verified": False},
    ):
        with pytest.raises(HTTPException):
            await oidc.synchronize_user(db, claims | changed)
    user.is_active = False
    await db.flush()
    with pytest.raises(HTTPException, match="inactive"):
        await oidc.synchronize_user(db, claims)


@pytest.mark.asyncio
async def test_signed_api_tokens_reject_issuer_audience_expiry_signature_and_long_lifetime(
    oidc_config,
):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key())) | {
        "kid": "test-key"
    }
    client = SimpleNamespace(
        load_server_metadata=AsyncMock(
            return_value={"issuer": settings.OIDC_ISSUER_URL}
        ),
        fetch_jwk_set=AsyncMock(return_value={"keys": [jwk]}),
    )
    request = Request(
        {"type": "http", "app": SimpleNamespace(state=SimpleNamespace(oidc=client))}
    )
    now = int(time.time())
    claims = {
        "iss": settings.OIDC_ISSUER_URL,
        "sub": "user",
        "aud": "shim-api",
        "iat": now,
        "exp": now + 300,
    }

    def signed(data):
        return jwt.encode(data, private, algorithm="RS256", headers={"kid": "test-key"})

    assert (await oidc.access_token_claims(request, signed(claims)))["sub"] == "user"
    for data in (
        claims | {"iss": "https://attacker.internal"},
        claims | {"aud": "dashboard"},
        claims | {"exp": now - 1},
        claims | {"exp": now + 301},
        {key: value for key, value in claims.items() if key != "exp"},
    ):
        with pytest.raises(HTTPException) as error:
            await oidc.access_token_claims(request, signed(data))
        assert error.value.status_code == 401
    invalid = jwt.encode(
        claims,
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    with pytest.raises(HTTPException):
        await oidc.access_token_claims(request, invalid)


@pytest.mark.asyncio
async def test_authorization_code_pkce_cookie_refresh_csrf_and_logout(
    db, test_org, monkeypatch, oidc_config
):
    monkeypatch.setattr(settings, "OIDC_ORGANIZATION_ID", test_org.id)
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key())) | {
        "kid": "test-key"
    }
    login_parameters = {}
    groups = ["/shim/owners"]
    subject = uuid4().hex

    def provider(request):
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": settings.OIDC_ISSUER_URL,
                    "authorization_endpoint": "https://identity.internal/authorize",
                    "token_endpoint": "https://identity.internal/token",
                    "jwks_uri": "https://identity.internal/jwks",
                    "id_token_signing_alg_values_supported": ["RS256", "HS256"],
                    "end_session_endpoint": "https://identity.internal/logout",
                },
            )
        if request.url.path == "/jwks":
            return httpx.Response(200, json={"keys": [jwk]})
        assert request.url.path == "/token"
        parameters = parse_qs(request.content.decode())
        now = int(time.time())
        claims = dict(
            iss=settings.OIDC_ISSUER_URL,
            sub=subject,
            aud="dashboard",
            iat=now,
            exp=now + 300,
            email=f"{subject}@example.com",
            email_verified=True,
            groups=groups,
        )
        if parameters["grant_type"] == ["authorization_code"]:
            verifier = parameters["code_verifier"][0]
            challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                .decode()
                .rstrip("=")
            )
            assert challenge == login_parameters["code_challenge"][0]
            claims["nonce"] = login_parameters["nonce"][0]
        else:
            assert parameters["grant_type"] == ["refresh_token"]
        return httpx.Response(
            200,
            json={
                "access_token": "provider-access-token",
                "refresh_token": "provider-refresh-token",
                "token_type": "Bearer",
                "expires_in": 300,
                "id_token": jwt.encode(
                    claims, private, algorithm="RS256", headers={"kid": "test-key"}
                ),
            },
        )

    cache = CacheService()
    await cache.connect()
    app = FastAPI()
    app.state.cache = cache
    oidc.install_oidc(app)
    app.state.oidc.client_kwargs["transport"] = httpx.MockTransport(provider)
    app.include_router(oidc.router, prefix="/api/v1")

    async def database():
        yield db

    app.dependency_overrides[get_db] = database
    key = None
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://shim.internal"
        ) as browser:
            for path in ("//evil.example", "/\\evil.example", "https://evil.example"):
                assert (
                    await browser.get("/api/v1/auth/login", params={"next": path})
                ).status_code == 400
            response = await browser.get(
                "/api/v1/auth/login", params={"next": "/dashboard/workspace/settings"}
            )
            login_parameters.update(
                parse_qs(urlsplit(response.headers["location"]).query)
            )
            assert login_parameters["code_challenge_method"] == ["S256"]
            assert (
                await browser.get(
                    "/api/v1/auth/callback", params={"code": "one", "state": "forged"}
                )
            ).status_code == 401
            response = await browser.get(
                "/api/v1/auth/login", params={"next": "/dashboard/workspace/settings"}
            )
            login_parameters.update(
                parse_qs(urlsplit(response.headers["location"]).query)
            )
            response = await browser.get(
                "/api/v1/auth/callback",
                params={"code": "one", "state": login_parameters["state"][0]},
            )
            assert response.status_code == 303, response.text
            assert response.headers["location"].endswith(
                "/dashboard/workspace/settings"
            )
            cookie = response.headers["set-cookie"]
            assert (
                "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie
            )
            assert (
                "provider-access-token" not in cookie
                and "provider-refresh-token" not in cookie
            )
            key = oidc._session_key(browser.cookies[oidc.SESSION_COOKIE])
            stored = await cache.redis.get(key)
            assert "provider-refresh-token" not in stored
            assert (await browser.get("/api/v1/auth/session")).json()["user"][
                "role"
            ] == "owner"
            assert (
                await browser.post(
                    "/api/v1/auth/logout", headers={"origin": "https://evil.example"}
                )
            ).status_code == 403
            groups[:] = ["/shim/members"]
            data = json.loads(oidc._cipher().decrypt(stored.encode()))
            data["checked_at"] -= 61
            await cache.redis.set(
                key, oidc._cipher().encrypt(json.dumps(data).encode()).decode(), ex=300
            )
            assert (await browser.get("/api/v1/auth/session")).json()["user"][
                "role"
            ] == "member"
            groups.clear()
            stored = await cache.redis.get(key)
            data = json.loads(oidc._cipher().decrypt(stored.encode()))
            data["checked_at"] -= 61
            await cache.redis.set(
                key, oidc._cipher().encrypt(json.dumps(data).encode()).decode(), ex=300
            )
            assert (await browser.get("/api/v1/auth/session")).status_code == 403
            response = await browser.post(
                "/api/v1/auth/logout", headers={"origin": "https://shim.internal"}
            )
            assert response.status_code == 200
            assert response.json()["logout_url"].startswith(
                "https://identity.internal/logout?"
            )
            assert await cache.redis.get(key) is None
            assert (await browser.get("/api/v1/auth/session")).status_code == 401
    finally:
        if key:
            await cache.redis.delete(key, key + ":refresh")
        await cache.close()
