import html
import json
import os
import re
from urllib.parse import urlsplit
from types import SimpleNamespace

from fastapi import FastAPI
import httpx
import pytest

from shim_enterprise.cache.redis_index import CacheService
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim_enterprise.tenants import oidc


@pytest.mark.asyncio
@pytest.mark.skipif(
    not os.environ.get("KEYCLOAK_TRIAL_URL"),
    reason="Explicit local Keycloak trial required",
)
async def test_real_keycloak_pkce_signed_callback_local_mapping_refresh_and_logout(
    db, test_user_with_org, monkeypatch
):
    issuer = os.environ["KEYCLOAK_TRIAL_URL"].rstrip("/") + "/realms/shim-trial"
    configuration = {
        "AUTH_MODE": "keycloak",
        "OIDC_ISSUER_URL": issuer,
        "OIDC_CLIENT_ID": "shim-console",
        "OIDC_CLIENT_SECRET": "local-trial-client-secret",
        "OIDC_REDIRECT_URI": "http://localhost:3000/api/v1/auth/callback",
        "DASHBOARD_ORIGIN": "http://localhost:3000",
        "ENVIRONMENT": "development",
    }
    for key, value in configuration.items():
        monkeypatch.setattr(settings, key, value)
    user = test_user_with_org
    user.oidc_issuer, user.oidc_subject = issuer, "11111111-1111-4111-8111-111111111111"
    user.role = "member"
    await db.flush()
    app = FastAPI()
    oidc.install_oidc(app)
    app.include_router(oidc.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    cache = CacheService()
    await cache.connect()
    app.state.cache = cache
    try:
        async with (
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://localhost:3000"
            ) as browser,
            httpx.AsyncClient(follow_redirects=False) as identity,
        ):
            response = await browser.get("/api/v1/auth/login")
            assert response.status_code == 302
            page = await identity.get(response.headers["location"])
            assert page.status_code == 200
            action = re.search(r'<form[^>]*action="([^"]+)"', page.text)
            assert action, "Keycloak login form unavailable"
            authenticated = await identity.post(
                html.unescape(action.group(1)),
                data={"username": "trial-member", "password": "local-trial-password"},
                headers={
                    "Cookie": "; ".join(
                        f"{cookie.name}={cookie.value}"
                        for cookie in identity.cookies.jar
                    )
                },
            )
            assert authenticated.status_code == 302, authenticated.text
            callback = urlsplit(authenticated.headers["location"])
            assert callback.path == "/api/v1/auth/callback", callback.path
            response = await browser.get(callback.path + "?" + callback.query)
            assert response.status_code == 303, response.text
            safe = await browser.get("/api/v1/auth/session")
            assert safe.status_code == 200, safe.text
            assert safe.json()["user"]["id"] == str(user.id)
            assert safe.json()["workspace"]["id"] == str(user.organization_id)
            assert (
                safe.json()["auth_mode"] == "keycloak"
                and safe.json()["user"]["role"] == "member"
            )
            session_id = browser.cookies[oidc.SESSION_COOKIE]
            data = json.loads(
                oidc._cipher().decrypt(
                    (await cache.redis.get(oidc._session_key(session_id))).encode()
                )
            )
            data["checked_at"] = 0
            await oidc._save_session(
                SimpleNamespace(app=app), oidc._session_key(session_id), data
            )
            assert (await browser.get("/api/v1/auth/session")).status_code == 200
            assert browser.cookies[oidc.SESSION_COOKIE] == session_id
            logout = await browser.post(
                "/api/v1/auth/logout", headers={"Origin": settings.DASHBOARD_ORIGIN}
            )
            assert logout.status_code == 200 and issuer in logout.json()["logout_url"]
            assert (await browser.get("/api/v1/auth/session")).status_code == 401
    finally:
        await cache.close()
