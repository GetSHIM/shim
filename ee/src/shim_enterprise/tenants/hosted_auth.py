"""Temporary hosted provider adapter; remove after the Keycloak migration gate."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from typing import Any, Literal
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr, Field, SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim_enterprise.tenants import oidc
from shim_enterprise.tenants.service import JwtIdentityVerifier

router = APIRouter(prefix="/auth", tags=["identity"])
verifier = JwtIdentityVerifier()


class AuthResult(BaseModel):
    ok: Literal[True] = True


class EmailInput(BaseModel):
    email: EmailStr
    next: str = Field(default="/dashboard", max_length=2048)


class PasswordInput(BaseModel):
    password: SecretStr = Field(min_length=8, max_length=1024)


class PasswordLogin(EmailInput):
    password: SecretStr = Field(min_length=1, max_length=1024)


class Registration(EmailInput, PasswordInput):
    full_name: str | None = Field(default=None, max_length=200)
    organization: str | None = Field(default=None, min_length=1, max_length=200)


class PasswordChange(PasswordInput):
    current_password: SecretStr = Field(min_length=1, max_length=1024)


def require_hosted(request: Request) -> None:
    if settings.AUTH_MODE != "supabase":
        raise HTTPException(
            403, "Account credentials are managed by your identity provider"
        )
    oidc.require_origin(request)


async def provider_request(
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    token: str | None = None,
    params: dict[str, str] | None = None,
    generic: bool = False,
) -> dict[str, Any]:
    if (
        settings.AUTH_MODE != "supabase"
        or not settings.SUPABASE_URL
        or not settings.SUPABASE_KEY
    ):
        raise HTTPException(503, "Hosted identity is not configured")
    headers = {"apikey": settings.SUPABASE_KEY}
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            result = await client.request(
                method,
                settings.SUPABASE_URL.rstrip("/") + "/auth/v1/" + path,
                headers=headers,
                json=body,
                params=params,
            )
    except httpx.HTTPError as exc:
        raise HTTPException(503, "Identity provider unavailable") from exc
    if result.status_code == 429:
        raise HTTPException(429, "Identity request rate limited")
    if result.status_code >= 500:
        raise HTTPException(503, "Identity provider unavailable")
    if result.is_error:
        if generic and result.status_code in {400, 401, 403, 422}:
            return {}
        raise HTTPException(401, "Identity request was not authorized")
    if result.status_code == 204:
        return {}
    try:
        value = result.json()
        if not isinstance(value, dict):
            raise ValueError("Invalid response")
        return value
    except ValueError as exc:
        raise HTTPException(503, "Invalid identity provider response") from exc


async def validated_token(token: dict[str, Any]) -> dict[str, Any]:
    access_token = token.get("access_token")
    refresh_token = token.get("refresh_token")
    expires_in = token.get("expires_in")
    if (
        not isinstance(access_token, str)
        or not isinstance(refresh_token, str)
        or not isinstance(expires_in, int)
        or expires_in <= 0
    ):
        raise HTTPException(401, "Invalid identity session")
    try:
        user = await verifier.verify(access_token)
    except Exception as exc:
        raise HTTPException(503, "Identity verification unavailable") from exc
    if user is None:
        raise HTTPException(401, "Invalid identity session")
    return {
        "token": {"access_token": access_token, "refresh_token": refresh_token},
        "claims": {"sub": str(user.id), "exp": time.time() + min(expires_in, 86_400)},
        "checked_at": time.time(),
        "expires_at": time.time() + settings.OIDC_SESSION_SECONDS,
        "provider": "supabase",
    }


async def create_session(
    request: Request,
    response: Response,
    token: dict[str, Any],
    session: AsyncSession,
    *,
    recovery: bool = False,
) -> None:
    from shim_enterprise.api.enterprise_deps import _load_jwt_user

    data = await validated_token(token)
    user = await _load_jwt_user(data["token"]["access_token"], session)
    if user is None or str(user.id) != data["claims"]["sub"]:
        raise HTTPException(401, "Identity membership is inactive")
    data["recovery"] = recovery
    previous = request.cookies.get(oidc.SESSION_COOKIE)
    session_id = secrets.token_urlsafe(32)
    await oidc._save_session(request, oidc._session_key(session_id), data, create=True)
    if previous:
        await oidc._redis(request).delete(oidc._session_key(previous))
    oidc.set_session_cookie(response, session_id, data["expires_at"])


async def refresh_session(data: dict[str, Any]) -> dict[str, Any]:
    token = await provider_request(
        "POST",
        "token",
        body={"refresh_token": data["token"]["refresh_token"]},
        params={"grant_type": "refresh_token"},
    )
    refreshed = await validated_token(token)
    if refreshed["claims"]["sub"] != data["claims"]["sub"]:
        raise HTTPException(401, "Session identity changed")
    return data | {
        "token": refreshed["token"],
        "claims": refreshed["claims"],
        "checked_at": refreshed["checked_at"],
    }


async def start_flow(
    request: Request, *, next_path: str, recovery: bool = False
) -> str:
    oidc.validate_return_path(next_path)
    flow_id, verifier_value = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
    data = {"verifier": verifier_value, "next": next_path, "recovery": recovery}
    await oidc._redis(request).set(
        "identity:flow:" + hashlib.sha256(flow_id.encode()).hexdigest(),
        oidc._cipher().encrypt(json.dumps(data).encode()).decode(),
        ex=300,
    )
    request.session.clear()
    request.session["flow_id"] = flow_id
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier_value.encode()).digest())
        .decode()
        .rstrip("=")
    )


async def oauth_login(
    request: Request, next_path: str, provider: Literal["google", "github"] | None
) -> Response:
    if provider is None:
        raise HTTPException(422, "Choose a hosted identity provider")
    if not settings.DASHBOARD_ORIGIN or not settings.SUPABASE_URL:
        raise HTTPException(503, "Hosted identity is not configured")
    challenge = await start_flow(request, next_path=next_path)
    query = urlencode(
        {
            "provider": provider,
            "redirect_to": str(settings.DASHBOARD_ORIGIN).rstrip("/")
            + "/api/v1/auth/callback",
            "code_challenge": challenge,
            "code_challenge_method": "s256",
        }
    )
    return RedirectResponse(
        str(settings.SUPABASE_URL).rstrip("/") + "/auth/v1/authorize?" + query,
        headers={"Cache-Control": "no-store"},
    )


async def callback(request: Request, session: AsyncSession) -> Response:
    flow_id = request.session.pop("flow_id", None)
    code = request.query_params.get("code")
    if not isinstance(flow_id, str) or not code:
        raise HTTPException(401, "Sign-in flow expired")
    key = "identity:flow:" + hashlib.sha256(flow_id.encode()).hexdigest()
    stored = await oidc._redis(request).getdel(key)
    if not stored:
        raise HTTPException(401, "Sign-in flow expired")
    data = json.loads(oidc._cipher().decrypt(stored.encode()))
    token = await provider_request(
        "POST",
        "token",
        params={"grant_type": "pkce"},
        body={"auth_code": code, "code_verifier": data["verifier"]},
    )
    response = RedirectResponse(
        str(settings.DASHBOARD_ORIGIN).rstrip("/") + data["next"], status_code=303
    )
    await create_session(request, response, token, session, recovery=data["recovery"])
    return response


@router.post("/password/login", response_model=AuthResult)
async def password_login(
    payload: PasswordLogin,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_db),
) -> AuthResult:
    require_hosted(request)
    token = await provider_request(
        "POST",
        "token",
        params={"grant_type": "password"},
        body={
            "email": str(payload.email),
            "password": payload.password.get_secret_value(),
        },
    )
    await create_session(request, response, token, session)
    return AuthResult()


@router.post("/register", response_model=AuthResult)
async def register(
    payload: Registration,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_db),
) -> AuthResult:
    require_hosted(request)
    challenge = await start_flow(request, next_path=payload.next)
    token = await provider_request(
        "POST",
        "signup",
        params={
            "redirect_to": str(settings.DASHBOARD_ORIGIN).rstrip("/")
            + "/api/v1/auth/callback"
        },
        body={
            "email": str(payload.email),
            "password": payload.password.get_secret_value(),
            "data": {
                "full_name": payload.full_name,
                "organization": payload.organization,
            },
            "code_challenge": challenge,
            "code_challenge_method": "s256",
        },
        generic=True,
    )
    if token.get("access_token"):
        await create_session(request, response, token, session)
    response.headers["Cache-Control"] = "no-store"
    return AuthResult()


@router.post("/recovery", response_model=AuthResult)
async def recovery(
    payload: EmailInput, request: Request, response: Response
) -> AuthResult:
    require_hosted(request)
    oidc.validate_return_path(payload.next)
    challenge = await start_flow(request, next_path="/reset-password", recovery=True)
    await provider_request(
        "POST",
        "recover",
        params={
            "redirect_to": str(settings.DASHBOARD_ORIGIN).rstrip("/")
            + "/api/v1/auth/callback"
        },
        body={
            "email": str(payload.email),
            "code_challenge": challenge,
            "code_challenge_method": "s256",
        },
        generic=True,
    )
    response.headers["Cache-Control"] = "no-store"
    return AuthResult()


@router.post("/resend", response_model=AuthResult)
async def resend(
    payload: EmailInput, request: Request, response: Response
) -> AuthResult:
    require_hosted(request)
    challenge = await start_flow(request, next_path=payload.next)
    await provider_request(
        "POST",
        "resend",
        params={
            "redirect_to": str(settings.DASHBOARD_ORIGIN).rstrip("/")
            + "/api/v1/auth/callback"
        },
        body={
            "email": str(payload.email),
            "type": "signup",
            "code_challenge": challenge,
            "code_challenge_method": "s256",
        },
        generic=True,
    )
    response.headers["Cache-Control"] = "no-store"
    return AuthResult()


@router.get("/confirm")
async def confirm(
    request: Request,
    token_hash: str,
    type: Literal["signup", "recovery", "invite", "email"],
    next: str = "/dashboard",
    session: AsyncSession = Depends(get_db),
) -> Response:
    if settings.AUTH_MODE != "supabase":
        raise HTTPException(404, "Hosted confirmation is not configured")
    oidc.validate_return_path(next)
    token = await provider_request(
        "POST",
        "verify",
        body={
            "token_hash": token_hash,
            "type": type,
        },
    )
    next_path = "/reset-password" if type == "recovery" else next
    response = RedirectResponse(
        str(settings.DASHBOARD_ORIGIN).rstrip("/") + next_path, status_code=303
    )
    await create_session(request, response, token, session, recovery=type == "recovery")
    return response


@router.post("/password/reset", response_model=AuthResult)
async def reset_password(
    payload: PasswordInput, request: Request, response: Response
) -> AuthResult:
    require_hosted(request)
    data = await oidc.session_data(request)
    if not data.get("recovery"):
        raise HTTPException(403, "A verified recovery session is required")
    await provider_request(
        "PUT",
        "user",
        token=data["token"]["access_token"],
        body={"password": payload.password.get_secret_value()},
    )
    data["recovery"] = False
    await oidc._save_session(
        request, oidc._session_key(request.cookies[oidc.SESSION_COOKIE]), data
    )
    response.headers["Cache-Control"] = "no-store"
    return AuthResult()


@router.post("/account/password", response_model=AuthResult)
async def change_password(
    payload: PasswordChange, request: Request, response: Response
) -> AuthResult:
    require_hosted(request)
    data = await oidc.session_data(request)
    user = await verifier.verify(data["token"]["access_token"])
    if user is None:
        raise HTTPException(401, "Invalid identity session")
    token = await provider_request(
        "POST",
        "token",
        params={"grant_type": "password"},
        body={
            "email": user.email,
            "password": payload.current_password.get_secret_value(),
        },
    )
    validated = await validated_token(token)
    if validated["claims"]["sub"] != data["claims"]["sub"]:
        raise HTTPException(401, "Session identity changed")
    await provider_request(
        "PUT",
        "user",
        token=validated["token"]["access_token"],
        body={"password": payload.password.get_secret_value()},
    )
    data.update(
        token=validated["token"],
        claims=validated["claims"],
        checked_at=validated["checked_at"],
    )
    await oidc._save_session(
        request, oidc._session_key(request.cookies[oidc.SESSION_COOKIE]), data
    )
    response.headers["Cache-Control"] = "no-store"
    return AuthResult()
