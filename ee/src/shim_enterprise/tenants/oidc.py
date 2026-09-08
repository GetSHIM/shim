"""Customer OIDC login and identity projection; tokens stay on the server."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import time
from typing import Any
from urllib.parse import urlencode, urlsplit
from uuid import uuid4

from authlib.integrations.base_client import OAuthError
from authlib.integrations.starlette_client import OAuth
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
import httpx
import jwt
from joserfc.errors import JoseError
from pydantic import EmailStr, TypeAdapter, ValidationError
from redis.exceptions import RedisError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.sessions import SessionMiddleware

from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim_enterprise.tenants.models import Organization, User

router = APIRouter(prefix="/auth", tags=["identity"])
SESSION_COOKIE = "shim_session"
ASYMMETRIC_ALGORITHMS = {
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
}


def install_oidc(application: Any) -> None:
    if settings.AUTH_MODE != "oidc":
        return
    logging.getLogger("uvicorn.access").addFilter(_redact_login_query)
    oauth = OAuth()
    application.state.oidc = oauth.register(
        "customer",
        client_id=settings.OIDC_CLIENT_ID,
        client_secret=settings.OIDC_CLIENT_SECRET,
        server_metadata_url=f"{str(settings.OIDC_ISSUER_URL).rstrip('/')}/.well-known/openid-configuration",
        client_kwargs={
            "scope": "openid profile email",
            "code_challenge_method": "S256",
            "timeout": 10,
            "follow_redirects": False,
        },
    )
    application.add_middleware(
        SessionMiddleware,
        secret_key=settings.SECRET_KEY,
        session_cookie="shim_login",
        max_age=300,
        same_site="lax",
        https_only=settings.ENVIRONMENT == "production",
    )


def _redact_login_query(record: logging.LogRecord) -> bool:
    if isinstance(record.args, tuple) and len(record.args) == 5:
        address, method, path, version, status = record.args
        if isinstance(path, str) and path.startswith("/api/v1/auth/"):
            record.args = (address, method, path.split("?", 1)[0], version, status)
    return True


def require_origin(request: Request) -> None:
    if request.headers.get("origin") != str(settings.DASHBOARD_ORIGIN).rstrip("/"):
        raise HTTPException(403, "Same-origin request required")


def _redis(request: Request) -> Any:
    redis = request.app.state.cache.redis
    if redis is None:
        raise HTTPException(503, "Identity session store unavailable")
    return redis


def _cipher() -> Fernet:
    return Fernet(
        base64.urlsafe_b64encode(
            hashlib.sha256(
                ("shim-oidc-session:" + settings.SECRET_KEY).encode()
            ).digest()
        )
    )


def _session_key(session_id: str) -> str:
    return "identity:session:" + hashlib.sha256(session_id.encode()).hexdigest()


async def _client(request: Request) -> Any:
    if settings.AUTH_MODE != "oidc":
        raise HTTPException(404, "OIDC is not configured")
    client = request.app.state.oidc
    metadata = await client.load_server_metadata()
    if metadata.get("issuer") != settings.OIDC_ISSUER_URL:
        raise HTTPException(503, "OIDC discovery issuer does not match configuration")
    algorithms = metadata.get("id_token_signing_alg_values_supported", ["RS256"])
    algorithms = sorted(set(algorithms) & ASYMMETRIC_ALGORITHMS)
    if not algorithms:
        raise HTTPException(503, "OIDC requires asymmetric token signatures")
    metadata["id_token_signing_alg_values_supported"] = algorithms
    return client


def _claims_options() -> dict[str, Any]:
    return {
        "iss": {"essential": True, "value": settings.OIDC_ISSUER_URL},
        "sub": {"essential": True},
        "exp": {"essential": True},
        "iat": {"essential": True},
    }


def identity_groups(claims: dict[str, Any]) -> list[str]:
    groups = claims.get(settings.OIDC_GROUPS_CLAIM, [])
    if not isinstance(groups, list) or not all(
        isinstance(group, str) for group in groups
    ):
        raise HTTPException(403, "Identity groups must be an array of strings")
    return groups


async def synchronize_user(session: AsyncSession, claims: dict[str, Any]) -> User:
    issuer, subject = claims.get("iss"), claims.get("sub")
    if (
        issuer != settings.OIDC_ISSUER_URL
        or not isinstance(subject, str)
        or not subject
        or len(subject) > 255
        or not subject.isascii()
    ):
        raise HTTPException(401, "Invalid OIDC identity")
    groups = identity_groups(claims)
    roles = [
        settings.OIDC_GROUP_ROLE_MAP[group]
        for group in groups
        if group in settings.OIDC_GROUP_ROLE_MAP
    ]
    if not roles:
        raise HTTPException(403, "No authorized identity group")
    role = next(
        role for role in ("owner", "admin", "member", "auditor") if role in roles
    )
    # Tenant mutations share this lock order with team/key administration.
    if not await session.scalar(
        select(Organization.id)
        .where(Organization.id == settings.OIDC_ORGANIZATION_ID)
        .with_for_update()
    ):
        raise HTTPException(503, "OIDC organization has not been provisioned")
    user = await session.scalar(
        select(User)
        .where(User.oidc_issuer == issuer, User.oidc_subject == subject)
        .with_for_update()
    )
    if user is None:
        if claims.get("email_verified") is not True:
            raise HTTPException(403, "A verified email address is required")
        try:
            email = str(
                TypeAdapter(EmailStr).validate_python(claims.get("email"))
            ).casefold()
        except ValidationError as exc:
            raise HTTPException(403, "A verified email address is required") from exc
        if await session.scalar(select(User.id).where(func.lower(User.email) == email)):
            raise HTTPException(
                403, "Identity email is already assigned; contact your administrator"
            )
        name = claims.get("name")
        user = User(
            id=uuid4(),
            organization_id=settings.OIDC_ORGANIZATION_ID,
            oidc_issuer=issuer,
            oidc_subject=subject,
            email=email,
            full_name=name[:200] if isinstance(name, str) else None,
            role=role,
            is_active=True,
            is_verified=True,
        )
        session.add(user)
    if user.organization_id != settings.OIDC_ORGANIZATION_ID or not user.is_active:
        raise HTTPException(
            403, "Identity membership is inactive or belongs to another organization"
        )
    user.role = role
    try:
        await session.flush()
        # Team synchronization is wired to the tenant-owned helper in T07.
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            409, "Identity provisioning conflicted; sign in again"
        ) from exc
    return user


async def _save_session(
    request: Request, key: str, data: dict[str, Any], *, create: bool = False
) -> None:
    ttl = int(data["expires_at"] - time.time())
    if ttl <= 0:
        raise HTTPException(401, "Session expired")
    encrypted = _cipher().encrypt(json.dumps(data).encode()).decode()
    if not await _redis(request).set(key, encrypted, ex=ttl, nx=create, xx=not create):
        raise HTTPException(401, "Identity session was revoked")


@router.get("/login")
async def login(request: Request, next: str = "/dashboard") -> Response:
    client = await _client(request)
    parsed = urlsplit(next)
    if (
        not next.startswith("/")
        or next.startswith("//")
        or "\\" in next
        or parsed.netloc
        or parsed.scheme
        or any(ord(c) < 32 for c in next)
    ):
        raise HTTPException(400, "Invalid return path")
    request.session.clear()
    request.session["next"] = next
    return await client.authorize_redirect(request, settings.OIDC_REDIRECT_URI)


@router.get("/callback")
async def callback(
    request: Request, session: AsyncSession = Depends(get_db)
) -> Response:
    try:
        client = await _client(request)
        token = await client.authorize_access_token(
            request, claims_options=_claims_options(), leeway=0
        )
        claims = dict(token["userinfo"])
        await synchronize_user(session, claims)
        session_id = secrets.token_urlsafe(32)
        data = {
            "token": dict(token),
            "claims": claims,
            "checked_at": time.time(),
            "expires_at": time.time() + settings.OIDC_SESSION_SECONDS,
        }
        if not token.get("refresh_token"):
            data["expires_at"] = min(
                data["expires_at"],
                claims["exp"],
                token.get("expires_at", claims["exp"]),
            )
        await _save_session(request, _session_key(session_id), data, create=True)
    except (
        OAuthError,
        JoseError,
        jwt.PyJWTError,
        KeyError,
        ValueError,
        httpx.HTTPError,
        RedisError,
    ) as exc:
        request.session.clear()
        raise HTTPException(401, "OIDC sign-in failed") from exc
    next_path = request.session.get("next", "/dashboard")
    request.session.clear()
    response = RedirectResponse(
        str(settings.DASHBOARD_ORIGIN).rstrip("/") + next_path, status_code=303
    )
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        httponly=True,
        secure=settings.ENVIRONMENT == "production",
        samesite="lax",
        max_age=int(data["expires_at"] - time.time()),
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


async def session_claims(request: Request) -> dict[str, Any]:
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id or len(session_id) > 128:
        raise HTTPException(401, "Session expired")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        require_origin(request)
    key = _session_key(session_id)
    redis = _redis(request)
    try:
        stored = await redis.get(key)
        if not stored:
            raise HTTPException(401, "Session expired")
        data = json.loads(_cipher().decrypt(stored.encode()))
        if data["expires_at"] <= time.time():
            raise HTTPException(401, "Session expired")
        if (
            time.time() - data["checked_at"] >= settings.OIDC_REVALIDATE_SECONDS
            or data["claims"]["exp"] <= time.time()
        ):
            # One refresh per session prevents concurrent use of a rotated refresh token.
            lock = redis.lock(key + ":refresh", timeout=30, blocking=False)
            if not await lock.acquire():
                raise HTTPException(
                    503, "Session refresh in progress", headers={"Retry-After": "1"}
                )
            try:
                latest = await redis.get(key)
                if not latest:
                    raise HTTPException(401, "Session expired")
                data = json.loads(_cipher().decrypt(latest.encode()))
                if (
                    time.time() - data["checked_at"] < settings.OIDC_REVALIDATE_SECONDS
                    and data["claims"]["exp"] > time.time()
                ):
                    return data["claims"]
                client = await _client(request)
                refresh_token = data["token"].get("refresh_token")
                if not refresh_token:
                    raise HTTPException(
                        401, "Sign in again to revalidate identity membership"
                    )
                token = await client.fetch_access_token(
                    grant_type="refresh_token", refresh_token=refresh_token
                )
                claims = dict(
                    await client.parse_id_token(
                        token, nonce=None, claims_options=_claims_options(), leeway=0
                    )
                )
                if (claims["sub"], claims["iss"]) != (
                    data["claims"]["sub"],
                    data["claims"]["iss"],
                ):
                    raise HTTPException(401, "Session identity changed")
                data.update(
                    token=dict(
                        token, refresh_token=token.get("refresh_token", refresh_token)
                    ),
                    claims=claims,
                    checked_at=time.time(),
                )
                await _save_session(request, key, data)
            except (OAuthError, JoseError, KeyError, ValueError, HTTPException):
                await redis.delete(key)
                raise HTTPException(
                    401, "Identity session is no longer authorized"
                ) from None
            finally:
                await lock.release()
        return data["claims"]
    except (InvalidToken, ValueError, KeyError) as exc:
        raise HTTPException(401, "Invalid identity session") from exc
    except (RedisError, httpx.HTTPError) as exc:
        raise HTTPException(503, "Identity verification unavailable") from exc


async def access_token_claims(request: Request, token: str) -> dict[str, Any]:
    if not settings.OIDC_API_AUDIENCE:
        raise HTTPException(401, "OIDC bearer access is not configured")
    try:
        client = await _client(request)
        header = jwt.get_unverified_header(token)
        if header.get("alg") not in ASYMMETRIC_ALGORITHMS or not header.get("kid"):
            raise jwt.InvalidTokenError("Invalid signing header")
        jwks = await client.fetch_jwk_set()
        key = next(
            (key for key in jwks["keys"] if key.get("kid") == header["kid"]), None
        )
        if key is None:
            jwks = await client.fetch_jwk_set(force=True)
            key = next(
                (key for key in jwks["keys"] if key.get("kid") == header["kid"]), None
            )
        if key is None:
            raise jwt.InvalidTokenError("Unknown signing key")
        claims = jwt.decode(
            token,
            jwt.PyJWK.from_dict(key).key,
            algorithms=list(ASYMMETRIC_ALGORITHMS),
            audience=settings.OIDC_API_AUDIENCE,
            issuer=settings.OIDC_ISSUER_URL,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )
        if claims["exp"] - claims["iat"] > settings.OIDC_API_MAX_TOKEN_SECONDS:
            raise jwt.InvalidTokenError(
                "Access token lifetime exceeds configured revocation bound"
            )
        return claims
    except (jwt.PyJWTError, ValueError, KeyError, TypeError) as exc:
        raise HTTPException(401, "Invalid OIDC access token") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(503, "Identity verification unavailable") from exc


async def current_oidc_user(
    request: Request, session: AsyncSession, token: str | None = None
) -> User:
    claims = (
        await access_token_claims(request, token)
        if token
        else await session_claims(request)
    )
    return await synchronize_user(session, claims)


@router.get("/session")
async def get_session(
    request: Request, response: Response, session: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    if settings.AUTH_MODE != "oidc":
        raise HTTPException(404, "OIDC is not configured")
    user = await current_oidc_user(request, session)
    response.headers["Cache-Control"] = "no-store"
    return {
        "user": {
            "id": str(user.id),
            "email": user.email,
            "user_metadata": {"full_name": user.full_name},
            "role": user.role,
        }
    }


@router.post("/logout")
async def logout(request: Request) -> Response:
    require_origin(request)
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        await _redis(request).delete(_session_key(session_id))
    request.session.clear()
    client = await _client(request)
    endpoint = (await client.load_server_metadata()).get("end_session_endpoint")
    logout_url = (
        endpoint
        + "?"
        + urlencode(
            {
                "client_id": settings.OIDC_CLIENT_ID,
                "post_logout_redirect_uri": str(settings.DASHBOARD_ORIGIN).rstrip("/")
                + "/login",
            }
        )
        if endpoint
        else "/login"
    )
    response = JSONResponse(
        {"logout_url": logout_url}, headers={"Cache-Control": "no-store"}
    )
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        secure=settings.ENVIRONMENT == "production",
        httponly=True,
        samesite="lax",
    )
    return response
