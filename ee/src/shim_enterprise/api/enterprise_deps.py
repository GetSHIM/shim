"""Enterprise database and control-plane dependencies."""

import logging
import uuid
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import (
    APIKeyHeader,
    HTTPAuthorizationCredentials,
    HTTPBearer,
)
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim_enterprise.core.database import AsyncSessionLocal, get_db
from shim.gateway.auth import authentication_error, select_gateway_credential
from shim.gateway.contracts.ids import ApiKeyId, UserId
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim_enterprise.services.gateway.enterprise import EnterpriseGatewayService
from shim_enterprise.tenants.models import ApiKey, User
from shim_enterprise.tenants.service import (
    API_KEY_PREFIX,
    JwtIdentityVerifier,
    authenticate_api_key,
    delete_empty_bootstrap_identity_conflict,
    ensure_privacy_defaults,
    get_or_create_organization,
)

logger = logging.getLogger(__name__)
jwt_verifier = JwtIdentityVerifier()


def get_enterprise_gateway_service(request: Request) -> EnterpriseGatewayService:
    gateway_service = getattr(request.app.state, "gateway_service", None)
    if gateway_service is None:
        raise HTTPException(status_code=503, detail="Gateway Service not available")
    return gateway_service


api_key_header_scheme = APIKeyHeader(
    name="x-shim-key", scheme_name="ShimAPIKey", auto_error=False
)
bearer_scheme = HTTPBearer(auto_error=False)


class DatabaseGatewayAuthenticator:
    """Resolve an inference principal inside one short database session."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._session_factory = session_factory

    async def resolve(self, candidate: str | None) -> AuthenticatedPrincipal:
        async with self._session_factory() as session:
            api_key = await _authenticate_gateway_key(session, candidate)
            return _api_key_principal(api_key)


async def _load_or_sync_supabase_user(
    session: AsyncSession,
    sb_user,
) -> User:
    """Return the local user, provisioning mandatory tenant ownership if new."""
    user_id = uuid.UUID(str(sb_user.id))
    email = str(sb_user.email or "").strip()
    if not email:
        raise ValueError("Verified identity must include an email address")
    query = select(User).where(User.id == user_id)
    result = await session.execute(query)
    user = result.scalar_one_or_none()

    if user is not None:
        if not user.is_verified and getattr(sb_user, "email_confirmed_at", None):
            user.is_verified = True
            await session.commit()
        return user

    if await delete_empty_bootstrap_identity_conflict(
        session,
        user_id=user_id,
        email=email,
        email_confirmed=bool(getattr(sb_user, "email_confirmed_at", None)),
    ):
        logger.info("Removed empty stale Supabase identity bootstrap")

    logger.info("Supabase identity missing locally; synchronizing tenant ownership")
    metadata = getattr(sb_user, "user_metadata", None)
    organization_name = email
    full_name = None
    if isinstance(metadata, dict):
        if "full_name" in metadata:
            full_name = metadata["full_name"]
        organization_name = metadata.get("organization") or email

    org = await get_or_create_organization(
        session,
        name=organization_name,
        creator_user_id=user_id,
    )
    await ensure_privacy_defaults(session, org.id)
    user = (
        await session.execute(
            insert(User)
            .values(
                id=user_id,
                organization_id=org.id,
                email=email,
                full_name=full_name,
                is_verified=bool(getattr(sb_user, "email_confirmed_at", None)),
                is_active=True,
                role="owner",
            )
            .on_conflict_do_nothing()
            .returning(User)
        )
    ).scalar_one_or_none()
    if user is None:
        user = (
            await session.execute(select(User).where(User.id == user_id))
        ).scalar_one_or_none()
    if user is None:
        raise RuntimeError("user upsert returned no row")
    await session.commit()
    return user


async def get_current_api_key(
    request: Request,
    _api_key_header: str | None = Security(api_key_header_scheme),
    _bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> ApiKey:
    """Validate a gateway key from x-shim-key or Bearer authentication."""

    async with AsyncSessionLocal() as session:
        return await _authenticate_gateway_key(
            session,
            select_gateway_credential(request.headers),
        )


async def _authenticate_gateway_key(
    session: AsyncSession,
    plain_key: str | None,
) -> ApiKey:
    if plain_key is None:
        raise authentication_error("Missing API Key")
    if not plain_key:
        raise authentication_error("Invalid API Key")

    api_key = await authenticate_api_key(session, plain_key)

    if not api_key:
        logger.warning("Invalid API Key attempt (key redacted)")
        raise authentication_error("Invalid API Key")

    return api_key


def _api_key_principal(current_api_key: ApiKey) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        actor_type="api_key",
        api_key_id=ApiKeyId(current_api_key.id),
        authenticated_at=datetime.now(timezone.utc),
    )


async def _load_jwt_user(token: str, session: AsyncSession) -> User | None:
    try:
        sb_user = await jwt_verifier.verify(token)
    except Exception as exc:
        logger.error(
            "Supabase token verification unavailable type=%s", type(exc).__name__
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Identity verification unavailable",
        ) from exc
    if not sb_user:
        return None
    try:
        return await _load_or_sync_supabase_user(session, sb_user)
    except Exception as exc:
        logger.error("JWT synchronization failed type=%s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="User synchronization unavailable",
        ) from exc


async def get_scan_principal(
    request: Request,
    _api_key_header: str | None = Security(api_key_header_scheme),
    _bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    session: AsyncSession = Depends(get_db),
) -> AuthenticatedPrincipal:
    """Authenticate scan callers without accepting caller-supplied tenancy."""

    token = select_gateway_credential(request.headers)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication — provide x-shim-key header or Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not token:
        raise authentication_error("Invalid authentication credential")
    if "x-shim-key" in request.headers or token.startswith(API_KEY_PREFIX):
        api_key = await authenticate_api_key(session, token)
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API Key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return _api_key_principal(api_key)
    user = await _load_jwt_user(token, session)
    if user is not None and user.is_active:
        return AuthenticatedPrincipal(
            actor_type="user_jwt",
            user_id=UserId(user.id),
            authenticated_at=datetime.now(timezone.utc),
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_invite_user(
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    session: AsyncSession = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if bearer is None:
        raise credentials_exception

    user = await _load_jwt_user(bearer.credentials, session)
    if user is None:
        logger.warning("Supabase token verification failed")
        raise credentials_exception
    return user


async def get_current_user(
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    session: AsyncSession = Depends(get_db),
) -> User:
    user = await get_invite_user(bearer, session)
    if not user.is_active:
        logger.warning("Rejected deactivated user")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_org_admin(user: User = Depends(get_current_user)) -> User:
    if user.role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Organization admin required")
    return user


async def get_org_owner(user: User = Depends(get_current_user)) -> User:
    if user.role != "owner":
        raise HTTPException(status_code=403, detail="Organization owner required")
    return user
