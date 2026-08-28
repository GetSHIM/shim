"""Tenant lifecycle operations used by authenticated control-plane flows."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import re
import secrets
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from supabase import AuthApiError

from shim_enterprise.core.config import settings
from shim_enterprise.core.database import Base
from shim_enterprise.tenants.models import (
    ApiKey,
    Organization,
    OrganizationPIIConfig,
    User,
)

API_KEY_PREFIX = "sk-shim-"


async def get_or_create_organization(
    session: AsyncSession,
    *,
    name: str,
    creator_user_id: UUID | None = None,
) -> Organization:
    slug = _slug(name)
    if creator_user_id is not None:
        slug = f"{slug}-{str(creator_user_id)[:8]}"
    statement = (
        insert(Organization)
        .values(id=uuid4(), name=name.strip(), slug=slug)
        .on_conflict_do_nothing(index_elements=[Organization.slug])
        .returning(Organization)
    )
    organization = (await session.execute(statement)).scalar_one_or_none()
    if organization is None:
        organization = (
            await session.execute(select(Organization).where(Organization.slug == slug))
        ).scalar_one_or_none()
    if organization is None:
        raise RuntimeError("organization upsert returned no row")
    return organization


async def ensure_privacy_defaults(
    session: AsyncSession,
    tenant_id: UUID,
) -> OrganizationPIIConfig:
    statement = (
        insert(OrganizationPIIConfig)
        .values(
            id=uuid4(),
            organization_id=tenant_id,
        )
        .on_conflict_do_nothing(index_elements=[OrganizationPIIConfig.organization_id])
        .returning(OrganizationPIIConfig)
    )
    config = (await session.execute(statement)).scalar_one_or_none()
    if config is None:
        config = (
            await session.execute(
                select(OrganizationPIIConfig).where(
                    OrganizationPIIConfig.organization_id == tenant_id
                )
            )
        ).scalar_one_or_none()
    if config is None:
        raise RuntimeError("privacy-default upsert returned no row")
    return config


async def create_api_key(
    session: AsyncSession,
    *,
    user_id: UUID,
    name: str,
    cost_center: str | None = None,
    team: str | None = None,
) -> tuple[str, ApiKey]:
    tenant_id = await session.scalar(
        select(User.organization_id).where(User.id == user_id)
    )
    if tenant_id is None:
        raise ValueError("API-key owner must be active and belong to a tenant")
    tier = await session.scalar(
        select(Organization.tier)
        .where(Organization.id == tenant_id)
        .with_for_update(of=Organization)
    )
    owner_id = await session.scalar(
        select(User.id)
        .where(
            User.id == user_id,
            User.organization_id == tenant_id,
            User.is_active.is_(True),
        )
        .with_for_update(of=User)
    )
    if tier is None or owner_id is None:
        raise ValueError("API-key owner must be active and belong to a tenant")
    plaintext = f"{API_KEY_PREFIX}{secrets.token_hex(32)}"
    api_key = ApiKey(
        user_id=user_id,
        organization_id=tenant_id,
        key_hash=_digest_api_key(plaintext),
        prefix=plaintext[:16],
        name=name,
        tier=tier,
        is_active=True,
        cost_center=cost_center,
        team=team,
    )
    session.add(api_key)
    await session.flush()
    return plaintext, api_key


async def move_user_from_bootstrap(
    session: AsyncSession,
    *,
    user_id: UUID,
    source_organization_id: UUID,
    destination_organization_id: UUID,
    role: str,
) -> User | None:
    source = await session.scalar(
        select(Organization)
        .where(Organization.id == source_organization_id)
        .with_for_update(of=Organization)
    )
    if source is None:
        return None
    user = await session.scalar(
        select(User)
        .where(
            User.id == user_id,
            User.organization_id == source_organization_id,
        )
        .with_for_update(of=User)
    )
    if user is None or not await _bootstrap_is_empty(session, source):
        return None
    user.organization_id = destination_organization_id
    user.role = role
    user.is_active = True
    await session.flush()
    await session.delete(source)
    await session.flush()
    return user


async def delete_empty_bootstrap_identity_conflict(
    session: AsyncSession,
    *,
    user_id: UUID,
    email: str,
    email_confirmed: bool,
) -> bool:
    """Remove an unused local identity replaced by a confirmed Supabase user."""
    existing = await session.scalar(
        select(User).where(func.lower(User.email) == email.casefold())
    )
    if existing is None or existing.id == user_id:
        return False
    if not email_confirmed:
        raise RuntimeError("unconfirmed identity conflicts with an existing user")

    organization = await session.scalar(
        select(Organization)
        .where(Organization.id == existing.organization_id)
        .with_for_update(of=Organization)
    )
    if organization is None:
        return False
    existing = await session.scalar(
        select(User)
        .where(
            User.id == existing.id,
            User.organization_id == organization.id,
        )
        .with_for_update(of=User)
    )
    if existing is None:
        return False
    if not await _bootstrap_is_empty(session, organization):
        raise RuntimeError("identity conflicts with a non-empty tenant")

    await session.delete(organization)
    await session.flush()
    return True


async def authenticate_api_key(
    session: AsyncSession,
    plaintext: str,
) -> ApiKey | None:
    if not plaintext.startswith(API_KEY_PREFIX):
        return None
    statement = select(ApiKey).where(
        ApiKey.key_hash == _digest_api_key(plaintext),
        ApiKey.is_active.is_(True),
    )
    api_key = (await session.execute(statement)).scalar_one_or_none()
    if api_key is None:
        return None
    if api_key.expires_at is not None:
        expiry = api_key.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= datetime.now(timezone.utc):
            return None
    return api_key


async def _bootstrap_is_empty(
    session: AsyncSession,
    organization: Organization,
) -> bool:
    users = int(
        await session.scalar(
            select(func.count(User.id)).where(User.organization_id == organization.id)
        )
        or 0
    )
    if (
        users != 1
        or organization.tier != "free"
        or organization.billing_source is not None
    ):
        return False
    ignored = {
        "organizations",
        "users",
        "organization_pii_configs",
    }
    for table in Base.metadata.sorted_tables:
        if table.name in ignored or "organization_id" not in table.c:
            continue
        exists = await session.scalar(
            select(table.c.organization_id)
            .where(table.c.organization_id == organization.id)
            .limit(1)
        )
        if exists is not None:
            return False
    return True


def _digest_api_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()


class JwtIdentityVerifier:
    """Verify a Supabase bearer token without using privileged credentials."""

    def __init__(self, client: Any | None = None) -> None:
        self._client = client

    async def verify(self, token: str) -> Any | None:
        if not token:
            return None
        if self._client is None:
            self._client = self._build_client()
        try:
            response = await asyncio.to_thread(self._client.auth.get_user, token)
        except AuthApiError as exc:
            if exc.status in {400, 401, 403, 422}:
                return None
            raise
        return response.user if response is not None else None

    @staticmethod
    def _build_client() -> Any:
        if not settings.SUPABASE_KEY:
            raise RuntimeError("SUPABASE_KEY is required for JWT verification")
        from supabase import create_client

        return create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)


def _slug(name: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", name.strip().casefold()).strip("-")
    if not value:
        raise ValueError("tenant name must contain letters or numbers")
    return value
