"""Tenant-owned policy resolution for authenticated gateway requests."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim_enterprise.cache.redis_index import CacheManager
from shim_enterprise.core.config import settings
from shim.gateway.contracts.context import TenantPolicy, TierPolicy
from shim.gateway.contracts.ids import TenantId
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim_enterprise.gateway.pipeline.audit_intent import resolve_audit_policy
from shim.gateway.request_policy import (
    RequestPolicyContext,
    ResolvedRequestPolicy,
)
from shim_enterprise.tenants.models import (
    ApiKey,
    OrganizationPIIConfig,
    TierDefinition,
)


class TenantPolicyConfigurationError(RuntimeError):
    """Trusted tenant policy configuration could not be validated safely."""


async def load_api_key_for_principal(
    principal: AuthenticatedPrincipal,
    session: AsyncSession,
) -> ApiKey:
    """Load current key state by trusted ID without re-authenticating a secret."""

    if principal.actor_type != "api_key" or principal.api_key_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Gateway inference requires an API-key principal.",
        )
    result = await session.execute(
        select(ApiKey).where(
            ApiKey.id == UUID(str(principal.api_key_id)),
            ApiKey.is_active.is_(True),
            or_(
                ApiKey.expires_at.is_(None),
                ApiKey.expires_at > datetime.now(timezone.utc),
            ),
        )
    )
    api_key = result.scalar_one_or_none()
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if UUID(str(api_key.id)) != UUID(str(principal.api_key_id)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated principal does not match the resolved API key.",
        )
    return api_key


def _unlimited_as_none(value: object) -> int | None:
    if not isinstance(value, int) or value < 0:
        return None
    return value


def _resolve_tenant_policy(
    tier_definition: Mapping[str, object] | None,
) -> TenantPolicy:
    if not tier_definition:
        return TenantPolicy()
    features = tier_definition.get("features")
    if features is None:
        return TenantPolicy()
    if not isinstance(features, Mapping):
        raise ValueError("tier features must be an object")
    provider_policy = features.get("provider_policy")
    if provider_policy is None:
        return TenantPolicy()
    if not isinstance(provider_policy, Mapping):
        raise ValueError("provider policy must be an object")
    return TenantPolicy.model_validate(dict(provider_policy))


@dataclass(frozen=True, slots=True)
class ResolvedTenantSettings:
    tenant_id: UUID
    pii_config: dict[str, bool] | None
    tier_definition: dict[str, Any] | None


class TenantPolicyService:
    """Resolve policy only after the trusted API-key owner is known."""

    def __init__(self, cache: CacheManager) -> None:
        self.cache = cache

    async def resolve(
        self,
        api_key: ApiKey,
        session: AsyncSession,
    ) -> ResolvedTenantSettings:
        tenant_id = api_key.organization_id
        if tenant_id is None:
            raise ValueError("authenticated API key has no tenant owner")
        pii_config = await self._pii_config(tenant_id, session)
        tier = await self._tier_definition(api_key.tier, session)
        return ResolvedTenantSettings(
            tenant_id=tenant_id,
            pii_config=pii_config,
            tier_definition=tier,
        )

    async def _pii_config(
        self,
        tenant_id: UUID,
        session: AsyncSession,
    ) -> dict[str, bool] | None:
        cache_key = str(tenant_id)
        cached = await self.cache.get_pii_config(cache_key)
        if cached is not None:
            return {key: bool(value) for key, value in cached.items()}
        row = (
            await session.execute(
                select(OrganizationPIIConfig).where(
                    OrganizationPIIConfig.organization_id == tenant_id
                )
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        value = {
            "block_email": row.block_email,
            "block_phone": row.block_phone,
            "block_credit_card": row.block_credit_card,
            "block_secrets": row.block_secrets,
            "block_pii_tr": row.block_pii_tr,
        }
        await self.cache.set_pii_config(cache_key, value)
        return value

    async def _tier_definition(
        self,
        slug: str,
        session: AsyncSession,
    ) -> dict[str, Any] | None:
        cached = await self.cache.get_tier_definition(slug)
        if cached is not None:
            return cached
        row = (
            await session.execute(
                select(TierDefinition).where(TierDefinition.slug == slug)
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        value = {
            "rate_limit_rpm": row.rate_limit_rpm,
            "rate_limit_tpm": row.rate_limit_tpm,
            "monthly_request_limit": row.monthly_request_limit,
            "monthly_token_limit": row.monthly_token_limit,
            "daily_request_limit": row.daily_request_limit,
            "features": dict(row.features or {}),
        }
        await self.cache.set_tier_definition(slug, value)
        return value


class TenantRequestPolicyResolver:
    """Resolve enterprise tenant policy inside one short database session."""

    def __init__(
        self,
        policy_service: TenantPolicyService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self.policy_service = policy_service
        self.session_factory = session_factory

    async def resolve(
        self,
        principal: AuthenticatedPrincipal,
    ) -> ResolvedRequestPolicy:
        async with self.session_factory() as session:
            api_key = await load_api_key_for_principal(principal, session)
            tenant_settings = await self.policy_service.resolve(api_key, session)
            tier_definition = tenant_settings.tier_definition
            tier = tier_definition or {}
            try:
                tenant_policy = _resolve_tenant_policy(tier_definition)
                audit_policy = resolve_audit_policy(tier_definition)
            except (TypeError, ValueError) as exc:
                raise TenantPolicyConfigurationError(
                    "tenant policy is invalid"
                ) from exc
            resolved = ResolvedRequestPolicy(
                tenant_id=TenantId(tenant_settings.tenant_id),
                tenant_policy=tenant_policy,
                tier_policy=TierPolicy(
                    rate_limit_rpm=_unlimited_as_none(
                        tier.get("rate_limit_rpm", settings.DEFAULT_RPM_LIMIT)
                    ),
                    rate_limit_tpm=_unlimited_as_none(
                        tier.get("rate_limit_tpm", settings.DEFAULT_TPM_LIMIT)
                    ),
                    daily_request_limit=_unlimited_as_none(
                        tier.get("daily_request_limit")
                    ),
                    monthly_request_limit=_unlimited_as_none(
                        tier.get("monthly_request_limit", 1_000)
                    ),
                    monthly_token_limit=_unlimited_as_none(
                        tier.get(
                            "monthly_token_limit",
                            settings.DEFAULT_MONTHLY_TOKEN_LIMIT,
                        )
                    ),
                ),
                audit_policy=audit_policy,
                request_policy=RequestPolicyContext(
                    rate_limit_key_hash=api_key.key_hash,
                    tier=api_key.tier,
                    cost_center=api_key.cost_center,
                    team=api_key.team,
                ),
                pii_config=tenant_settings.pii_config,
            )
        return resolved
