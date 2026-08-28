"""Enterprise scan actor and tenant-policy resolution."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Literal
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shim.gateway.contracts.ids import ApiKeyId, TenantId, UserId
from shim.gateway.contracts.inference import ScanPolicy
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim_enterprise.gateway.pipeline.audit_intent import resolve_audit_policy
from shim.privacy.pii_scrubber import effective_pii_config
from shim_enterprise.tenants.models import (
    Organization,
    OrganizationPIIConfig,
    TierDefinition,
    User,
)
from shim_enterprise.tenants.policy import load_api_key_for_principal


@dataclass(frozen=True, slots=True)
class ResolvedScanActor:
    tenant_id: TenantId
    actor_type: Literal["api_key", "user_jwt"]
    api_key_id: ApiKeyId | None
    user_id: UserId | None
    subject_id: UUID
    tier: str
    policy: ScanPolicy
    scan_limit: int
    audit_mode: Literal["off", "best_effort", "strict"]
    pii_config: dict[str, bool]


class ScanPolicyResolver:
    """Resolve current scan ownership and policy from a trusted principal."""

    async def resolve(
        self,
        principal: AuthenticatedPrincipal,
        session: AsyncSession,
    ) -> ResolvedScanActor:
        if principal.actor_type == "api_key" and principal.api_key_id is not None:
            actor = await self._api_key_actor(principal, session)
        elif principal.actor_type == "user_jwt" and principal.user_id is not None:
            actor = await self._user_actor(principal, session)
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Scan requires an API-key or user-JWT principal.",
            )
        config = (
            await session.execute(
                select(OrganizationPIIConfig).where(
                    OrganizationPIIConfig.organization_id == actor.tenant_id
                )
            )
        ).scalar_one_or_none()
        overrides = None
        if config is not None:
            overrides = {
                "block_email": config.block_email,
                "block_phone": config.block_phone,
                "block_credit_card": config.block_credit_card,
                "block_secrets": config.block_secrets,
                "block_pii_tr": config.block_pii_tr,
            }
        return replace(actor, pii_config=effective_pii_config(overrides))

    async def _api_key_actor(
        self,
        principal: AuthenticatedPrincipal,
        session: AsyncSession,
    ) -> ResolvedScanActor:
        api_key = await load_api_key_for_principal(principal, session)
        tier = (
            await session.execute(
                select(TierDefinition).where(TierDefinition.slug == api_key.tier)
            )
        ).scalar_one_or_none()
        if tier is None or api_key.organization_id is None or api_key.user_id is None:
            raise _scan_policy_unavailable()
        return _scan_actor(
            tenant_id=TenantId(api_key.organization_id),
            actor_type="api_key",
            api_key_id=ApiKeyId(api_key.id),
            user_id=None,
            subject_id=api_key.user_id,
            tier=tier,
            default_policy="block",
        )

    async def _user_actor(
        self,
        principal: AuthenticatedPrincipal,
        session: AsyncSession,
    ) -> ResolvedScanActor:
        resolved = (
            await session.execute(
                select(User, TierDefinition)
                .join(Organization, Organization.id == User.organization_id)
                .join(TierDefinition, TierDefinition.slug == Organization.tier)
                .where(
                    User.id == UUID(str(principal.user_id)),
                    User.is_active.is_(True),
                )
            )
        ).one_or_none()
        if resolved is None:
            raise _scan_policy_unavailable()
        user, tier = resolved
        return _scan_actor(
            tenant_id=TenantId(user.organization_id),
            actor_type="user_jwt",
            api_key_id=None,
            user_id=UserId(user.id),
            subject_id=user.id,
            tier=tier,
            default_policy="warn",
        )


def _scan_actor(
    *,
    tenant_id: TenantId,
    actor_type: Literal["api_key", "user_jwt"],
    api_key_id: ApiKeyId | None,
    user_id: UserId | None,
    subject_id: UUID,
    tier: TierDefinition,
    default_policy: ScanPolicy,
) -> ResolvedScanActor:
    features = tier.features or {}
    if not isinstance(features, Mapping):
        raise _scan_policy_unavailable()
    policy = features.get("scan_policy", default_policy)
    limit = features.get("monthly_scan_limit", 200)
    if policy not in {"warn", "block"} or not isinstance(limit, int) or limit < -1:
        raise _scan_policy_unavailable()
    audit_mode = resolve_audit_policy({"features": dict(features)}).mode
    return ResolvedScanActor(
        tenant_id=tenant_id,
        actor_type=actor_type,
        api_key_id=api_key_id,
        user_id=user_id,
        subject_id=subject_id,
        tier=tier.slug,
        policy=policy,
        scan_limit=limit,
        audit_mode=audit_mode,
        pii_config={},
    )


def _scan_policy_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "code": "TENANT_NOT_FOUND",
            "message": "Trusted scan tenant policy is unavailable.",
        },
    )
