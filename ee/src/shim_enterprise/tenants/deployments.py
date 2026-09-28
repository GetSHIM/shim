"""Tenant deployment resolution and operator-owned outbound destination policy."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import ipaddress
from typing import cast, Literal
from urllib.parse import urlsplit

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim.billing.pricing import DEFAULT_PRICE_BOOK
from shim.gateway.kernel.result import (
    PreparedInference,
    ProviderTarget,
    UNSPECIFIED_PROVIDER_MODEL,
)
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.api.v1.chat import model_record
from shim_enterprise.core.config import settings
from shim_enterprise.tenants.models import ModelDeployment, ApiKey, User
from shim_enterprise.tenants.teams import require_team


def validate_deployment_url(url: str) -> str:
    """Exact origins are approved by the platform operator, never by API callers."""
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "\\" in url
        or any(ord(char) < 33 for char in url)
    ):
        raise ValueError(
            "Deployment URL must be an absolute HTTP(S) URL without credentials, query or fragment"
        )
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    origin = (parsed.scheme, parsed.hostname.casefold(), port)
    approved = {
        (
            item.scheme,
            item.hostname,
            item.port or (443 if item.scheme == "https" else 80),
        )
        for item in map(urlsplit, settings.MODEL_DEPLOYMENT_ALLOWED_ORIGINS)
        if item.path in {"", "/"}
        and not item.query
        and not item.fragment
        and item.username is None
    }
    if origin not in approved:
        raise ValueError("Deployment origin is not approved by the platform operator")
    host = parsed.hostname.casefold().rstrip(".")
    if host in {"metadata.google.internal", "metadata", "instance-data"}:
        raise ValueError("Metadata endpoints are forbidden")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if address.is_link_local or address.is_multicast or address.is_unspecified:
            raise ValueError("Metadata and non-unicast destinations are forbidden")
    return url.rstrip("/")


async def require_model_aliases(
    session: AsyncSession, tenant_id, aliases: list[str] | None
) -> None:
    if not aliases:
        return
    registered = set(
        (
            await session.scalars(
                select(ModelDeployment.alias).where(
                    ModelDeployment.organization_id == tenant_id,
                    ModelDeployment.alias.in_(aliases),
                    ModelDeployment.enabled.is_(True),
                )
            )
        ).all()
    )
    if not settings.MODEL_DEPLOYMENT_REQUIRED:
        registered.update(
            alias
            for alias in aliases
            if any(
                DEFAULT_PRICE_BOOK.supports(alias, provider)
                for provider in ("openai", "anthropic", "google")
            )
        )
    if set(aliases) - registered:
        raise HTTPException(
            422, detail="Model allowlist contains an unregistered model"
        )


class DeploymentResolver:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def resolve(self, prepared: PreparedInference) -> PreparedInference:
        async with self.session_factory() as session:
            try:
                key = await self._active_key(session, prepared.api_key_id)
                if key.organization_id != prepared.tenant_id:
                    raise HTTPException(403, detail="Model access is not allowed")
            except HTTPException:
                prepared.record_verdict(
                    "access.api_key",
                    stage="admission",
                    outcome="deny",
                    reason_code="API_KEY_NOT_ACTIVE",
                )
                raise
            allowed = key.allowed_models
            prepared.record_verdict(
                "access.key_models",
                stage="admission",
                outcome="deny"
                if allowed is not None and prepared.model not in allowed
                else "allow",
                reason_code="MODEL_NOT_ALLOWED"
                if allowed is not None and prepared.model not in allowed
                else "KEY_MODEL_ALLOWED",
                policy=allowed,
            )
            if allowed is not None and prepared.model not in allowed:
                raise HTTPException(
                    403,
                    detail={
                        "code": "MODEL_NOT_ALLOWED",
                        "message": "The gateway key does not permit this model.",
                    },
                )
            deployment = (
                await session.execute(
                    select(ModelDeployment).where(
                        ModelDeployment.organization_id == prepared.tenant_id,
                        ModelDeployment.alias == prepared.model,
                    )
                )
            ).scalar_one_or_none()
        if deployment is None:
            if not settings.MODEL_DEPLOYMENT_REQUIRED and (
                DEFAULT_PRICE_BOOK.supports(prepared.model, str(prepared.provider))
                or (
                    prepared.provider == "openai"
                    and prepared.protocol == "responses"
                    and prepared.model == UNSPECIFIED_PROVIDER_MODEL
                )
            ):
                prepared.record_verdict(
                    "deployment.registry",
                    stage="admission",
                    outcome="skip",
                    reason_code="CATALOG_ROUTING_ENABLED",
                    policy={"required": False},
                )
                return prepared
            prepared.record_verdict(
                "deployment.registry",
                stage="admission",
                outcome="deny",
                reason_code="MODEL_NOT_REGISTERED",
                policy={"required": settings.MODEL_DEPLOYMENT_REQUIRED},
            )
            raise HTTPException(
                403,
                detail={
                    "code": "MODEL_NOT_REGISTERED",
                    "message": "The requested model is not registered for this tenant.",
                },
            )
        registry_policy = {
            "deployment_id": str(deployment.id),
            "updated_at": deployment.updated_at,
            "enabled": deployment.enabled,
            "provider": deployment.provider,
            "version": deployment.declared_version,
        }
        if not deployment.enabled or deployment.provider != str(prepared.provider):
            prepared.record_verdict(
                "deployment.registry",
                stage="admission",
                outcome="deny",
                reason_code="MODEL_NOT_ALLOWED",
                policy=registry_policy,
            )
            raise HTTPException(
                403,
                detail={
                    "code": "MODEL_NOT_ALLOWED",
                    "message": "The model is disabled or does not support this provider protocol.",
                },
            )
        try:
            base_url = validate_deployment_url(deployment.base_url)
        except ValueError:
            prepared.record_verdict(
                "deployment.destination",
                stage="admission",
                outcome="deny",
                reason_code="DEPLOYMENT_NOT_APPROVED",
                policy=settings.MODEL_DEPLOYMENT_ALLOWED_ORIGINS,
            )
            raise HTTPException(
                503,
                detail={
                    "code": "DEPLOYMENT_NOT_APPROVED",
                    "message": "The deployment destination is not approved.",
                },
            ) from None
        prepared.record_verdict(
            "deployment.registry",
            stage="admission",
            outcome="allow",
            reason_code="MODEL_REGISTERED",
            policy=registry_policy,
        )
        prepared.record_verdict(
            "deployment.destination",
            stage="admission",
            outcome="allow",
            reason_code="DEPLOYMENT_APPROVED",
            policy=settings.MODEL_DEPLOYMENT_ALLOWED_ORIGINS,
        )
        return replace(
            prepared,
            payload={**prepared.payload, "model": deployment.upstream_model},
            deployment_kind=cast(
                Literal["internal", "external"], deployment.deployment_kind
            ),
            target=ProviderTarget(
                deployment_id=str(deployment.id),
                base_url=base_url,
                upstream_model=deployment.upstream_model,
                credential_reference=str(deployment.provider_secret_id),
                timeout_seconds=deployment.timeout_seconds,
                declared_version=deployment.declared_version,
            ),
        )

    async def catalog(
        self, principal: AuthenticatedPrincipal, provider: str
    ) -> list[dict[str, object]]:
        async with self.session_factory() as session:
            key = await self._active_key(session, principal.api_key_id)
            rows = (
                (
                    await session.execute(
                        select(ModelDeployment)
                        .where(
                            ModelDeployment.organization_id == key.organization_id,
                        )
                        .order_by(ModelDeployment.alias)
                    )
                )
                .scalars()
                .all()
            )
        records = (
            {}
            if settings.MODEL_DEPLOYMENT_REQUIRED
            else {
                alias: model_record(alias, provider)
                for alias in DEFAULT_PRICE_BOOK.models(provider)
            }
        )
        for row in rows:
            records.pop(row.alias, None)
            if not row.enabled or row.provider != provider:
                continue
            records[row.alias] = (
                {
                    "id": row.alias,
                    "type": "model",
                    "display_name": row.alias,
                    "created_at": row.created_at,
                }
                if provider == "anthropic"
                else {
                    "id": row.alias,
                    "object": "model",
                    "created": int(row.created_at.timestamp()),
                    "owned_by": row.owner,
                }
            )
        return [
            records[alias]
            for alias in sorted(records)
            if key.allowed_models is None or alias in key.allowed_models
        ]

    async def _active_key(self, session: AsyncSession, key_id) -> ApiKey:
        row = (
            await session.execute(
                select(ApiKey, User)
                .join(
                    User,
                    (User.id == ApiKey.user_id)
                    & (User.organization_id == ApiKey.organization_id),
                )
                .where(
                    ApiKey.id == key_id,
                    ApiKey.is_active.is_(True),
                    User.is_active.is_(True),
                )
            )
        ).one_or_none()
        if row is None:
            raise HTTPException(
                401,
                detail={
                    "code": "INVALID_API_KEY",
                    "message": "The gateway key is no longer active.",
                },
            )
        key, owner = row
        if owner.role == "auditor" or (
            key.expires_at is not None and key.expires_at <= datetime.now(timezone.utc)
        ):
            raise HTTPException(
                401,
                detail={
                    "code": "INVALID_API_KEY",
                    "message": "The gateway key is no longer active.",
                },
            )
        if key.team_id is not None:
            await require_team(session, owner, key.team_id)
        return key
