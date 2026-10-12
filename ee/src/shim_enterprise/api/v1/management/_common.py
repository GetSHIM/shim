"""Helpers the management resource modules share."""

from __future__ import annotations

from collections.abc import Callable, Collection, Coroutine, Mapping
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import logging
from typing import TYPE_CHECKING, Any
from uuid import UUID

import httpx
from fastapi import HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.routing import APIRoute
from starlette.types import Message
from pydantic import BaseModel, ValidationError
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import ADMIN_REQUIRED
from shim.billing.attribution import normalize_attribution
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.compliance.services.forwarder import ComplianceForwarderService
from shim.secrets.azure import EntraTokenCache
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import AsyncSessionLocal
from shim.gateway.contracts.ids import SecretRef, TenantId
from shim_enterprise.secrets.store import (
    ManagedProviderCredentialResolver,
    get_secret_store,
)
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim_enterprise.tenants.models import (
    ApiKey,
    Organization,
    ProviderSecret,
    TierDefinition,
    User,
)
from shim_enterprise.policy.plans import (
    Impact,
    Risk,
    State,
    lock_tenant,
    record_managed_write,
    version_detail,
)
from shim_enterprise.tenants.permissions import Permission, user_permissions
from shim_enterprise.tenants.teams import member_team_ids


if TYPE_CHECKING:
    from shim_enterprise.policy.resources import ManagedResource


logger = logging.getLogger(__package__)


_BINARY = {"schema": {"type": "string", "format": "binary"}}
_ATTACHMENT = {
    "Content-Disposition": {
        "description": "Attachment disposition and filename.",
        "schema": {"type": "string"},
    }
}


_MAX_SYNC_WINDOW = timedelta(days=31)
_MAX_SYNC_REQUEST_EXPORT_ROWS = 10_000


def _validate_attribution(value: str | None) -> str | None:
    if value is None:
        return None
    return normalize_attribution(
        value,
        maximum_length=settings.COST_TAG_MAX_LENGTH,
    )


class BillingPeriodView(BaseModel):
    start: datetime
    end: datetime


def _fresh_resolver(
    provider: str, client: httpx.AsyncClient
) -> ManagedProviderCredentialResolver:
    """A resolver with a token cache of its own, so a check always asks Entra afresh."""
    return ManagedProviderCredentialResolver(
        provider,
        get_secret_store(),
        AsyncSessionLocal,
        entra=EntraTokenCache(
            client, authority_host=settings.SHIM_AZURE_AUTHORITY_HOST
        ),
    )


def bounded_body(limit: int, message: str) -> type[APIRoute]:
    """A route that counts the body's bytes as they arrive and refuses past `limit`,
    so neither a chunked body nor the parser sees more."""

    class Bounded(APIRoute):
        def get_route_handler(
            self,
        ) -> Callable[[Request], Coroutine[Any, Any, Response]]:
            handler = super().get_route_handler()

            async def bounded(request: Request) -> Response:
                receive, size = request.receive, 0

                async def counted() -> Message:
                    nonlocal size
                    message_in = await receive()
                    size += len(message_in.get("body", b""))
                    if size > limit:
                        raise HTTPException(
                            status_code=413,
                            detail={"code": "REQUEST_TOO_LARGE", "message": message},
                        )
                    return message_in

                return await handler(Request(request.scope, counted))

            return bounded

    return Bounded


def _own_or_administered_key(user: User) -> Any:
    return or_(
        ApiKey.user_id == user.id,
        ApiKey.team_id.in_(member_team_ids(user, administer=True)),
    )


async def _owned_member(
    session: AsyncSession,
    user: User,
    member_id: UUID,
) -> User:
    tenant_id = _tenant_id(user)
    await lock_tenant(session, tenant_id)
    row = (
        await session.execute(
            select(User)
            .where(
                User.id == member_id,
                User.organization_id == tenant_id,
                User.is_active.is_(True),
                User.kind == "human",
            )
            .with_for_update(of=User)
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Team member not found")
    return row


def _require_person(user: User) -> None:
    if user.kind == "service":
        raise HTTPException(
            status_code=403, detail="Service accounts cannot change team access"
        )


async def _require_permission(
    session: AsyncSession, user: User, permission: Permission
) -> None:
    if permission not in await user_permissions(session, user):
        raise HTTPException(status_code=403, detail=ADMIN_REQUIRED)


async def _require_entitlement(
    session: AsyncSession,
    tenant_id: UUID,
    feature: str,
) -> None:
    current_plan, features = (
        await session.execute(
            select(Organization.tier, TierDefinition.features)
            .outerjoin(TierDefinition, Organization.tier == TierDefinition.slug)
            .where(Organization.id == tenant_id)
        )
    ).one()
    if isinstance(features, dict) and features.get(feature) is True:
        return
    eligible_plans = await session.scalars(
        select(TierDefinition.slug)
        .where(TierDefinition.features.contains({feature: True}))
        .order_by(TierDefinition.slug)
    )
    raise HTTPException(
        status_code=403,
        detail={
            "code": "PLAN_UPGRADE_REQUIRED",
            "feature": feature,
            "current_plan": current_plan,
            "eligible_plans": list(eligible_plans),
            "message": "This feature needs one of the plans listed in eligible_plans.",
        },
    )


async def _owned_provider_secret(
    session: AsyncSession,
    user: User,
    secret_id: UUID,
) -> ProviderSecret:
    statement = select(ProviderSecret).where(
        ProviderSecret.id == secret_id,
        ProviderSecret.organization_id == _tenant_id(user),
    )
    row = (await session.execute(statement)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Provider secret not found")
    return row


async def _delete_budget_targets(
    tenant_id: UUID,
    targets: list[dict[str, str]],
) -> None:
    for target in targets:
        for field, purpose in (
            ("secret_ref", "budget-alert-endpoint"),
            ("signing_secret_ref", "budget-alert-signing"),
        ):
            reference = target.get(field)
            if reference is not None:
                await _delete_secret_best_effort(
                    tenant_id, SecretRef(reference), purpose
                )


async def _delete_secret_best_effort(
    tenant_id: UUID,
    secret_ref: SecretRef | str,
    purpose: str,
) -> None:
    try:
        await get_secret_store().delete_secret(
            TenantId(tenant_id),
            SecretRef(str(secret_ref)),
            expected_purpose=purpose,
        )
    except Exception as exc:
        logger.warning("Secret cleanup failed type=%s", type(exc).__name__)


async def _tenant(session: AsyncSession, user: User) -> Organization:
    tenant = await session.get(Organization, _tenant_id(user))
    if tenant is None:
        raise HTTPException(status_code=403, detail="Tenant does not exist")
    return tenant


def _tenant_id(user: User) -> UUID:
    if user.organization_id is None:
        raise HTTPException(status_code=403, detail="Authenticated user has no tenant")
    return user.organization_id


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _sync_window(
    start: datetime | None, end: datetime | None, *, days: int
) -> tuple[datetime, datetime]:
    """The asked window: ending now and starting `days` before its end by default."""
    end_at = _aware(end or datetime.now(timezone.utc))
    start_at = _aware(start or end_at - timedelta(days=days))
    _validate_sync_window(start_at, end_at)
    return start_at, end_at


def _validate_sync_window(start: datetime, end: datetime) -> None:
    if start > end:
        raise HTTPException(status_code=422, detail="start must not be after end")
    if end - start > _MAX_SYNC_WINDOW:
        raise HTTPException(
            status_code=422,
            detail="synchronous operations are limited to 31 days",
        )


async def _refreshed[M](session: AsyncSession, model: type[M], row_id: UUID) -> M:
    row = await session.get(model, row_id)
    assert row is not None
    await session.refresh(row)
    return row


async def _managed_write(
    session: AsyncSession,
    user: User,
    resource: ManagedResource,
    item: str,
    before: State | None,
    after: State | None,
) -> None:
    """One API write of one managed item, recorded in a policy version."""
    tenant_id = _tenant_id(user)
    async with record_managed_write(
        session, user, tenant_id, [(resource, item, before, after)], source="api"
    ) as version:
        await resource.apply(
            session, user, tenant_id, item, before, after, policy_version=version
        )


async def _record_privacy_relaxed(
    session: AsyncSession,
    actor: User,
    organization_id: UUID,
    relaxed: list[str],
    policy_version: int | None,
) -> None:
    """Audit a privacy relaxation and forward it to the compliance sinks."""
    event_id = await _audit(
        session,
        actor,
        "tenant.privacy_protection_relaxed",
        str(organization_id),
        details={"relaxed": relaxed, **version_detail(policy_version)},
    )
    await ComplianceForwarderService().send_privacy_protection_relaxed(
        session,
        TenantId(organization_id),
        fields=relaxed,
        actor=str(actor.id),
        actor_email=actor.email,
        event_id=event_id,
    )


# Managed resources (ee/src/shim_enterprise/policy): the write paths a version records.


def _plain(value: Any) -> Any:
    if isinstance(value, Decimal):
        return format(value.normalize(), "f")
    if isinstance(value, UUID):
        return str(value)
    return value


def _validated[M: BaseModel](model: type[M], data: Mapping[str, Any]) -> M:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=jsonable_encoder(
                exc.errors(include_url=False, include_context=False)
            ),
        ) from None


def _only(proposed: Mapping[str, Any], fields: Collection[str]) -> None:
    unknown = sorted(set(proposed) - set(fields))
    if unknown:
        raise HTTPException(
            status_code=422, detail=f"Fields not managed here: {', '.join(unknown)}"
        )


def _since(window_days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=window_days)


async def _lifecycle_count(
    session: AsyncSession, organization_id: UUID, window_days: int, *filters: Any
) -> int:
    return int(
        await session.scalar(
            select(func.count())
            .select_from(RequestLifecycle)
            .where(
                RequestLifecycle.organization_id == organization_id,
                RequestLifecycle.started_at >= _since(window_days),
                *filters,
            )
        )
        or 0
    )


def _counted(requests: int, window_days: int, note: str | None = None) -> Impact:
    return {
        "requests": requests,
        "basis": "metadata",
        "window_days": window_days,
        "note": note,
    }


def _raised(before: int | None, after: int | None) -> bool:
    return before is not None and (after is None or after > before)


def _lowered(before: int | None, after: int | None) -> bool:
    return after is not None and (before is None or after < before)


def _limit(before: Any, after: Any) -> Risk:
    """A changed limit: removing or raising it relaxes. Dollars arrive as strings."""
    if before is None:
        return "tightening"
    if after is None or Decimal(after) > Decimal(before):
        return "relaxing"
    return "tightening"


def _uuids(item_ids: Collection[str]) -> list[UUID]:
    valid = []
    for item in item_ids:
        try:
            valid.append(UUID(item))
        except ValueError:
            continue
    return valid
