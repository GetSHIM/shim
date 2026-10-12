"""Tenant API keys."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import (
    ADMIN_REQUIRED,
    get_current_user,
    require,
)
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.core.database import get_db
from shim_enterprise.tenants.audit import (
    change_details,
    record_management_action as _audit,
)
from shim_enterprise.tenants.gateway_settings import Directions, classify_fields
from shim_enterprise.tenants.models import ApiKey, User
from shim_enterprise.tenants.deployments import require_model_aliases
from shim_enterprise.policy.plans import (
    Impact,
    Risk,
    State,
    approval_required,
    four_eyes_on,
    lock_tenant,
    no_impact,
    record_managed_write,
    version_detail,
)
from shim_enterprise.tenants.permissions import Permission, user_permissions
from shim_enterprise.tenants.teams import (
    may_hold_team_key,
    member_team_ids,
    require_team,
)
from shim_enterprise.tenants.service import (
    create_api_key as create_tenant_api_key,
    rotate_api_key as rotate_tenant_api_key,
)
from shim_enterprise.api.v1.management._common import (
    _aware,
    _counted,
    _lifecycle_count,
    _only,
    _own_or_administered_key,
    _require_permission,
    _tenant_id,
    _uuids,
    _validate_attribution,
    _validated,
)


router = APIRouter()


def _validate_allowed_models(value: list[str] | None) -> list[str] | None:
    if value is not None and any(
        not item or item != item.strip() or len(item) > 200 for item in value
    ):
        raise ValueError(
            "Model identifiers must be nonblank and at most 200 characters"
        )
    return list(dict.fromkeys(value)) if value is not None else None


class ApiKeyInput(BaseModel):
    name: str = Field(min_length=1, max_length=50)
    cost_center: str | None = None
    team: str | None = None
    team_id: UUID | None = None
    allowed_models: list[str] | None = Field(default=None, max_length=200)
    expires_in_days: int | None = Field(default=None, ge=1, le=365)

    validate_models = field_validator("allowed_models")(_validate_allowed_models)
    validate_attribution = field_validator("cost_center", "team")(_validate_attribution)


class ApiKeyPatch(BaseModel):
    cost_center: str | None = None
    team: str | None = None
    team_id: UUID | None = None
    allowed_models: list[str] | None = Field(default=None, max_length=200)

    validate_models = field_validator("allowed_models")(_validate_allowed_models)
    validate_attribution = field_validator("cost_center", "team")(_validate_attribution)


class ApiKeyView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str | None
    prefix: str
    tier: str
    created_at: datetime
    is_active: bool
    expires_at: datetime | None
    cost_center: str | None
    team: str | None
    team_id: UUID | None
    allowed_models: list[str] | None
    user_id: UUID = Field(description="The key's owner: only they may rotate it.")


class CreatedApiKey(ApiKeyView):
    plaintext: str


@router.get("/api-keys", response_model=list[ApiKeyView])
async def list_api_keys(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[ApiKey]:
    tenant_id = _tenant_id(user)
    statement = select(ApiKey).where(
        ApiKey.organization_id == tenant_id,
        ApiKey.is_active.is_(True),
    )
    if not {"usage.read", "keys.manage"} & await user_permissions(session, user):
        statement = statement.where(_own_or_administered_key(user))
    now = datetime.now(timezone.utc)
    return [
        item
        for item in (await session.execute(statement)).scalars().all()
        if item.expires_at is None or _aware(item.expires_at) > now
    ]


@router.post("/api-keys", response_model=CreatedApiKey)
async def create_api_key(
    payload: ApiKeyInput,
    user: User = Depends(require("keys.own", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> CreatedApiKey:
    tenant_id = _tenant_id(user)
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Verified email required")
    # Role changes take the tenant lock, so the guard's answer is re-read under it.
    await lock_tenant(session, tenant_id)
    if "keys.own" not in await user_permissions(session, user, reload=True):
        raise HTTPException(status_code=403, detail=ADMIN_REQUIRED)
    if payload.team_id is not None:
        await require_team(session, user, payload.team_id)
        if not await may_hold_team_key(session, user, payload.team_id):
            raise HTTPException(
                status_code=403, detail="API-key owner is not a member of this team"
            )
    elif "keys.manage" not in await user_permissions(
        session, user
    ) and await session.scalar(member_team_ids(user).limit(1)):
        raise HTTPException(status_code=403, detail="Choose a team for this API key")
    await require_model_aliases(session, tenant_id, payload.allowed_models)
    if payload.allowed_models is None and await four_eyes_on(session, tenant_id):
        # Create it with allowed_models; widening it later is a plan.
        raise approval_required(["api_keys.new.allowed_models"])
    plaintext, api_key = await create_tenant_api_key(
        session,
        user_id=user.id,
        name=payload.name,
        cost_center=payload.cost_center,
        team=payload.team,
        team_id=payload.team_id,
        allowed_models=payload.allowed_models,
        expires_at=(
            datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days)
            if payload.expires_in_days is not None
            else None
        ),
    )
    await _audit(session, user, "tenant.api_key_created", str(api_key.id))
    await session.commit()
    await session.refresh(api_key)
    return CreatedApiKey(
        **ApiKeyView.model_validate(api_key).model_dump(),
        plaintext=plaintext,
    )


@router.post("/api-keys/{api_key_id}/rotate", response_model=CreatedApiKey)
async def rotate_api_key(
    api_key_id: UUID,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> CreatedApiKey:
    api_key = await _owned_api_key(session, user, api_key_id)
    # Whoever holds the plaintext must never approve the key's held requests.
    if api_key.user_id != user.id:
        raise HTTPException(
            status_code=403,
            detail="Only the key's owner can rotate it; an administrator can revoke it.",
        )
    if not api_key.is_active or (
        api_key.expires_at is not None
        and _aware(api_key.expires_at) <= datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=409, detail="Only active API keys can be rotated"
        )
    plaintext = rotate_tenant_api_key(api_key)
    await _audit(
        session,
        user,
        "tenant.api_key_rotated",
        str(api_key.id),
        details={"rotation_policy": "immediate"},
    )
    await session.commit()
    await session.refresh(api_key)
    return CreatedApiKey(
        **ApiKeyView.model_validate(api_key).model_dump(), plaintext=plaintext
    )


@router.patch("/api-keys/{api_key_id}", response_model=ApiKeyView)
async def update_api_key(
    api_key_id: UUID,
    patch: ApiKeyPatch,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> ApiKey:
    changes = patch.model_dump(exclude_unset=True)
    api_key = await _key_for_change(session, user, api_key_id, changes)
    before = _key_state(api_key)
    after = {
        **before,
        **patch.model_dump(mode="json", include=set(_KEY_FIELDS), exclude_unset=True),
    }
    async with record_managed_write(
        session,
        user,
        api_key.organization_id,
        [(API_KEYS, str(api_key.id), before, after)],
        source="api",
    ) as version:
        await _write_api_key(session, user, api_key, changes, policy_version=version)
    await session.commit()
    await session.refresh(api_key)
    return api_key


@router.delete(
    "/api-keys/{api_key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def revoke_api_key(
    api_key_id: UUID,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> None:
    api_key = await _owned_api_key(session, user, api_key_id)
    api_key.is_active = False
    await _audit(session, user, "tenant.api_key_revoked", str(api_key.id))
    await session.commit()


async def _owned_api_key(
    session: AsyncSession,
    user: User,
    api_key_id: UUID,
) -> ApiKey:
    permissions = await user_permissions(session, user)
    if not {"keys.own", "keys.manage"} & permissions:
        raise HTTPException(status_code=403, detail=ADMIN_REQUIRED)
    await lock_tenant(session, _tenant_id(user))
    statement = (
        select(ApiKey)
        .where(
            ApiKey.id == api_key_id,
            ApiKey.organization_id == _tenant_id(user),
        )
        .with_for_update()
    )
    if "keys.manage" not in permissions:
        statement = statement.where(
            or_(
                (ApiKey.user_id == user.id)
                & (
                    ApiKey.team_id.is_(None) | ApiKey.team_id.in_(member_team_ids(user))
                ),
                ApiKey.team_id.in_(member_team_ids(user, administer=True)),
            )
        )
    row = (await session.execute(statement)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="API key not found")
    return row


async def _key_for_change(
    session: AsyncSession, user: User, api_key_id: UUID, changes: Mapping[str, Any]
) -> ApiKey:
    api_key = await _owned_api_key(session, user, api_key_id)
    if {"team_id", "allowed_models"} & changes.keys():
        if api_key.team_id is None:
            await _require_permission(session, user, "keys.manage")
        else:
            await require_team(session, user, api_key.team_id, administer=True)
    if "team_id" in changes and changes["team_id"] != api_key.team_id:
        await _require_permission(session, user, "keys.manage")
        if changes["team_id"] is not None:
            await require_team(session, user, changes["team_id"], administer=True)
            # The gateway refuses a team key whose owner may not hold it.
            owner = await session.get(User, api_key.user_id)
            if owner is None or not await may_hold_team_key(
                session, owner, changes["team_id"]
            ):
                raise HTTPException(
                    status_code=403, detail="API-key owner is not a member of this team"
                )
    return api_key


_KEY_FIELDS = ("allowed_models", "team_id")


def _models(before: list[str] | None, after: list[str] | None) -> Risk:
    if after is None or (before is not None and not set(after) <= set(before)):
        return "relaxing"
    if before is not None and set(after) == set(before):
        return "neutral"
    return "tightening"


_KEY_DIRECTIONS: Directions = {
    "allowed_models": _models,
    # Off its team, a key leaves the team's limits behind.
    "team_id": lambda before, _after: (
        "relaxing" if before is not None else "tightening"
    ),
}


class _ApiKeyResource:
    name = "api_keys"
    # Who may change which key is the PATCH route's rule, checked in validate and apply.
    permission: Permission = "keys.own"
    creatable = False
    deletable = False

    async def snapshot(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_ids: Collection[str] | None,
    ) -> dict[str, State]:
        statement = select(ApiKey).where(
            ApiKey.organization_id == organization_id, ApiKey.is_active.is_(True)
        )
        if item_ids is not None:
            statement = statement.where(ApiKey.id.in_(_uuids(item_ids)))
        return {
            str(key.id): _key_state(key) for key in await session.scalars(statement)
        }

    async def validate(
        self,
        session: AsyncSession,
        actor: User,
        item_id: str | None,
        before: State | None,
        proposed: State,
    ) -> State:
        _only(proposed, _KEY_FIELDS)
        patch = _validated(ApiKeyPatch, proposed)
        assert item_id is not None
        await _key_for_change(
            session, actor, UUID(item_id), patch.model_dump(exclude_unset=True)
        )
        await require_model_aliases(session, _tenant_id(actor), patch.allowed_models)
        return {**(before or {}), **patch.model_dump(mode="json", exclude_unset=True)}

    async def apply(
        self,
        session: AsyncSession,
        actor: User,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        *,
        policy_version: int | None,
    ) -> None:
        assert before is not None and after is not None
        changes = {
            field: UUID(after[field])
            if field == "team_id" and after[field] is not None
            else after[field]
            for field in _KEY_FIELDS
            if after[field] != before[field]
        }
        api_key = await _key_for_change(session, actor, UUID(item_id), changes)
        await _write_api_key(
            session, actor, api_key, changes, policy_version=policy_version
        )

    def classify(self, before: State | None, after: State | None) -> Risk:
        assert before is not None and after is not None
        return classify_fields(before, after, _KEY_DIRECTIONS)[0]

    async def impact(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        window_days: int,
    ) -> Impact:
        assert before is not None and after is not None
        if after["allowed_models"] == before["allowed_models"]:
            return no_impact(window_days)
        if after["allowed_models"] is None:
            return _counted(0, window_days)
        return _counted(
            await _lifecycle_count(
                session,
                organization_id,
                window_days,
                RequestLifecycle.api_key_id == UUID(item_id),
                RequestLifecycle.requested_model.not_in(after["allowed_models"]),
            ),
            window_days,
        )


def _key_state(key: ApiKey) -> State:
    return {
        "allowed_models": key.allowed_models,
        "team_id": str(key.team_id) if key.team_id is not None else None,
    }


async def _write_api_key(
    session: AsyncSession,
    actor: User,
    api_key: ApiKey,
    changes: Mapping[str, Any],
    *,
    policy_version: int | None,
) -> None:
    if "allowed_models" in changes:
        await require_model_aliases(
            session, api_key.organization_id, changes["allowed_models"]
        )
    before = {field: getattr(api_key, field) for field in changes}
    for field, value in changes.items():
        setattr(api_key, field, value)
    await _audit(
        session,
        actor,
        "tenant.api_key_updated",
        str(api_key.id),
        details={
            **change_details(before, dict(changes)),
            **version_detail(policy_version),
        },
    )


API_KEYS = _ApiKeyResource()
