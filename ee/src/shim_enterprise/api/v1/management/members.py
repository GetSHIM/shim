"""Profile, subscription, members, invites, custom roles and service accounts."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import Any, Literal, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from shim_enterprise.api.enterprise_deps import (
    ADMIN_REQUIRED,
    OWNER_REQUIRED,
    get_current_user,
    get_invite_user,
    require,
)
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim_enterprise.tenants.audit import (
    change_details,
    record_management_action as _audit,
)
from shim_enterprise.tenants.models import (
    ApiKey,
    OrganizationInvite,
    OrganizationRole,
    ServiceAccountCredential,
    TierDefinition,
    User,
)
from shim_enterprise.policy.plans import keep_two_approvers, lock_tenant
from shim_enterprise.tenants.permissions import (
    BUILTIN_ROLE_PERMISSIONS,
    PERMISSIONS,
    RESERVED_PERMISSIONS,
    Permission,
    user_permissions,
)
from shim_enterprise.tenants.teams import member_team_ids, plausible_email
from shim_enterprise.tenants.service import (
    SERVICE_ACCOUNT_EMAIL_DOMAIN,
    WorkspaceHasRequestHistory,
    issue_service_account_key,
    move_user_from_bootstrap,
)
from shim_enterprise.api.v1.management._common import (
    _aware,
    _delete_budget_targets,
    _delete_secret_best_effort,
    _owned_member,
    _require_entitlement,
    _require_permission,
    _require_person,
    _tenant,
    _tenant_id,
)


router = APIRouter()


_MAX_CUSTOM_ROLES = 20


ServiceRole = Literal["admin", "auditor", "recommender"]
# What a user row can hold; inputs for people keep the four human roles.
UserRole = Literal["owner", "admin", "member", "auditor", "recommender"]


class UserView(BaseModel):
    id: UUID
    email: str
    full_name: str | None
    organization_name: str
    role: UserRole
    custom_role: str | None
    permissions: list[Permission]
    is_active: bool
    is_verified: bool
    created_at: datetime


class UserPatch(BaseModel):
    full_name: str | None = Field(default=None, max_length=200)
    organization_name: str | None = Field(default=None, min_length=1, max_length=200)


class SubscriptionView(BaseModel):
    plan: Literal["free", "managed", "agency", "enterprise"]
    status: str
    source: str | None
    entitlements: dict[str, bool]


class ServiceAccountInput(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    role: ServiceRole
    expires_in_days: int = Field(ge=1, le=365)


class ServiceAccountView(BaseModel):
    id: UUID
    name: str | None
    role: ServiceRole
    prefix: str
    expires_at: datetime
    last_used_at: datetime | None
    created_by: UUID
    created_at: datetime


class CreatedServiceAccount(ServiceAccountView):
    plaintext: str


class TeamMemberView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str | None = Field(
        description="Null for team administrators without the members.read permission."
    )
    full_name: str | None
    role: UserRole
    custom_role: str | None = None
    is_active: bool
    created_at: datetime


class TeamInviteInput(BaseModel):
    email: str
    role: Literal["admin", "member", "auditor"] = "member"

    @field_validator("email")
    @classmethod
    def _internal_domains_are_valid(cls, email: str) -> str:
        if not plausible_email(email):
            raise ValueError("not a valid email address")
        return email.casefold()


class TeamInviteView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    role: Literal["owner", "admin", "member", "auditor"]
    expires_at: datetime
    accepted_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class CreatedTeamInvite(TeamInviteView):
    token: str


class AcceptTeamInvite(BaseModel):
    token: str = Field(min_length=32, max_length=512)


class TeamRolePatch(BaseModel):
    role: Literal["owner", "admin", "member", "auditor"]
    custom_role_id: UUID | None = None


class CustomRoleInput(BaseModel):
    slug: str = Field(pattern=r"^[a-z][a-z0-9-]{1,31}$")
    name: str = Field(min_length=1, max_length=100)
    permissions: list[str] = Field(max_length=len(PERMISSIONS))

    @field_validator("slug")
    @classmethod
    def _not_builtin(cls, value: str) -> str:
        if value in BUILTIN_ROLE_PERMISSIONS:
            raise ValueError(f"{value} is a built-in role")
        return value

    @field_validator("permissions")
    @classmethod
    def _grantable(cls, value: list[str]) -> list[str]:
        for item in value:
            if item not in PERMISSIONS - RESERVED_PERMISSIONS:
                raise ValueError(f"Permission not allowed in a custom role: {item}")
        return sorted(set(value))


class CustomRoleView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    slug: str
    name: str
    permissions: list[Permission]
    created_by: str | None
    created_at: datetime
    updated_at: datetime


@router.get("/auth/me", response_model=UserView)
async def current_profile(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> UserView:
    return await _user_view(session, user)


@router.put("/auth/me", response_model=UserView)
async def update_profile(
    patch: UserPatch,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> UserView:
    # The audit chain is immutable, so a person's name is recorded as changed, never stored.
    previous_full_name = user.full_name
    if "full_name" in patch.model_fields_set:
        user.full_name = patch.full_name
    before: dict[str, Any] = {}
    after: dict[str, Any] = {}
    if patch.organization_name is not None:
        await _require_permission(session, user, "settings.write")
        tenant = await _tenant(session, user)
        before["organization_name"] = tenant.name
        tenant.name = patch.organization_name.strip()
        after["organization_name"] = tenant.name
    await _audit(
        session,
        user,
        "tenant.profile_updated",
        str(user.id),
        details={
            **change_details(before, after),
            "full_name_changed": user.full_name != previous_full_name,
        },
    )
    await session.commit()
    await session.refresh(user)
    return await _user_view(session, user)


@router.get("/subscription", response_model=SubscriptionView)
async def get_subscription(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> SubscriptionView:
    organization = await _tenant(session, user)
    tier = await session.get(TierDefinition, organization.tier)
    if tier is None:
        raise HTTPException(
            status_code=503, detail="Organization tier is not configured"
        )
    return SubscriptionView(
        plan=cast(
            Literal["free", "managed", "agency", "enterprise"],
            organization.tier,
        ),
        status=organization.billing_status,
        source=organization.billing_source,
        entitlements={key: bool(value) for key, value in tier.features.items()},
    )


@router.get("/team/members", response_model=list[TeamMemberView])
async def list_team_members(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[TeamMemberView]:
    # Team admins pick members to add from this list, without their e-mail addresses.
    with_email = "members.read" in await user_permissions(session, user)
    if not with_email and not await session.scalar(
        select(member_team_ids(user, administer=True).exists())
    ):
        raise HTTPException(
            status_code=403, detail="Organization reader or team admin required"
        )
    members = (
        await session.scalars(
            select(User)
            .where(
                User.organization_id == _tenant_id(user),
                User.is_active.is_(True),
                User.kind == "human",
            )
            .order_by(User.created_at, User.id)
        )
    ).all()
    roles = await _roles_by_id(session, _tenant_id(user))
    return [_member_view(member, roles, with_email=with_email) for member in members]


@router.get("/team/invites", response_model=list[TeamInviteView])
async def list_team_invites(
    user: User = Depends(require("members.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> list[OrganizationInvite]:
    return list(
        (
            await session.execute(
                select(OrganizationInvite)
                .where(OrganizationInvite.organization_id == _tenant_id(user))
                .order_by(OrganizationInvite.created_at.desc())
            )
        )
        .scalars()
        .all()
    )


@router.post(
    "/team/invites",
    response_model=CreatedTeamInvite,
    status_code=status.HTTP_201_CREATED,
)
async def create_team_invite(
    payload: TeamInviteInput,
    user: User = Depends(require("members.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> CreatedTeamInvite:
    _require_person(user)
    if payload.role != "member" and "roles.manage" not in await user_permissions(
        session, user
    ):
        raise HTTPException(status_code=403, detail="Only owners can invite admins")
    tenant_id = _tenant_id(user)
    await _require_entitlement(session, tenant_id, "team_rbac")
    await lock_tenant(session, tenant_id)
    normalized_email = payload.email
    member = (
        await session.execute(
            select(User).where(
                func.lower(User.email) == normalized_email,
                User.organization_id == tenant_id,
                User.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()
    if member is not None:
        raise HTTPException(status_code=409, detail="User is already a team member")
    now = datetime.now(timezone.utc)
    await session.execute(
        update(OrganizationInvite)
        .where(
            OrganizationInvite.organization_id == tenant_id,
            func.lower(OrganizationInvite.email) == normalized_email,
            OrganizationInvite.accepted_at.is_(None),
            OrganizationInvite.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    token = secrets.token_urlsafe(32)
    invite = OrganizationInvite(
        organization_id=tenant_id,
        invited_by_user_id=user.id,
        email=normalized_email,
        role=payload.role,
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        expires_at=now + timedelta(days=7),
    )
    session.add(invite)
    await session.flush()
    await _audit(session, user, "tenant.team_invited", str(invite.id))
    await session.commit()
    await session.refresh(invite)
    return CreatedTeamInvite(
        **TeamInviteView.model_validate(invite, from_attributes=True).model_dump(),
        token=token,
    )


@router.delete(
    "/team/invites/{invite_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def revoke_team_invite(
    invite_id: UUID,
    user: User = Depends(require("members.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> None:
    tenant_id = _tenant_id(user)
    await lock_tenant(session, tenant_id)
    invite = (
        await session.execute(
            select(OrganizationInvite)
            .where(
                OrganizationInvite.id == invite_id,
                OrganizationInvite.organization_id == tenant_id,
            )
            .with_for_update(of=OrganizationInvite)
        )
    ).scalar_one_or_none()
    if invite is None:
        raise HTTPException(status_code=404, detail="Invitation not found")
    if invite.accepted_at is not None:
        raise HTTPException(
            status_code=409, detail="Accepted invitations cannot be revoked"
        )
    if invite.role != "member" and "roles.manage" not in await user_permissions(
        session, user
    ):
        raise HTTPException(
            status_code=403, detail="Only owners can revoke admin invites"
        )
    if invite.revoked_at is None:
        invite.revoked_at = datetime.now(timezone.utc)
        await _audit(session, user, "tenant.team_invite_revoked", str(invite.id))
        await session.commit()


@router.post("/team/invites/accept", response_model=TeamMemberView)
async def accept_team_invite(
    payload: AcceptTeamInvite,
    user: User = Depends(get_invite_user),
    session: AsyncSession = Depends(get_db),
) -> User:
    digest = hashlib.sha256(payload.token.encode()).hexdigest()
    destination_organization_id = await session.scalar(
        select(OrganizationInvite.organization_id).where(
            OrganizationInvite.token_hash == digest
        )
    )
    if destination_organization_id is None:
        raise HTTPException(status_code=400, detail="Invitation is invalid or expired")
    await lock_tenant(session, destination_organization_id)
    invite = (
        await session.execute(
            select(OrganizationInvite)
            .where(OrganizationInvite.token_hash == digest)
            .with_for_update(of=OrganizationInvite)
        )
    ).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if (
        invite is None
        or invite.organization_id != destination_organization_id
        or invite.accepted_at is not None
        or invite.revoked_at is not None
        or _aware(invite.expires_at) <= now
        or invite.email.casefold() != user.email.casefold()
    ):
        raise HTTPException(status_code=400, detail="Invitation is invalid or expired")
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Verified email required")
    if user.kind == "service":
        raise HTTPException(
            status_code=403, detail="Service accounts cannot accept invitations"
        )
    await _require_entitlement(session, invite.organization_id, "team_rbac")
    previous_tenant_id = _tenant_id(user)
    changing_tenant = previous_tenant_id != invite.organization_id
    secrets_to_delete: list[tuple[str, str]] = []
    budget_targets: list[dict[str, str]] = []
    if changing_tenant:
        try:
            moved = await move_user_from_bootstrap(
                session,
                user_id=user.id,
                source_organization_id=previous_tenant_id,
                destination_organization_id=invite.organization_id,
                role=invite.role,
            )
        except WorkspaceHasRequestHistory as exc:
            raise HTTPException(
                status_code=409,
                detail="Your personal workspace has request history and cannot be "
                "archived; ask the inviting organization's owner to contact support.",
            ) from exc
        if moved is None:
            raise HTTPException(
                status_code=409,
                detail="Leave or empty the current organization before accepting",
            )
        user, secrets_to_delete, budget_targets = moved
    else:
        user.role = invite.role
        user.custom_role_id = None
        user.is_active = True
    invite.accepted_at = now
    await _audit(session, user, "tenant.team_invite_accepted", str(invite.id))
    await session.commit()
    for reference, purpose in secrets_to_delete:
        await _delete_secret_best_effort(previous_tenant_id, reference, purpose)
    await _delete_budget_targets(previous_tenant_id, budget_targets)
    await session.refresh(user)
    return user


@router.patch("/team/members/{member_id}", response_model=TeamMemberView)
async def update_team_member(
    member_id: UUID,
    patch: TeamRolePatch,
    user: User = Depends(require("roles.manage", legacy_detail=OWNER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> TeamMemberView:
    custom_role_id = patch.custom_role_id
    if "custom_role_id" in patch.model_fields_set:
        if settings.AUTH_MODE == "oidc":
            raise HTTPException(
                status_code=409, detail="Manage this role in the identity provider"
            )
        if custom_role_id is not None and patch.role != "member":
            raise HTTPException(
                status_code=422, detail="A custom role needs the member role"
            )
    member = await _owned_member(session, user, member_id)
    if "custom_role_id" not in patch.model_fields_set and patch.role == "member":
        custom_role_id = member.custom_role_id
    if member.role == "owner" and patch.role != "owner":
        await _protect_last_owner(session, _tenant_id(user))
    await keep_two_approvers(session, member, _tenant_id(user), patch.role)
    roles = await _roles_by_id(session, _tenant_id(user))
    if custom_role_id is not None:
        if custom_role_id not in roles:
            raise HTTPException(status_code=404, detail="Role not found")
        if "keys.own" not in roles[custom_role_id].permissions:
            await _refuse_key_holders(session, User.id == member.id)
    previous_role = member.role
    previous_custom_role_id = member.custom_role_id
    member.role = patch.role
    member.custom_role_id = custom_role_id
    await _audit(
        session,
        user,
        "tenant.team_role_updated",
        str(member.id),
        details={"before": previous_role, "after": patch.role},
    )
    if previous_custom_role_id != custom_role_id:
        await _audit(
            session,
            user,
            "tenant.member_custom_role_changed",
            str(member.id),
            details={
                "before": _role_slug(roles, previous_custom_role_id),
                "after": _role_slug(roles, custom_role_id),
            },
        )
    await session.commit()
    await session.refresh(member)
    return _member_view(member, roles, with_email=True)


@router.delete(
    "/team/members/{member_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def remove_team_member(
    member_id: UUID,
    user: User = Depends(require("members.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> None:
    _require_person(user)
    member = await _owned_member(session, user, member_id)
    if member.role != "member" and "roles.manage" not in await user_permissions(
        session, user
    ):
        raise HTTPException(status_code=403, detail="Only owners can remove admins")
    if member.role == "owner":
        await _protect_last_owner(session, _tenant_id(user))
    await keep_two_approvers(session, member, _tenant_id(user), None)
    await _deactivate(session, member)
    await _audit(session, user, "tenant.team_member_removed", str(member.id))
    await session.commit()


@router.get("/roles", response_model=list[CustomRoleView])
async def list_custom_roles(
    user: User = Depends(require("roles.manage")),
    session: AsyncSession = Depends(get_db),
) -> list[OrganizationRole]:
    await _require_entitlement(session, _tenant_id(user), "team_rbac")
    return sorted(
        (await _roles_by_id(session, _tenant_id(user))).values(),
        key=lambda role: role.slug,
    )


@router.post("/roles", response_model=CustomRoleView, status_code=201)
async def create_custom_role(
    payload: CustomRoleInput,
    user: User = Depends(require("roles.manage")),
    session: AsyncSession = Depends(get_db),
) -> OrganizationRole:
    tenant_id = _tenant_id(user)
    await _require_entitlement(session, tenant_id, "team_rbac")
    if len(await _roles_by_id(session, tenant_id, lock=True)) >= _MAX_CUSTOM_ROLES:
        raise HTTPException(
            status_code=409,
            detail=f"An organization can have at most {_MAX_CUSTOM_ROLES} custom roles",
        )
    role = await session.scalar(
        insert(OrganizationRole)
        .values(
            organization_id=tenant_id,
            created_by=str(user.id),
            **payload.model_dump(),
        )
        .on_conflict_do_nothing()
        .returning(OrganizationRole)
    )
    if role is None:
        raise HTTPException(status_code=409, detail="A role with this slug exists")
    await _audit(
        session,
        user,
        "tenant.custom_role_created",
        str(role.id),
        details={"after": payload.model_dump()},
    )
    await session.commit()
    return role


@router.put("/roles/{role_id}", response_model=CustomRoleView)
async def update_custom_role(
    role_id: UUID,
    payload: CustomRoleInput,
    user: User = Depends(require("roles.manage")),
    session: AsyncSession = Depends(get_db),
) -> OrganizationRole:
    tenant_id = _tenant_id(user)
    await _require_entitlement(session, tenant_id, "team_rbac")
    role = (await _roles_by_id(session, tenant_id, lock=True)).get(role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found")
    if "keys.own" not in payload.permissions:
        await _refuse_key_holders(session, User.custom_role_id == role.id)
    changes = payload.model_dump()
    before = {field: getattr(role, field) for field in changes}
    for field, value in changes.items():
        setattr(role, field, value)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=409, detail="A role with this slug exists"
        ) from exc
    await _audit(
        session,
        user,
        "tenant.custom_role_updated",
        str(role.id),
        details=change_details(before, changes),
    )
    await session.commit()
    await session.refresh(role)
    return role


@router.delete("/roles/{role_id}", status_code=204, response_model=None)
async def delete_custom_role(
    role_id: UUID,
    user: User = Depends(require("roles.manage")),
    session: AsyncSession = Depends(get_db),
) -> None:
    tenant_id = _tenant_id(user)
    await _require_entitlement(session, tenant_id, "team_rbac")
    role = (await _roles_by_id(session, tenant_id, lock=True)).get(role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found")
    if await session.scalar(
        select(User.id).where(
            User.organization_id == tenant_id, User.custom_role_id == role.id
        )
    ):
        raise HTTPException(
            status_code=409, detail="Role is assigned; unassign it before deleting"
        )
    await session.delete(role)
    await _audit(
        session,
        user,
        "tenant.custom_role_deleted",
        str(role.id),
        details={"before": {"slug": role.slug, "permissions": role.permissions}},
    )
    await session.commit()


@router.post(
    "/service-accounts",
    response_model=CreatedServiceAccount,
    status_code=status.HTTP_201_CREATED,
)
async def create_service_account(
    payload: ServiceAccountInput,
    user: User = Depends(require("roles.manage", legacy_detail=OWNER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> CreatedServiceAccount:
    account_id = uuid4()
    account = User(
        id=account_id,
        organization_id=_tenant_id(user),
        email=f"{account_id}@{SERVICE_ACCOUNT_EMAIL_DOMAIN}",
        full_name=payload.name,
        role=payload.role,
        kind="service",
        is_active=True,
        is_verified=True,
    )
    session.add(account)
    await session.flush()
    expires_at = datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days)
    plaintext, credential = issue_service_account_key(
        session, account, created_by=user.id, expires_at=expires_at
    )
    await session.flush()
    await _audit(
        session,
        user,
        "tenant.service_account_created",
        str(account.id),
        details={
            "after": {
                "name": payload.name,
                "role": payload.role,
                "expires_at": expires_at.isoformat(),
            }
        },
    )
    await session.commit()
    return CreatedServiceAccount(
        **_service_account_row(account, credential).model_dump(), plaintext=plaintext
    )


@router.get("/service-accounts", response_model=list[ServiceAccountView])
async def list_service_accounts(
    user: User = Depends(require("roles.manage", legacy_detail=OWNER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> list[ServiceAccountView]:
    if user.kind == "service":
        raise HTTPException(403, "Service accounts cannot manage service accounts")
    rows = await session.execute(
        select(User, ServiceAccountCredential)
        .join(
            ServiceAccountCredential,
            (ServiceAccountCredential.user_id == User.id)
            & ServiceAccountCredential.revoked_at.is_(None),
        )
        .where(
            User.organization_id == _tenant_id(user),
            User.kind == "service",
            User.is_active.is_(True),
        )
        .order_by(User.created_at, User.id)
    )
    return [_service_account_row(account, credential) for account, credential in rows]


@router.post(
    "/service-accounts/{account_id}/rotate", response_model=CreatedServiceAccount
)
async def rotate_service_account(
    account_id: UUID,
    user: User = Depends(require("roles.manage", legacy_detail=OWNER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> CreatedServiceAccount:
    account = await _owned_service_account(session, user, account_id)
    current = await session.scalar(
        select(ServiceAccountCredential).where(
            ServiceAccountCredential.user_id == account.id,
            ServiceAccountCredential.revoked_at.is_(None),
        )
    )
    if current is None:
        raise HTTPException(status_code=404, detail="Service account not found")
    if current.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=409,
            detail="The service account's key has expired; create a new service account",
        )
    await _revoke_service_account_keys(session, account)
    plaintext, credential = issue_service_account_key(
        session, account, created_by=user.id, expires_at=current.expires_at
    )
    await session.flush()
    await _audit(session, user, "tenant.service_account_rotated", str(account.id))
    await session.commit()
    return CreatedServiceAccount(
        **_service_account_row(account, credential).model_dump(), plaintext=plaintext
    )


@router.delete(
    "/service-accounts/{account_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def delete_service_account(
    account_id: UUID,
    user: User = Depends(require("roles.manage", legacy_detail=OWNER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> None:
    account = await _owned_service_account(session, user, account_id)
    await _revoke_service_account_keys(session, account)
    await _deactivate(session, account)
    await _audit(session, user, "tenant.service_account_deleted", str(account.id))
    await session.commit()


async def _user_view(session: AsyncSession, user: User) -> UserView:
    tenant = await _tenant(session, user)
    role = (
        await session.get(OrganizationRole, user.custom_role_id)
        if user.custom_role_id is not None
        else None
    )
    return UserView(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        organization_name=tenant.name,
        role=cast(UserRole, user.role),
        custom_role=role.slug if role is not None else None,
        permissions=sorted(await user_permissions(session, user)),
        is_active=user.is_active,
        is_verified=user.is_verified,
        created_at=user.created_at,
    )


async def _owned_service_account(
    session: AsyncSession, user: User, account_id: UUID
) -> User:
    account = await session.scalar(
        select(User)
        .where(
            User.id == account_id,
            User.organization_id == _tenant_id(user),
            User.kind == "service",
            User.is_active.is_(True),
        )
        .with_for_update(of=User)
    )
    if account is None:
        raise HTTPException(status_code=404, detail="Service account not found")
    return account


async def _deactivate(session: AsyncSession, member: User) -> None:
    """Deactivate a user and the gateway keys it owns, and free its custom role."""
    member.is_active = False
    member.custom_role_id = None
    await session.execute(
        update(ApiKey)
        .where(ApiKey.user_id == member.id, ApiKey.is_active.is_(True))
        .values(is_active=False)
    )


async def _revoke_service_account_keys(session: AsyncSession, account: User) -> None:
    await session.execute(
        update(ServiceAccountCredential)
        .where(
            ServiceAccountCredential.user_id == account.id,
            ServiceAccountCredential.revoked_at.is_(None),
        )
        .values(revoked_at=datetime.now(timezone.utc))
    )


def _service_account_row(
    account: User, credential: ServiceAccountCredential
) -> ServiceAccountView:
    return ServiceAccountView(
        id=account.id,
        name=account.full_name,
        role=cast(ServiceRole, account.role),
        prefix=credential.prefix,
        expires_at=credential.expires_at,
        last_used_at=credential.last_used_at,
        created_by=credential.created_by,
        created_at=credential.created_at,
    )


async def _roles_by_id(
    session: AsyncSession, tenant_id: UUID, *, lock: bool = False
) -> dict[UUID, OrganizationRole]:
    if lock:
        # Role writes take the tenant lock that member and key changes take.
        await lock_tenant(session, tenant_id)
    roles = await session.scalars(
        select(OrganizationRole).where(OrganizationRole.organization_id == tenant_id)
    )
    return {role.id: role for role in roles}


def _role_slug(
    roles: Mapping[UUID, OrganizationRole], role_id: UUID | None
) -> str | None:
    role = roles.get(role_id) if role_id is not None else None
    return role.slug if role is not None else None


def _member_view(
    member: User, roles: Mapping[UUID, OrganizationRole], *, with_email: bool
) -> TeamMemberView:
    return TeamMemberView(
        id=member.id,
        email=member.email if with_email else None,
        full_name=member.full_name,
        role=cast(UserRole, member.role),
        custom_role=_role_slug(roles, member.custom_role_id),
        is_active=member.is_active,
        created_at=member.created_at,
    )


# The gateway checks only the base role, so only keys.own holders may hold active keys.
async def _refuse_key_holders(session: AsyncSession, holders: Any) -> None:
    users = await session.scalar(
        select(func.count(func.distinct(ApiKey.user_id)))
        .join(User, User.id == ApiKey.user_id)
        .where(ApiKey.is_active.is_(True), holders)
    )
    if users:
        raise HTTPException(
            status_code=409, detail={"code": "ROLE_HOLDERS_HAVE_KEYS", "users": users}
        )


async def _protect_last_owner(session: AsyncSession, tenant_id: UUID) -> None:
    await lock_tenant(session, tenant_id)
    owners = int(
        await session.scalar(
            select(func.count(User.id)).where(
                User.organization_id == tenant_id,
                User.role == "owner",
                User.is_active.is_(True),
            )
        )
        or 0
    )
    if owners <= 1:
        raise HTTPException(status_code=409, detail="Organization needs an owner")
