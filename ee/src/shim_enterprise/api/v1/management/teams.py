"""Teams and team memberships."""

from __future__ import annotations

from collections.abc import Collection
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from shim_enterprise.api.enterprise_deps import (
    ADMIN_REQUIRED,
    get_current_user,
    require,
)
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.core.database import get_db
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim_enterprise.tenants.gateway_settings import (
    COST_TAG,
    Directions,
    classify_fields,
    neutral,
)
from shim_enterprise.tenants.models import Team, TeamMembership, User
from shim_enterprise.policy.plans import Impact, Risk, State, version_detail
from shim_enterprise.tenants.permissions import Permission, user_permissions
from shim_enterprise.tenants.teams import member_team_ids, require_team
from shim_enterprise.api.v1.management._common import (
    _counted,
    _limit,
    _lowered,
    _managed_write,
    _only,
    _owned_member,
    _refreshed,
    _require_permission,
    _require_person,
    _since,
    _tenant_id,
    _uuids,
    _validated,
)


router = APIRouter()


class TeamInput(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    daily_request_limit: int | None = Field(default=None, ge=0, le=2_000_000_000)
    monthly_request_limit: int | None = Field(default=None, ge=0, le=2_000_000_000)
    monthly_token_limit: int | None = Field(default=None, ge=0, le=2_000_000_000)
    aws_cost_tag: str | None = Field(
        default=None,
        pattern=COST_TAG,
        description="The STS session tag value this team's Bedrock requests carry "
        "onto the AWS bill (bedrock_attribution).",
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Team name cannot be blank")
        return value.strip()


class TeamView(TeamInput):
    model_config = ConfigDict(from_attributes=True)
    id: UUID


class MembershipInput(BaseModel):
    role: Literal["member", "team_admin"] = "member"


class MembershipView(MembershipInput):
    model_config = ConfigDict(from_attributes=True)
    user_id: UUID
    team_id: UUID
    source: Literal["local", "oidc"]


@router.get("/teams", response_model=list[TeamView])
async def list_teams(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[Team]:
    statement = select(Team).where(Team.organization_id == _tenant_id(user))
    if not {"usage.read", "teams.manage"} & await user_permissions(session, user):
        statement = statement.where(Team.id.in_(member_team_ids(user)))
    return list((await session.scalars(statement.order_by(Team.name, Team.id))).all())


@router.post("/teams", response_model=TeamView, status_code=201)
async def create_team(
    payload: TeamInput,
    user: User = Depends(require("teams.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> Team:
    item = str(uuid4())
    await _managed_write(session, user, TEAMS, item, None, payload.model_dump())
    await session.commit()
    return await _refreshed(session, Team, UUID(item))


@router.put("/teams/{team_id}", response_model=TeamView)
async def update_team(
    team_id: UUID,
    payload: TeamInput,
    user: User = Depends(require("teams.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> Team:
    tenant_id, item = _tenant_id(user), str(team_id)
    await require_team(session, user, team_id, administer=True)
    before = (await TEAMS.snapshot(session, tenant_id, [item]))[item]
    # A client that predates the cost tag never erases it.
    kept = set() if "aws_cost_tag" in payload.model_fields_set else {"aws_cost_tag"}
    await _managed_write(
        session, user, TEAMS, item, before, payload.model_dump(exclude=kept)
    )
    await session.commit()
    return await _refreshed(session, Team, team_id)


@router.get("/teams/{team_id}/members", response_model=list[MembershipView])
async def list_memberships(
    team_id: UUID,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[TeamMembership]:
    await require_team(session, user, team_id)
    return list(
        (
            await session.scalars(
                select(TeamMembership)
                .where(
                    TeamMembership.organization_id == _tenant_id(user),
                    TeamMembership.team_id == team_id,
                )
                .order_by(TeamMembership.user_id)
            )
        ).all()
    )


@router.put("/teams/{team_id}/members/{member_id}", response_model=MembershipView)
async def set_membership(
    team_id: UUID,
    member_id: UUID,
    payload: MembershipInput,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> TeamMembership:
    _require_person(user)
    await require_team(session, user, team_id, administer=True)
    member = await _owned_member(session, user, member_id)
    existing = await session.scalar(
        select(TeamMembership)
        .where(
            TeamMembership.organization_id == user.organization_id,
            TeamMembership.team_id == team_id,
            TeamMembership.user_id == member_id,
        )
        .with_for_update()
    )
    if existing is not None and existing.source == "oidc":
        raise HTTPException(
            status_code=409, detail="Manage this membership in the identity provider"
        )
    if payload.role == "team_admin" or (
        existing is not None and existing.role == "team_admin"
    ):
        await _require_permission(session, user, "teams.manage")
    statement = insert(TeamMembership).values(
        organization_id=user.organization_id,
        team_id=team_id,
        user_id=member.id,
        role=payload.role,
        source="local",
    )
    membership = await session.scalar(
        statement.on_conflict_do_update(
            index_elements=[
                TeamMembership.organization_id,
                TeamMembership.team_id,
                TeamMembership.user_id,
            ],
            set_={"role": payload.role},
            where=TeamMembership.source == "local",
        ).returning(TeamMembership)
    )
    if membership is None:
        raise HTTPException(
            status_code=409, detail="Membership changed; reload and try again"
        )
    await _audit(
        session,
        user,
        "tenant.team_membership_updated",
        str(team_id) + ":" + str(member_id),
    )
    await session.commit()
    await session.refresh(membership)
    return membership


@router.delete(
    "/teams/{team_id}/members/{member_id}", status_code=204, response_model=None
)
async def remove_membership(
    team_id: UUID,
    member_id: UUID,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> None:
    _require_person(user)
    await require_team(session, user, team_id, administer=True)
    membership = await session.scalar(
        select(TeamMembership)
        .where(
            TeamMembership.organization_id == user.organization_id,
            TeamMembership.team_id == team_id,
            TeamMembership.user_id == member_id,
        )
        .with_for_update()
    )
    if membership is None:
        raise HTTPException(status_code=404, detail="Team membership not found")
    if membership.source == "oidc":
        raise HTTPException(
            status_code=409, detail="Manage this membership in the identity provider"
        )
    if membership.role == "team_admin":
        await _require_permission(session, user, "teams.manage")
    await session.delete(membership)
    await _audit(
        session,
        user,
        "tenant.team_membership_removed",
        str(team_id) + ":" + str(member_id),
    )
    await session.commit()


_TEAM_DIRECTIONS: Directions = {
    "name": neutral,
    # A label on the AWS bill, not a control.
    "aws_cost_tag": neutral,
    "daily_request_limit": _limit,
    "monthly_request_limit": _limit,
    "monthly_token_limit": _limit,
}


class _TeamResource:
    name = "teams"
    permission: Permission = "teams.manage"
    creatable = True
    deletable = False

    async def snapshot(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_ids: Collection[str] | None,
    ) -> dict[str, State]:
        statement = select(Team).where(Team.organization_id == organization_id)
        if item_ids is not None:
            statement = statement.where(Team.id.in_(_uuids(item_ids)))
        return {
            str(team.id): TeamInput.model_validate(
                team, from_attributes=True
            ).model_dump()
            for team in await session.scalars(statement)
        }

    async def validate(
        self,
        session: AsyncSession,
        actor: User,
        item_id: str | None,
        before: State | None,
        proposed: State,
    ) -> State:
        _only(proposed, TeamInput.model_fields)
        after = _validated(TeamInput, {**(before or {}), **proposed}).model_dump()
        taken = select(Team.id).where(
            Team.organization_id == _tenant_id(actor), Team.name == after["name"]
        )
        if item_id is not None:
            taken = taken.where(Team.id != UUID(item_id))
        if await session.scalar(taken) is not None:
            raise HTTPException(
                status_code=409, detail="A team with this name already exists"
            )
        return after

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
        assert after is not None
        if before is None:
            team = await session.scalar(
                insert(Team)
                .values(id=UUID(item_id), organization_id=organization_id, **after)
                .on_conflict_do_nothing()
                .returning(Team)
            )
            if team is None:
                raise HTTPException(
                    status_code=409, detail="A team with this name already exists"
                )
            await _audit(
                session,
                actor,
                "tenant.team_created",
                item_id,
                details={"after": after, **version_detail(policy_version)},
            )
            return
        team = await require_team(session, actor, UUID(item_id), administer=True)
        duplicate = await session.scalar(
            select(Team.id).where(
                Team.organization_id == organization_id,
                Team.name == after["name"],
                Team.id != team.id,
            )
        )
        if duplicate is not None:
            raise HTTPException(
                status_code=409, detail="A team with this name already exists"
            )
        previous = TeamView.model_validate(team).model_dump(mode="json")
        for field, value in after.items():
            setattr(team, field, value)
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            if getattr(exc.orig, "sqlstate", None) == "23505":
                raise HTTPException(
                    status_code=409, detail="A team with this name already exists"
                ) from exc
            raise
        await _audit(
            session,
            actor,
            "tenant.team_policy_updated",
            item_id,
            details={
                "before": previous,
                "after": after,
                **version_detail(policy_version),
            },
        )

    def classify(self, before: State | None, after: State | None) -> Risk:
        if before is None or after is None:
            return "neutral"
        return classify_fields(before, after, _TEAM_DIRECTIONS)[0]

    async def impact(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        window_days: int,
    ) -> Impact:
        if before is None or after is None:
            return _counted(0, window_days)
        on_team = RequestLifecycle.lifecycle_metadata["team_id"].as_string() == item_id
        requests = 0
        if _lowered(before["daily_request_limit"], after["daily_request_limit"]):
            day = func.date_trunc(
                "day", func.timezone("UTC", RequestLifecycle.started_at)
            )
            daily = (
                select(func.count().label("requests"))
                .where(
                    RequestLifecycle.organization_id == organization_id,
                    RequestLifecycle.started_at >= _since(window_days),
                    on_team,
                )
                .group_by(day)
                .subquery()
            )
            requests += int(
                await session.scalar(
                    select(
                        func.coalesce(
                            func.sum(
                                func.greatest(
                                    daily.c.requests - after["daily_request_limit"], 0
                                )
                            ),
                            0,
                        )
                    )
                )
                or 0
            )
        if _lowered(before["monthly_request_limit"], after["monthly_request_limit"]):
            month_start = datetime.now(timezone.utc).replace(
                day=1, hour=0, minute=0, second=0, microsecond=0
            )
            month = int(
                await session.scalar(
                    select(func.count())
                    .select_from(RequestLifecycle)
                    .where(
                        RequestLifecycle.organization_id == organization_id,
                        RequestLifecycle.started_at >= month_start,
                        on_team,
                    )
                )
                or 0
            )
            requests += max(0, month - after["monthly_request_limit"])
        note = (
            "token limits are not estimated"
            if _lowered(before["monthly_token_limit"], after["monthly_token_limit"])
            else None
        )
        return _counted(requests, window_days, note)


TEAMS = _TeamResource()
