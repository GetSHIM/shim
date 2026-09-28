"""Tenant-scoped team access and identity-provider membership synchronization."""

from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.tenants.models import Organization, Team, TeamMembership, User


def member_team_ids(user: User, *, administer: bool = False):
    statement = select(TeamMembership.team_id).where(
        TeamMembership.organization_id == user.organization_id,
        TeamMembership.user_id == user.id,
    )
    if administer:
        statement = statement.where(TeamMembership.role == "team_admin")
    return statement


async def require_team(
    session: AsyncSession, user: User, team_id: UUID, *, administer: bool = False
) -> Team:
    if administer:
        if user.role == "auditor":
            raise HTTPException(
                status_code=403, detail="Auditors have read-only access"
            )
        # The same tenant lock fences role and membership changes before authorization.
        await session.scalar(
            select(Organization.id)
            .where(Organization.id == user.organization_id)
            .with_for_update()
        )
    statement = select(Team).where(
        Team.organization_id == user.organization_id, Team.id == team_id
    )
    if user.role not in {"owner", "admin", "auditor"}:
        statement = statement.where(
            Team.id.in_(member_team_ids(user, administer=administer))
        )
    if administer:
        statement = statement.with_for_update()
    team = await session.scalar(statement)
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found")
    return team


async def synchronize_oidc_teams(
    session: AsyncSession,
    user: User,
    groups: list[str],
    mapping: dict[str, dict[str, str]],
) -> None:
    """Replace IdP grants atomically; explicit local membership stays authoritative."""
    await session.scalar(
        select(Organization.id)
        .where(Organization.id == user.organization_id)
        .with_for_update()
    )
    desired: dict[UUID, str] = {}
    for group in groups:
        if group not in mapping:
            continue
        config = mapping[group]
        team_id, role = UUID(config["team_id"]), config["role"]
        if role not in {"member", "team_admin"}:
            raise ValueError("Invalid OIDC team role")
        if desired.get(team_id) != "team_admin":
            desired[team_id] = role
    owned = set(
        (
            await session.scalars(
                select(Team.id).where(
                    Team.organization_id == user.organization_id, Team.id.in_(desired)
                )
            )
        ).all()
    )
    if owned != set(desired):
        raise ValueError("OIDC team does not belong to the configured organization")
    await session.execute(
        delete(TeamMembership).where(
            TeamMembership.organization_id == user.organization_id,
            TeamMembership.user_id == user.id,
            TeamMembership.source == "oidc",
            TeamMembership.team_id.not_in(desired),
        )
    )
    for team_id, role in sorted(desired.items()):
        statement = insert(TeamMembership).values(
            organization_id=user.organization_id,
            team_id=team_id,
            user_id=user.id,
            role=role,
            source="oidc",
        )
        await session.execute(
            statement.on_conflict_do_update(
                index_elements=[
                    TeamMembership.organization_id,
                    TeamMembership.team_id,
                    TeamMembership.user_id,
                ],
                set_={"role": role},
                where=TeamMembership.source == "oidc",
            )
        )
