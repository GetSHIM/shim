"""Operator-managed organization plans and inherited API-key tiers."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.tenants.models import ApiKey, Organization, TierDefinition
from shim_enterprise.tenants.service import ensure_privacy_defaults


async def create_organization_plan(
    session: AsyncSession,
    name: str,
    tier: str,
) -> Organization:
    name = name.strip()
    if not 1 <= len(name) <= 200:
        raise ValueError("Organization name must contain 1 to 200 characters")
    organization_id = uuid4()
    organization = Organization(
        id=organization_id, name=name, slug=f"org-{organization_id}"
    )
    session.add(organization)
    await session.flush()
    await ensure_privacy_defaults(session, organization.id)
    return await activate_organization_plan(session, organization.id, tier)


async def activate_organization_plan(
    session: AsyncSession,
    organization_id: UUID,
    tier: str,
) -> Organization:
    if await session.get(TierDefinition, tier) is None:
        raise ValueError(f"Unknown tier: {tier}")
    organization = await session.scalar(
        select(Organization)
        .where(Organization.id == organization_id)
        .with_for_update(of=Organization)
    )
    if organization is None:
        raise ValueError(f"Organization not found: {organization_id}")
    organization.tier = tier
    organization.billing_status = "free" if tier == "free" else "active"
    organization.billing_source = "operator"
    organization.billing_event_at = datetime.now(timezone.utc)
    # Retain legacy billing references and period fields as historical records.
    await session.flush()
    await session.execute(
        update(ApiKey)
        .where(
            ApiKey.organization_id == organization.id,
            ApiKey.is_active.is_(True),
        )
        .values(tier=tier)
    )
    return organization
