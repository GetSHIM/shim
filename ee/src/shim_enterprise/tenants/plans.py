"""Operator-managed organization plans and inherited API-key tiers."""

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.tenants.models import ApiKey, Organization, TierDefinition, User
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
    organization = await _locked_organization(session, organization_id)
    await _apply_tier(session, organization, tier)
    organization.billing_status = "free" if tier == "free" else "active"
    organization.billing_source = "operator"
    organization.billing_event_at = datetime.now(timezone.utc)
    organization.billing_revision += 1
    # Retain legacy billing references and period fields as historical records.
    await session.flush()
    return organization


async def _apply_tier(
    session: AsyncSession, organization: Organization, tier: str
) -> TierDefinition:
    definition = await session.get(TierDefinition, tier)
    if definition is None:
        raise ValueError(f"Unknown tier: {tier}")
    organization.tier = tier
    if (
        organization.quota_monthly_request_limit is not None
        or organization.quota_monthly_token_limit is not None
    ):
        organization.quota_monthly_request_limit = definition.monthly_request_limit
        organization.quota_monthly_token_limit = definition.monthly_token_limit
    await session.execute(
        update(ApiKey)
        .where(
            ApiKey.organization_id == organization.id,
            ApiKey.is_active.is_(True),
        )
        .values(tier=tier)
    )
    return definition


async def _locked_organization(
    session: AsyncSession, organization_id: UUID
) -> Organization:
    organization = await session.scalar(
        select(Organization)
        .where(Organization.id == organization_id)
        .execution_options(populate_existing=True)
        .with_for_update(of=Organization)
    )
    if organization is None:
        raise ValueError(f"Organization not found: {organization_id}")
    return organization


@dataclass(frozen=True)
class OrganizationPlan:
    organization_id: UUID
    tier: str
    source: str | None
    status: str
    customer_id: str | None
    subscription_id: str | None
    current_period_end: datetime | None
    cancel_at_period_end: bool
    revision: int


def _plan(organization: Organization) -> OrganizationPlan:
    return OrganizationPlan(
        organization.id,
        organization.tier,
        organization.billing_source,
        organization.billing_status,
        organization.external_customer_id,
        organization.external_subscription_id,
        organization.current_period_end,
        organization.cancel_at_period_end,
        organization.billing_revision,
    )


async def organization_plan(
    session: AsyncSession, organization_id: UUID, *, lock: bool = False
) -> OrganizationPlan:
    organization = (
        await _locked_organization(session, organization_id)
        if lock
        else await session.get(Organization, organization_id, populate_existing=True)
    )
    if organization is None:
        raise ValueError("Organization does not exist")
    return _plan(organization)


async def claim_billing_source(
    session: AsyncSession, organization_id: UUID, source: str
) -> OrganizationPlan:
    """Bind a free tenant to an explicitly selected provisioning authority."""
    organization = await _locked_organization(session, organization_id)
    if organization.billing_source not in {None, source} or (
        organization.billing_source is None and organization.tier != "free"
    ):
        raise ValueError("This organization has an operator-managed plan")
    if organization.billing_source is None:
        organization.billing_source = source
        organization.billing_revision += 1
        await session.flush()
    return _plan(organization)


async def apply_billing_plan(
    session: AsyncSession,
    organization_id: UUID,
    *,
    expected_revision: int,
    source: str,
    status: str,
    tier: str,
    customer_id: str,
    subscription_id: str | None,
    product_id: str | None,
    current_period_end: datetime | None,
    cancel_at_period_end: bool,
) -> bool:
    """Apply a verified billing snapshot and inherited keys in one transaction."""
    organization = await _locked_organization(session, organization_id)
    if (
        organization.billing_revision != expected_revision
        or organization.billing_source != source
    ):
        return False
    if organization.external_customer_id not in {None, customer_id}:
        raise ValueError("Billing customer does not match this organization")
    definition = await _apply_tier(session, organization, tier)
    organization.billing_status = status
    organization.external_customer_id = customer_id
    organization.external_subscription_id = subscription_id
    organization.billing_variant_id = product_id
    organization.current_period_end = current_period_end
    organization.cancel_at_period_end = cancel_at_period_end
    organization.billing_event_at = datetime.now(timezone.utc)
    organization.billing_revision += 1
    organization.quota_monthly_request_limit = definition.monthly_request_limit
    organization.quota_monthly_token_limit = definition.monthly_token_limit
    await session.flush()
    return True


async def billing_organization_ids(
    session: AsyncSession, source: str, *, after: UUID | None = None, limit: int = 100
) -> tuple[UUID, ...]:
    query = select(Organization.id).where(Organization.billing_source == source)
    if after is not None:
        query = query.where(Organization.id > after)
    return tuple(
        (await session.scalars(query.order_by(Organization.id).limit(limit))).all()
    )


async def configure_organization_quota(
    session: AsyncSession, organization_id: UUID
) -> None:
    """Opt an organization into the current tier's shared monthly allowance."""
    organization = await session.get(
        Organization, organization_id, populate_existing=True
    )
    if organization is None:
        raise ValueError(f"Organization not found: {organization_id}")
    definition = await session.get(TierDefinition, organization.tier)
    if definition is None:
        raise ValueError("Organization tier does not exist")
    # This runs on every authenticated cloud request, so the steady state must
    # stay lock-free instead of serializing tenants on the organization row.
    if (
        organization.quota_monthly_request_limit == definition.monthly_request_limit
        and organization.quota_monthly_token_limit == definition.monthly_token_limit
    ):
        return

    organization = await _locked_organization(session, organization_id)
    definition = await session.get(
        TierDefinition, organization.tier, populate_existing=True
    )
    if definition is None:
        raise ValueError("Organization tier does not exist")
    organization.quota_monthly_request_limit = definition.monthly_request_limit
    organization.quota_monthly_token_limit = definition.monthly_token_limit
    await session.flush()


async def billing_owner_email(
    session: AsyncSession, organization_id: UUID, user_id: UUID
) -> str | None:
    return await session.scalar(
        select(User.email).where(
            User.id == user_id,
            User.organization_id == organization_id,
            User.role == "owner",
            User.is_active.is_(True),
        )
    )
