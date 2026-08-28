"""Override an organization's plan after commercial approval or support."""

import argparse
import asyncio
from uuid import UUID

from sqlalchemy import select

from shim_enterprise.core.database import AsyncSessionLocal
from shim_enterprise.tenants.models import Organization
from shim_enterprise.tenants.subscriptions import set_organization_tier


async def activate(organization_id: UUID, tier: str) -> None:
    async with AsyncSessionLocal() as session:
        organization = (
            await session.execute(
                select(Organization)
                .where(Organization.id == organization_id)
                .with_for_update(of=Organization)
            )
        ).scalar_one_or_none()
        if organization is None:
            raise SystemExit(f"Organization not found: {organization_id}")
        await set_organization_tier(
            session,
            organization,
            tier,
            status="active" if tier != "free" else "free",
            source="operator",
        )
        organization.external_customer_id = None
        organization.external_subscription_id = None
        organization.billing_variant_id = None
        organization.current_period_end = None
        organization.cancel_at_period_end = False
        organization.customer_portal_url = None
        await session.commit()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("organization_id", type=UUID)
    parser.add_argument("tier", choices=("free", "managed", "agency", "enterprise"))
    args = parser.parse_args()
    asyncio.run(activate(args.organization_id, args.tier))


if __name__ == "__main__":
    main()
