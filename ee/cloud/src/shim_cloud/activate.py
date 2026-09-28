import argparse
import asyncio

from sqlalchemy import select
from sqlalchemy.orm import aliased
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.billing.models import UsageLedger
from shim_enterprise.core.database import AsyncSessionLocal
from shim_enterprise.tenants.models import Organization
from shim_enterprise.tenants.plans import configure_organization_quota
from shim_cloud.models import BillingActivation


async def require_activation(session: AsyncSession) -> None:
    if await session.get(BillingActivation, True) is None:
        raise ValueError(
            "Run shim_cloud.activate after draining old runtimes before enabling cloud billing"
        )


async def activate(session: AsyncSession) -> None:
    organizations = tuple(
        (
            await session.scalars(
                select(Organization.id).order_by(Organization.id).with_for_update()
            )
        ).all()
    )
    terminal = aliased(UsageLedger)
    pending = await session.scalar(
        select(UsageLedger.id)
        .where(
            UsageLedger.event_type == "quota_reservation",
            ~select(terminal.id)
            .where(
                terminal.organization_id == UsageLedger.organization_id,
                terminal.reservation_event_id == UsageLedger.id,
            )
            .exists(),
        )
        .limit(1)
    )
    if pending is not None:
        raise ValueError(
            "Quota reservations remain pending; drain requests and reconcile them before activation"
        )
    for organization_id in organizations:
        await configure_organization_quota(session, organization_id)
    if await session.get(BillingActivation, True) is None:
        session.add(BillingActivation(id=True))
    await session.flush()


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--confirm-old-runtimes-drained", required=True, action="store_true"
    )
    parser.parse_args()
    async with AsyncSessionLocal.begin() as session:
        await activate(session)


if __name__ == "__main__":
    asyncio.run(main())
