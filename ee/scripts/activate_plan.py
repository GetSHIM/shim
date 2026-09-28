"""Provision or change an organization's plan after commercial approval."""

import argparse
import asyncio
from uuid import UUID

from shim_enterprise.core.database import AsyncSessionLocal
from shim_enterprise.tenants.plans import (
    activate_organization_plan,
    create_organization_plan,
)


async def activate(
    organization_id: UUID | None,
    tier: str,
    create_name: str | None = None,
) -> UUID:
    async with AsyncSessionLocal() as session:
        try:
            if create_name is not None:
                organization = await create_organization_plan(
                    session, create_name, tier
                )
            elif organization_id is not None:
                organization = await activate_organization_plan(
                    session, organization_id, tier
                )
            else:
                raise ValueError("An organization ID or --create-name is required")
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        await session.commit()
        return organization.id


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("organization_id", type=UUID, nargs="?")
    target.add_argument(
        "--create-name", help="Create a new organization without an identity account"
    )
    parser.add_argument("tier", choices=("free", "managed", "agency", "enterprise"))
    args = parser.parse_args()
    print(asyncio.run(activate(args.organization_id, args.tier, args.create_name)))


if __name__ == "__main__":
    main()
