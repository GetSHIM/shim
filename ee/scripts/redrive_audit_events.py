"""Return dead-lettered audit-chain append events to the outbox queue."""

import argparse
import asyncio
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.core.database import AsyncSessionLocal
from shim_enterprise.outbox.handlers import AUDIT_CHAIN_APPEND
from shim_enterprise.outbox.models import OutboxEvent


async def redrive(
    session: AsyncSession, organization_id: UUID | None, *, dry_run: bool
) -> int:
    dead = [
        OutboxEvent.status == "dead_letter",
        OutboxEvent.event_type == AUDIT_CHAIN_APPEND,
    ]
    if organization_id is not None:
        dead.append(OutboxEvent.organization_id == organization_id)
    if dry_run:
        return await session.scalar(select(func.count()).where(*dead)) or 0
    return len(
        (
            await session.execute(
                update(OutboxEvent)
                .where(*dead)
                .values(
                    status="pending",
                    attempt_count=0,
                    next_attempt_at=func.now(),
                    updated_at=func.now(),
                )
                .returning(OutboxEvent.id)
            )
        ).all()
    )


async def main(organization_id: UUID | None, dry_run: bool) -> int:
    async with AsyncSessionLocal.begin() as session:
        return await redrive(session, organization_id, dry_run=dry_run)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--organization", type=UUID)
    parser.add_argument("--dry-run", action="store_true", help="print the count only")
    args = parser.parse_args()
    print(asyncio.run(main(args.organization, args.dry_run)))
