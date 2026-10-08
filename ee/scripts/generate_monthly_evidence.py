"""Generate one organization's monthly evidence file for a closed or current month."""

import argparse
import asyncio
from datetime import datetime, timezone
import sys
from uuid import UUID

from shim_enterprise.compliance.services.monthly_evidence import (
    generate_monthly_evidence,
    monthly_window,
)
from shim_enterprise.core.database import AsyncSessionLocal


async def main(organization_id: UUID, period: str) -> str:
    now = datetime.now(timezone.utc)
    window = monthly_window(period, now=now)
    async with AsyncSessionLocal.begin() as session:
        stored = await generate_monthly_evidence(
            session, organization_id, window, now=now
        )
        return f"{stored.kind} {stored.period} sha256={stored.sha256} bytes={stored.size_bytes}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--organization", type=UUID, required=True)
    parser.add_argument("--period", required=True, help="YYYY-MM")
    args = parser.parse_args()
    try:
        print(asyncio.run(main(args.organization, args.period)))
    except ValueError as exc:
        sys.exit(f"refused: {exc}")
