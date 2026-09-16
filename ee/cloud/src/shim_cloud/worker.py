"""One enterprise outbox consumer with cloud handlers and periodic sync intents."""

import asyncio
from contextlib import suppress
from datetime import datetime, timezone
from functools import partial
import logging

import httpx
from polar_sdk import Polar, PolarError
from sqlalchemy.exc import SQLAlchemyError

from shim_enterprise.core.database import AsyncSessionLocal
from shim_enterprise.outbox.handlers import build_publisher
from shim_enterprise.outbox.publisher import OutboxMessage
from shim_enterprise.tenants.plans import billing_organization_ids
from shim_enterprise.workers.outbox import main as run_outbox
from shim_cloud.billing import (
    OPERATION_EVENT,
    SYNC_EVENT,
    append_intent,
    deliver_operation,
    expire_operations,
    synchronize_plan,
)
from shim_cloud.config import CloudSettings
from shim_cloud.polar import POLAR_TIMEOUT_MS

logger = logging.getLogger(__name__)


async def sync_message(
    client: Polar, config: CloudSettings, message: OutboxMessage
) -> None:
    try:
        await synchronize_plan(client, config, message.organization_id)
    except (PolarError, httpx.HTTPError):
        # Outbox failure records must not contain vendor response bodies or URLs.
        raise ValueError(
            "Polar state refresh failed; retaining verified entitlements"
        ) from None


async def enqueue_reconciliation(config: CloudSettings) -> None:
    interval = config.CLOUD_BILLING_RECONCILE_SECONDS
    bucket = int(datetime.now(timezone.utc).timestamp()) // interval
    after = None
    while True:
        async with AsyncSessionLocal() as session:
            organizations = await billing_organization_ids(
                session, "polar", after=after
            )
            for organization_id in organizations:
                await append_intent(
                    session,
                    organization_id,
                    event_type=SYNC_EVENT,
                    aggregate_id=str(organization_id),
                    idempotency_key=f"polar:reconcile:{bucket}",
                    payload={},
                )
            await session.commit()
        if not organizations:
            break
        after = organizations[-1]
    async with AsyncSessionLocal() as session:
        await expire_operations(session)
        await session.commit()


async def reconcile(config: CloudSettings) -> None:
    while True:
        try:
            await enqueue_reconciliation(config)
        except SQLAlchemyError:
            logger.error("Cloud billing reconciliation enqueue failed")
        await asyncio.sleep(config.CLOUD_BILLING_RECONCILE_SECONDS)


async def main() -> None:
    config = CloudSettings()
    async with Polar(
        access_token=config.POLAR_ACCESS_TOKEN.get_secret_value(),
        server=config.POLAR_SERVER,
        retry_config=None,
        timeout_ms=POLAR_TIMEOUT_MS,
    ) as client:
        publisher = build_publisher()
        publisher.register(OPERATION_EVENT, partial(deliver_operation, client, config))
        publisher.register(SYNC_EVENT, partial(sync_message, client, config))
        task = asyncio.create_task(reconcile(config))
        try:
            await run_outbox(publisher)
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task


if __name__ == "__main__":
    asyncio.run(main())
