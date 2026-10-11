"""Write, open and delete archived requests; a write never fails the request."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import timedelta
import json
import logging
from typing import Any
from uuid import UUID

from cryptography.fernet import Fernet
from sqlalchemy import func, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim.gateway.kernel.result import PreparedInference
from shim.privacy.pii_scrubber import PIIScrubberService
from shim_enterprise.archive.models import RequestArchive
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import delete_in_batches
from shim_enterprise.observability.enterprise_metrics import (
    REQUEST_ARCHIVE_WRITES_TOTAL,
)
from shim_enterprise.observability.lifecycle import RequestLifecycleRepository
from shim_enterprise.tenants.gateway_settings import GatewaySettings

logger = logging.getLogger(__name__)

MAX_ARCHIVED_BYTES = 2_000_000
MAX_MATCHED = 64


def matched(prepared: PreparedInference) -> list[dict[str, Any]]:
    """What made the request worth keeping: entity types and rule ids, never values."""
    entries: list[dict[str, Any]] = []
    privacy = prepared.privacy
    if privacy is not None:
        for action, counts in (
            ("mask", privacy.pii_entities),
            ("monitor", privacy.monitored_entities),
            ("block", privacy.blocked_entities),
        ):
            entries += [
                {"kind": "entity", "id": entity, "action": action, "count": count}
                for entity, count in sorted(counts.items())
            ]
    entries += [
        {
            "kind": "rule",
            "id": match.rule_id,
            # A rule in monitor state only watched.
            "action": match.action if match.state == "enforced" else "monitor",
            "count": match.count,
        }
        for match in prepared.rule_matches
    ]
    return entries[:MAX_MATCHED]


def _retention_days(prepared: PreparedInference) -> int | None:
    """Both switches on: the tenant's retention; otherwise None."""
    if not settings.REQUEST_ARCHIVE_ENABLED:
        return None
    gateway = prepared.tenant_gateway_settings
    if (
        not isinstance(gateway, GatewaySettings)
        or not gateway.request_archive.enabled
        or prepared.protocol == "count_tokens"
    ):
        return None
    return gateway.request_archive.retention_days


def _sealed(payload: Any, edits: dict[str, str]) -> tuple[int, bytes, bytes] | None:
    """Size and ciphertexts of the masked payload and the edit; None when too large."""
    plain = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    if len(plain) > MAX_ARCHIVED_BYTES:
        return None
    cipher = Fernet(str(settings.ENCRYPTION_KEY).encode())
    edit = json.dumps(edits, ensure_ascii=False, separators=(",", ":")).encode()
    return len(plain), cipher.encrypt(plain), cipher.encrypt(edit)


async def _mark(session: AsyncSession, prepared: PreparedInference, value: str) -> None:
    await RequestLifecycleRepository.update(
        session,
        organization_id=prepared.tenant_id,
        request_id=prepared.request_id,
        values={
            "lifecycle_metadata": RequestLifecycle.lifecycle_metadata.op("||")(
                {"request_archive": value}
            )
        },
    )


async def archive_request(
    session_factory: Callable[[], AsyncSession], prepared: PreparedInference
) -> None:
    """Keep a matched request after its privacy facts committed; never raises."""
    days = _retention_days(prepared)
    if days is None:
        return
    entries = matched(prepared)
    if not entries:
        return
    try:
        privacy = prepared.privacy
        edits = {} if privacy is None else dict(privacy.verification_map)
        sealed = await asyncio.to_thread(_sealed, prepared.payload, edits)
        async with session_factory() as session, session.begin():
            if sealed is None:
                await _mark(session, prepared, "skipped_size")
            else:
                size, masked, edit = sealed
                session.add(
                    RequestArchive(
                        organization_id=prepared.tenant_id,
                        request_id=str(prepared.request_id),
                        api_key_id=prepared.api_key_id,
                        protocol=prepared.protocol,
                        model=prepared.model[:255],
                        matched=entries,
                        masked_payload=masked,
                        edit_map=edit,
                        size_bytes=size,
                        expires_at=func.now() + timedelta(days=days),
                    )
                )
                await _mark(session, prepared, "stored")
    except Exception as exc:
        REQUEST_ARCHIVE_WRITES_TOTAL.labels(result="failed").inc()
        logger.warning("Request archive write failed type=%s", type(exc).__name__)
        return
    REQUEST_ARCHIVE_WRITES_TOTAL.labels(
        result="skipped_size" if sealed is None else "stored"
    ).inc()


class ArchiveUndecryptable(Exception):
    """The row was sealed with another ENCRYPTION_KEY."""


def opened(row: RequestArchive) -> dict[str, Any]:
    """Decrypt a row and restore its placeholders; run in a thread."""
    try:
        cipher = Fernet(str(settings.ENCRYPTION_KEY).encode())
        masked = json.loads(cipher.decrypt(row.masked_payload))
        edits: dict[str, str] = json.loads(cipher.decrypt(row.edit_map))
    except Exception as exc:
        raise ArchiveUndecryptable from exc
    scrubber = PIIScrubberService()

    def restore(value: Any) -> Any:
        if isinstance(value, str):
            return scrubber.deanonymize(value, edits)
        if isinstance(value, list):
            return [restore(item) for item in value]
        if isinstance(value, dict):
            return {key: restore(item) for key, item in value.items()}
        return value

    return {
        "masked_payload": masked,
        "replacements": [
            {"placeholder": placeholder, "original": original}
            for placeholder, original in edits.items()
        ],
        "original_payload": restore(masked),
    }


async def shorten_retention(session: AsyncSession, tenant_id: UUID, days: int) -> None:
    await session.execute(
        update(RequestArchive)
        .where(RequestArchive.organization_id == tenant_id)
        .values(
            expires_at=func.least(
                RequestArchive.expires_at,
                RequestArchive.created_at + timedelta(days=days),
            )
        )
    )


async def delete_expired(session_factory: async_sessionmaker[AsyncSession]) -> int:
    return await delete_in_batches(
        session_factory,
        RequestArchive,
        RequestArchive.expires_at < func.now(),
        order_by=RequestArchive.expires_at,
    )
