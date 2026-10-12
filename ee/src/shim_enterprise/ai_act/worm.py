"""Copy audit evidence to an S3 bucket with Object Lock; the bucket's retention decides.

shim never sets a retention mode, a date or a legal hold: a wrong value would be
an irreversible choice. It refuses to upload unless the bucket reports Object Lock
with a default retention, and checks each object's lock after the upload. Every
network call runs outside a database transaction.
"""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import json
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import exists, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim_enterprise.ai_act.bundle import bundle_document
from shim_enterprise.ai_act.models import (
    AIActAuditAnchor,
    AIActAuditLog,
    WormArchiveObject,
)
from shim_enterprise.ai_act.verify import MAX_SYNC_AUDIT_ROWS
from shim_enterprise.compliance.models import MonthlyEvidenceFile
from shim_enterprise.core.config import settings
from shim_enterprise.tenants.models import Organization

logger = logging.getLogger(__name__)

MAX_OBJECTS_PER_PASS = 50
# A pass, and each S3 call in it, gives up on a slow endpoint instead of holding
# up the rest of the audit maintenance.
WORM_PASS_TIMEOUT_SECONDS = 300
_CLIENT_LIMITS = {
    "connect_timeout": 5,
    "read_timeout": 30,
    "retries": {"max_attempts": 2, "mode": "standard"},
}
ERROR_WINDOW = timedelta(hours=24)
OFF = "off, needs WORM_ARCHIVE_ENABLED and a bucket with Object Lock"
NO_BOTO3 = "off, needs boto3 (install shim-enterprise[archive-s3])"


class WormArchiveError(Exception):
    """A write-once check failed; the argument is the recorded error type."""


@dataclass(frozen=True, slots=True)
class _Item:
    organization_id: UUID
    kind: str
    period_key: str
    object_key: str
    from_seq: int | None = None
    to_seq: int | None = None


def unavailable_reason() -> str | None:
    if not settings.WORM_ARCHIVE_ENABLED or not settings.WORM_ARCHIVE_BUCKET:
        return OFF
    try:
        importlib.import_module("boto3")
    except ImportError:
        return NO_BOTO3
    return None


def build_client() -> Any:
    """An S3 client from boto3's default credential chain; shim adds no credential."""
    boto3 = importlib.import_module("boto3")
    config = importlib.import_module("botocore.config").Config(
        # S3-compatible stores behind an endpoint URL answer path-style requests.
        s3={"addressing_style": "path"} if settings.WORM_ARCHIVE_ENDPOINT_URL else {},
        **_CLIENT_LIMITS,
    )
    return boto3.client(
        "s3",
        endpoint_url=settings.WORM_ARCHIVE_ENDPOINT_URL,
        region_name=settings.WORM_ARCHIVE_REGION,
        config=config,
    )


def _key(organization_id: UUID, path: str) -> str:
    return f"{settings.WORM_ARCHIVE_PREFIX}/{organization_id}/{path}"


def _status(exc: Exception) -> tuple[str | None, int | None]:
    response = getattr(exc, "response", None) or {}
    return (
        response.get("Error", {}).get("Code"),
        response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
    )


async def _pending(
    session_factory: async_sessionmaker[AsyncSession],
) -> list[_Item]:
    """The next objects of every organization with chain rows, oldest first, capped."""
    items: list[_Item] = []
    async with session_factory() as session:
        organizations = await session.scalars(
            select(Organization.id)
            .where(exists().where(AIActAuditLog.organization_id == Organization.id))
            .order_by(Organization.id)
        )
        for organization_id in organizations.all():
            items += await _organization_items(session, organization_id)
            if len(items) >= MAX_OBJECTS_PER_PASS:
                break
    return items[:MAX_OBJECTS_PER_PASS]


async def _organization_items(
    session: AsyncSession, organization_id: UUID
) -> list[_Item]:
    archived = WormArchiveObject
    tenant = archived.organization_id == organization_id
    # A failed range is retried as it was; new ranges start after every range seen.
    retried = await session.execute(
        select(archived.from_seq, archived.to_seq)
        .where(tenant, archived.kind == "audit_rows", archived.status == "failed")
        .order_by(archived.from_seq)
    )
    ranges = [(row.from_seq, row.to_seq) for row in retried]
    seen = await session.scalar(
        select(func.max(archived.to_seq)).where(tenant, archived.kind == "audit_rows")
    )
    tip = await session.scalar(
        select(func.max(AIActAuditLog.seq)).where(
            AIActAuditLog.organization_id == organization_id
        )
    )
    start = (seen or 0) + 1
    while tip is not None and start <= tip and len(ranges) < MAX_OBJECTS_PER_PASS:
        end = min(start + MAX_SYNC_AUDIT_ROWS - 1, tip)
        ranges.append((start, end))
        start = end + 1
    items = [
        _Item(
            organization_id,
            "audit_rows",
            f"{first}-{last}",
            _key(organization_id, f"audit/rows/{first}-{last}.json"),
            first,
            last,
        )
        for first, last in ranges
    ]

    def stored(kind: str, period: Any) -> Any:
        return (
            exists()
            .where(
                tenant,
                archived.kind == kind,
                archived.period_key == period,
                archived.status == "stored",
            )
            .correlate_except(archived)
        )

    anchors = await session.scalars(
        select(AIActAuditAnchor.anchor_date)
        .where(
            AIActAuditAnchor.organization_id == organization_id,
            ~stored(
                "audit_anchor", func.to_char(AIActAuditAnchor.anchor_date, "YYYY-MM-DD")
            ),
        )
        .order_by(AIActAuditAnchor.anchor_date)
        .limit(MAX_OBJECTS_PER_PASS)
    )
    items += [
        _Item(
            organization_id,
            "audit_anchor",
            day.isoformat(),
            _key(organization_id, f"audit/anchors/{day.isoformat()}.json"),
        )
        for day in anchors
    ]
    months = await session.scalars(
        select(MonthlyEvidenceFile.period)
        .where(
            MonthlyEvidenceFile.organization_id == organization_id,
            # A partial month is never copied: it is replaced when the month closes.
            MonthlyEvidenceFile.kind == "monthly",
            ~stored("evidence_monthly", MonthlyEvidenceFile.period),
        )
        .order_by(MonthlyEvidenceFile.period)
        .limit(MAX_OBJECTS_PER_PASS)
    )
    items += [
        _Item(
            organization_id,
            "evidence_monthly",
            period,
            _key(organization_id, f"evidence/monthly/{period}.pdf"),
        )
        for period in months
    ]
    return items


def _canonical(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


async def _body(
    session_factory: async_sessionmaker[AsyncSession], item: _Item
) -> tuple[bytes, str, dict[str, str]]:
    """The object's bytes, read in one short read session."""
    async with session_factory() as session:
        if item.kind == "audit_rows":
            rows = list(
                await session.scalars(
                    select(AIActAuditLog)
                    .where(
                        AIActAuditLog.organization_id == item.organization_id,
                        AIActAuditLog.seq.between(item.from_seq, item.to_seq),
                    )
                    .order_by(AIActAuditLog.seq)
                )
            )
            if [row.seq for row in rows] != list(
                range(item.from_seq or 0, (item.to_seq or 0) + 1)
            ):
                raise WormArchiveError("SEQ_GAP")
            end = rows[-1].created_at.astimezone(timezone.utc)
            # The last row's time stands for "generated", so a retried range is the
            # same bytes and a crash after an upload is found by its checksum.
            document = await bundle_document(
                item.organization_id,
                rows,
                [],
                period_start=rows[0].created_at.astimezone(timezone.utc),
                period_end=end,
                now=end,
            )
            return await asyncio.to_thread(_canonical, document), "application/json", {}
        if item.kind == "audit_anchor":
            anchor = await session.scalar(
                select(AIActAuditAnchor).where(
                    AIActAuditAnchor.organization_id == item.organization_id,
                    AIActAuditAnchor.anchor_date
                    == datetime.fromisoformat(item.period_key).date(),
                )
            )
            assert anchor is not None
            return (
                _canonical(
                    {
                        "anchor_date": anchor.anchor_date.isoformat(),
                        "root_hash": anchor.root_hash,
                        "tip_hash": anchor.tip_hash,
                        "row_count": anchor.row_count,
                        "from_seq": anchor.from_seq,
                        "to_seq": anchor.to_seq,
                    }
                ),
                "application/json",
                {},
            )
        report = await session.scalar(
            select(MonthlyEvidenceFile).where(
                MonthlyEvidenceFile.organization_id == item.organization_id,
                MonthlyEvidenceFile.kind == "monthly",
                MonthlyEvidenceFile.period == item.period_key,
            )
        )
        assert report is not None
        return report.content, "application/pdf", {"sha256": report.sha256}


async def _head(client: Any, key: str) -> dict[str, Any] | None:
    try:
        return await asyncio.to_thread(
            client.head_object,
            Bucket=settings.WORM_ARCHIVE_BUCKET,
            Key=key,
            ChecksumMode="ENABLED",
        )
    except Exception as exc:
        if _status(exc)[1] == 404:
            return None
        raise


async def _store(
    client: Any, item: _Item, body: bytes, content_type: str, metadata: dict[str, str]
) -> dict[str, Any]:
    checksum = base64.b64encode(hashlib.sha256(body).digest()).decode()
    head = await _head(client, item.object_key)
    if head is None or head.get("ChecksumSHA256") != checksum:
        # No lock mode, retain-until date or legal hold: the bucket's default decides.
        await asyncio.to_thread(
            client.put_object,
            Bucket=settings.WORM_ARCHIVE_BUCKET,
            Key=item.object_key,
            Body=body,
            ContentType=content_type,
            ChecksumAlgorithm="SHA256",
            ChecksumSHA256=checksum,
            Metadata=metadata,
        )
        head = await _head(client, item.object_key)
    if head is None or not head.get("ObjectLockMode"):
        raise WormArchiveError("NOT_LOCKED")
    return head


async def _bucket_locked(client: Any) -> bool:
    try:
        answer = await asyncio.to_thread(
            client.get_object_lock_configuration, Bucket=settings.WORM_ARCHIVE_BUCKET
        )
    except Exception as exc:
        if _status(exc)[0] == "ObjectLockConfigurationNotFoundError":
            return False
        raise
    lock = answer.get("ObjectLockConfiguration") or {}
    retention = (lock.get("Rule") or {}).get("DefaultRetention") or {}
    return (
        lock.get("ObjectLockEnabled") == "Enabled"
        and bool(retention.get("Mode"))
        and bool(retention.get("Days") or retention.get("Years"))
    )


async def _record(
    session_factory: async_sessionmaker[AsyncSession],
    item: _Item,
    *,
    body: bytes | None = None,
    head: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    values = {
        "organization_id": item.organization_id,
        "kind": item.kind,
        "period_key": item.period_key,
        "from_seq": item.from_seq,
        "to_seq": item.to_seq,
        "object_key": item.object_key,
        "sha256": None if body is None else hashlib.sha256(body).hexdigest(),
        "size_bytes": None if body is None else len(body),
        "version_id": (head or {}).get("VersionId"),
        "lock_mode": (head or {}).get("ObjectLockMode"),
        "retain_until": (head or {}).get("ObjectLockRetainUntilDate"),
        "status": "failed" if error else "stored",
        "error_type": error,
    }
    statement = insert(WormArchiveObject).values(**values)
    async with session_factory.begin() as session:
        await session.execute(
            statement.on_conflict_do_update(
                index_elements=["organization_id", "kind", "period_key"],
                set_={
                    **{key: statement.excluded[key] for key in values},
                    "updated_at": func.now(),
                },
            )
        )


async def archive_pass(
    session_factory: async_sessionmaker[AsyncSession], client: Any
) -> int:
    """Upload up to MAX_OBJECTS_PER_PASS objects; the number stored."""
    items = await _pending(session_factory)
    if not items:
        return 0
    try:
        refused = None if await _bucket_locked(client) else "BUCKET_NOT_LOCKED"
    except Exception as exc:
        refused = type(exc).__name__
    if refused is not None:
        logger.warning("Write-once archive bucket refused type=%s", refused)
        first = {item.organization_id: item for item in reversed(items)}
        for item in first.values():
            await _record(session_factory, item, error=refused)
        return 0
    stored = 0
    for item in items:
        body = None
        try:
            body, content_type, metadata = await _body(session_factory, item)
            head = await _store(client, item, body, content_type, metadata)
        except Exception as exc:
            error = (
                exc.args[0] if isinstance(exc, WormArchiveError) else type(exc).__name__
            )
            logger.warning(
                "Write-once archive object failed kind=%s type=%s", item.kind, error
            )
            await _record(session_factory, item, body=body, error=error)
            continue
        await _record(session_factory, item, body=body, head=head)
        stored += 1
    return stored


async def archive_state(session: AsyncSession, organization_id: UUID) -> dict[str, Any]:
    archived = WormArchiveObject
    tenant = archived.organization_id == organization_id
    stored = archived.status == "stored"
    counts = (
        await session.execute(
            select(
                func.max(archived.to_seq).filter(stored, archived.kind == "audit_rows"),
                func.count().filter(stored, archived.kind == "audit_anchor"),
                func.count().filter(stored, archived.kind == "evidence_monthly"),
                func.count().filter(archived.status == "failed"),
            ).where(tenant)
        )
    ).one()
    recent = await session.scalar(
        select(archived.error_type)
        .where(
            tenant,
            archived.status == "failed",
            archived.updated_at > func.now() - ERROR_WINDOW,
        )
        .order_by(archived.updated_at.desc())
        .limit(1)
    )
    reason = unavailable_reason()
    return {
        "state": "off" if reason else "error" if recent else "on",
        "unavailable_reason": reason,
        "prefix": settings.WORM_ARCHIVE_PREFIX,
        "last_archived_seq": counts[0],
        "chain_tip_seq": await session.scalar(
            select(func.max(AIActAuditLog.seq)).where(
                AIActAuditLog.organization_id == organization_id
            )
        ),
        "anchors_archived": counts[1],
        "months_archived": counts[2],
        "failed": counts[3],
        "last_error_type": recent,
    }
