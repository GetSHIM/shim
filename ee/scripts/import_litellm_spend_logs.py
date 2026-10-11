"""Import an existing LiteLLM gateway's spend logs and raise findings from them.

One source per run: a JSON Lines file, LiteLLM's /spend/logs/v2 (admin key in
LITELLM_ADMIN_KEY) or its database (LITELLM_DATABASE_URL). Rows land in
external_usage_records only, never in shim's accounting. Prompts and answers in
an export are ignored: only whether they are present is counted. Nothing free-form
is kept: a model is named only when the price book or the tenant's registry knows
it ("other" otherwise), and a key only as a SHA-256 digest.
"""

import argparse
import asyncio
from collections.abc import AsyncIterator, Mapping
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json
import logging
import os
from pathlib import Path
import sys
import re
from typing import Any
from uuid import UUID, uuid4

import asyncpg
import httpx
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim.billing.pricing import DEFAULT_PRICE_BOOK
from shim_enterprise.core.database import AsyncSessionLocal
from shim_enterprise.findings.models import ExternalUsageRecord
from shim_enterprise.findings.service import evaluate_litellm
from shim_enterprise.tenants.models import ModelDeployment, Organization

logger = logging.getLogger(__name__)

MAX_WINDOW = timedelta(days=31)
PAGE_SIZE = 1_000
PAGE_TIMEOUT_SECONDS = 30.0
OTHER_MODEL = "other"
# Numeric(18, 8): a cost at or past this does not fit and is not a real amount.
MAX_COST = Decimal(10) ** 10
_KEY_DIGEST = re.compile(r"[0-9a-fA-F]{64}")
_EMPTY = (None, "", {}, [])
_LITELLM_TIME = "%Y-%m-%d %H:%M:%S"
# LiteLLM's own column names; messages and response are reduced to "present".
_SELECT = """
    SELECT request_id, api_key, spend, prompt_tokens, completion_tokens,
           "startTime", "endTime", "completionStartTime", model, model_group, status,
           coalesce(messages, '{}'::jsonb) NOT IN ('{}', '[]', 'null', '""')
               OR coalesce(response, '{}'::jsonb) NOT IN ('{}', '[]', 'null', '""')
               AS content_present
    FROM "LiteLLM_SpendLogs"
    WHERE "startTime" >= $1 AND "startTime" < $2
      AND ("startTime", request_id) > ($3, $4)
    ORDER BY "startTime", request_id
    LIMIT $5
"""


class ImportRefused(Exception):
    """A source answered something this script will not read past."""


def _time(value: Any) -> datetime | None:
    if isinstance(value, str) and value:
        value = datetime.fromisoformat(value)
    if not isinstance(value, datetime):
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _text(value: Any, limit: int) -> str | None:
    return value[:limit] if isinstance(value, str) and value else None


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _ms(start: datetime | None, end: datetime | None) -> int | None:
    if start is None or end is None:
        return None
    return int((end - start).total_seconds() * 1000)


def _model(value: Any, registered: frozenset[str]) -> str | None:
    """A name the price book or the registry knows, or "other"; never caller text."""
    if not isinstance(value, str) or not value:
        return None
    known = value in registered or any(
        DEFAULT_PRICE_BOOK.supports(value, provider)
        for provider in DEFAULT_PRICE_BOOK.provider_prices
    )
    return value[:255] if known else OTHER_MODEL


def _cost(spend: Any) -> Decimal | None:
    """The source's cost when it is a finite amount from 0 up; None otherwise."""
    if spend is None or isinstance(spend, bool):
        return None
    try:
        cost = Decimal(str(spend))
    except InvalidOperation:
        return None
    return cost if cost.is_finite() and 0 <= cost < MAX_COST else None


def _key(value: Any) -> str | None:
    """LiteLLM's hashed key as it is; a raw key only as its SHA-256 digest."""
    if not isinstance(value, str) or not value:
        return None
    if _KEY_DIGEST.fullmatch(value):
        return value.lower()
    return hashlib.sha256(value.encode()).hexdigest()


def content_present(row: Mapping[str, Any]) -> bool:
    if "content_present" in row:
        return bool(row["content_present"])
    return any(row.get(field) not in _EMPTY for field in ("messages", "response"))


def mapped(
    row: Mapping[str, Any], registered: frozenset[str] = frozenset()
) -> dict[str, Any] | None:
    """One LiteLLM_SpendLogs row as an external usage record; None without its keys.

    `registered` holds the tenant's registry aliases and upstream models.
    """
    request_id, started = _text(row.get("request_id"), 255), _time(row.get("startTime"))
    if request_id is None or started is None:
        return None
    ended, first = _time(row.get("endTime")), _time(row.get("completionStartTime"))
    return {
        "source_request_id": request_id,
        "started_at": started,
        # LiteLLM writes completionStartTime = endTime when it saw no first token.
        "ttft_ms": None if first is None or first == ended else _ms(started, first),
        "status": _text(row.get("status"), 32),
        "model": _model(row.get("model"), registered),
        "model_group": _model(row.get("model_group"), registered),
        "source_key_hash": _key(row.get("api_key")),
        "prompt_tokens": _int(row.get("prompt_tokens")),
        "completion_tokens": _int(row.get("completion_tokens")),
        "cost_usd": _cost(row.get("spend")),
    }


async def file_rows(path: Path) -> AsyncIterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as lines:
        for line in lines:
            if line.strip():
                yield json.loads(line)


async def url_rows(
    base_url: str,
    key: str,
    since: datetime,
    until: datetime,
    transport: httpx.AsyncBaseTransport | None = None,
) -> AsyncIterator[dict[str, Any]]:
    async with httpx.AsyncClient(
        base_url=base_url,
        headers={"authorization": f"Bearer {key}"},
        timeout=PAGE_TIMEOUT_SECONDS,
        follow_redirects=False,
        trust_env=False,
        transport=transport,
    ) as client:
        page = 1
        while True:
            response = await client.get(
                "/spend/logs/v2",
                params={
                    "start_date": since.strftime(_LITELLM_TIME),
                    "end_date": until.strftime(_LITELLM_TIME),
                    "page": page,
                    "page_size": PAGE_SIZE,
                    "sort_by": "startTime",
                    "sort_order": "asc",
                },
            )
            if response.is_redirect:
                raise ImportRefused(f"page {page} answered a redirect; not followed")
            if response.status_code != 200:
                raise ImportRefused(f"page {page} answered {response.status_code}")
            try:
                data = response.json()["data"]
            except (ValueError, KeyError, TypeError):
                raise ImportRefused(f"page {page} is not a spend log page") from None
            if not isinstance(data, list) or not all(
                isinstance(row, dict) for row in data
            ):
                raise ImportRefused(f"page {page} is not a spend log page")
            if len(data) > PAGE_SIZE:
                raise ImportRefused(f"page {page} has more than {PAGE_SIZE} rows")
            for row in data:
                yield row
            if len(data) < PAGE_SIZE:
                return
            page += 1


async def database_rows(
    url: str, since: datetime, until: datetime
) -> AsyncIterator[dict[str, Any]]:
    # The columns are timestamp without time zone, read as UTC.
    start, end = (moment.replace(tzinfo=None) for moment in (since, until))
    connection = await asyncpg.connect(
        url.replace("postgresql+asyncpg://", "postgresql://")
    )
    try:
        async with connection.transaction(readonly=True):
            after: tuple[datetime, str] = (start - timedelta(microseconds=1), "")
            while True:
                rows = await connection.fetch(_SELECT, start, end, *after, PAGE_SIZE)
                for row in rows:
                    yield dict(row)
                if len(rows) < PAGE_SIZE:
                    return
                after = (rows[-1]["startTime"], rows[-1]["request_id"])
    finally:
        await connection.close()


async def import_rows(
    session: AsyncSession,
    organization_id: UUID,
    rows: AsyncIterator[dict[str, Any]],
    *,
    since: datetime,
    until: datetime,
) -> dict[str, Any]:
    import_id = uuid4()
    counts = dict.fromkeys(
        ("rows_read", "rows_inserted", "rows_duplicate", "rows_skipped"), 0
    )
    counts["rows_with_content_ignored"] = 0
    latest: datetime | None = None
    batch: list[dict[str, Any]] = []
    registered = frozenset(
        name
        for row in await session.execute(
            select(ModelDeployment.alias, ModelDeployment.upstream_model).where(
                ModelDeployment.organization_id == organization_id
            )
        )
        for name in row
    )

    async def flush() -> None:
        inserted = (
            await session.scalars(
                insert(ExternalUsageRecord)
                .values(
                    [
                        {
                            **record,
                            "organization_id": organization_id,
                            "source": "litellm",
                            "import_id": import_id,
                        }
                        for record in batch
                    ]
                )
                .on_conflict_do_nothing(
                    index_elements=["organization_id", "source", "source_request_id"]
                )
                .returning(ExternalUsageRecord.id)
            )
        ).all()
        counts["rows_inserted"] += len(inserted)
        counts["rows_duplicate"] += len(batch) - len(inserted)
        batch.clear()

    async for row in rows:
        counts["rows_read"] += 1
        if content_present(row):
            counts["rows_with_content_ignored"] += 1
        record = mapped(row, registered)
        if record is None or not since <= record["started_at"] < until:
            counts["rows_skipped"] += 1
            continue
        latest = max(latest or record["started_at"], record["started_at"])
        batch.append(record)
        if len(batch) == PAGE_SIZE:
            await flush()
    if batch:
        await flush()
    opened: dict[str, int] = {}
    updated: dict[str, int] = {}
    if latest is not None:
        for rule_id, was_opened in await evaluate_litellm(
            session, organization_id, end=latest, import_id=import_id
        ):
            totals = opened if was_opened else updated
            totals[rule_id] = totals.get(rule_id, 0) + 1
    return {
        "import_id": str(import_id),
        **counts,
        "findings_opened": opened,
        "findings_updated": updated,
    }


async def delete_import(
    session: AsyncSession, organization_id: UUID, import_id: UUID
) -> dict[str, Any]:
    deleted = (
        await session.scalars(
            delete(ExternalUsageRecord)
            .where(
                ExternalUsageRecord.organization_id == organization_id,
                ExternalUsageRecord.import_id == import_id,
            )
            .returning(ExternalUsageRecord.id)
        )
    ).all()
    return {"import_id": str(import_id), "rows_deleted": len(deleted)}


def _source(args: argparse.Namespace) -> AsyncIterator[dict[str, Any]]:
    if args.file is not None:
        return file_rows(args.file)
    if args.url is not None:
        key = os.environ.get("LITELLM_ADMIN_KEY")
        if not key:
            raise ImportRefused("--url reads the admin key from LITELLM_ADMIN_KEY")
        return url_rows(args.url, key, args.since, args.until)
    url = os.environ.get("LITELLM_DATABASE_URL")
    if not url:
        raise ImportRefused("--database reads its URL from LITELLM_DATABASE_URL")
    return database_rows(url, args.since, args.until)


async def main(args: argparse.Namespace) -> dict[str, Any]:
    if args.delete_import is None and (
        args.since is None
        or args.until is None
        or not args.since < args.until
        or args.until - args.since > MAX_WINDOW
    ):
        raise ImportRefused("--since must be before --until, at most 31 days apart")
    async with AsyncSessionLocal.begin() as session:
        if await session.get(Organization, args.organization) is None:
            raise ImportRefused("no such organization")
        if args.delete_import is not None:
            return await delete_import(session, args.organization, args.delete_import)
        return await import_rows(
            session,
            args.organization,
            _source(args),
            since=args.since,
            until=args.until,
        )


def parser() -> argparse.ArgumentParser:
    parsed = argparse.ArgumentParser(description=__doc__)
    parsed.add_argument("--organization", type=UUID, required=True)
    parsed.add_argument("--since", type=_time)
    parsed.add_argument("--until", type=_time)
    sources = parsed.add_mutually_exclusive_group(required=True)
    sources.add_argument("--file", type=Path)
    sources.add_argument("--url")
    sources.add_argument("--database", action="store_true")
    sources.add_argument("--delete-import", type=UUID, metavar="IMPORT_ID")
    return parsed


if __name__ == "__main__":
    try:
        print(json.dumps(asyncio.run(main(parser().parse_args())), sort_keys=True))
    except ImportRefused as exc:
        sys.exit(f"refused: {exc}")
    except (OSError, httpx.HTTPError, asyncpg.PostgresError, ValueError) as exc:
        # Counts and exception types only: a URL or a key never reaches a log.
        sys.exit(f"failed: {type(exc).__name__}")
