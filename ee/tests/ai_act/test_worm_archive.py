from __future__ import annotations

import asyncio
import base64
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import hashlib
import importlib
import json
from types import SimpleNamespace
from uuid import uuid4

import httpx
from fastapi import FastAPI
from pydantic import ValidationError
import pytest
import pytest_asyncio
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim_enterprise.ai_act import audit_writer, worm
from shim_enterprise.ai_act.anchor import write_anchor
from shim_enterprise.ai_act.audit_writer import write_audit_row
from shim_enterprise.ai_act.hashing import canonical_row, chain_hash
from shim_enterprise.ai_act.models import WormArchiveObject
from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.compliance.models import MonthlyEvidenceFile
from shim_enterprise.core.config import Settings, settings
from shim_enterprise.core.database import get_db
from shim_enterprise.tenants.models import Organization, User
from shim_enterprise.workers import ai_act as worker_module


class _Missing(Exception):
    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.response = {
            "Error": {"Code": code},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }


class FakeBucket:
    """put_object, head_object and get_object_lock_configuration, recorded."""

    def __init__(self, tracked, *, retention: bool = True, objects_locked: bool = True):
        self.tracked = tracked
        self.retention = retention
        self.objects_locked = objects_locked
        self.objects: dict[str, dict] = {}
        self.puts: list[dict] = []
        self.fail_prefix: str | None = None

    def _no_transaction(self) -> None:
        assert self.tracked.open == 0, "a network call inside a database session"

    def get_object_lock_configuration(self, Bucket: str) -> dict:  # noqa: N803
        self._no_transaction()
        rule = (
            {"Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Years": 7}}}
            if self.retention
            else {}
        )
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled", **rule}}

    def put_object(self, **kwargs) -> dict:
        self._no_transaction()
        if self.fail_prefix and kwargs["Key"].startswith(self.fail_prefix):
            raise ConnectionError("bucket unreachable")
        self.puts.append(kwargs)
        self.objects[kwargs["Key"]] = kwargs
        return {"VersionId": f"v{len(self.puts)}"}

    def head_object(
        self, Bucket: str, Key: str, ChecksumMode: str | None = None
    ) -> dict:  # noqa: N803
        self._no_transaction()
        if Key not in self.objects:
            raise _Missing("404", 404)
        head = {
            "ChecksumSHA256": self.objects[Key]["ChecksumSHA256"],
            "VersionId": "v1",
        }
        if self.objects_locked:
            head |= {
                "ObjectLockMode": "COMPLIANCE",
                "ObjectLockRetainUntilDate": datetime(
                    2033, 10, 12, tzinfo=timezone.utc
                ),
            }
        return head


class Tracked:
    """A session factory that counts the sessions open right now."""

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self.factory = factory
        self.open = 0

    @asynccontextmanager
    async def __call__(self):
        self.open += 1
        try:
            async with self.factory() as session:
                yield session
        finally:
            self.open -= 1

    @asynccontextmanager
    async def begin(self):
        self.open += 1
        try:
            async with self.factory.begin() as session:
                yield session
        finally:
            self.open -= 1


@pytest.fixture
def enabled(monkeypatch) -> None:
    monkeypatch.setattr(settings, "WORM_ARCHIVE_ENABLED", True)
    monkeypatch.setattr(settings, "WORM_ARCHIVE_BUCKET", "evidence")
    monkeypatch.setattr(settings, "WORM_ARCHIVE_PREFIX", "shim")
    # Ten rows a chunk stands for ten thousand.
    monkeypatch.setattr(worm, "MAX_SYNC_AUDIT_ROWS", 10)


@pytest_asyncio.fixture
async def tracked(db) -> Tracked:
    return Tracked(
        async_sessionmaker(
            bind=await db.connection(),
            join_transaction_mode="create_savepoint",
            expire_on_commit=False,
        )
    )


async def _tenant(db, rows: int) -> Organization:
    organization = Organization(id=uuid4(), name="Worm", slug=f"worm-{uuid4().hex}")
    db.add(organization)
    await db.flush()
    await _rows(db, organization, rows)
    return organization


async def _rows(db, organization: Organization, count: int) -> None:
    for index in range(count):
        await write_audit_row(
            {
                "organization_id": organization.id,
                "event_type": "ai_request",
                "request_id": f"req-worm-{uuid4().hex}",
                "model": "gpt-5-nano",
                "extra": {"index": index},
            },
            db,
        )


def _keys(bucket: FakeBucket, organization: Organization) -> list[str]:
    prefix = f"shim/{organization.id}/"
    return [
        put["Key"].removeprefix(prefix)
        for put in bucket.puts
        if put["Key"].startswith(prefix)
    ]


def _verifies(document: dict) -> bool:
    previous = document["chain_start"]["prev_hash"]
    for row in document["rows"]:
        fields = {key: row[key] for key in audit_writer.CANONICAL_KEYS}
        if row["prev_hash"] != previous:
            return False
        if chain_hash(previous, canonical_row(fields)) != row["row_hash"]:
            return False
        previous = row["row_hash"]
    return True


def test_off_by_default_and_refused_without_a_bucket_or_with_http_in_production() -> (
    None
):
    assert worm.unavailable_reason() == worm.OFF
    with pytest.raises(ValidationError, match="requires WORM_ARCHIVE_BUCKET"):
        Settings(_env_file=None, WORM_ARCHIVE_ENABLED=True)  # ty: ignore[unknown-argument]
    with pytest.raises(ValidationError, match="production requires HTTPS"):
        Settings(  # ty: ignore[unknown-argument]
            _env_file=None,
            ENVIRONMENT="production",
            WORM_ARCHIVE_ENDPOINT_URL="http://minio.internal:9000",
        )


@pytest.mark.asyncio
async def test_the_worker_builds_no_client_while_off(db, tracked, monkeypatch) -> None:
    def no_client():
        raise AssertionError("no client while the archive is off")

    monkeypatch.setattr(worker_module, "build_client", no_client)
    organization = await _tenant(db, 3)

    await worker_module.AuditMaintenanceWorker(
        session_factory=tracked.factory, interval_seconds=60
    ).run_once()

    assert not list(
        await db.scalars(
            select(WormArchiveObject).where(
                WormArchiveObject.organization_id == organization.id
            )
        )
    )


@pytest.mark.asyncio
async def test_rows_go_in_contiguous_chunks_that_verify_alone(
    db, tracked, enabled
) -> None:
    organization = await _tenant(db, 25)
    bucket = FakeBucket(tracked)

    first = await worm.archive_pass(tracked, bucket)
    again = await worm.archive_pass(tracked, bucket)
    await _rows(db, organization, 3)
    later = await worm.archive_pass(tracked, bucket)

    assert (first, again, later) == (3, 0, 1)
    assert _keys(bucket, organization) == [
        "audit/rows/1-10.json",
        "audit/rows/11-20.json",
        "audit/rows/21-25.json",
        "audit/rows/26-28.json",
    ]
    for put in bucket.puts:
        document = json.loads(put["Body"])
        assert document["format"] == "shim.audit.bundle"
        assert document["anchors"] == []
        assert _verifies(document)
        # The checksum travels with the object, and shim never chooses its lock.
        assert put["ChecksumAlgorithm"] == "SHA256"
        assert (
            put["ChecksumSHA256"]
            == base64.b64encode(hashlib.sha256(put["Body"]).digest()).decode()
        )
        assert not {
            "ObjectLockMode",
            "ObjectLockRetainUntilDate",
            "ObjectLockLegalHoldStatus",
        } & set(put)
    stored = list(
        await db.scalars(
            select(WormArchiveObject)
            .where(WormArchiveObject.organization_id == organization.id)
            .order_by(WormArchiveObject.from_seq)
        )
    )
    assert [(row.from_seq, row.to_seq, row.status) for row in stored] == [
        (1, 10, "stored"),
        (11, 20, "stored"),
        (21, 25, "stored"),
        (26, 28, "stored"),
    ]
    assert stored[0].lock_mode == "COMPLIANCE" and stored[0].retain_until is not None


@pytest.mark.parametrize(
    ("retention", "objects_locked", "error"),
    [(False, True, "BUCKET_NOT_LOCKED"), (True, False, "NOT_LOCKED")],
)
@pytest.mark.asyncio
async def test_an_unlocked_bucket_or_object_is_a_recorded_failure(
    db, tracked, enabled, monkeypatch, retention, objects_locked, error
) -> None:
    # boto3 is not installed here; the fake stands in for its client.
    monkeypatch.setattr(worm, "unavailable_reason", lambda: None)
    organization = await _tenant(db, 3)
    bucket = FakeBucket(tracked, retention=retention, objects_locked=objects_locked)

    stored = await worm.archive_pass(tracked, bucket)

    [row] = list(
        await db.scalars(
            select(WormArchiveObject).where(
                WormArchiveObject.organization_id == organization.id
            )
        )
    )
    assert stored == 0
    assert (row.status, row.error_type, row.period_key) == ("failed", error, "1-3")
    assert bool(bucket.puts) is (error == "NOT_LOCKED")
    state = await worm.archive_state(db, organization.id)
    assert (state["state"], state["last_error_type"], state["failed"]) == (
        "error",
        error,
        1,
    )


@pytest.mark.asyncio
async def test_after_a_crash_the_object_is_found_by_its_checksum(
    db, tracked, enabled
) -> None:
    organization = await _tenant(db, 4)
    bucket = FakeBucket(tracked)
    await worm.archive_pass(tracked, bucket)
    # The upload landed but its record did not.
    await db.execute(
        delete(WormArchiveObject).where(
            WormArchiveObject.organization_id == organization.id
        )
    )

    stored = await worm.archive_pass(tracked, bucket)

    assert stored == 1 and len(bucket.puts) == 1
    [row] = list(
        await db.scalars(
            select(WormArchiveObject).where(
                WormArchiveObject.organization_id == organization.id
            )
        )
    )
    assert row.status == "stored"


@pytest.mark.asyncio
async def test_one_organizations_failure_leaves_the_others_and_a_pass_is_capped(
    db, tracked, enabled, monkeypatch
) -> None:
    broken, healthy = await _tenant(db, 3), await _tenant(db, 3)
    bucket = FakeBucket(tracked)
    bucket.fail_prefix = f"shim/{broken.id}/"

    await worm.archive_pass(tracked, bucket)

    assert _keys(bucket, healthy) == ["audit/rows/1-3.json"]
    statuses = {
        row.organization_id: (row.status, row.error_type)
        for row in await db.scalars(
            select(WormArchiveObject).where(
                WormArchiveObject.organization_id.in_([broken.id, healthy.id])
            )
        )
    }
    assert statuses == {
        broken.id: ("failed", "ConnectionError"),
        healthy.id: ("stored", None),
    }
    monkeypatch.setattr(worm, "MAX_OBJECTS_PER_PASS", 2)
    await _tenant(db, 40)
    capped = FakeBucket(tracked)

    assert await worm.archive_pass(tracked, capped) == 2
    assert len(capped.puts) == 2


@pytest.mark.asyncio
async def test_anchors_and_closed_months_are_copied_partial_months_never(
    db, tracked, enabled
) -> None:
    organization = await _tenant(db, 2)
    anchor = await write_anchor(db, organization.id, datetime.now(timezone.utc).date())
    for kind, period in (("monthly", "2026-09"), ("monthly_partial", "2026-10")):
        content = f"%PDF-{kind}".encode()
        db.add(
            MonthlyEvidenceFile(
                organization_id=organization.id,
                kind=kind,
                period=period,
                content=content,
                sha256=hashlib.sha256(content).hexdigest(),
                size_bytes=len(content),
                generated_at=datetime.now(timezone.utc),
                generator_version="test",
            )
        )
    await db.flush()
    bucket = FakeBucket(tracked)

    await worm.archive_pass(tracked, bucket)

    assert anchor is not None
    assert _keys(bucket, organization) == [
        "audit/rows/1-2.json",
        f"audit/anchors/{anchor.anchor_date.isoformat()}.json",
        "evidence/monthly/2026-09.pdf",
    ]
    monthly = bucket.objects[f"shim/{organization.id}/evidence/monthly/2026-09.pdf"]
    assert monthly["Metadata"] == {
        "sha256": hashlib.sha256(b"%PDF-monthly").hexdigest()
    }
    assert (
        json.loads(
            bucket.objects[
                f"shim/{organization.id}/audit/anchors/{anchor.anchor_date.isoformat()}.json"
            ]["Body"]
        )["root_hash"]
        == anchor.root_hash
    )
    state = await worm.archive_state(db, organization.id)
    assert (state["anchors_archived"], state["months_archived"]) == (1, 1)


def test_without_boto3_the_state_says_why(enabled, monkeypatch) -> None:
    real = importlib.import_module

    def missing(name: str, *args):
        if name == "boto3":
            raise ImportError(name)
        return real(name, *args)

    monkeypatch.setattr(worm.importlib, "import_module", missing)

    assert worm.unavailable_reason() == worm.NO_BOTO3


@pytest.mark.asyncio
async def test_readers_see_the_state_members_do_not(
    db, tracked, enabled, monkeypatch
) -> None:
    monkeypatch.setattr(worm, "unavailable_reason", lambda: None)
    organization = await _tenant(db, 12)
    await worm.archive_pass(tracked, FakeBucket(tracked))
    users = {
        role: User(
            id=uuid4(),
            organization_id=organization.id,
            email=f"worm-{role}-{uuid4().hex}@example.com",
            role=role,
            is_active=True,
            is_verified=True,
        )
        for role in ("auditor", "member")
    }
    db.add_all(users.values())
    await db.flush()

    async def read(user: User) -> httpx.Response:
        app = FastAPI()
        app.include_router(management_router, prefix="/api/v1")
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_current_user] = lambda: user
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            return await client.get("/api/v1/compliance/archive")

    answers = {role: await read(user) for role, user in users.items()}

    assert answers["member"].status_code == 403
    # The installation's bucket is the operator's, not the tenant's.
    assert "evidence" not in answers["auditor"].text
    assert answers["auditor"].json() == {
        "state": "on",
        "unavailable_reason": None,
        "prefix": "shim",
        "last_archived_seq": 12,
        "chain_tip_seq": 12,
        "anchors_archived": 0,
        "months_archived": 0,
        "failed": 0,
        "last_error_type": None,
    }


def test_the_client_gives_up_on_a_slow_endpoint(enabled, monkeypatch) -> None:
    made: dict = {}
    # boto3 is an optional extra: the call it receives is what is checked.
    modules = {
        "boto3": SimpleNamespace(client=lambda *_args, **kwargs: made.update(kwargs)),
        "botocore.config": SimpleNamespace(Config=lambda **kwargs: kwargs),
    }
    monkeypatch.setattr(worm.importlib, "import_module", modules.__getitem__)

    worm.build_client()

    assert made["config"]["connect_timeout"] == 5
    assert made["config"]["read_timeout"] == 30
    assert made["config"]["retries"] == {"max_attempts": 2, "mode": "standard"}


@pytest.mark.asyncio
async def test_a_stuck_pass_does_not_hold_up_the_other_maintenance(
    tracked, enabled, monkeypatch
) -> None:
    async def stuck(*_args):
        await asyncio.sleep(3600)

    async def none(*_args, **_kwargs):
        return 0, 0

    monkeypatch.setattr(worker_module, "unavailable_reason", lambda: None)
    monkeypatch.setattr(worker_module, "build_client", lambda: object())
    monkeypatch.setattr(worker_module, "archive_pass", stuck)
    monkeypatch.setattr(worker_module, "WORM_PASS_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(worker_module, "generate_due_monthly_evidence", none)
    monkeypatch.setattr(worker_module, "remind_incident_deadlines", none)
    monkeypatch.setattr(settings, "AI_ACT_AUDIT_ANCHOR_ENABLED", False)
    monkeypatch.setattr(settings, "OVERSIGHT_ENABLED", False)

    summary = await asyncio.wait_for(
        worker_module.AuditMaintenanceWorker(
            session_factory=tracked.factory, interval_seconds=60
        ).run_once(),
        10,
    )

    assert (summary.worm_archived, summary.errors) == (0, 1)


@pytest.mark.asyncio
async def test_incident_reminders_and_monthly_files_never_wait_for_the_archive(
    tracked, enabled, monkeypatch
) -> None:
    ran: list[str] = []

    async def slow(*_args):
        ran.append("archive")
        await asyncio.sleep(3600)

    def done(name):
        async def step(*_args, **_kwargs):
            ran.append(name)
            return 0, 0

        return step

    monkeypatch.setattr(worker_module, "unavailable_reason", lambda: None)
    monkeypatch.setattr(worker_module, "build_client", lambda: object())
    monkeypatch.setattr(worker_module, "archive_pass", slow)
    monkeypatch.setattr(worker_module, "WORM_PASS_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(worker_module, "generate_due_monthly_evidence", done("monthly"))
    monkeypatch.setattr(worker_module, "remind_incident_deadlines", done("reminders"))
    monkeypatch.setattr(settings, "AI_ACT_AUDIT_ANCHOR_ENABLED", False)
    monkeypatch.setattr(settings, "OVERSIGHT_ENABLED", False)

    await worker_module.AuditMaintenanceWorker(
        session_factory=tracked.factory, interval_seconds=60
    ).run_once()

    # A slow bucket may take the whole pass timeout; a statutory reminder may not.
    assert ran == ["monthly", "reminders", "archive"]
