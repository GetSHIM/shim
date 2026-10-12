"""Record sets (S51): hashed customer records and document fingerprints."""

from __future__ import annotations

from collections.abc import Collection
import base64
from datetime import datetime, timezone
import re
import secrets
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import delete as sql_delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from shim_enterprise.api.enterprise_deps import ADMIN_REQUIRED, READER_REQUIRED, require
from shim_enterprise.cache.redis_index import CacheManager, CacheService
from shim.privacy.record_match import FINGERPRINT_VERSION, KEY_BYTES
from shim_enterprise.core.database import get_db
from shim.gateway.contracts.ids import SecretRef, TenantId
from shim.privacy.policies import effective_entity_actions
from shim_enterprise.secrets.store import get_secret_store
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim_enterprise.rules.models import OrganizationRuleSet
from shim_enterprise.tenants.gateway_settings import (
    Directions,
    classify_fields,
    neutral,
)
from shim_enterprise.tenants.models import RecordSet, RecordSetChunk, User
from shim_enterprise.tenants.record_sets import (
    KEY_PURPOSE as RECORD_SET_KEY_PURPOSE,
    pack_documents,
    pack_records,
    unpack_documents,
)
from shim_enterprise.policy.models import PolicyPlan
from shim_enterprise.policy.plans import (
    Impact,
    Risk,
    State,
    lock_tenant,
    no_impact,
    record_managed_write,
    version_detail,
)
from shim_enterprise.tenants.permissions import Permission
from shim_enterprise.api.v1.management._common import (
    _only,
    _record_privacy_relaxed,
    _tenant_id,
    _uuids,
    _validated,
    bounded_body,
    logger,
)


router = APIRouter()


# Record sets (S51): hashed customer records and document fingerprints.

_RECORD_SETS_PER_ORGANIZATION = 10
_RECORD_SET_LIMITS = {
    "chunks": 500,
    "records_per_chunk": 10_000,
    "documents_per_chunk": 50,
    "prints_per_document": 20_000,
    "records": 250_000,
    "documents": 2_000,
    "prints": 2_000_000,
}
_HASH = re.compile(r"[0-9a-f]{16}")


class RecordSetFieldSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    kind: Literal["tckn", "vkn", "iban", "email", "phone", "digits", "token", "name"]
    primary: bool = False
    length: tuple[int, int] | None = Field(
        default=None, description="digits only: the shortest and longest run, 4 to 34."
    )

    @model_validator(mode="after")
    def coherent(self) -> RecordSetFieldSpec:
        if self.kind == "name" and self.primary:
            raise ValueError("a name field is never primary")
        if (self.length is not None) != (self.kind == "digits"):
            raise ValueError("length is given for digits fields, and only for them")
        if self.length is not None and not 4 <= self.length[0] <= self.length[1] <= 34:
            raise ValueError("length is a range within 4 to 34")
        return self


class RecordSetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    kind: Literal["records", "fingerprints"]
    label: str = Field(
        default="RECORD",
        max_length=32,
        pattern=r"^[A-Z][A-Z0-9]{1,15}(?:_[A-Z0-9]{1,15})?$",
    )
    fields: list[RecordSetFieldSpec] = []

    @model_validator(mode="after")
    def coherent(self) -> RecordSetCreate:
        if self.label in effective_entity_actions():
            raise ValueError(f"{self.label} is a built-in entity type")
        if self.kind == "fingerprints" and self.fields:
            raise ValueError("a fingerprints set has no fields")
        if self.kind == "records" and not (
            2 <= len(self.fields) <= 6 and any(field.primary for field in self.fields)
        ):
            raise ValueError("a records set has 2 to 6 fields, at least one primary")
        return self


class RecordSetView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    kind: Literal["records", "fingerprints"]
    label: str
    fields: list[dict[str, Any]]
    fingerprint_version: int | None
    active_revision: int
    previous_revision: int
    entry_count: int
    created_at: datetime
    updated_at: datetime


class RecordSetCreatedView(RecordSetView):
    hash_key: str = Field(
        description="Shown once: the base64url key the hashing tool uses."
    )


class RecordSetChunkPut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    records: list[list[str]] | None = None
    documents: list[list[str]] | None = None


def _record_set_error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status_code, detail={"code": code, "message": message}
    )


async def _record_set(
    session: AsyncSession, tenant_id: UUID, set_id: UUID
) -> RecordSet:
    row = await session.scalar(
        select(RecordSet)
        .where(RecordSet.organization_id == tenant_id, RecordSet.id == set_id)
        .with_for_update()
    )
    if row is None:
        raise _record_set_error(404, "RECORD_SET_NOT_FOUND", "No such record set.")
    return row


async def _invalidate_policy(request: Request, tenant_id: UUID) -> None:
    try:
        cache: CacheService = request.app.state.cache
        await CacheManager(cache).invalidate_pii_config(str(tenant_id))
    except Exception as exc:
        logger.warning(
            "Record set cache invalidation failed type=%s", type(exc).__name__
        )


@router.post("/record-sets", response_model=RecordSetCreatedView, status_code=201)
async def create_record_set(
    payload: RecordSetCreate,
    request: Request,
    user: User = Depends(require("rules.write", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> Any:
    tenant_id = _tenant_id(user)
    await lock_tenant(session, tenant_id)
    existing = await session.scalar(
        select(func.count())
        .select_from(RecordSet)
        .where(RecordSet.organization_id == tenant_id)
    )
    if (existing or 0) >= _RECORD_SETS_PER_ORGANIZATION:
        raise _record_set_error(
            422, "RECORD_SET_LIMIT", "An organization holds at most 10 record sets."
        )
    key = base64.urlsafe_b64encode(secrets.token_bytes(KEY_BYTES)).decode()
    key_ref = await get_secret_store().put_secret(
        TenantId(tenant_id), RECORD_SET_KEY_PURPOSE, key
    )
    row = RecordSet(
        organization_id=tenant_id,
        kind=payload.kind,
        name=payload.name,
        label=payload.label,
        fields=[
            field.model_dump(mode="json", exclude_none=True) for field in payload.fields
        ],
        fingerprint_version=FINGERPRINT_VERSION
        if payload.kind == "fingerprints"
        else None,
        key_ref=key_ref,
        created_by=str(user.id),
    )
    session.add(row)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        raise _record_set_error(
            409, "RECORD_SET_NAME_TAKEN", "A record set with this name exists."
        ) from None
    await _audit(
        session,
        user,
        "tenant.record_set_created",
        str(tenant_id),
        details={
            "record_set_id": str(row.id),
            "kind": row.kind,
            "fields": len(row.fields),
        },
    )
    await session.commit()
    await session.refresh(row)
    return {**RecordSetView.model_validate(row).model_dump(), "hash_key": key}


@router.get("/record-sets", response_model=list[RecordSetView])
async def list_record_sets(
    user: User = Depends(require("rules.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> Any:
    return (
        await session.scalars(
            select(RecordSet)
            .where(RecordSet.organization_id == _tenant_id(user))
            .order_by(RecordSet.name)
        )
    ).all()


@router.get("/record-sets/{set_id}", response_model=RecordSetView)
async def get_record_set(
    set_id: UUID,
    user: User = Depends(require("rules.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> Any:
    row = await session.scalar(
        select(RecordSet).where(
            RecordSet.organization_id == _tenant_id(user), RecordSet.id == set_id
        )
    )
    if row is None:
        raise _record_set_error(404, "RECORD_SET_NOT_FOUND", "No such record set.")
    return row


@router.post("/record-sets/{set_id}/revisions", status_code=201)
async def open_record_set_revision(
    set_id: UUID,
    user: User = Depends(require("rules.write", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> dict[str, int]:
    row = await _record_set(session, _tenant_id(user), set_id)
    uploaded = await session.scalar(
        select(func.max(RecordSetChunk.revision)).where(
            RecordSetChunk.record_set_id == set_id
        )
    )
    await session.commit()
    return {
        "revision": max(row.active_revision, row.previous_revision, uploaded or 0) + 1
    }


def _hashes(values: list[str], path: str) -> list[int]:
    if not all(_HASH.fullmatch(value) for value in values):
        raise _record_set_error(
            422,
            "RECORD_SET_CHUNK_INVALID",
            f"{path} holds a value that is not 16 hex digits.",
        )
    return [int(value, 16) for value in values]


async def put_record_set_chunk(
    set_id: UUID,
    revision: int,
    chunk_index: int,
    payload: RecordSetChunkPut,
    user: User = Depends(require("rules.write", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> dict[str, int]:
    tenant_id = _tenant_id(user)
    row = await _record_set(session, tenant_id, set_id)
    limits = _RECORD_SET_LIMITS
    if not 0 <= chunk_index < limits["chunks"]:
        raise _record_set_error(
            422, "RECORD_SET_CHUNK_INVALID", "A chunk index is 0 to 499."
        )
    if revision <= max(row.active_revision, row.previous_revision):
        raise _record_set_error(
            409,
            "RECORD_SET_REVISION_SEALED",
            "Chunks go to a newly opened revision; an activated one never changes.",
        )
    # What a reviewer sees in a plan is what its approval activates.
    planned = await session.scalar(
        select(PolicyPlan.id)
        .where(
            PolicyPlan.organization_id == tenant_id,
            PolicyPlan.status.in_(("draft", "pending_approval")),
            PolicyPlan.expires_at > datetime.now(timezone.utc),
            PolicyPlan.changes.contains(
                [
                    {
                        "resource": "record_sets",
                        "item": str(set_id),
                        "after": {"active_revision": revision},
                    }
                ]
            ),
        )
        .limit(1)
    )
    if planned is not None:
        raise _record_set_error(
            409,
            "RECORD_SET_REVISION_PLANNED",
            "A pending plan activates this revision; it takes no more chunks until "
            "the plan is applied, rejected or expires.",
        )
    if row.kind == "records":
        if payload.records is None or payload.documents is not None:
            raise _record_set_error(
                422, "RECORD_SET_CHUNK_INVALID", "A records set takes `records`."
            )
        width = len(row.fields)
        primary = [
            index for index, field in enumerate(row.fields) if field.get("primary")
        ]
        if not 1 <= len(payload.records) <= limits["records_per_chunk"]:
            raise _record_set_error(
                422, "RECORD_SET_CHUNK_INVALID", "A chunk holds 1 to 10,000 records."
            )
        rows = []
        for number, record in enumerate(payload.records):
            hashes = _hashes(record, f"records[{number}]")
            if len(hashes) != width or not any(hashes[index] for index in primary):
                raise _record_set_error(
                    422,
                    "RECORD_SET_CHUNK_INVALID",
                    f"records[{number}] needs {width} fields and a primary value.",
                )
            rows.append(hashes)
        data, count = pack_records(rows), len(rows)
    else:
        if payload.documents is None or payload.records is not None:
            raise _record_set_error(
                422, "RECORD_SET_CHUNK_INVALID", "A fingerprints set takes `documents`."
            )
        if not 1 <= len(payload.documents) <= limits["documents_per_chunk"] or any(
            len(prints) > limits["prints_per_document"] for prints in payload.documents
        ):
            raise _record_set_error(
                422,
                "RECORD_SET_CHUNK_INVALID",
                "A chunk holds 1 to 50 documents of at most 20,000 fingerprints.",
            )
        documents = [
            _hashes(prints, f"documents[{number}]")
            for number, prints in enumerate(payload.documents)
        ]
        data, count = pack_documents(documents), len(documents)
    await session.merge(
        RecordSetChunk(
            record_set_id=set_id,
            revision=revision,
            chunk_index=chunk_index,
            organization_id=tenant_id,
            entry_count=count,
            data=data,
        )
    )
    await session.commit()
    return {"revision": revision, "chunk_index": chunk_index, "entry_count": count}


router.add_api_route(
    "/record-sets/{set_id}/revisions/{revision}/chunks/{chunk_index}",
    put_record_set_chunk,
    methods=["PUT"],
    route_class_override=bounded_body(
        4_000_000, "A record set chunk is at most 4,000,000 bytes."
    ),
)


async def _revision_chunks(
    session: AsyncSession, set_id: UUID, revision: int
) -> list[tuple[int, bytes]]:
    return list(
        (
            await session.execute(
                select(RecordSetChunk.entry_count, RecordSetChunk.data).where(
                    RecordSetChunk.record_set_id == set_id,
                    RecordSetChunk.revision == revision,
                )
            )
        ).tuples()
    )


def _entries(row: RecordSet, chunks: list[tuple[int, bytes]]) -> set[bytes]:
    """Each record or document of a revision, byte for byte."""
    if row.kind == "records":
        size = 8 * len(row.fields)
        return {
            data[start : start + size]
            for _, data in chunks
            for start in range(0, len(data), size)
        }
    return {
        document.tobytes() for _, data in chunks for document in unpack_documents(data)
    }


async def _activatable(
    session: AsyncSession, row: RecordSet, revision: int
) -> list[tuple[int, bytes]]:
    chunks = await _revision_chunks(session, row.id, revision)
    if revision == row.active_revision or not chunks:
        raise _record_set_error(
            409,
            "RECORD_SET_REVISION_EMPTY",
            "That revision is active or holds no chunks.",
        )
    entries = sum(count for count, _ in chunks)
    limits = _RECORD_SET_LIMITS
    # Fingerprints after each document's 4-byte count.
    prints = sum(len(data) - 4 * count for count, data in chunks) // 8
    too_many = (
        entries > limits["records"]
        if row.kind == "records"
        else entries > limits["documents"] or prints > limits["prints"]
    )
    if too_many:
        raise _record_set_error(
            422,
            "RECORD_SET_TOO_LARGE",
            "A set holds at most 250,000 records, or 2,000 documents and 2,000,000 "
            "fingerprints.",
        )
    return chunks


@router.post(
    "/record-sets/{set_id}/revisions/{revision}/activate", response_model=RecordSetView
)
async def activate_record_set_revision(
    set_id: UUID,
    revision: int,
    request: Request,
    user: User = Depends(require("rules.write", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> Any:
    tenant_id, item = _tenant_id(user), str(set_id)
    await lock_tenant(session, tenant_id)
    before = (await RECORD_SETS.snapshot(session, tenant_id, [item])).get(item)
    if before is None:
        raise _record_set_error(404, "RECORD_SET_NOT_FOUND", "No such record set.")
    after = await RECORD_SETS.validate(
        session, user, item, before, {"active_revision": revision}
    )
    async with record_managed_write(
        session, user, tenant_id, [(RECORD_SETS, item, before, after)], source="api"
    ) as version:
        await RECORD_SETS.apply(
            session, user, tenant_id, item, before, after, policy_version=version
        )
    await session.commit()
    await _invalidate_policy(request, tenant_id)
    return await session.get(RecordSet, set_id, populate_existing=True)


@router.delete("/record-sets/{set_id}", status_code=204)
async def delete_record_set(
    set_id: UUID,
    request: Request,
    user: User = Depends(require("rules.write", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> Response:
    tenant_id = _tenant_id(user)
    row = await _record_set(session, tenant_id, set_id)
    # Locked, so a rule naming the set cannot be written while it goes.
    rule_set = await session.get(OrganizationRuleSet, tenant_id, with_for_update=True)
    if any(
        rule.get("kind") == "record_set"
        and (rule.get("match") or {}).get("set_id") == str(set_id)
        for rule in (rule_set.rules if rule_set is not None else [])
    ):
        raise _record_set_error(
            409,
            "RECORD_SET_IN_USE",
            "A rule references this record set; remove it first.",
        )
    key_ref = row.key_ref
    await session.delete(row)
    await _audit(
        session,
        user,
        "tenant.record_set_deleted",
        str(tenant_id),
        details={"record_set_id": str(set_id)},
    )
    await session.commit()
    try:
        await get_secret_store().delete_secret(
            TenantId(tenant_id),
            SecretRef(key_ref),
            expected_purpose=RECORD_SET_KEY_PURPOSE,
        )
    except Exception as exc:
        logger.warning("Record set key deletion failed type=%s", type(exc).__name__)
    await _invalidate_policy(request, tenant_id)
    return Response(status_code=204)


class _RecordSetRevision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    active_revision: int = Field(ge=1, le=2_147_483_647)
    enforced: bool


class _RecordSetResource:
    """A set's active revision; `enforced` says whether an enforced rule uses it."""

    name = "record_sets"
    permission: Permission = "rules.write"
    creatable = False
    deletable = False

    async def snapshot(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_ids: Collection[str] | None,
    ) -> dict[str, State]:
        statement = select(RecordSet.id, RecordSet.active_revision).where(
            RecordSet.organization_id == organization_id
        )
        if item_ids is not None:
            statement = statement.where(RecordSet.id.in_(_uuids(item_ids)))
        rule_set = await session.get(OrganizationRuleSet, organization_id)
        enforced = {
            (rule.get("match") or {}).get("set_id")
            for rule in (rule_set.rules if rule_set is not None else [])
            if rule.get("kind") == "record_set" and rule.get("state") == "enforced"
        }
        return {
            str(set_id): {
                "active_revision": revision,
                "enforced": str(set_id) in enforced,
            }
            for set_id, revision in (await session.execute(statement)).tuples()
        }

    async def validate(
        self,
        session: AsyncSession,
        actor: User,
        item_id: str | None,
        before: State | None,
        proposed: State,
    ) -> State:
        assert item_id is not None and before is not None
        _only(proposed, _RecordSetRevision.model_fields)
        # Whether a rule enforces the set is the rule set's to change, not this one's.
        after = _validated(
            _RecordSetRevision, {**before, **proposed, "enforced": before["enforced"]}
        ).model_dump()
        if "active_revision" in proposed:
            row = await _record_set(session, _tenant_id(actor), UUID(item_id))
            await _activatable(session, row, after["active_revision"])
        return after

    async def apply(
        self,
        session: AsyncSession,
        actor: User,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        *,
        policy_version: int | None,
    ) -> None:
        assert before is not None and after is not None
        revision = after["active_revision"]
        if revision == before["active_revision"]:
            return
        row = await _record_set(session, organization_id, UUID(item_id))
        chunks = await _activatable(session, row, revision)
        entries = sum(count for count, _ in chunks)
        # Any record or document the active revision has and this one lacks
        # can no longer be found.
        shrinks = row.active_revision > 0 and not _entries(
            row, await _revision_chunks(session, row.id, row.active_revision)
        ) <= _entries(row, chunks)
        row.previous_revision, row.active_revision, row.entry_count = (
            row.active_revision,
            revision,
            entries,
        )
        # One revision back stays for a rollback; every other one goes.
        await session.execute(
            sql_delete(RecordSetChunk).where(
                RecordSetChunk.record_set_id == row.id,
                RecordSetChunk.revision.not_in(
                    {row.active_revision, row.previous_revision}
                ),
            )
        )
        await _audit(
            session,
            actor,
            "tenant.record_set_revision_activated",
            str(organization_id),
            details={
                "record_set_id": item_id,
                "revision": revision,
                "entry_count": entries,
                **version_detail(policy_version),
            },
        )
        if shrinks:
            await _record_privacy_relaxed(
                session,
                actor,
                organization_id,
                [f"record_sets.{item_id}"],
                policy_version,
            )

    def classify(self, before: State | None, after: State | None) -> Risk:
        assert before is not None and after is not None
        # Another revision can drop any record, so swapping the set of an
        # enforced rule relaxes; an unlisted field relaxes.
        directions: Directions = (
            {"enforced": neutral}
            if before["enforced"]
            else {"enforced": neutral, "active_revision": neutral}
        )
        return classify_fields(before, after, directions)[0]

    async def impact(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        window_days: int,
    ) -> Impact:
        assert before is not None and after is not None
        revision = after["active_revision"]
        if revision == before["active_revision"]:
            return no_impact(window_days)
        row = await _record_set(session, organization_id, UUID(item_id))
        proposed = sum(
            count for count, _ in await _revision_chunks(session, row.id, revision)
        )
        unit = "records" if row.kind == "records" else "documents"
        return {
            "requests": None,
            "basis": "metadata",
            "window_days": window_days,
            "note": f"{row.entry_count} {unit} now, {proposed} in revision {revision}",
        }

    async def after_commit(self, request: Request, organization_id: UUID) -> None:
        await _invalidate_policy(request, organization_id)


RECORD_SETS = _RecordSetResource()
