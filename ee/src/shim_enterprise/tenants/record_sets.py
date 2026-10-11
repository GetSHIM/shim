"""Record sets on the gateway: chunk encoding, and loaded indexes held per process."""

from __future__ import annotations

import asyncio
from array import array
import base64
from collections import OrderedDict
from collections.abc import Callable, Hashable, Iterable, Sequence
from contextlib import AbstractAsyncContextManager
import logging
import sys
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shim.core.single_flight import single_flight
from shim.gateway.contracts.ids import SecretRef, TenantId
from shim.privacy.record_match import FINGERPRINT_VERSION, RecordField, RecordSetIndex
from shim_enterprise.secrets.store import get_secret_store
from shim_enterprise.tenants.models import RecordSet, RecordSetChunk

logger = logging.getLogger(__name__)

KEY_PURPOSE = "record_set:hash-key"
# The bytes every loaded index of this process may hold together.
MAX_LOADED_BYTES = 128_000_000


def _big_endian(values: array) -> bytes:
    if sys.byteorder == "little":
        values = array(values.typecode, values)
        values.byteswap()
    return values.tobytes()


def _from_big_endian(data: bytes, typecode: str) -> array:
    values = array(typecode, data)
    if sys.byteorder == "little":
        values.byteswap()
    return values


def pack_records(rows: Iterable[Sequence[int]]) -> bytes:
    values = array("Q")
    for row in rows:
        values.extend(row)
    return _big_endian(values)


def pack_documents(documents: Iterable[Sequence[int]]) -> bytes:
    """Per document a 4-byte count, then its fingerprints."""
    data = bytearray()
    for prints in documents:
        data += len(prints).to_bytes(4, "big") + _big_endian(array("Q", prints))
    return bytes(data)


def unpack_documents(data: bytes) -> list[array]:
    documents, offset = [], 0
    while offset < len(data):
        count = int.from_bytes(data[offset : offset + 4], "big")
        end = offset + 4 + count * 8
        documents.append(_from_big_endian(data[offset + 4 : end], "Q"))
        offset = end
    return documents


def record_fields(fields: Sequence[dict[str, Any]]) -> tuple[RecordField, ...]:
    return tuple(
        RecordField(
            field["kind"],
            bool(field.get("primary")),
            tuple(field["length"]) if field.get("length") else None,
        )
        for field in fields
    )


async def load_index(
    session_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    organization_id: UUID,
    set_id: UUID,
    revision: int,
) -> RecordSetIndex | None:
    """One select of the set and its chunks in a short session of its own; the index is
    built after it closes. None when the set or revision is gone."""
    async with session_factory() as session:
        row = await session.scalar(
            select(RecordSet).where(
                RecordSet.organization_id == organization_id, RecordSet.id == set_id
            )
        )
        # A fingerprints set built with another version cannot be matched.
        if (
            row is None
            or revision < 1
            or (
                row.kind == "fingerprints"
                and row.fingerprint_version != FINGERPRINT_VERSION
            )
        ):
            return None
        chunks = (
            await session.scalars(
                select(RecordSetChunk.data)
                .where(
                    RecordSetChunk.record_set_id == set_id,
                    RecordSetChunk.revision == revision,
                )
                .order_by(RecordSetChunk.chunk_index)
            )
        ).all()
        fields, label, kind, key_ref = (
            record_fields(row.fields),
            row.label,
            row.kind,
            row.key_ref,
        )
    # A revision whose chunks are gone (a stale cached revision) cannot be matched.
    if not chunks:
        return None
    key = base64.urlsafe_b64decode(
        await get_secret_store().get_secret(
            TenantId(organization_id),
            SecretRef(key_ref),
            expected_purpose=KEY_PURPOSE,
        )
    )

    def build() -> RecordSetIndex:
        if kind == "records":
            values = _from_big_endian(b"".join(chunks), "Q")
            return RecordSetIndex.records(key, fields, values, label)
        return RecordSetIndex.documents(
            key, (prints for chunk in chunks for prints in unpack_documents(chunk))
        )

    # Sorting a quarter of a million hashes must not hold the event loop.
    return await asyncio.to_thread(build)


class RecordSetCache:
    """Loaded indexes by (organization, set, revision), least recently used evicted first."""

    def __init__(self, max_bytes: int = MAX_LOADED_BYTES) -> None:
        self.max_bytes = max_bytes
        self.entries: OrderedDict[tuple[UUID, UUID, int], RecordSetIndex] = (
            OrderedDict()
        )
        self.pending: dict[Hashable, asyncio.Future[RecordSetIndex | None]] = {}

    async def get(
        self,
        session_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
        organization_id: UUID,
        set_id: UUID,
        revision: int,
    ) -> RecordSetIndex | None:
        key = (organization_id, set_id, revision)
        if key in self.entries:
            self.entries.move_to_end(key)
            return self.entries[key]

        async def load() -> RecordSetIndex | None:
            index = await load_index(session_factory, organization_id, set_id, revision)
            if index is not None:
                self.entries[key] = index
                total = sum(entry.size for entry in self.entries.values())
                while total > self.max_bytes and len(self.entries) > 1:
                    _, evicted = self.entries.popitem(last=False)
                    total -= evicted.size
            return index

        # One load per set and revision at a time; later requests share it.
        return await single_flight(self.pending, key, load)


RECORD_SETS = RecordSetCache()
