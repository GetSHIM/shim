from __future__ import annotations

from array import array
import asyncio
import base64
from contextlib import nullcontext
from types import SimpleNamespace
from uuid import UUID, uuid4

from fastapi import HTTPException
from pydantic import ValidationError
import pytest
from sqlalchemy import select

import shim_enterprise.tenants.record_sets as record_sets_module
from shim.privacy.record_match import (
    RecordField,
    RecordSetIndex,
    normalize,
    record_hash,
)
from shim_enterprise.api.v1 import management
from shim_enterprise.rules.models import OrganizationRuleSet
from shim_enterprise.tenants.models import RecordSetChunk, User
from shim_enterprise.tenants.record_sets import RecordSetCache, load_index


def _request():
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(cache=None)))


async def _admin(db, organization_id: UUID, role: str = "admin") -> User:
    user = User(
        id=uuid4(),
        email=f"record-sets-{uuid4().hex}@example.com",
        full_name="Record Sets Admin",
        is_active=True,
        is_verified=True,
        organization_id=organization_id,
        role=role,
    )
    db.add(user)
    await db.flush()
    return user


def _customers(name: str = "customers") -> management.record_sets.RecordSetCreate:
    return management.record_sets.RecordSetCreate(
        name=name,
        kind="records",
        fields=[
            management.record_sets.RecordSetFieldSpec(
                name="Müşteri No", kind="token", primary=True
            ),
            management.record_sets.RecordSetFieldSpec(name="Ad Soyad", kind="name"),
        ],
    )


# Names are letter words: a digit never joins a name in text.
_NAMES = ["Ayşe Yılmaz", "İsmail Işık", "Çağrı Öztürk", "Şule Ünal", "Gökhan Demir"]


def _row(key: bytes, number: int, name: str) -> list[str]:
    return [
        f"{record_hash(key, 'token', normalize('token', f'MUS{number:06d}')):016x}",
        f"{record_hash(key, 'name', normalize('name', name)):016x}",
    ]


async def _activate(db, admin, set_id, key: bytes, count: int) -> int:
    revision = (
        await management.record_sets.open_record_set_revision(set_id, admin, db)
    )["revision"]
    await management.record_sets.put_record_set_chunk(
        set_id,
        revision,
        0,
        management.record_sets.RecordSetChunkPut(
            records=[
                _row(key, number, _NAMES[number % len(_NAMES)])
                for number in range(count)
            ]
        ),
        admin,
        db,
    )
    await management.record_sets.activate_record_set_revision(
        set_id, revision, _request(), admin, db
    )
    return revision


@pytest.mark.asyncio
async def test_a_set_shows_its_key_once_and_only_metadata_after(db, test_org) -> None:
    admin = await _admin(db, test_org.id)

    created = await management.record_sets.create_record_set(
        _customers(), _request(), admin, db
    )
    listed = await management.record_sets.list_record_sets(admin, db)
    read = await management.record_sets.get_record_set(
        UUID(str(created["id"])), admin, db
    )

    assert len(base64.urlsafe_b64decode(created["hash_key"])) == 32
    assert [row.id for row in listed] == [created["id"]]
    assert (
        "hash_key"
        not in management.record_sets.RecordSetView.model_validate(read).model_dump()
    )
    assert created["fields"][0] == {
        "name": "Müşteri No",
        "kind": "token",
        "primary": True,
    }


@pytest.mark.asyncio
async def test_an_organization_holds_ten_sets(db, test_org) -> None:
    admin = await _admin(db, test_org.id)
    for number in range(10):
        await management.record_sets.create_record_set(
            _customers(f"set-{number}"), _request(), admin, db
        )

    with pytest.raises(HTTPException) as refused:
        await management.record_sets.create_record_set(
            _customers("set-10"), _request(), admin, db
        )

    assert (refused.value.status_code, refused.value.detail["code"]) == (
        422,
        "RECORD_SET_LIMIT",
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "x", "kind": "records", "fields": [{"name": "a", "kind": "token"}]},
        {
            "name": "x",
            "kind": "records",
            "fields": [
                {"name": "a", "kind": "name", "primary": True},
                {"name": "b", "kind": "tckn"},
            ],
        },
        {"name": "x", "kind": "records", "fields": [{"name": "a", "kind": "tckn"}] * 2},
        {
            "name": "x",
            "kind": "fingerprints",
            "fields": [{"name": "a", "kind": "tckn"}],
        },
        {"name": "x", "kind": "records", "label": "TR_NATIONAL_ID", "fields": []},
        {
            "name": "x",
            "kind": "records",
            "fields": [
                {"name": "a", "kind": "digits", "primary": True},
                {"name": "b", "kind": "name"},
            ],
        },
    ],
)
def test_a_set_definition_is_refused_when_it_cannot_be_matched(payload) -> None:
    with pytest.raises(ValidationError):
        management.record_sets.RecordSetCreate.model_validate(payload)


@pytest.mark.asyncio
async def test_chunk_limits_hold_at_their_bound(db, test_org) -> None:
    admin = await _admin(db, test_org.id)
    created = await management.record_sets.create_record_set(
        _customers(), _request(), admin, db
    )
    set_id, key = created["id"], base64.urlsafe_b64decode(created["hash_key"])
    revision = (
        await management.record_sets.open_record_set_revision(set_id, admin, db)
    )["revision"]

    async def put(index: int, records: list[list[str]]):
        return await management.record_sets.put_record_set_chunk(
            set_id,
            revision,
            index,
            management.record_sets.RecordSetChunkPut(records=records),
            admin,
            db,
        )

    full = await put(499, [_row(key, number, "Ad") for number in range(10_000)])
    refusals = []
    for index, records in (
        (0, [_row(key, number, "Ad") for number in range(10_001)]),
        (500, [_row(key, 1, "Ad")]),
        (0, [_row(key, 1, "Ad")[:1]]),
        (0, [["0" * 16, _row(key, 1, "Ad")[1]]]),
        (0, [["NOT-HEX-AT-ALL!!", "0" * 16]]),
    ):
        with pytest.raises(HTTPException) as refused:
            await put(index, records)
        refusals.append(refused.value.status_code)

    assert full["entry_count"] == 10_000
    assert refusals == [422] * 5


@pytest.mark.asyncio
async def test_activation_keeps_one_revision_back_and_rolls_back(
    db, test_org, audit_events
) -> None:
    admin = await _admin(db, test_org.id)
    created = await management.record_sets.create_record_set(
        _customers(), _request(), admin, db
    )
    set_id, key = created["id"], base64.urlsafe_b64decode(created["hash_key"])

    first = await _activate(db, admin, set_id, key, 3)
    second = await _activate(db, admin, set_id, key, 5)
    third = await _activate(db, admin, set_id, key, 2)
    kept = set(
        await db.scalars(
            select(RecordSetChunk.revision).where(
                RecordSetChunk.record_set_id == set_id
            )
        )
    )
    rolled = await management.record_sets.activate_record_set_revision(
        set_id, second, _request(), admin, db
    )
    with pytest.raises(HTTPException) as sealed:
        await management.record_sets.put_record_set_chunk(
            set_id,
            third,
            1,
            management.record_sets.RecordSetChunkPut(records=[_row(key, 9, "Ad")]),
            admin,
            db,
        )
    relaxed = [
        event["extra"]["relaxed"]
        for event in await audit_events(test_org.id)
        if event["endpoint"] == "tenant.privacy_protection_relaxed"
    ]

    assert (first, second, third) == (1, 2, 3)
    assert kept == {2, 3}, "only the active revision and the one before it stay"
    assert (rolled.active_revision, rolled.previous_revision, rolled.entry_count) == (
        2,
        3,
        5,
    )
    assert sealed.value.status_code == 409
    assert relaxed == [[f"record_sets.{set_id}"]], "5 to 2 entries is a relaxation"


@pytest.mark.asyncio
async def test_a_revision_with_fewer_values_to_match_is_a_relaxation(
    db, test_org, audit_events
) -> None:
    admin = await _admin(db, test_org.id)
    created = await management.record_sets.create_record_set(
        _customers(), _request(), admin, db
    )
    set_id, key = created["id"], base64.urlsafe_b64decode(created["hash_key"])
    await _activate(db, admin, set_id, key, 3)
    revision = (
        await management.record_sets.open_record_set_revision(set_id, admin, db)
    )["revision"]
    # As many records, but the names are gone: none can match two fields any more.
    await management.record_sets.put_record_set_chunk(
        set_id,
        revision,
        0,
        management.record_sets.RecordSetChunkPut(
            records=[[_row(key, number, "Ad")[0], "0" * 16] for number in range(3)]
        ),
        admin,
        db,
    )
    await management.record_sets.activate_record_set_revision(
        set_id, revision, _request(), admin, db
    )

    assert [
        event["extra"]["relaxed"]
        for event in await audit_events(test_org.id)
        if event["endpoint"] == "tenant.privacy_protection_relaxed"
    ] == [[f"record_sets.{set_id}"]]


@pytest.mark.asyncio
async def test_a_same_size_revision_of_other_entries_is_a_relaxation(
    db, test_org, audit_events
) -> None:
    admin = await _admin(db, test_org.id)
    records = await management.record_sets.create_record_set(
        _customers(), _request(), admin, db
    )
    prints = await management.record_sets.create_record_set(
        management.record_sets.RecordSetCreate(name="docs", kind="fingerprints"),
        _request(),
        admin,
        db,
    )

    async def activate(
        set_id: UUID, chunk: management.record_sets.RecordSetChunkPut
    ) -> None:
        revision = (
            await management.record_sets.open_record_set_revision(set_id, admin, db)
        )["revision"]
        await management.record_sets.put_record_set_chunk(
            set_id, revision, 0, chunk, admin, db
        )
        await management.record_sets.activate_record_set_revision(
            set_id, revision, _request(), admin, db
        )

    def rows(first: int) -> management.record_sets.RecordSetChunkPut:
        return management.record_sets.RecordSetChunkPut(
            records=[[f"{first + n:016x}", f"{first + n + 99:016x}"] for n in range(3)]
        )

    def documents(first: int) -> management.record_sets.RecordSetChunkPut:
        return management.record_sets.RecordSetChunkPut(
            documents=[[f"{first + n:016x}" for n in range(8)]]
        )

    for set_id, chunk in ((records["id"], rows), (prints["id"], documents)):
        await activate(set_id, chunk(1))
        # The same entries again, then the same count of other ones.
        await activate(set_id, chunk(1))
        await activate(set_id, chunk(500))

    assert [
        event["extra"]["relaxed"]
        for event in await audit_events(test_org.id)
        if event["endpoint"] == "tenant.privacy_protection_relaxed"
    ] == [[f"record_sets.{records['id']}"], [f"record_sets.{prints['id']}"]]


@pytest.mark.asyncio
async def test_deleting_a_set_locks_the_rule_set_it_is_checked_against(
    db, test_org
) -> None:
    from sqlalchemy import event

    admin = await _admin(db, test_org.id)
    created = await management.record_sets.create_record_set(
        _customers(), _request(), admin, db
    )
    statements: list[str] = []
    listener = lambda *args: statements.append(args[2])  # noqa: E731
    event.listen(db.bind.sync_engine, "before_cursor_execute", listener)
    try:
        await management.record_sets.delete_record_set(
            created["id"], _request(), admin, db
        )
    finally:
        event.remove(db.bind.sync_engine, "before_cursor_execute", listener)

    assert any(
        "organization_rule_sets" in statement and "FOR UPDATE" in statement
        for statement in statements
    )


@pytest.mark.asyncio
async def test_a_set_in_use_cannot_be_deleted(db, test_org, audit_events) -> None:
    admin = await _admin(db, test_org.id)
    created = await management.record_sets.create_record_set(
        _customers(), _request(), admin, db
    )
    set_id = created["id"]
    db.add(
        OrganizationRuleSet(
            organization_id=test_org.id,
            revision=1,
            rules=[
                {
                    "id": "customers",
                    "kind": "record_set",
                    "match": {"set_id": str(set_id)},
                }
            ],
        )
    )
    await db.flush()

    with pytest.raises(HTTPException) as in_use:
        await management.record_sets.delete_record_set(set_id, _request(), admin, db)
    rule_set = await db.get(OrganizationRuleSet, test_org.id)
    rule_set.rules = []
    await db.flush()
    await management.record_sets.delete_record_set(set_id, _request(), admin, db)

    assert (in_use.value.status_code, in_use.value.detail["code"]) == (
        409,
        "RECORD_SET_IN_USE",
    )
    assert await management.record_sets.list_record_sets(admin, db) == []
    assert "tenant.record_set_deleted" in {
        event["endpoint"] for event in await audit_events(test_org.id)
    }


@pytest.mark.asyncio
async def test_a_record_set_rule_needs_an_active_set_of_its_kind(db, test_org) -> None:
    admin = await _admin(db, test_org.id)
    records = await management.record_sets.create_record_set(
        _customers(), _request(), admin, db
    )
    prints = await management.record_sets.create_record_set(
        management.record_sets.RecordSetCreate(name="docs", kind="fingerprints"),
        _request(),
        admin,
        db,
    )
    await _activate(
        db, admin, records["id"], base64.urlsafe_b64decode(records["hash_key"]), 2
    )

    async def put(match: dict, action: str = "block") -> int:
        current = await management.configuration.get_rules(admin, db)
        try:
            await management.configuration.replace_rules(
                management.configuration.RuleSetPut(
                    revision=current.revision,
                    rules=[
                        {
                            "id": "r",
                            "name": "r",
                            "kind": "record_set",
                            "action": action,
                            "state": "monitor",
                            "match": match,
                        }
                    ],
                ),
                _request(),
                admin,
                db,
            )
        except HTTPException as error:
            return error.status_code
        return 200

    assert await put({"set_id": str(records["id"]), "min_fields": 2}) == 200
    assert await put({"set_id": str(records["id"]), "min_fields": 3}) == 422, (
        "two fields can never give three"
    )
    assert await put({"set_id": str(uuid4())}) == 422
    assert await put({"set_id": str(prints["id"])}) == 422, "not activated"
    assert await put({"set_id": str(records["id"]), "min_shared": 6}) == 422
    revision = (
        await management.record_sets.open_record_set_revision(prints["id"], admin, db)
    )["revision"]
    await management.record_sets.put_record_set_chunk(
        prints["id"],
        revision,
        0,
        management.record_sets.RecordSetChunkPut(
            documents=[[f"{value:016x}" for value in range(1, 9)]]
        ),
        admin,
        db,
    )
    await management.record_sets.activate_record_set_revision(
        prints["id"], revision, _request(), admin, db
    )
    assert await put({"set_id": str(prints["id"]), "min_shared": 6}, "warn") == 200
    assert await put({"set_id": str(prints["id"])}, "mask") == 422, (
        "fingerprints never mask"
    )


@pytest.mark.asyncio
async def test_a_loaded_set_matches_and_the_cache_evicts_the_oldest(
    db, test_org, monkeypatch
) -> None:
    admin = await _admin(db, test_org.id)
    created = await management.record_sets.create_record_set(
        _customers(), _request(), admin, db
    )
    set_id, key = created["id"], base64.urlsafe_b64decode(created["hash_key"])
    revision = await _activate(db, admin, set_id, key, 4)

    sessions = lambda: nullcontext(db)  # noqa: E731
    index = await load_index(sessions, test_org.id, set_id, revision)

    assert index is not None
    assert index.match_records("MUS000002 numaralı ÇAĞRI ÖZTÜRK", 2)[0] == {2}
    assert index.match_records("MUS000002 numaralı Şule Ünal", 2)[0] == set()
    assert await load_index(sessions, test_org.id, set_id, revision + 5) is None
    assert await load_index(sessions, uuid4(), set_id, revision) is None

    small = RecordSetIndex.records(
        key, (RecordField("token", True),), array("Q", [1, 2])
    )

    async def fake_load(_sessions, organization, loaded_set, loaded_revision):
        return small

    monkeypatch.setattr(record_sets_module, "load_index", fake_load)
    cache = RecordSetCache(max_bytes=2 * small.size)
    for number in range(3):
        await cache.get(sessions, test_org.id, uuid4(), number + 1)

    assert len(cache.entries) == 2, "the cap counts the bytes every index holds"


@pytest.mark.asyncio
async def test_concurrent_requests_share_one_load_and_one_failure(monkeypatch) -> None:
    calls: list[int] = []
    release = asyncio.Event()

    async def slow_load(_sessions, organization, loaded_set, revision):
        calls.append(revision)
        await release.wait()
        if len(calls) == 1:
            raise ConnectionError
        return RecordSetIndex.records(
            b"k" * 32, (RecordField("token", True),), array("Q", [1])
        )

    monkeypatch.setattr(record_sets_module, "load_index", slow_load)
    cache = RecordSetCache()
    org, set_id = uuid4(), uuid4()
    waiting = [
        asyncio.create_task(cache.get(nullcontext, org, set_id, 1)) for _ in range(5)
    ]
    await asyncio.sleep(0)
    release.set()
    failures = await asyncio.gather(*waiting, return_exceptions=True)
    retried = await cache.get(nullcontext, org, set_id, 1)

    assert calls == [1, 1], "one load for five waiters, then one retry"
    assert all(isinstance(failure, ConnectionError) for failure in failures)
    assert retried is not None and not cache.pending
