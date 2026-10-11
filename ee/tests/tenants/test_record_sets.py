from __future__ import annotations

import base64
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


def _customers(name: str = "customers") -> management.RecordSetCreate:
    return management.RecordSetCreate(
        name=name,
        kind="records",
        fields=[
            management.RecordSetFieldSpec(
                name="Müşteri No", kind="token", primary=True
            ),
            management.RecordSetFieldSpec(name="Ad Soyad", kind="name"),
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
    revision = (await management.open_record_set_revision(set_id, admin, db))[
        "revision"
    ]
    await management.put_record_set_chunk(
        set_id,
        revision,
        0,
        management.RecordSetChunkPut(
            records=[
                _row(key, number, _NAMES[number % len(_NAMES)])
                for number in range(count)
            ]
        ),
        admin,
        db,
    )
    await management.activate_record_set_revision(
        set_id, revision, _request(), admin, db
    )
    return revision


@pytest.mark.asyncio
async def test_a_set_shows_its_key_once_and_only_metadata_after(db, test_org) -> None:
    admin = await _admin(db, test_org.id)

    created = await management.create_record_set(_customers(), _request(), admin, db)
    listed = await management.list_record_sets(admin, db)
    read = await management.get_record_set(UUID(str(created["id"])), admin, db)

    assert len(base64.urlsafe_b64decode(created["hash_key"])) == 32
    assert [row.id for row in listed] == [created["id"]]
    assert "hash_key" not in management.RecordSetView.model_validate(read).model_dump()
    assert created["fields"][0] == {
        "name": "Müşteri No",
        "kind": "token",
        "primary": True,
    }


@pytest.mark.asyncio
async def test_an_organization_holds_ten_sets(db, test_org) -> None:
    admin = await _admin(db, test_org.id)
    for number in range(10):
        await management.create_record_set(
            _customers(f"set-{number}"), _request(), admin, db
        )

    with pytest.raises(HTTPException) as refused:
        await management.create_record_set(_customers("set-10"), _request(), admin, db)

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
        management.RecordSetCreate.model_validate(payload)


@pytest.mark.asyncio
async def test_chunk_limits_hold_at_their_bound(db, test_org) -> None:
    admin = await _admin(db, test_org.id)
    created = await management.create_record_set(_customers(), _request(), admin, db)
    set_id, key = created["id"], base64.urlsafe_b64decode(created["hash_key"])
    revision = (await management.open_record_set_revision(set_id, admin, db))[
        "revision"
    ]

    async def put(index: int, records: list[list[str]]):
        return await management.put_record_set_chunk(
            set_id,
            revision,
            index,
            management.RecordSetChunkPut(records=records),
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
    created = await management.create_record_set(_customers(), _request(), admin, db)
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
    rolled = await management.activate_record_set_revision(
        set_id, second, _request(), admin, db
    )
    with pytest.raises(HTTPException) as sealed:
        await management.put_record_set_chunk(
            set_id,
            third,
            1,
            management.RecordSetChunkPut(records=[_row(key, 9, "Ad")]),
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
async def test_a_set_in_use_cannot_be_deleted(db, test_org, audit_events) -> None:
    admin = await _admin(db, test_org.id)
    created = await management.create_record_set(_customers(), _request(), admin, db)
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
        await management.delete_record_set(set_id, _request(), admin, db)
    rule_set = await db.get(OrganizationRuleSet, test_org.id)
    rule_set.rules = []
    await db.flush()
    await management.delete_record_set(set_id, _request(), admin, db)

    assert (in_use.value.status_code, in_use.value.detail["code"]) == (
        409,
        "RECORD_SET_IN_USE",
    )
    assert await management.list_record_sets(admin, db) == []
    assert "tenant.record_set_deleted" in {
        event["endpoint"] for event in await audit_events(test_org.id)
    }


@pytest.mark.asyncio
async def test_a_record_set_rule_needs_an_active_set_of_its_kind(db, test_org) -> None:
    admin = await _admin(db, test_org.id)
    records = await management.create_record_set(_customers(), _request(), admin, db)
    prints = await management.create_record_set(
        management.RecordSetCreate(name="docs", kind="fingerprints"),
        _request(),
        admin,
        db,
    )
    await _activate(
        db, admin, records["id"], base64.urlsafe_b64decode(records["hash_key"]), 2
    )

    async def put(match: dict, action: str = "block") -> int:
        current = await management.get_rules(admin, db)
        try:
            await management.replace_rules(
                management.RuleSetPut(
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
    assert await put({"set_id": str(uuid4())}) == 422
    assert await put({"set_id": str(prints["id"])}) == 422, "not activated"
    assert await put({"set_id": str(records["id"]), "min_shared": 6}) == 422
    revision = (await management.open_record_set_revision(prints["id"], admin, db))[
        "revision"
    ]
    await management.put_record_set_chunk(
        prints["id"],
        revision,
        0,
        management.RecordSetChunkPut(
            documents=[[f"{value:016x}" for value in range(1, 9)]]
        ),
        admin,
        db,
    )
    await management.activate_record_set_revision(
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
    created = await management.create_record_set(_customers(), _request(), admin, db)
    set_id, key = created["id"], base64.urlsafe_b64decode(created["hash_key"])
    revision = await _activate(db, admin, set_id, key, 4)

    index = await load_index(db, test_org.id, set_id, revision)

    assert index is not None
    assert index.match_records("MUS000002 numaralı ÇAĞRI ÖZTÜRK", 2)[0] == {2}
    assert index.match_records("MUS000002 numaralı Şule Ünal", 2)[0] == set()
    assert await load_index(db, test_org.id, set_id, revision + 5) is None, "no chunks"
    assert await load_index(db, uuid4(), set_id, revision) is None, "another tenant"

    small = RecordSetIndex.records(key, (RecordField("token", True),), [[1], [2]])

    async def fake_load(_session, organization, loaded_set, loaded_revision):
        return small

    monkeypatch.setattr(record_sets_module, "load_index", fake_load)
    cache = RecordSetCache(max_hashes=4)
    for number in range(3):
        await cache.get(db, test_org.id, uuid4(), number + 1)

    assert len(cache.entries) == 2, "two sets of two hashes fit in four"
