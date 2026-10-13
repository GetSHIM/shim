from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

import httpx
import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import FastAPI
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.compliance.models import ComplianceForwardTarget
from shim_enterprise.config_file.loader import ConfigLoader
from shim_enterprise.config_file.models import OrganizationConfigMode
from shim_enterprise.config_file.signing import key_id, sign
from shim_enterprise.core.database import get_db
from shim_enterprise.outbox.handlers import COMPLIANCE_DELIVERY, _compliance_text
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.policy.models import PolicyPlan, PolicyVersion
from shim_enterprise.rules.models import OrganizationRuleSet
from shim_enterprise.tenants.models import Organization, User

CONFIG = "/api/v1/management/config"
LATER = datetime(2099, 1, 1, tzinfo=timezone.utc)


async def tenant(db, *names: str) -> dict[str, User]:
    """`owner` and the named users: `admin…` admins, `service` an admin service account,
    `member` and `auditor` by role."""
    organization = Organization(
        id=uuid4(), name="Config", slug=f"config-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    users = {
        name: User(
            id=uuid4(),
            organization_id=organization.id,
            email=f"config-{uuid4().hex}@example.com",
            role=name if name in ("owner", "member", "auditor") else "admin",
            kind="service" if name == "service" else "human",
            is_active=True,
            is_verified=True,
        )
        for name in ("owner", *names)
    }
    db.add_all(users.values())
    await db.flush()
    return users


async def call(db, user: User, method: str, path: str, **kwargs) -> httpx.Response:
    connection = await db.connection()

    async def request_session():
        # Each request in its own savepoint, so a refused one rolls back as in production.
        async with AsyncSession(
            bind=connection,
            join_transaction_mode="create_savepoint",
            expire_on_commit=False,
        ) as session:
            yield session

    app = FastAPI()
    app.include_router(management_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = request_session
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.request(method, path, **kwargs)


def public_pem(key: Ed25519PrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


async def add_key(db, owner: User, holder: User | None = None) -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.generate()
    response = await call(
        db,
        owner,
        "POST",
        f"{CONFIG}/signing-keys",
        json={
            "public_key_pem": public_pem(key),
            "user_id": str((holder or owner).id),
            "name": "release",
        },
    )
    assert response.status_code == 201, response.text
    return key


async def file_mode(db, owner: User, *resources: str) -> Ed25519PrivateKey:
    key = await add_key(db, owner)
    response = await call(
        db,
        owner,
        "PUT",
        f"{CONFIG}/mode",
        json={"mode": "file", "resources": list(resources)},
    )
    assert response.status_code == 200, response.text
    return key


async def exported(db, user: User, **params) -> dict:
    response = await call(db, user, "GET", f"{CONFIG}/export", params=params)
    assert response.status_code == 200, response.text
    return yaml.load(response.text, Loader=ConfigLoader)  # noqa: S506


def dumped(document: dict) -> bytes:
    return yaml.safe_dump(document, sort_keys=False, allow_unicode=True).encode()


async def push(
    db,
    user: User,
    data: bytes,
    key: Ed25519PrivateKey | None,
    *,
    organization_id: UUID | None = None,
    route: str = "apply",
) -> httpx.Response:
    organization_id = organization_id or user.organization_id
    return await call(
        db,
        user,
        "POST",
        f"{CONFIG}/{route}",
        json={
            "file": data.decode(),
            "signature": sign(key, organization_id, data) if key else None,
        },
    )


def rule(rule_id: str, **values) -> dict:
    return {
        "id": rule_id,
        "name": "Projects",
        "kind": "term",
        "action": "mask",
        "state": "monitor",
        "match": {"terms": [f"Project {rule_id}"]},
        **values,
    }


async def stored_rule_ids(db, organization_id: UUID) -> list[str]:
    row = await db.get(OrganizationRuleSet, organization_id, populate_existing=True)
    return [stored["id"] for stored in row.rules] if row is not None else []


async def mode_row(db, organization_id: UUID) -> OrganizationConfigMode | None:
    return await db.get(OrganizationConfigMode, organization_id, populate_existing=True)


async def count(db, model, organization_id: UUID) -> int:
    return int(
        await db.scalar(
            select(func.count()).where(model.organization_id == organization_id)
        )
    )


@pytest.mark.asyncio
async def test_file_mode_needs_a_key_and_api_mode_no_resources(db) -> None:
    users = await tenant(db, "admin")
    owner = users["owner"]

    without_key = await call(
        db,
        owner,
        "PUT",
        f"{CONFIG}/mode",
        json={"mode": "file", "resources": ["rules"]},
    )
    await add_key(db, owner)
    empty = await call(
        db, owner, "PUT", f"{CONFIG}/mode", json={"mode": "file", "resources": []}
    )
    api_with = await call(
        db, owner, "PUT", f"{CONFIG}/mode", json={"mode": "api", "resources": ["rules"]}
    )
    unknown = await call(
        db,
        owner,
        "PUT",
        f"{CONFIG}/mode",
        json={"mode": "file", "resources": ["teams"]},
    )
    by_admin = await call(
        db,
        users["admin"],
        "PUT",
        f"{CONFIG}/mode",
        json={"mode": "file", "resources": ["rules"]},
    )
    on = await call(
        db,
        owner,
        "PUT",
        f"{CONFIG}/mode",
        json={"mode": "file", "resources": ["rules", "privacy"]},
    )
    read = await call(db, users["admin"], "GET", f"{CONFIG}/mode")

    assert (without_key.status_code, without_key.json()["detail"]["code"]) == (
        409,
        "CONFIG_NO_SIGNING_KEY",
    )
    assert (
        without_key.json()["detail"]["hint"] == "Register a public signing key first."
    )
    assert (empty.status_code, api_with.status_code, unknown.status_code) == (
        422,
        422,
        422,
    )
    assert by_admin.status_code == 403
    assert on.status_code == 200
    assert read.json() == {
        "mode": "file",
        "resources": ["privacy", "rules"],
        "last_serial": 0,
        "last_applied_at": None,
        "active_signing_keys": 1,
    }
    version = await db.scalar(
        select(PolicyVersion)
        .where(PolicyVersion.organization_id == owner.organization_id)
        .order_by(PolicyVersion.version.desc())
    )
    assert (version.source, version.risk, list(version.snapshot)) == (
        "api",
        "neutral",
        ["config_mode"],
    )


@pytest.mark.asyncio
async def test_signing_keys_are_checked_capped_alerted_and_revoked(db) -> None:
    users = await tenant(db, "service", "member", "auditor")
    owner = users["owner"]

    def body(key: Ed25519PrivateKey, holder: User) -> dict:
        return {
            "public_key_pem": public_pem(key),
            "user_id": str(holder.id),
            "name": "k",
        }

    rsa_like = await call(
        db,
        owner,
        "POST",
        f"{CONFIG}/signing-keys",
        json={"public_key_pem": "not a key", "user_id": str(owner.id), "name": "k"},
    )
    service = await call(
        db,
        owner,
        "POST",
        f"{CONFIG}/signing-keys",
        json=body(Ed25519PrivateKey.generate(), users["service"]),
    )
    member = await call(
        db,
        owner,
        "POST",
        f"{CONFIG}/signing-keys",
        json=body(Ed25519PrivateKey.generate(), users["member"]),
    )
    first = await add_key(db, owner)
    twice = await call(
        db, owner, "POST", f"{CONFIG}/signing-keys", json=body(first, owner)
    )
    for _ in range(9):
        await add_key(db, owner)
    eleventh = await call(
        db,
        owner,
        "POST",
        f"{CONFIG}/signing-keys",
        json=body(Ed25519PrivateKey.generate(), owner),
    )
    listed = await call(db, users["auditor"], "GET", f"{CONFIG}/signing-keys")
    alerts = list(
        await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == owner.organization_id,
                OutboxEvent.event_type == "audit.chain_append_requested",
            )
        )
    )

    assert (rsa_like.status_code, service.status_code, member.status_code) == (
        422,
        422,
        422,
    )
    assert (twice.status_code, twice.json()["detail"]["code"]) == (
        409,
        "SIGNING_KEY_EXISTS",
    )
    assert (eleventh.status_code, eleventh.json()["detail"]["code"]) == (
        409,
        "SIGNING_KEY_LIMIT",
    )
    assert len(listed.json()) == 10
    assert key_id(first.public_key()) in {item["key_id"] for item in listed.json()}
    added = [
        event.payload["extra"]
        for event in alerts
        if event.payload["endpoint"] == "tenant.config_signing_key_added"
    ]
    assert len(added) == 10
    assert set(added[0]) >= {"key_id", "user_id"}


@pytest.mark.asyncio
async def test_a_new_key_queues_a_tenant_alert(db) -> None:
    users = await tenant(db)
    owner = users["owner"]
    db.add(
        ComplianceForwardTarget(
            organization_id=owner.organization_id,
            kind="slack",
            endpoint_origin="https://hooks.slack.com",
            secret_ref="fernet:v2:config",
            secret_backend="fernet",
            secret_version="v2",
            enabled=True,
        )
    )
    await db.flush()

    key = await add_key(db, owner)

    [delivery] = await db.scalars(
        select(OutboxEvent).where(
            OutboxEvent.organization_id == owner.organization_id,
            OutboxEvent.event_type == COMPLIANCE_DELIVERY,
        )
    )
    body = delivery.payload["body"]
    assert {field: body[field] for field in ("kind", "key_id", "holder", "actor")} == {
        "kind": "config_signing_key_added",
        "key_id": key_id(key.public_key()),
        "holder": str(owner.id),
        "actor": str(owner.id),
    }
    assert _compliance_text(body).startswith(
        f"shim configuration signing key {key_id(key.public_key())} added"
    )


@pytest.mark.asyncio
async def test_revoking_keeps_the_last_key_in_file_mode_and_expires_its_plans(
    db,
) -> None:
    users = await tenant(db, "admin")
    owner = users["owner"]
    key = await file_mode(db, owner, "privacy")
    first_id = key_id(key.public_key())
    last = await call(db, owner, "DELETE", f"{CONFIG}/signing-keys/{first_id}")
    second = await add_key(db, owner)
    pending = PolicyPlan(
        organization_id=owner.organization_id,
        base_version=0,
        changes=[],
        risk="relaxing",
        status="pending_approval",
        source="file",
        context={"key_id": first_id},
        created_by=str(owner.id),
        created_by_actor_type="user_jwt",
        expires_at=LATER,
    )
    db.add(pending)
    await db.flush()

    revoked = await call(db, owner, "DELETE", f"{CONFIG}/signing-keys/{first_id}")
    again = await call(db, owner, "DELETE", f"{CONFIG}/signing-keys/{first_id}")
    await db.refresh(pending)

    assert (last.status_code, last.json()["detail"]["code"]) == (
        409,
        "CONFIG_LAST_SIGNING_KEY",
    )
    assert revoked.status_code == 200 and revoked.json()["revoked_by"] == str(owner.id)
    assert again.status_code == 404
    assert pending.status == "expired"
    assert (await call(db, owner, "GET", f"{CONFIG}/mode")).json()[
        "active_signing_keys"
    ] == 1
    assert second is not None


@pytest.mark.asyncio
async def test_export_gives_every_resource_in_api_mode_and_quotes_off(db) -> None:
    users = await tenant(db, "member")
    owner = users["owner"]

    response = await call(db, owner, "GET", f"{CONFIG}/export")
    document = yaml.load(response.text, Loader=ConfigLoader)  # noqa: S506
    member = await call(db, users["member"], "GET", f"{CONFIG}/export")

    assert response.headers["content-type"].startswith("application/yaml")
    assert "attachment" in response.headers["content-disposition"]
    assert "response_scan: 'off'" in response.text
    assert (document["format"], document["version"], document["serial"]) == (
        "shim.config",
        1,
        1,
    )
    assert document["organization_id"] == str(owner.organization_id)
    assert list(document["resources"]) == ["privacy", "gateway_settings", "rules"]
    assert document["resources"]["privacy"]["response_scan"] == "off"
    assert document["resources"]["gateway_settings"]["four_eyes"] == "off"
    assert document["resources"]["rules"] == []
    assert member.status_code == 403


@pytest.mark.asyncio
async def test_export_at_a_version_is_the_undo_path(db) -> None:
    users = await tenant(db)
    owner = users["owner"]
    key = await file_mode(db, owner, "rules")
    start = await exported(db, owner)
    start["resources"]["rules"] = [rule("atlas")]
    applied = await push(db, owner, dumped(start), key)
    version = applied.json()["policy_version"]
    later = await exported(db, owner)
    later.update(serial=3)
    later["resources"]["rules"] = [rule("atlas", action="block"), rule("borea")]
    assert (await push(db, owner, dumped(later), key)).status_code == 200

    back = await exported(db, owner, version=version)
    missing = await call(db, owner, "GET", f"{CONFIG}/export", params={"version": 999})
    assert [item["id"] for item in back["resources"]["rules"]] == ["atlas"]
    assert back["resources"]["rules"][0]["action"] == "mask"
    assert back["exported_from"] == {"policy_version": version}
    assert back["serial"] == 4
    assert missing.status_code == 404
    pushed = await push(db, owner, dumped(back), key)
    assert pushed.status_code == 200, pushed.text
    assert await stored_rule_ids(db, owner.organization_id) == ["atlas"]


@pytest.mark.asyncio
async def test_plan_stores_nothing_in_either_mode(db) -> None:
    users = await tenant(db, "member")
    owner = users["owner"]
    document = await exported(db, owner)
    document["resources"]["rules"] = [rule("atlas")]
    data = dumped(document)
    key = await add_key(db, owner)
    before = (
        await count(db, PolicyPlan, owner.organization_id),
        await count(db, PolicyVersion, owner.organization_id),
    )

    in_api = await push(db, owner, data, key, route="plan")
    unsigned = await push(db, owner, data, None, route="plan")
    forged = await call(
        db,
        owner,
        "POST",
        f"{CONFIG}/plan",
        json={"file": data.decode(), "signature": "0" * 32 + ".AAAA"},
    )
    as_member = await push(db, users["member"], data, key, route="plan")
    del document["resources"]["privacy"], document["resources"]["gateway_settings"]
    await file_mode(db, owner, "rules")
    after_mode = (
        await count(db, PolicyPlan, owner.organization_id),
        await count(db, PolicyVersion, owner.organization_id),
    )
    in_file = await push(db, owner, dumped(document), key, route="plan")

    assert in_api.status_code == 200, in_api.text
    body = in_api.json()
    assert (body["stored"], body["serial"], body["risk"]) == (False, 1, "neutral")
    assert [(c["resource"], c["item"], c["before"]) for c in body["changes"]] == [
        ("rules", "atlas", None)
    ]
    assert body["signature"] == {"valid": True, "key_id": key_id(key.public_key())}
    assert unsigned.json()["signature"] is None
    assert forged.json()["signature"] == {"valid": False, "key_id": None}
    assert as_member.status_code == 403
    assert in_file.status_code == 200 and len(in_file.json()["changes"]) == 1
    # The mode switch is the only write: plans store nothing in either mode.
    assert after_mode[0] == before[0]
    assert (
        await count(db, PolicyPlan, owner.organization_id),
        await count(db, PolicyVersion, owner.organization_id),
    ) == after_mode
    assert await stored_rule_ids(db, owner.organization_id) == []


@pytest.mark.asyncio
async def test_apply_refuses_in_api_mode_stale_serials_and_other_tenants(db) -> None:
    users = await tenant(db)
    owner = users["owner"]
    other = (await tenant(db))["owner"]
    key = await add_key(db, owner)
    document = await exported(db, owner)
    document["resources"] = {"rules": [rule("atlas")]}
    data = dumped(document)

    api_mode = await push(db, owner, data, key)
    await call(
        db,
        owner,
        "PUT",
        f"{CONFIG}/mode",
        json={"mode": "file", "resources": ["rules"]},
    )
    applied = await push(db, owner, data, key)
    stale = await push(db, owner, data, key)
    unsigned = await push(db, owner, data, None)
    foreign = {**document, "organization_id": str(other.organization_id), "serial": 5}
    for_other = await push(
        db, owner, dumped(foreign), key, organization_id=other.organization_id
    )
    signed_for_us = await push(db, owner, dumped(foreign), key)

    assert (api_mode.status_code, api_mode.json()["detail"]["code"]) == (
        409,
        "CONFIG_FILE_MODE_OFF",
    )
    assert applied.status_code == 200, applied.text
    assert (applied.json()["status"], applied.json()["serial"]) == ("applied", 1)
    assert applied.json()["plan"]["source"] == "file"
    assert set(applied.json()["plan"]["context"]) == {
        "serial",
        "key_id",
        "signer_user_id",
        "file_sha256",
    }
    assert (stale.status_code, stale.json()["detail"]) == (
        409,
        {
            "code": "CONFIG_SERIAL_STALE",
            "last_serial": 1,
            "message": "The file's serial is not above the last applied one.",
            "hint": "Raise serial above last_serial, sign the file and push it.",
        },
    )
    assert (unsigned.status_code, for_other.status_code) == (403, 403)
    assert (signed_for_us.status_code, signed_for_us.json()["detail"]["path"]) == (
        422,
        "organization_id",
    )
    version = await db.scalar(
        select(PolicyVersion)
        .where(PolicyVersion.organization_id == owner.organization_id)
        .order_by(PolicyVersion.version.desc())
    )
    assert version.source == "file"
    row = await mode_row(db, owner.organization_id)
    assert (
        row.last_serial,
        len(row.last_file_sha256),
        row.last_applied_at is not None,
    ) == (
        1,
        64,
        True,
    )


@pytest.mark.asyncio
async def test_an_unchanged_file_moves_only_the_serial_and_supersedes_older_plans(
    db,
) -> None:
    users = await tenant(db)
    owner = users["owner"]
    key = await file_mode(db, owner, "rules")
    waiting = PolicyPlan(
        organization_id=owner.organization_id,
        base_version=0,
        changes=[],
        risk="relaxing",
        status="pending_approval",
        source="file",
        context={},
        created_by=str(owner.id),
        created_by_actor_type="user_jwt",
        expires_at=LATER,
    )
    db.add(waiting)
    await db.flush()
    document = await exported(db, owner)

    response = await push(db, owner, dumped(document), key)
    await db.refresh(waiting)

    assert response.status_code == 200
    assert response.json() == {
        "status": "unchanged",
        "serial": 1,
        "plan": None,
        "policy_version": None,
    }
    assert waiting.status == "expired"
    assert (await mode_row(db, owner.organization_id)).last_serial == 1


@pytest.mark.asyncio
async def test_rules_missing_from_the_file_are_deleted_before_new_ones_are_made(
    db,
) -> None:
    users = await tenant(db)
    owner = users["owner"]
    key = await file_mode(db, owner, "rules")
    document = await exported(db, owner)
    document["resources"]["rules"] = [rule(f"r{index:03d}") for index in range(100)]
    assert (await push(db, owner, dumped(document), key)).status_code == 200

    # At the 100-rule limit: one rule leaves and another comes in the same file.
    document.update(serial=2)
    document["resources"]["rules"] = [rule(f"r{index:03d}") for index in range(1, 101)]
    swapped = await push(db, owner, dumped(document), key)

    assert swapped.status_code == 200, swapped.text
    assert [c["item"] for c in swapped.json()["plan"]["changes"]] == ["r000", "r100"]
    assert [c["after"] is None for c in swapped.json()["plan"]["changes"]] == [
        True,
        False,
    ]
    ids = await stored_rule_ids(db, owner.organization_id)
    assert (len(ids), "r000" in ids, "r100" in ids) == (100, False, True)


@pytest.mark.asyncio
async def test_a_refused_change_rolls_back_the_serial_too(db) -> None:
    users = await tenant(db)
    owner = users["owner"]
    key = await file_mode(db, owner, "rules")
    document = await exported(db, owner)
    document["resources"]["rules"] = [rule("atlas", state="enforced")]

    refused = await push(db, owner, dumped(document), key)

    assert (refused.status_code, refused.json()["detail"]["code"]) == (
        422,
        "RULE_MUST_START_IN_MONITOR",
    )
    assert (await mode_row(db, owner.organization_id)).last_serial == 0
    assert await stored_rule_ids(db, owner.organization_id) == []
    assert await count(db, PolicyPlan, owner.organization_id) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("change", "path"),
    [
        (
            {"rules": [{**rule("atlas"), "match": {}}]},
            "resources.rules[0].match",
        ),
        ({"rules": "atlas"}, "resources.rules"),
        ({"privacy": {"block_email": True}}, "resources.privacy.block_credit_card"),
        ({"privacy": "on"}, "resources.privacy"),
        (
            {"gateway_settings": {"no_such_switch": True}},
            "resources.gateway_settings.no_such_switch",
        ),
        ({"teams": []}, "resources.teams"),
    ],
)
async def test_section_errors_point_at_the_file(db, change, path) -> None:
    users = await tenant(db)
    owner = users["owner"]
    document = await exported(db, owner)
    document["resources"].update(change)
    if "privacy" in change and change["privacy"] != "on":
        document["resources"]["privacy"] = change["privacy"]

    response = await push(db, owner, dumped(document), None, route="plan")

    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert (detail["code"], detail["hint"]) == (
        "CONFIG_FILE_INVALID",
        "Fix the file at path and sign it again.",
    )
    assert detail["path"].startswith(path), detail


@pytest.mark.asyncio
async def test_a_file_with_an_anchor_is_invalid_and_a_missing_section_is_named(
    db,
) -> None:
    users = await tenant(db)
    owner = users["owner"]
    key = await file_mode(db, owner, "privacy", "rules")
    document = await exported(db, owner)
    anchored = dumped(document).replace(b"resources:", b"resources: &all", 1)
    missing = {**document, "resources": {"rules": []}}

    with_anchor = await push(db, owner, anchored, key)
    without_privacy = await push(db, owner, dumped(missing), key)

    assert (with_anchor.status_code, with_anchor.json()["detail"]["code"]) == (
        422,
        "CONFIG_FILE_INVALID",
    )
    assert without_privacy.json()["detail"]["path"] == "resources.privacy"
