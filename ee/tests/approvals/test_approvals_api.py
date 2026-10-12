from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.approvals.models import RequestApproval
from shim_enterprise.core.database import get_db
from shim_enterprise.observability.enterprise_metrics import (
    REQUEST_APPROVAL_DECISIONS_TOTAL,
)
from shim_enterprise.rules.models import OrganizationRuleSet
from shim_enterprise.archive.models import RequestArchive
from shim_enterprise.tenants.models import (
    ApiKey,
    Organization,
    ServiceAccountCredential,
    Team,
    User,
)


async def _tenant(db) -> dict:
    organization = Organization(
        id=uuid4(), name="Approvals", slug=f"apr-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    users = {
        name: User(
            id=uuid4(),
            organization_id=organization.id,
            email=f"apr-{name}-{uuid4().hex}@example.com",
            role=role,
            kind=kind,
            is_active=True,
            is_verified=True,
        )
        for name, role, kind in (
            ("owner", "owner", "human"),
            ("admin", "admin", "human"),
            ("key_owner", "admin", "human"),
            ("member", "member", "human"),
            ("auditor", "auditor", "human"),
            ("service", "admin", "service"),
        )
    }
    team = Team(id=uuid4(), organization_id=organization.id, name="risk")
    db.add_all([*users.values(), team])
    await db.flush()
    key = ApiKey(
        id=uuid4(),
        organization_id=organization.id,
        user_id=users["key_owner"].id,
        key_hash=uuid4().hex,
        prefix="sk-shim-apr",
        name="ledger app",
        tier="enterprise",
        is_active=True,
    )
    db.add(key)
    db.add(
        OrganizationRuleSet(
            organization_id=organization.id,
            revision=1,
            rules=[{"id": "kasa", "name": "Kasa terms"}],
        )
    )
    await db.flush()
    return {"organization": organization, "key": key, "team": team, **users}


def _approval(tenant: dict, **values) -> RequestApproval:
    return RequestApproval(
        **{
            "expires_at": datetime.now(timezone.utc) + timedelta(hours=24),
            "api_key_id": tenant["key"].id,
            "requested_by": tenant["key_owner"].id,
            **values,
        },
        id=uuid4(),
        organization_id=tenant["organization"].id,
        team_id=tenant["team"].id,
        request_digest=uuid4().hex * 2,
        request_id=f"req_apr_{uuid4().hex}",
        protocol="chat",
        provider="openai",
        model="gpt-5.6-luna",
        stream=False,
        rule_ids=["gone", "kasa"],
        detected={"entities": {"PERSON": 1}, "rules": {"kasa": 2}},
        input_bytes=120,
        estimated_input_tokens=30,
    )


async def _call(
    db, user: User, method: str, path: str, json: dict | None = None, **params
) -> httpx.Response:
    await db.flush()
    app = FastAPI()
    app.include_router(management_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = lambda: db
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.request(
            method, f"/api/v1/management/approvals{path}", params=params, json=json
        )


@pytest.mark.asyncio
async def test_the_detail_names_rule_key_requester_and_team_and_never_content(
    db,
) -> None:
    tenant = await _tenant(db)
    row = _approval(tenant)
    db.add(row)

    response = await _call(db, tenant["auditor"], "GET", f"/{row.id}")

    body = response.json()
    assert response.status_code == 200
    assert body["rules"] == [
        {"id": "gone", "name": None},
        {"id": "kasa", "name": "Kasa terms"},
    ]
    assert body["api_key"] == {
        "id": str(tenant["key"].id),
        "name": "ledger app",
        "prefix": "sk-shim-apr",
    }
    assert body["requested_by"] == {
        "user_id": str(tenant["key_owner"].id),
        "email": tenant["key_owner"].email,
    }
    assert body["team"] == {"id": str(tenant["team"].id), "name": "risk"}
    assert (body["status"], body["input_bytes"], body["estimated_input_tokens"]) == (
        "pending",
        120,
        30,
    )
    assert body["detected"] == {"entities": {"PERSON": 1}, "rules": {"kasa": 2}}
    assert (body["content"], body["content_note"]) == (None, "content is not stored")


@pytest.mark.asyncio
async def test_the_list_is_newest_first_filtered_limited_and_expires_lazily(
    db,
) -> None:
    tenant = await _tenant(db)
    now = datetime.now(timezone.utc)
    rows = [
        _approval(tenant, created_at=now - timedelta(minutes=minutes))
        for minutes in (30, 20, 10)
    ]
    late = _approval(
        tenant,
        created_at=now - timedelta(hours=25),
        expires_at=now - timedelta(hours=1),
    )
    db.add_all([*rows, late])

    everything = await _call(db, tenant["admin"], "GET", "")
    limited = await _call(db, tenant["admin"], "GET", "", limit=2)
    before = await _call(
        db, tenant["admin"], "GET", "", before=(now - timedelta(minutes=15)).isoformat()
    )
    expired = await _call(db, tenant["admin"], "GET", "", status="expired")
    bad = await _call(db, tenant["admin"], "GET", "", limit=101)

    ids = [item["id"] for item in everything.json()["items"]]
    assert ids == [str(row.id) for row in reversed(rows)] + [str(late.id)]
    assert len(limited.json()["items"]) == 2
    assert [item["id"] for item in before.json()["items"]] == [
        str(rows[1].id),
        str(rows[0].id),
        str(late.id),
    ]
    assert [item["id"] for item in expired.json()["items"]] == [str(late.id)]
    assert bad.status_code == 422


@pytest.mark.asyncio
async def test_approve_and_reject_decide_once_with_audit_and_metrics(
    db, audit_events
) -> None:
    tenant = await _tenant(db)
    approved, rejected = _approval(tenant), _approval(tenant)
    db.add_all([approved, rejected])
    counted = REQUEST_APPROVAL_DECISIONS_TOTAL.labels(decision="approved")._value.get()

    yes = await _call(db, tenant["admin"], "POST", f"/{approved.id}/approve")
    no = await _call(db, tenant["owner"], "POST", f"/{rejected.id}/reject")

    assert yes.status_code == 200 and no.status_code == 200
    assert yes.json()["status"] == "approved"
    assert yes.json()["decided_by"] == str(tenant["admin"].id)
    use_by = datetime.fromisoformat(yes.json()["use_by"])
    decided = datetime.fromisoformat(yes.json()["decided_at"])
    assert use_by - decided == timedelta(minutes=60)
    assert (no.json()["status"], no.json()["use_by"]) == ("rejected", None)
    assert (
        REQUEST_APPROVAL_DECISIONS_TOTAL.labels(decision="approved")._value.get()
        == counted + 1
    )
    events = await audit_events(tenant["organization"].id)
    decisions = [
        (event["endpoint"], event["actor"], event["extra"])
        for event in events
        if event["endpoint"].startswith("tenant.request_approval_")
    ]
    common = {
        "rule_ids": ["gone", "kasa"],
        "api_key_id": str(tenant["key"].id),
        "model": "gpt-5.6-luna",
        "actor_type": "user_jwt",
    }
    assert decisions == [
        (
            "tenant.request_approval_approved",
            str(tenant["admin"].id),
            {
                "subject_id": str(approved.id),
                **common,
                "request_id": approved.request_id,
            },
        ),
        (
            "tenant.request_approval_rejected",
            str(tenant["owner"].id),
            {
                "subject_id": str(rejected.id),
                **common,
                "request_id": rejected.request_id,
            },
        ),
    ]


@pytest.mark.parametrize(
    "values",
    [
        {"status": "approved"},
        {"status": "rejected"},
        {"status": "used"},
        {"expires_at": datetime(2026, 1, 1, tzinfo=timezone.utc)},
    ],
)
@pytest.mark.asyncio
async def test_only_a_pending_unexpired_approval_can_be_decided(db, values) -> None:
    tenant = await _tenant(db)
    row = _approval(tenant, **values)
    db.add(row)

    response = await _call(db, tenant["admin"], "POST", f"/{row.id}/approve")

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "APPROVAL_STATE_CONFLICT"
    assert response.json()["detail"]["status"] == values.get("status", "expired")
    assert "hint" in response.json()["detail"]


@pytest.mark.asyncio
async def test_who_may_decide_and_read(db) -> None:
    tenant = await _tenant(db)
    other = await _tenant(db)
    row = _approval(tenant)
    db.add(row)

    outcomes = {
        name: (await _call(db, tenant[name], "POST", f"/{row.id}/approve"))
        for name in ("key_owner", "service", "member", "auditor")
    }
    auditor_reads = await _call(db, tenant["auditor"], "GET", "")
    member_reads = await _call(db, tenant["member"], "GET", "")
    foreign = await _call(db, other["owner"], "GET", f"/{row.id}")
    foreign_decision = await _call(db, other["owner"], "POST", f"/{row.id}/reject")

    for name in ("key_owner", "service"):
        assert outcomes[name].status_code == 403
        assert outcomes[name].json()["detail"]["code"] == "APPROVER_NOT_ELIGIBLE"
    assert outcomes["member"].status_code == 403
    assert outcomes["auditor"].status_code == 403
    assert auditor_reads.status_code == 200
    assert member_reads.status_code == 403
    assert foreign.status_code == foreign_decision.status_code == 404
    assert (
        await db.scalar(
            select(RequestApproval.status).where(RequestApproval.id == row.id)
        )
        == "pending"
    )


async def _service_key(db, tenant: dict, created_by: User) -> ApiKey:
    """A gateway key the service account owns; `created_by` made its credential."""
    db.add(
        ServiceAccountCredential(
            organization_id=tenant["organization"].id,
            user_id=tenant["service"].id,
            key_hash=uuid4().hex,
            prefix="sk-shim-sa",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            created_by=created_by.id,
        )
    )
    key = ApiKey(
        id=uuid4(),
        organization_id=tenant["organization"].id,
        user_id=tenant["service"].id,
        key_hash=uuid4().hex,
        prefix="sk-shim-sak",
        tier="enterprise",
        is_active=True,
    )
    db.add(key)
    await db.flush()
    return key


@pytest.mark.asyncio
async def test_no_one_decides_for_a_service_account_key_they_hold(db) -> None:
    tenant = await _tenant(db)
    key = await _service_key(db, tenant, created_by=tenant["admin"])
    row = _approval(tenant, api_key_id=key.id, requested_by=tenant["service"].id)
    db.add(row)

    holder = await _call(db, tenant["admin"], "POST", f"/{row.id}/approve")
    other = await _call(db, tenant["owner"], "POST", f"/{row.id}/approve")

    assert holder.status_code == 403
    assert holder.json()["detail"]["code"] == "APPROVER_NOT_ELIGIBLE"
    assert other.status_code == 200


@pytest.mark.asyncio
async def test_without_a_recorded_requester_the_key_owner_still_cannot_decide(
    db,
) -> None:
    tenant = await _tenant(db)
    row = _approval(tenant, requested_by=None)
    db.add(row)

    owner_of_key = await _call(db, tenant["key_owner"], "POST", f"/{row.id}/approve")
    other = await _call(db, tenant["admin"], "POST", f"/{row.id}/approve")

    assert owner_of_key.status_code == 403
    assert other.status_code == 200


@pytest.mark.asyncio
async def test_a_decided_or_expired_row_keeps_no_digest(db) -> None:
    tenant = await _tenant(db)
    rejected, expired, approved = (
        _approval(tenant),
        _approval(tenant, expires_at=datetime(2026, 1, 1, tzinfo=timezone.utc)),
        _approval(tenant),
    )
    db.add_all([rejected, expired, approved])

    await _call(db, tenant["admin"], "POST", f"/{rejected.id}/reject")
    await _call(db, tenant["admin"], "POST", f"/{approved.id}/approve")
    await _call(db, tenant["admin"], "GET", "")

    digests = dict(
        (
            await db.execute(
                select(RequestApproval.id, RequestApproval.request_digest).where(
                    RequestApproval.organization_id == tenant["organization"].id
                )
            )
        ).all()
    )
    assert digests[rejected.id] is None and digests[expired.id] is None
    # An approved row is still matched against the request sent again.
    assert digests[approved.id] is not None


@pytest.mark.asyncio
async def test_a_key_s_pending_requests_are_rejected_at_once(db, audit_events) -> None:
    tenant = await _tenant(db)
    other_key = await _service_key(db, tenant, created_by=tenant["owner"])
    mine = [_approval(tenant) for _ in range(3)]
    done = _approval(tenant, status="used")
    elsewhere = _approval(tenant, api_key_id=other_key.id)
    db.add_all([*mine, done, elsewhere])
    body = {"api_key_id": str(tenant["key"].id)}

    refused = await _call(db, tenant["key_owner"], "POST", "/reject", json=body)
    rejected = await _call(db, tenant["admin"], "POST", "/reject", json=body)

    assert refused.status_code == 403
    assert rejected.status_code == 200, rejected.text
    assert rejected.json() == {"rejected": 3}
    statuses = dict(
        (
            await db.execute(
                select(RequestApproval.id, RequestApproval.status).where(
                    RequestApproval.organization_id == tenant["organization"].id
                )
            )
        ).all()
    )
    assert {statuses[row.id] for row in mine} == {"rejected"}
    assert (statuses[done.id], statuses[elsewhere.id]) == ("used", "pending")
    events = [
        event["extra"]
        for event in await audit_events(tenant["organization"].id)
        if event["endpoint"] == "tenant.request_approvals_rejected"
    ]
    assert events == [
        {
            "subject_id": str(tenant["key"].id),
            "rejected": 3,
            "actor_type": "user_jwt",
        }
    ]


@pytest.mark.asyncio
async def test_the_note_says_when_the_request_archive_holds_the_content(db) -> None:
    tenant = await _tenant(db)
    archived, plain = _approval(tenant), _approval(tenant)
    db.add_all([archived, plain])
    db.add(
        RequestArchive(
            organization_id=tenant["organization"].id,
            request_id=archived.request_id,
            api_key_id=tenant["key"].id,
            protocol="chat",
            model="gpt-5.6-luna",
            matched=[],
            masked_payload=b"x",
            edit_map=b"x",
            size_bytes=1,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
    )

    notes = {
        item["id"]: (item["content"], item["content_note"])
        for item in (await _call(db, tenant["admin"], "GET", "")).json()["items"]
    }

    assert notes[str(archived.id)] == (None, "content is in the request archive")
    assert notes[str(plain.id)] == (None, "content is not stored")
