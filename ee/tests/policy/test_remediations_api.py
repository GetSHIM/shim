from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from ee.tests.policy.test_recommender_apply import _audits, _call
from ee.tests.policy.test_remediation import (
    _approved_origin,  # noqa: F401  (autouse fixture)
    _deployment_enabled,
    _rows,
    _tenant,
    _versions,
    _watched,
)
from shim_enterprise.policy import remediation
from shim_enterprise.policy.models import PolicyRemediation
from shim_enterprise.tenants.models import OrganizationGatewaySettings, User

REMEDIATIONS = "/api/v1/management/remediations"


async def _people(db, tenant: UUID) -> dict[str, User]:
    users = {
        name: User(
            id=uuid4(),
            organization_id=tenant,
            email=f"fix-{uuid4().hex}@example.com",
            role=role,
            kind=kind,
            is_active=True,
            is_verified=True,
        )
        for name, role, kind in (
            ("owner", "owner", "human"),
            ("admin", "admin", "human"),
            ("auditor", "auditor", "human"),
            ("member", "member", "human"),
            ("service", "admin", "service"),
        )
    }
    db.add_all(users.values())
    await db.flush()
    return users


@pytest.mark.asyncio
async def test_the_list_is_newest_first_and_needs_findings_or_audit_reads(db) -> None:
    tenant = await _tenant(db)
    people = await _people(db, tenant)
    now = datetime.now(timezone.utc)
    rows = [
        PolicyRemediation(
            organization_id=tenant,
            actor_type="system",
            items=[],
            status=status,
            created_at=now - timedelta(minutes=minutes),
        )
        for status, minutes in (("kept", 3), ("skipped", 2), ("kept", 1))
    ]
    db.add_all(rows)
    other = await _tenant(db)
    db.add(
        PolicyRemediation(
            organization_id=other, actor_type="system", items=[], status="kept"
        )
    )
    await db.flush()

    listed = await _call(db, people["auditor"], "GET", REMEDIATIONS)
    kept = await _call(
        db, people["owner"], "GET", REMEDIATIONS, params={"status": "kept", "limit": 1}
    )
    older = await _call(
        db,
        people["owner"],
        "GET",
        REMEDIATIONS,
        params={"before": rows[1].created_at.isoformat()},
    )
    one = await _call(db, people["auditor"], "GET", f"{REMEDIATIONS}/{rows[0].id}")
    foreign = await _call(db, people["owner"], "GET", f"{REMEDIATIONS}/{uuid4()}")
    refused = await _call(db, people["member"], "GET", REMEDIATIONS)
    naive = await _call(
        db, people["owner"], "GET", REMEDIATIONS, params={"before": "2026-10-13T00:00"}
    )

    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [
        str(row.id) for row in reversed(rows)
    ]
    assert [item["id"] for item in kept.json()] == [str(rows[2].id)]
    assert [item["id"] for item in older.json()] == [str(rows[0].id)]
    assert (one.status_code, one.json()["status"]) == (200, "kept")
    assert foreign.status_code == 404
    assert refused.status_code == 403
    assert naive.status_code == 422


@pytest.mark.parametrize("status", ["watching", "kept"])
@pytest.mark.asyncio
async def test_a_person_undoes_an_automatic_change(db, status) -> None:
    tenant = await _tenant(db)
    people = await _people(db, tenant)
    row = await _watched(db, tenant)
    row.status = status
    await db.flush()

    undone = await _call(
        db,
        people["owner"],
        "POST",
        f"{REMEDIATIONS}/{row.id}/undo",
        json={"reason": "we still need it"},
    )
    again = await _call(
        db, people["owner"], "POST", f"{REMEDIATIONS}/{row.id}/undo", json={}
    )

    [after] = await _rows(db, tenant)
    versions = await _versions(db, tenant)
    assert undone.status_code == 200, undone.text
    assert (undone.json()["status"], undone.json()["restored_version"]) == (
        "undone",
        versions[-1].version,
    )
    assert (versions[-1].source, versions[-1].actor_type) == ("restore", "user_jwt")
    assert await _deployment_enabled(db, after) is True
    assert (again.status_code, again.json()["detail"]) == (
        409,
        {"code": "REMEDIATION_STATE_CONFLICT", "status": "undone"},
    )
    [audit] = await _audits(db, tenant, "tenant.remediation_undone")
    assert audit["actor_type"] == "user_jwt"


@pytest.mark.asyncio
async def test_undo_is_refused_for_a_service_account_and_a_closed_row(db) -> None:
    tenant = await _tenant(db)
    people = await _people(db, tenant)
    row = await _watched(db, tenant)

    by_service = await _call(
        db, people["service"], "POST", f"{REMEDIATIONS}/{row.id}/undo", json={}
    )
    by_auditor = await _call(
        db, people["auditor"], "POST", f"{REMEDIATIONS}/{row.id}/undo", json={}
    )
    row.status = "restored"
    await db.flush()
    restored = await _call(
        db, people["owner"], "POST", f"{REMEDIATIONS}/{row.id}/undo", json={}
    )

    assert (by_service.status_code, by_service.json()["detail"]["code"]) == (
        403,
        "UNDO_NEEDS_HUMAN",
    )
    assert by_auditor.status_code == 403
    assert (restored.status_code, restored.json()["detail"]["code"]) == (
        409,
        "REMEDIATION_STATE_CONFLICT",
    )
    assert len(await _versions(db, tenant)) == 1


@pytest.mark.asyncio
async def test_under_four_eyes_an_undo_waits_for_a_second_approver(db) -> None:
    tenant = await _tenant(db)
    people = await _people(db, tenant)
    row = await _watched(db, tenant)
    gateway = await db.get(OrganizationGatewaySettings, tenant)
    assert gateway is not None
    gateway.settings = {**gateway.settings, "four_eyes": "relaxing"}
    await db.flush()

    held = await _call(
        db, people["owner"], "POST", f"{REMEDIATIONS}/{row.id}/undo", json={}
    )

    [after] = await _rows(db, tenant)
    assert held.status_code == 202, held.text
    assert (held.json()["status"], held.json()["restore_plan_id"]) == (
        "watching",
        str(after.restore_plan_id),
    )
    assert await _deployment_enabled(db, after) is False
    assert len(await _versions(db, tenant)) == 1

    approved = await _call(
        db,
        people["admin"],
        "POST",
        f"/api/v1/management/policy/plans/{after.restore_plan_id}/approve",
        json={},
    )

    [undone] = await _rows(db, tenant)
    versions = await _versions(db, tenant)
    assert approved.status_code == 200, approved.text
    assert (undone.status, undone.restored_version) == (
        "undone",
        versions[-1].version,
    )
    assert await _deployment_enabled(db, undone) is True
    [audit] = await _audits(db, tenant, "tenant.remediation_undone")
    assert audit["actor_type"] == "user_jwt"


@pytest.mark.asyncio
async def test_an_undo_plans_before_the_tenant_lock(
    db, monkeypatch, tenant_lock
) -> None:
    tenant = await _tenant(db)
    people = await _people(db, tenant)
    row = await _watched(db, tenant)
    locked: list[bool] = []
    planned = remediation._restore_changes

    async def restore_changes(*args, **kwargs):
        locked.append(tenant_lock())
        return await planned(*args, **kwargs)

    monkeypatch.setattr(remediation, "_restore_changes", restore_changes)

    undone = await _call(
        db, people["owner"], "POST", f"{REMEDIATIONS}/{row.id}/undo", json={}
    )

    assert undone.status_code == 200, undone.text
    assert locked == [False]
