from __future__ import annotations

import pytest

from ee.tests.config_file.test_config_api import (
    call,
    dumped,
    exported,
    file_mode,
    push,
    tenant,
)

MANAGEMENT = "/api/v1/management"


async def _waiting(db, users: dict, pusher_name: str) -> dict:
    """A relaxing privacy file signed by the owner and pushed by `pusher_name`."""
    owner = users["owner"]
    key = await file_mode(db, owner, "privacy")
    four_eyes = await call(
        db,
        owner,
        "PATCH",
        f"{MANAGEMENT}/gateway-settings",
        json={"four_eyes": "relaxing"},
    )
    assert four_eyes.status_code == 200, four_eyes.text
    document = await exported(db, owner)
    document["resources"]["privacy"]["entity_actions"] = {"EMAIL_ADDRESS": "monitor"}
    response = await push(
        db,
        users[pusher_name],
        dumped(document),
        key,
        organization_id=owner.organization_id,
    )
    assert response.status_code == 202, response.text
    assert response.json()["status"] == "pending_approval"
    return response.json()["plan"]


async def _approve(db, user, plan: dict):
    return await call(
        db, user, "POST", f"{MANAGEMENT}/policy/plans/{plan['id']}/approve", json={}
    )


@pytest.mark.asyncio
async def test_a_loosening_file_waits_and_its_signer_cannot_approve(db) -> None:
    users = await tenant(db, "admin", "service")
    plan = await _waiting(db, users, "service")

    by_signer = await _approve(db, users["owner"], plan)
    by_pusher = await _approve(db, users["service"], plan)
    by_admin = await _approve(db, users["admin"], plan)
    privacy = await call(db, users["admin"], "GET", f"{MANAGEMENT}/settings/pii")

    assert plan["context"]["signer_user_id"] == str(users["owner"].id)
    assert (by_signer.status_code, by_signer.json()["detail"]) == (
        403,
        {"code": "APPROVER_NOT_ELIGIBLE"},
    )
    assert (by_pusher.status_code, by_pusher.json()["detail"]) == (
        403,
        {"code": "APPROVER_NOT_ELIGIBLE"},
    )
    assert by_admin.status_code == 200, by_admin.text
    assert by_admin.json()["status"] == "applied"
    assert privacy.json()["effective_actions"]["EMAIL_ADDRESS"] == "monitor"


@pytest.mark.asyncio
async def test_a_human_pusher_cannot_approve_either(db) -> None:
    users = await tenant(db, "admin", "admin2")
    plan = await _waiting(db, users, "admin")

    by_pusher = await _approve(db, users["admin"], plan)
    by_other = await _approve(db, users["admin2"], plan)

    assert by_pusher.status_code == 403
    assert by_other.status_code == 200, by_other.text


@pytest.mark.asyncio
async def test_a_tightening_file_applies_at_once_under_four_eyes(db) -> None:
    users = await tenant(db, "admin")
    owner = users["owner"]
    key = await file_mode(db, owner, "privacy")
    await call(
        db,
        owner,
        "PATCH",
        f"{MANAGEMENT}/gateway-settings",
        json={"four_eyes": "relaxing"},
    )
    document = await exported(db, owner)
    document["resources"]["privacy"]["entity_actions"] = {"EMAIL_ADDRESS": "block"}

    response = await push(db, owner, dumped(document), key)

    assert response.status_code == 200, response.text
    assert response.json()["plan"]["risk"] == "tightening"
