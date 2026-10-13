from __future__ import annotations

import pytest
from fastapi import HTTPException

from ee.tests.config_file.test_config_api import (
    CONFIG,
    call,
    dumped,
    exported,
    file_mode,
    push,
    rule,
    stored_rule_ids,
    tenant,
)
from shim_enterprise.policy.api import new_plan
from shim_enterprise.policy.plans import refuse_file_managed

MANAGEMENT = "/api/v1/management"
HINT = "Change the file, sign it and push it; or switch the tenant back to api mode."


def _managed(response, resource: str) -> bool:
    detail = response.json()["detail"]
    return (
        response.status_code == 409
        and detail["code"] == "CONFIG_FILE_MANAGED"
        and detail["resource"] == resource
        and detail["hint"] == HINT
    )


@pytest.mark.asyncio
async def test_api_writes_to_file_managed_resources_answer_409(db) -> None:
    users = await tenant(db, "admin")
    owner, admin = users["owner"], users["admin"]
    await file_mode(db, owner, "privacy", "rules")

    rules = await call(
        db,
        admin,
        "PUT",
        f"{MANAGEMENT}/rules",
        json={"revision": 0, "rules": [rule("atlas")]},
    )
    privacy = await call(
        db, admin, "PUT", f"{MANAGEMENT}/settings/pii", json={"block_email": False}
    )
    unchanged = await call(db, admin, "PUT", f"{MANAGEMENT}/settings/pii", json={})
    gateway = await call(
        db,
        admin,
        "PATCH",
        f"{MANAGEMENT}/gateway-settings",
        json={"response_analysis": ["shape"]},
    )
    read = await call(db, admin, "GET", f"{MANAGEMENT}/settings/pii")

    assert _managed(rules, "rules")
    assert _managed(privacy, "privacy") and _managed(unchanged, "privacy")
    assert privacy.json()["detail"]["message"] == (
        "This tenant manages privacy from a signed configuration file."
    )
    # Outside the file's subset the panel and the API work as before; reads are open.
    assert gateway.status_code == 200, gateway.text
    assert read.status_code == 200
    assert await stored_rule_ids(db, owner.organization_id) == []


@pytest.mark.asyncio
async def test_plans_of_every_other_source_are_refused(db) -> None:
    users = await tenant(db, "admin")
    owner, admin = users["owner"], users["admin"]
    early = await call(
        db,
        admin,
        "POST",
        f"{MANAGEMENT}/policy/plans",
        json={
            "changes": [
                {"resource": "privacy", "item": "_", "set": {"block_email": False}}
            ]
        },
    )
    assert early.status_code == 201, early.text
    await file_mode(db, owner, "privacy")

    planned = await call(
        db,
        admin,
        "POST",
        f"{MANAGEMENT}/policy/plans",
        json={
            "changes": [
                {"resource": "privacy", "item": "_", "set": {"block_phone": False}}
            ]
        },
    )
    stale_plan = await call(
        db, admin, "POST", f"{MANAGEMENT}/policy/plans/{early.json()['id']}/apply"
    )
    change = [
        {
            "resource": "privacy",
            "item": "_",
            "before": {},
            "after": {},
            "risk": "neutral",
        }
    ]
    refused = []
    for source in ("api", "import"):
        with pytest.raises(HTTPException) as error:
            await new_plan(
                db, admin, owner.organization_id, change, source=source, reason=None
            )
        refused.append(error.value.detail["code"])
    for source in ("mcp", "proposal", "auto", "plan", "restore"):
        with pytest.raises(HTTPException) as error:
            await refuse_file_managed(db, owner.organization_id, ["privacy"], source)
        refused.append(error.value.detail["code"])
    await refuse_file_managed(db, owner.organization_id, ["privacy"], "file")
    await refuse_file_managed(db, owner.organization_id, ["rules", "teams"], "api")

    assert _managed(planned, "privacy")
    # A plan made before the switch cannot apply after it.
    assert _managed(stale_plan, "privacy")
    assert refused == ["CONFIG_FILE_MANAGED"] * 7


@pytest.mark.asyncio
async def test_a_restore_skips_file_managed_items_and_names_them(db) -> None:
    users = await tenant(db, "admin")
    owner, admin = users["owner"], users["admin"]
    changed = await call(
        db, admin, "PUT", f"{MANAGEMENT}/settings/pii", json={"block_email": False}
    )
    teamed = await call(
        db,
        admin,
        "PATCH",
        f"{MANAGEMENT}/gateway-settings",
        json={"response_analysis": ["shape"]},
    )
    assert (changed.status_code, teamed.status_code) == (200, 200)
    await file_mode(db, owner, "privacy")

    by_admin = await call(
        db, admin, "POST", f"{MANAGEMENT}/policy/versions/0/restore", json={}
    )
    restored = await call(
        db, owner, "POST", f"{MANAGEMENT}/policy/versions/0/restore", json={}
    )

    # Going back past the switch also restores the mode, which only the owner may.
    assert by_admin.status_code == 403
    assert restored.status_code == 200, restored.text
    assert {
        "resource": "privacy",
        "item": "_",
        "reason": "file_managed",
    } in restored.json()["not_restored"]
    assert {c["resource"] for c in restored.json()["plan"]["changes"]} == {
        "gateway_settings",
        "config_mode",
    }


@pytest.mark.asyncio
async def test_file_plans_change_what_the_api_may_not(db) -> None:
    users = await tenant(db)
    owner = users["owner"]
    key = await file_mode(db, owner, "privacy", "rules")
    document = await exported(db, owner)
    document["resources"]["rules"] = [rule("atlas")]
    document["resources"]["privacy"]["block_phone"] = False

    applied = await push(db, owner, dumped(document), key)
    read = await call(db, owner, "GET", f"{MANAGEMENT}/settings/pii")
    mode = await call(db, owner, "GET", f"{CONFIG}/mode")

    assert applied.status_code == 200, applied.text
    assert [c["resource"] for c in applied.json()["plan"]["changes"]] == [
        "privacy",
        "rules",
    ]
    assert read.json()["block_phone"] is False
    assert await stored_rule_ids(db, owner.organization_id) == ["atlas"]
    assert mode.json()["last_serial"] == 1
