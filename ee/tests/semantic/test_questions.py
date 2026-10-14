from __future__ import annotations

import json

import pytest

from ee.tests.rules.test_rules_resource import (
    MANAGEMENT,
    POLICY,
    _call,
    _organization,
    _versions,
)
from shim_enterprise.semantic.questions import SEMANTIC_QUESTIONS

QUESTIONS = f"{MANAGEMENT}/semantic-questions"
ATLAS = {
    "id": "atlas",
    "text": "The request discusses Project Atlas, the unannounced acquisition, even "
    "without naming it.",
    "examples": [
        "the company we are buying next quarter",
        "the deal the strategy team is running",
    ],
}


class _Untouchable:
    @property
    def redis(self):
        pytest.fail("the questions reached Redis")


async def _put(db, user, revision: int, questions: list[dict]):
    return await _call(
        db,
        user,
        "PUT",
        QUESTIONS,
        cache=_Untouchable(),
        json={"revision": revision, "questions": questions},
    )


@pytest.mark.asyncio
async def test_the_set_is_replaced_whole_and_its_audit_holds_ids_only(
    db, audit_events
) -> None:
    owner = (await _organization(db))["owner"]

    stored = await _put(db, owner, 0, [ATLAS])
    read = await _call(db, owner, "GET", QUESTIONS)
    renamed = await _put(
        db, owner, 1, [{**ATLAS, "text": "The request discusses Project Atlas at all."}]
    )

    assert stored.status_code == 200, stored.text
    assert read.json() == {"revision": 1, "questions": [ATLAS]}
    assert renamed.json()["revision"] == 2
    events = [
        event
        for event in await audit_events(owner.organization_id)
        if event["endpoint"] == "tenant.semantic_questions_updated"
    ]
    assert [event["extra"]["added"] for event in events] == [["atlas"], []]
    assert events[1]["extra"]["changed"] == ["atlas"]
    dumped = json.dumps(events)
    assert "Atlas" not in dumped and "acquisition" not in dumped


@pytest.mark.asyncio
async def test_a_stale_revision_is_refused_with_the_current_one(db) -> None:
    owner = (await _organization(db))["owner"]
    await _put(db, owner, 0, [ATLAS])

    stale = await _put(db, owner, 0, [])

    assert stale.status_code == 409
    assert stale.json()["detail"]["revision"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "questions",
    [
        [{**ATLAS, "id": "Atlas"}],
        [{**ATLAS, "text": "too short"}],
        [{**ATLAS, "text": "x" * 501}],
        [{**ATLAS, "examples": ["abc"]}],
        [{**ATLAS, "examples": ["x" * 301]}],
        [{**ATLAS, "examples": ["example"] * 6}],
        [ATLAS, ATLAS],
        [{**ATLAS, "id": f"q{index}"} for index in range(21)],
        [{**ATLAS, "extra": 1}],
    ],
)
async def test_every_bound_is_refused(db, questions) -> None:
    owner = (await _organization(db))["owner"]

    assert (await _put(db, owner, 0, questions)).status_code == 422


@pytest.mark.asyncio
async def test_reading_needs_rules_read_and_writing_rules_write(db) -> None:
    users = await _organization(db, "admin")
    auditor = users["admin"]
    auditor.role = "auditor"
    member = users["owner"]
    await db.flush()

    read = await _call(db, auditor, "GET", QUESTIONS)
    written = await _put(db, auditor, 0, [ATLAS])
    member.role = "member"
    await db.flush()
    refused = await _call(db, member, "GET", QUESTIONS)

    assert read.status_code == 200
    assert written.status_code == 403
    assert refused.status_code == 403


@pytest.mark.parametrize(
    ("before", "after", "risk"),
    [
        ([], [ATLAS], "tightening"),
        ([ATLAS], [], "relaxing"),
        ([ATLAS], [{**ATLAS, "examples": []}], "relaxing"),
        ([ATLAS], [{**ATLAS, "text": "Another meaning entirely here."}], "relaxing"),
        ([ATLAS], [ATLAS], "neutral"),
    ],
)
def test_each_change_classifies(before, after, risk) -> None:
    assert (
        SEMANTIC_QUESTIONS.classify({"questions": before}, {"questions": after}) == risk
    )


@pytest.mark.asyncio
async def test_a_version_restores_the_previous_set(db) -> None:
    owner = (await _organization(db))["owner"]
    await _put(db, owner, 0, [ATLAS])
    await _put(db, owner, 1, [])
    newest = (await _versions(db, owner.organization_id))[-1].version

    restored = await _call(
        db,
        owner,
        "POST",
        f"{POLICY}/versions/{newest - 1}/restore",
        json={"reason": "bring atlas back"},
    )

    assert restored.status_code in (200, 201), restored.text
    assert (await _call(db, owner, "GET", QUESTIONS)).json()["questions"] == [ATLAS]
