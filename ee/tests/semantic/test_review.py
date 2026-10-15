"""The review loop over archived items, with a stand-in kernel; the call itself is
tested through the real kernel in test_call.py."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from types import SimpleNamespace
from uuid import uuid4

from cryptography.fernet import Fernet
from fastapi import HTTPException
from fastapi.responses import JSONResponse
import pytest
from sqlalchemy import delete, func, select

from ee.tests.gateway.test_attempts import _deployment, origins  # noqa: F401
from ee.tests.observability.test_tasks import _request, _tenant
from ee.tests.rules.test_rules_resource import MANAGEMENT, _call
from shim_enterprise.archive import service as archive_service
from shim_enterprise.archive.models import RequestArchive
from shim_enterprise.core.config import settings
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.semantic.call import CHECK_TAG, REVIEW_TAG
from shim_enterprise.semantic.models import (
    OrganizationSemanticQuestions,
    SemanticReview,
)
from shim.gateway.usage import UsageLimitExceeded
from shim_enterprise.semantic import review as review_module
from shim_enterprise.semantic.review import STALE_CLAIM, review_once, review_tenant
from shim_enterprise.tenants.gateway_settings import (
    GatewaySettings,
    SemanticReviewSettings,
)
from shim_enterprise.tenants.models import OrganizationGatewaySettings

pytestmark = pytest.mark.usefixtures("origins")
KEY = Fernet.generate_key().decode()
NOW = datetime.now(timezone.utc)
QUESTION = {
    "id": "atlas",
    "text": "The request discusses Project Atlas.",
    "examples": [],
}


@pytest.fixture(autouse=True)
def encryption(monkeypatch):
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", KEY)
    monkeypatch.setattr(settings, "REQUEST_ARCHIVE_ENABLED", True)


class _Kernel:
    """Answers every call with `matches`; records each request's text."""

    def __init__(
        self,
        match: bool = True,
        *,
        error: Exception | None = None,
        status: int = 200,
        delay: float = 0,
        ids: list[str] | None = None,
    ) -> None:
        self.match = match
        self.error = error
        self.status = status
        self.delay = delay
        self.ids = ids
        self.texts: list[str] = []

    async def execute(self, invocation):
        self.texts.append(invocation.payload["messages"][1]["content"])
        await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        if self.status != 200:
            return JSONResponse({"error": {}}, status_code=self.status)
        answer = {"matches": [{"question_id": "atlas", "match": self.match}]}
        return JSONResponse(
            {
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": json.dumps(answer)},
                    }
                ]
            },
            headers={
                "x-shim-request-id": self.ids[len(self.texts) - 1]
                if self.ids
                else f"req_review_{len(self.texts)}"
            },
        )


def _factory(db):
    @asynccontextmanager
    async def session():
        yield db

    return session


async def _setup(
    db,
    *,
    items: int = 1,
    alias_kind: str = "internal",
    alias_url: str = "https://a.internal/v1",
    item_kind="internal",
):
    user, key, review_key = await _tenant(db)
    await _deployment(
        db, key, "denetci", deployment_kind=alias_kind, base_url=alias_url
    )
    db.add(
        OrganizationSemanticQuestions(
            organization_id=user.organization_id, revision=1, questions=[QUESTION]
        )
    )
    cipher = Fernet(KEY.encode())
    archived = []
    for index in range(items):
        request_id = _request(
            db,
            key,
            None,
            started_at=NOW - timedelta(minutes=10 + index),
            deployment_kind=item_kind,
        )
        payload = {
            "model": "kurum",
            "messages": [
                {
                    "role": "user",
                    "content": f"Satın alacağımız şirket <TR_NATIONAL_ID_{index}>",
                }
            ],
        }
        row = RequestArchive(
            organization_id=user.organization_id,
            request_id=request_id,
            api_key_id=key.id,
            protocol="chat",
            model="kurum",
            matched=[
                {"kind": "entity", "id": "TR_NATIONAL_ID", "action": "mask", "count": 1}
            ],
            masked_payload=cipher.encrypt(json.dumps(payload).encode()),
            edit_map=cipher.encrypt(
                json.dumps({"<TR_NATIONAL_ID_0>": "10000000146"}).encode()
            ),
            size_bytes=100,
            created_at=NOW - timedelta(minutes=10 + index),
            expires_at=NOW + timedelta(days=30),
        )
        db.add(row)
        archived.append(row)
    await db.flush()
    review = SemanticReviewSettings(
        enabled=True, model="denetci", api_key_id=review_key.id
    )
    return user, key, review_key, review, archived


async def _reviews(db, organization_id):
    return list(
        await db.scalars(
            select(SemanticReview)
            .where(SemanticReview.organization_id == organization_id)
            .order_by(SemanticReview.request_id)
            .execution_options(populate_existing=True)
        )
    )


@pytest.mark.asyncio
async def test_a_claimed_item_is_reviewed_from_its_masked_payload_only(
    db, monkeypatch
) -> None:
    user, key, _, review, archived = await _setup(db)
    kernel = _Kernel()
    decrypted = []
    original = Fernet.decrypt

    def recording(self, token, *args):
        decrypted.append(token)
        return original(self, token, *args)

    monkeypatch.setattr(Fernet, "decrypt", recording)

    await review_tenant(kernel, _factory(db), user.organization_id, review, NOW)

    [row] = await _reviews(db, user.organization_id)
    assert (row.status, row.matched_question_ids) == ("matched", ["atlas"])
    assert row.review_request_id == "req_review_1"
    assert row.completed_at is not None
    assert decrypted == [archived[0].masked_payload]
    assert (
        "<TR_NATIONAL_ID_0>" in kernel.texts[0] and "10000000146" not in kernel.texts[0]
    )
    [scan] = [
        event
        for event in await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == user.organization_id
            )
        )
        if event.payload.get("endpoint") == "tenant.request_content_scanned"
    ]
    assert scan.payload["actor"] == "system:semantic_review"
    assert scan.payload["extra"]["request_ids"] == [archived[0].request_id]
    assert "Atlas" not in json.dumps(scan.payload)


@pytest.mark.asyncio
async def test_an_item_is_reviewed_once_per_revision_and_a_stale_claim_returns(
    db,
) -> None:
    user, _, _, review, archived = await _setup(db, items=3)
    kernel = _Kernel(match=False)
    db.add(
        SemanticReview(
            organization_id=user.organization_id,
            archive_id=archived[2].id,
            request_id=archived[2].request_id,
            questions_revision=1,
            status="pending",
            claimed_at=NOW - timedelta(minutes=11),
        )
    )
    await db.flush()
    once = review.model_copy(update={"max_items_per_hour": 2})

    await review_tenant(kernel, _factory(db), user.organization_id, once, NOW)
    await review_tenant(kernel, _factory(db), user.organization_id, review, NOW)

    rows = await _reviews(db, user.organization_id)
    assert [row.status for row in rows] == ["clear", "clear", "clear"]
    assert len(kernel.texts) == 3


@pytest.mark.asyncio
async def test_the_hourly_and_daily_caps_stop_new_claims(db) -> None:
    user, _, _, review, _ = await _setup(db, items=3)
    kernel = _Kernel()

    await review_tenant(
        kernel,
        _factory(db),
        user.organization_id,
        review.model_copy(update={"max_items_per_hour": 2}),
        NOW,
    )
    assert len(kernel.texts) == 2
    await db.execute(
        SemanticReview.__table__.update()
        .where(SemanticReview.organization_id == user.organization_id)
        .values(cost_usd=Decimal("3"))
    )
    await review_tenant(
        kernel,
        _factory(db),
        user.organization_id,
        review.model_copy(update={"max_cost_usd_per_day": Decimal("5")}),
        NOW,
    )

    assert len(kernel.texts) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("alias_kind", "alias_url"),
    [
        ("external", "https://a.internal/v1"),
        # Labelled internal, but outside the operator's internal origins.
        ("internal", "https://b.internal/v1"),
    ],
)
@pytest.mark.parametrize("item_kind", ["internal", "external", None])
async def test_no_item_is_sent_to_a_review_model_that_is_not_internal(
    db, alias_kind, alias_url, item_kind
) -> None:
    user, _, _, review, _ = await _setup(
        db, alias_kind=alias_kind, alias_url=alias_url, item_kind=item_kind
    )
    kernel = _Kernel()

    await review_tenant(kernel, _factory(db), user.organization_id, review, NOW)

    # Nothing claimed: the items wait for an internal model, none is used up.
    assert await _reviews(db, user.organization_id) == []
    assert kernel.texts == []


@pytest.mark.asyncio
async def test_items_of_the_review_key_are_never_claimed(db) -> None:
    user, _, review_key, review, archived = await _setup(db)
    archived[0].api_key_id = review_key.id
    await db.flush()

    await review_tenant(_Kernel(), _factory(db), user.organization_id, review, NOW)

    assert await _reviews(db, user.organization_id) == []


@pytest.mark.asyncio
async def test_a_review_goes_with_its_archive_item(db) -> None:
    user, _, _, review, archived = await _setup(db)
    await review_tenant(_Kernel(), _factory(db), user.organization_id, review, NOW)

    await db.execute(delete(RequestArchive).where(RequestArchive.id == archived[0].id))

    assert (
        await db.scalar(
            select(func.count()).where(
                SemanticReview.organization_id == user.organization_id
            )
        )
        == 0
    )


@pytest.mark.asyncio
async def test_the_pass_reads_only_tenants_that_turned_the_review_on(db) -> None:
    user, _, _, review, _ = await _setup(db)
    other, *_ = await _setup(db)
    db.add_all(
        [
            OrganizationGatewaySettings(
                organization_id=user.organization_id,
                settings=GatewaySettings(semantic_review=review).model_dump(
                    mode="json"
                ),
            ),
            OrganizationGatewaySettings(
                organization_id=other.organization_id,
                settings={},
            ),
        ]
    )
    await db.flush()
    kernel = _Kernel()

    await review_once(kernel, _factory(db))

    assert len(kernel.texts) == 1


def test_a_review_or_check_call_is_never_archived(monkeypatch) -> None:
    monkeypatch.setattr(settings, "REQUEST_ARCHIVE_ENABLED", True)
    review_key, check_key, other_key = uuid4(), uuid4(), uuid4()
    gateway = GatewaySettings.model_validate(
        {
            "request_archive": {"enabled": True},
            "semantic_review": {"model": "denetci", "api_key_id": str(review_key)},
            "semantic_check": {"model": "kontrol", "api_key_id": str(check_key)},
        }
    )

    def prepared(tags, key):
        return SimpleNamespace(
            tenant_gateway_settings=gateway,
            protocol="chat",
            admission=SimpleNamespace(tags=tags),
            api_key_id=key,
        )

    assert archive_service._retention_days(prepared(("hukuk",), other_key)) == 90
    assert archive_service._retention_days(prepared((REVIEW_TAG,), review_key)) is None
    assert archive_service._retention_days(prepared((CHECK_TAG,), check_key)) is None
    # The tag alone, from any other key, opts nothing out (D10).
    for tag in (REVIEW_TAG, CHECK_TAG):
        assert (
            archive_service._retention_days(prepared(("hukuk", tag), other_key)) == 90
        )
    assert archive_service._retention_days(prepared((CHECK_TAG,), review_key)) == 90


@pytest.mark.asyncio
async def test_the_openings_read_lists_each_scanned_request(db) -> None:
    user, _, _, review, archived = await _setup(db, items=2)
    await review_tenant(_Kernel(), _factory(db), user.organization_id, review, NOW)
    [scan] = [
        event
        for event in await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == user.organization_id
            )
        )
        if event.payload.get("endpoint") == "tenant.request_content_scanned"
    ]
    from shim_enterprise.ai_act.audit_writer import write_audit_row

    await write_audit_row(dict(scan.payload), db)

    openings = await _call(db, user, "GET", f"{MANAGEMENT}/request-archive/openings")

    assert openings.status_code == 200, openings.text
    items = openings.json()["items"]
    assert sorted(item["request_id"] for item in items) == sorted(
        row.request_id for row in archived
    )
    assert {item["actor_user_id"] for item in items} == {"system:semantic_review"}


@pytest.mark.asyncio
async def test_the_loop_starts_only_with_the_archive_switch(monkeypatch) -> None:
    from shim_enterprise import application

    started = []

    async def loop(kernel, factory):
        started.append(1)

    monkeypatch.setattr(application, "run_review_loop", loop)
    for enabled in (False, True):
        monkeypatch.setattr(settings, "REQUEST_ARCHIVE_ENABLED", enabled)
        app = application.create_enterprise_app()
        async with app.router.lifespan_context(app):
            # Let a started task run once before shutdown cancels it.
            await asyncio.sleep(0)

    assert started == [1]


@pytest.mark.asyncio
async def test_the_finding_counts_matched_reviews_per_key_in_seven_days(db) -> None:
    from shim_enterprise.findings import service

    user, key, _, _, archived = await _setup(db, items=3)
    for index, (row, status, age) in enumerate(
        zip(archived, ("matched", "matched", "clear"), (1, 2, 3))
    ):
        db.add(
            SemanticReview(
                organization_id=user.organization_id,
                archive_id=row.id,
                request_id=row.request_id,
                api_key_id=key.id,
                questions_revision=1,
                status=status,
                matched_question_ids=["atlas"] if status == "matched" else [],
                claimed_at=NOW - timedelta(hours=age),
                completed_at=NOW - timedelta(hours=age),
            )
        )
    # Older than the window: not counted.
    db.add(
        SemanticReview(
            organization_id=user.organization_id,
            archive_id=archived[2].id,
            request_id=archived[2].request_id,
            api_key_id=key.id,
            questions_revision=2,
            status="matched",
            matched_question_ids=["atlas"],
            claimed_at=NOW - timedelta(days=8),
            completed_at=NOW - timedelta(days=8),
        )
    )
    await db.flush()

    [found] = await service._semantic_review_matches(db, user.organization_id, NOW)

    assert found.subject == {"api_key_id": str(key.id)}
    assert found.evidence == {
        "window_days": 7,
        "matched_requests": 2,
        "reviewed_requests": 3,
        "questions_matched": 1,
        "questions_revision": 1,
        "request_ids": [archived[0].request_id, archived[1].request_id],
    }
    assert service.RULES[service.SEMANTIC_REVIEW_MATCH].MAX_MODE == "observe"


@pytest.mark.asyncio
async def test_the_reviews_read_filters_and_bounds_its_window(db) -> None:
    user, _, _, review, archived = await _setup(db, items=2)
    await review_tenant(_Kernel(), _factory(db), user.organization_id, review, NOW)
    reviews = f"{MANAGEMENT}/semantic-reviews"

    listed = await _call(db, user, "GET", reviews, params={"status": "matched"})
    one = await _call(
        db, user, "GET", reviews, params={"request_id": archived[0].request_id}
    )
    none = await _call(db, user, "GET", reviews, params={"status": "clear"})
    too_long = await _call(
        db,
        user,
        "GET",
        reviews,
        params={"start": (NOW - timedelta(days=40)).isoformat()},
    )

    assert listed.json()["total"] == 2
    assert [item["request_id"] for item in one.json()["items"]] == [
        archived[0].request_id
    ]
    assert none.json()["total"] == 0
    assert too_long.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kernel",
    [
        _Kernel(error=HTTPException(401, detail={"code": "INVALID_API_KEY"})),
        _Kernel(error=HTTPException(429, detail={"code": "CONCURRENCY_LIMITED"})),
        _Kernel(error=UsageLimitExceeded("budget")),
        _Kernel(status=503),
        _Kernel(error=RuntimeError("shim down")),
    ],
)
async def test_a_temporary_refusal_is_tried_again_and_never_uses_up_the_backlog(
    db, kernel
) -> None:
    user, _, _, review, _ = await _setup(db, items=3)

    await review_tenant(kernel, _factory(db), user.organization_id, review, NOW)

    # The first refusal ends the pass; the item waits for a re-claim, the rest
    # go back unclaimed.
    [row] = await _reviews(db, user.organization_id)
    assert (row.status, row.completed_at) == ("pending", None)
    assert len(kernel.texts) == 1
    await review_tenant(
        _Kernel(match=False),
        _factory(db),
        user.organization_id,
        review,
        NOW + STALE_CLAIM + timedelta(seconds=1),
    )
    assert [row.status for row in await _reviews(db, user.organization_id)] == [
        "clear"
    ] * 3


@pytest.mark.asyncio
async def test_a_refusal_of_the_content_itself_is_final(db) -> None:
    user, _, _, review, _ = await _setup(db)
    kernel = _Kernel(error=HTTPException(400, detail={"code": "RULE_BLOCKED"}))

    await review_tenant(kernel, _factory(db), user.organization_id, review, NOW)

    [row] = await _reviews(db, user.organization_id)
    assert (row.status, row.error_code) == ("failed", "RULE_BLOCKED")


@pytest.mark.asyncio
async def test_a_slow_item_and_a_slow_pass_stop_at_their_bounds(
    db, monkeypatch
) -> None:
    user, _, _, review, _ = await _setup(db, items=3)
    monkeypatch.setattr(review_module, "ITEM_SECONDS", 0.2)
    started = asyncio.get_running_loop().time()

    await review_tenant(
        _Kernel(delay=5), _factory(db), user.organization_id, review, NOW
    )

    [row] = await _reviews(db, user.organization_id)
    assert (row.status, row.error_code) == ("pending", "TIMEOUT")
    monkeypatch.setattr(review_module, "ITEM_SECONDS", 5)
    monkeypatch.setattr(review_module, "PASS_SECONDS", 0.5)
    await review_tenant(
        _Kernel(delay=0.3), _factory(db), user.organization_id, review, NOW
    )
    # One item answered inside the pass; the one cut off and the rest are unclaimed,
    # so nothing is left to be claimed again and reviewed twice.
    statuses = sorted(row.status for row in await _reviews(db, user.organization_id))
    assert statuses == ["matched", "pending"]
    assert asyncio.get_running_loop().time() - started < 5
    assert review_module.PASS_SECONDS * 2 <= review_module.STALE_CLAIM.total_seconds()


@pytest.mark.asyncio
async def test_the_daily_cost_cap_is_read_before_every_call(db) -> None:
    user, key, _, review, _ = await _setup(db, items=3)
    ids = [_request(db, key, None, cost="6") for _ in range(3)]
    await db.flush()
    kernel = _Kernel(ids=ids)

    await review_tenant(kernel, _factory(db), user.organization_id, review, NOW)

    assert len(kernel.texts) == 1
    [row] = await _reviews(db, user.organization_id)
    assert row.cost_usd == Decimal("6")


@pytest.mark.asyncio
async def test_a_stale_claim_of_older_questions_is_reviewed_at_the_current_ones(
    db,
) -> None:
    user, _, _, review, archived = await _setup(db)
    db.add(
        SemanticReview(
            organization_id=user.organization_id,
            archive_id=archived[0].id,
            request_id=archived[0].request_id,
            questions_revision=0,
            status="pending",
            claimed_at=NOW - timedelta(minutes=11),
        )
    )
    await db.flush()

    await review_tenant(_Kernel(), _factory(db), user.organization_id, review, NOW)

    [row] = await _reviews(db, user.organization_id)
    assert (row.questions_revision, row.status) == (1, "matched")


@pytest.mark.asyncio
async def test_each_tenant_claims_at_its_own_time(db, monkeypatch) -> None:
    claimed = []

    async def recording(kernel, factory, organization_id, review, now):
        claimed.append(now)

    user, _, _, review, _ = await _setup(db)
    db.add(
        OrganizationGatewaySettings(
            organization_id=user.organization_id,
            settings=GatewaySettings(semantic_review=review).model_dump(mode="json"),
        )
    )
    await db.flush()
    monkeypatch.setattr(review_module, "review_tenant", recording)
    before = datetime.now(timezone.utc)

    await review_once(_Kernel(), _factory(db))

    assert claimed and claimed[0] >= before
