from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import event

from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.core.database import get_db
from shim_enterprise.observability import language_cost
from shim_enterprise.tenants.models import ApiKey, Organization, User

NOW = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)
PRICED = {
    "pricing_resolution": "catalog",
    "output_per_million": "2.00",
    "large_context_threshold": 200_000,
    "large_context_output_per_million": "4.00",
}


async def _tenant(db, role: str = "owner") -> tuple[User, ApiKey]:
    organization = Organization(
        id=uuid4(), name="Cost", slug=f"cost-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    user = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"cost-{uuid4().hex}@example.com",
        role=role,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await db.flush()
    key = ApiKey(
        id=uuid4(),
        organization_id=organization.id,
        user_id=user.id,
        key_hash=uuid4().hex,
        prefix="sk-shim-cos",
        name="app",
        tier="enterprise",
        is_active=True,
    )
    db.add(key)
    await db.flush()
    return user, key


def _answer(
    db,
    key: ApiKey,
    *,
    language: str | None = "tr",
    characters: int = 400,
    tokens: int = 120,
    prompt_tokens: int = 50,
    estimated: bool = False,
    pricing: dict | None = None,
    model: str = "gpt-5-mini",
    provider_model: str | None = None,
    **metadata,
) -> None:
    request_id = f"req_cost_{uuid4().hex}"
    db.add(
        RequestLifecycle(
            request_id=request_id,
            organization_id=key.organization_id,
            actor_type="api_key",
            api_key_id=key.id,
            source_endpoint="chat.completions",
            status="completed",
            requested_model=model,
            stream=False,
            started_at=NOW - timedelta(days=1),
            lifecycle_metadata={
                "completion_outcome": "complete",
                "answer_characters": characters,
                "tool_call_names": [],
                "reasoning_seen": False,
                **(
                    {"response_analysis": {"language": {"answer": language}}}
                    if language is not None
                    else {}
                ),
                **metadata,
            },
        )
    )
    ledger = {
        "request_id": request_id,
        "organization_id": key.organization_id,
        "api_key_id": key.id,
        "requested_model": model,
        "provider": "openai",
        "provider_model": provider_model or model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": tokens,
        "total_tokens": prompt_tokens + tokens,
        "estimated": estimated,
        "cost_usd": Decimal("0"),
    }
    reservation = uuid4()
    db.add_all(
        [
            UsageLedger(
                id=reservation,
                event_type="spend_reservation",
                idempotency_key=f"{request_id}:spend:reservation",
                **ledger,
            ),
            UsageLedger(
                event_type="spend_settlement",
                idempotency_key=f"{request_id}:spend:settlement",
                reservation_event_id=reservation,
                event_metadata={
                    "pricing": pricing or {"pricing_resolution": "unknown"}
                },
                **ledger,
            ),
        ]
    )


async def _read(db, user: User, **params) -> httpx.Response:
    await db.flush()
    app = FastAPI()
    app.include_router(management_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = lambda: db
    query = {
        "start": (NOW - timedelta(days=30)).isoformat(),
        "end": NOW.isoformat(),
        **params,
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.get("/api/v1/management/language-cost", params=query)


def _items(body: dict) -> dict[tuple, dict]:
    return {(item["group"]["id"], item["language"]): item for item in body["items"]}


@pytest.mark.asyncio
async def test_each_exclusion_is_counted_and_an_eligible_answer_once(db) -> None:
    user, key = await _tenant(db)
    _answer(db, key)
    _answer(db, key, estimated=True)
    _answer(db, key, tool_call_names=["lookup"])
    _answer(db, key, reasoning_seen=True)
    _answer(db, key, characters=199)
    _answer(db, key, language=None)
    _answer(db, key, language="other")

    body = (await _read(db, user)).json()

    assert body["excluded"] == {
        "estimated_usage": 1,
        "tool_calls": 1,
        "reasoning": 1,
        "short": 1,
        "not_analysed": 1,
        "language_unknown": 1,
    }
    assert [item["requests"] for item in body["items"]] == [1]
    assert body["analysed_share"] == round(1 / 7, 4)


@pytest.mark.asyncio
async def test_ratios_quartiles_and_money_per_model(db) -> None:
    user, key = await _tenant(db)
    for tokens in (100, 120, 140, 160):
        _answer(db, key, tokens=tokens, pricing=PRICED)
    # Large-context price past its threshold; an unpriced one adds no money.
    _answer(db, key, tokens=200, prompt_tokens=300_000, pricing=PRICED)
    _answer(db, key, tokens=200)
    # A registry alias groups under the model the provider billed.
    _answer(db, key, model="kurum-alias", provider_model="gpt-5-mini", tokens=100)

    item = _items((await _read(db, user)).json())[("gpt-5-mini", "tr")]

    tokens = 100 + 120 + 140 + 160 + 200 + 200 + 100
    assert (item["requests"], item["completion_tokens"]) == (7, tokens)
    assert item["answer_characters"] == 7 * 400
    assert item["tokens_per_1000_characters"] == round(1000 * tokens / 2800, 4)
    assert item["ratio_p25"] == 275.0 and item["ratio_p75"] == 450.0
    priced_usd = (
        Decimal(100 + 120 + 140 + 160) * Decimal("2") / 10**6
        + Decimal(200) * Decimal("4") / 10**6
    )
    assert item["priced_requests"] == 5
    assert Decimal(item["output_usd_per_1000_characters"]) == round(
        1000 * priced_usd / (5 * 400), 8
    )


@pytest.mark.parametrize(("answers", "compared"), [(30, True), (29, False)])
@pytest.mark.asyncio
async def test_tr_vs_en_needs_30_answers_in_each_language(
    db, answers, compared
) -> None:
    user, key = await _tenant(db)
    for _ in range(answers):
        _answer(db, key, language="tr", tokens=120)
    for _ in range(30):
        _answer(db, key, language="en", tokens=80)

    items = _items((await _read(db, user)).json())

    tr, en = items[("gpt-5-mini", "tr")], items[("gpt-5-mini", "en")]
    if compared:
        assert tr["tr_vs_en"] == en["tr_vs_en"] == 1.5
        assert tr["comparison_unavailable_reason"] is None
    else:
        assert tr["tr_vs_en"] is None
        assert tr["comparison_unavailable_reason"] == "not_enough_answers"


@pytest.mark.asyncio
async def test_by_api_key_window_readers_and_tenants(db) -> None:
    user, key = await _tenant(db)
    other, other_key = await _tenant(db)
    _answer(db, key)
    _answer(db, other_key)
    member = User(
        id=uuid4(),
        organization_id=user.organization_id,
        email=f"cost-{uuid4().hex}@example.com",
        role="member",
        is_active=True,
        is_verified=True,
    )
    db.add(member)

    by_key = (await _read(db, user, group_by="api_key")).json()
    too_long = await _read(db, user, start=(NOW - timedelta(days=32)).isoformat())
    refused = await _read(db, member)

    assert [
        (item["group"]["id"], item["group"]["name"]) for item in by_key["items"]
    ] == [(str(key.id), "app")]
    assert too_long.status_code == 422
    assert refused.status_code == 403


@pytest.mark.asyncio
async def test_the_read_takes_at_most_three_statements(db) -> None:
    user, key = await _tenant(db)
    _answer(db, key)
    await db.flush()
    connection = await db.connection()
    sent: list[str] = []

    def capture(_conn, _cursor, statement, *_args) -> None:
        if "request_lifecycle" in statement:
            sent.append(statement)

    event.listen(connection.sync_connection, "before_cursor_execute", capture)
    try:
        await language_cost.language_cost(
            db,
            user.organization_id,
            start=NOW - timedelta(days=30),
            end=NOW,
            group_by="model",
        )
    finally:
        event.remove(connection.sync_connection, "before_cursor_execute", capture)

    assert len(sent) <= 3
