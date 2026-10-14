from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace
from uuid import UUID, uuid4

from fastapi import HTTPException
import pytest

from shim_enterprise.api.v1 import management
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.billing.savings import estimate_route_saving, model_prices
from shim_enterprise.observability.analytics_projection import RequestLog
from shim_enterprise.tenants.models import (
    ApiKey,
    ModelDeployment,
    Organization,
    ProviderSecret,
    User,
)
from shim.billing.pricing import ModelPrice

NOW = datetime.now(timezone.utc)


def _user(organization_id: UUID) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid4(),
        kind="human",
        role="owner",
        custom_role_id=None,
        organization_id=organization_id,
    )


async def _tenant(db) -> ApiKey:
    organization = Organization(
        id=uuid4(), name="Savings", slug=f"savings-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    owner = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"savings-{uuid4().hex}@example.com",
        role="owner",
        is_active=True,
        is_verified=True,
    )
    db.add(owner)
    await db.flush()
    key = ApiKey(
        id=uuid4(),
        organization_id=organization.id,
        user_id=owner.id,
        key_hash=uuid4().hex,
        prefix="sk-shim-sav",
        tier="enterprise",
        is_active=True,
    )
    db.add(key)
    await db.flush()
    return key


def _add(
    db,
    key: ApiKey,
    metadata: dict,
    *,
    status: str = "completed",
    started_at: datetime = NOW - timedelta(hours=1),
    tokens: tuple[int, int] = (0, 0),
    route_decision: dict | None = None,
) -> None:
    request_id = f"req_savings_{uuid4().hex}"
    db.add(
        RequestLifecycle(
            request_id=request_id,
            organization_id=key.organization_id,
            actor_type="api_key",
            api_key_id=key.id,
            source_endpoint="chat.completions",
            status=status,
            provider="openai",
            requested_model="gpt-5-nano",
            stream=False,
            started_at=started_at,
            route_decision=route_decision,
            lifecycle_metadata=metadata,
        )
    )
    db.add(
        RequestLog(
            request_id=request_id,
            api_key_id=key.id,
            organization_id=key.organization_id,
            prompt_tokens=tokens[0],
            completion_tokens=tokens[1],
            details={},
        )
    )


async def _deployment(
    db, key: ApiKey, alias: str, price: tuple[str, str] | None, upstream: str
) -> None:
    secret = ProviderSecret(
        id=uuid4(),
        organization_id=key.organization_id,
        provider="openai",
        secret_ref=f"fernet:v2:{uuid4().hex}",
        secret_backend="fernet",
        secret_version="v2",
        masked_key="sk-...",
    )
    db.add(secret)
    await db.flush()
    db.add(
        ModelDeployment(
            organization_id=key.organization_id,
            alias=alias,
            provider="openai",
            upstream_model=upstream,
            base_url="https://a.internal/v1",
            provider_secret_id=secret.id,
            timeout_seconds=30,
            deployment_kind="internal",
            declared_version="v1",
            owner="Platform",
            input_price_per_million=Decimal(price[0]) if price else None,
            output_price_per_million=Decimal(price[1]) if price else None,
        )
    )
    await db.flush()


def _saved(**sections) -> dict:
    return {"savings": {"version": 1, **sections}}


async def _view(db, key: ApiKey, **query):
    await db.flush()
    return await management.usage.savings(
        start_date=query.get("start", NOW - timedelta(days=1)),
        end_date=query.get("end", NOW),
        api_key_id=query.get("api_key_id"),
        user=_user(key.organization_id),
        session=db,
    )


def _rows(view) -> dict[tuple[str, str], object]:
    return {(row.lever, row.method): row for row in view.levers}


@pytest.mark.asyncio
async def test_only_measured_figures_are_summed(db) -> None:
    key = await _tenant(db)
    _add(
        db,
        key,
        _saved(measured={"inflight_share": {"usd": "0.0012000000", "tokens": 1400}}),
    )
    _add(
        db,
        key,
        _saved(
            measured={
                "provider_cache": {
                    "usd": "-0.0010000000",
                    "read_tokens": 0,
                    "write_tokens": 4000,
                },
                "json_compaction": {"chars": 5200},
                "image_downscale": {"bytes": 2400000},
            },
            estimated={"json_compaction": {"tokens": 1300, "usd": "0.0013000000"}},
            not_attributed={
                "provider_cache_key": {"read_tokens": 4096, "usd": "0.0018000000"}
            },
        )
        | {
            "settings_applied": [
                {"id": "parameter_pin.temp", "version": 3},
                {"id": "image_detail", "version": 1},
            ],
            "transforms_applied": [{"id": "document_text", "version": 1}],
        },
    )
    _add(
        db,
        key,
        _saved(
            measured={
                "provider_cache": {
                    "usd": None,
                    "unpriced": True,
                    "read_tokens": None,
                    "write_tokens": None,
                }
            }
        ),
    )
    # A follower of an estimated answer: listed apart, never in the total (M6).
    _add(db, key, _saved(estimated={"inflight_share": {"usd": "0.5", "tokens": 9}}))
    _add(
        db,
        key,
        _saved(measured={"inflight_share": {"usd": "5", "tokens": 1}}),
        status="provider_error",
    )
    _add(
        db,
        key,
        _saved(measured={"inflight_share": {"usd": "7", "tokens": 1}}),
        started_at=NOW - timedelta(days=3),
    )

    view = await _view(db, key)

    rows = _rows(view)
    assert view.measured_usd == "0.0002000000"
    assert [(row.lever, row.method) for row in view.levers] == [
        ("inflight_share", "measured"),
        ("inflight_share", "estimated"),
        ("provider_cache", "measured"),
        ("provider_cache_key", "not_attributed"),
        ("json_compaction", "measured"),
        ("json_compaction", "estimated"),
        ("image_downscale", "measured"),
        ("image_detail", "counted"),
        ("parameter_pin", "counted"),
    ]
    assert (
        rows["provider_cache", "measured"].requests,
        rows["provider_cache", "measured"].unpriced,
    ) == (2, 1)
    assert rows["provider_cache", "measured"].usd == "-0.0010000000"
    assert rows["json_compaction", "measured"].chars == 5200
    assert rows["image_downscale", "measured"].bytes == 2400000
    assert rows["provider_cache_key", "not_attributed"].usd == "0.0018000000"
    assert rows["inflight_share", "measured"].note.startswith("A provider call")
    assert rows["inflight_share", "estimated"].usd == "0.5000000000"


@pytest.mark.asyncio
async def test_the_window_key_filter_and_tenant_hold(db) -> None:
    key = await _tenant(db)
    other = await _tenant(db)
    _add(db, key, _saved(measured={"inflight_share": {"usd": "0.1", "tokens": 1}}))
    _add(db, other, _saved(measured={"inflight_share": {"usd": "0.2", "tokens": 1}}))

    mine = await _view(db, key)
    theirs = await _view(db, other)
    filtered = await _view(db, key, api_key_id=uuid4())

    assert mine.measured_usd == "0.1000000000" and theirs.measured_usd == "0.2000000000"
    assert filtered.levers == [] and filtered.measured_usd == "0.0000000000"
    with pytest.raises(HTTPException) as refused:
        await _view(db, key, start=NOW - timedelta(days=40))
    assert refused.value.status_code == 422


def _decision(
    origin: str, target: str, outcome: str, reason: str = "keywords_any", **extra
) -> dict:
    return {
        "rule_id": "r",
        "state": "enforced",
        "from": origin,
        "to": target,
        "reason": reason,
        "outcome": outcome,
        **extra,
    }


@pytest.mark.asyncio
async def test_routing_reprices_the_same_tokens_at_both_models(db) -> None:
    key = await _tenant(db)
    await _deployment(db, key, "strong", ("3.00", "15.00"), "unknown-upstream")
    await _deployment(db, key, "cheap", ("0.50", "1.50"), "unknown-upstream")
    await _deployment(db, key, "unpriced-alias", None, "no-such-model")
    for _ in range(10):
        _add(
            db,
            key,
            {},
            tokens=(1000, 200),
            route_decision=_decision("strong", "cheap", "routed"),
        )
    _add(
        db,
        key,
        {},
        tokens=(1000, 200),
        route_decision=_decision("strong", "cheap", "would_route"),
    )
    _add(
        db,
        key,
        {},
        tokens=(1000, 200),
        route_decision=_decision("strong", "unpriced-alias", "routed"),
    )
    _add(
        db,
        key,
        {},
        tokens=(1000, 200),
        route_decision=_decision("strong", "cheap", "routed", reason="fallback"),
    )
    _add(
        db,
        key,
        {
            "route_decision": _decision(
                "cheap",
                "strong",
                "not_allowed_for_key",
                previous=_decision("strong", "cheap", "would_route"),
            )
        },
        tokens=(1000, 200),
    )

    rows = _rows(await _view(db, key))

    routed, monitor = rows["routing", "estimated"], rows["routing_monitor", "estimated"]
    assert (routed.requests, routed.unpriced, routed.usd) == (11, 1, "0.0520000000")
    assert (monitor.requests, monitor.usd) == (2, "0.0104000000")


@pytest.mark.asyncio
async def test_the_shared_route_fixture_prices_as_e71_does(db) -> None:
    key = await _tenant(db)
    await _deployment(db, key, "from-alias", ("3.00", "15.00"), "x")
    await _deployment(db, key, "to-alias", ("0.50", "1.50"), "x")
    await _deployment(db, key, "catalog-alias", None, "gpt-5-nano")
    await _deployment(db, key, "lost-alias", None, "no-such-model")

    prices = await model_prices(
        db,
        key.organization_id,
        ["from-alias", "to-alias", "catalog-alias", "lost-alias", "gpt-5-nano"],
    )

    origin, target = prices["from-alias"], prices["to-alias"]
    assert origin is not None and target is not None
    assert origin.cost(10_000, 2_000) == Decimal("0.0600000000")
    assert target.cost(10_000, 2_000) == Decimal("0.0080000000")
    assert estimate_route_saving(origin, target, 10_000, 2_000) == Decimal(
        "0.0520000000"
    )
    assert prices["catalog-alias"] == prices["gpt-5-nano"] is not None
    assert prices["lost-alias"] is None
    assert estimate_route_saving(origin, None, 1, 1) is None
    assert estimate_route_saving(ModelPrice(Decimal(1), Decimal(1)), origin, 0, 0) == 0


@pytest.mark.asyncio
async def test_the_request_list_and_its_csv_show_the_record(db) -> None:
    import csv
    import io
    import json

    key = await _tenant(db)
    record = {"version": 1, "measured": {"image_downscale": {"bytes": 10}}}
    _add(db, key, {"savings": record}, started_at=NOW - timedelta(minutes=5))
    _add(db, key, {}, started_at=NOW - timedelta(minutes=4))
    await db.flush()
    filters = dict(
        start=NOW - timedelta(hours=1),
        end=None,
        status_filter=None,
        model=None,
        request_id=None,
        pii_detected=None,
        tag=None,
        cost_center=None,
        user=_user(key.organization_id),
        session=db,
    )

    page = await management.activity.list_requests(**filters, limit=10, offset=0)
    exported = await management.activity.export_requests(**filters)
    rows = list(
        csv.DictReader(
            io.StringIO(
                b"".join([chunk async for chunk in exported.body_iterator]).decode(
                    "utf-8-sig"
                )
            )
        )
    )

    assert [item.savings for item in page.items] == [None, record]
    assert [row["savings"] for row in rows] == [
        "",
        json.dumps(record, sort_keys=True, separators=(",", ":")),
    ]
