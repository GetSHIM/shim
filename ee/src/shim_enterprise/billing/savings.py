"""What the tenant's levers saved over a window, read from the requests' own records."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import (
    Numeric,
    and_,
    cast,
    func,
    literal,
    or_,
    select,
    type_coerce,
    union_all,
)
from sqlalchemy.dialects.postgresql import JSONB, JSONPATH
from sqlalchemy.ext.asyncio import AsyncSession

from shim.billing.pricing import DEFAULT_PRICE_BOOK, ModelPrice
from shim.billing.savings import LEVERS, Method, usd
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.observability.analytics_projection import RequestLog
from shim_enterprise.tenants.models import ModelDeployment

# (lever, method, the record's section, {view field: record field}).
_RECORDED: tuple[tuple[str, Method, str, dict[str, str]], ...] = (
    ("inflight_share", "measured", "measured", {"usd": "usd", "tokens": "tokens"}),
    ("inflight_share", "estimated", "estimated", {"usd": "usd", "tokens": "tokens"}),
    ("provider_cache", "measured", "measured", {"usd": "usd", "tokens": "read_tokens"}),
    (
        "provider_cache_key",
        "not_attributed",
        "not_attributed",
        {"usd": "usd", "tokens": "read_tokens"},
    ),
    ("json_compaction", "measured", "measured", {"chars": "chars"}),
    ("json_compaction", "estimated", "estimated", {"usd": "usd", "tokens": "tokens"}),
    ("image_downscale", "measured", "measured", {"bytes": "bytes"}),
    ("context_clearing", "measured", "measured", {"tokens": "tokens"}),
    ("context_clearing", "estimated", "estimated", {"usd": "usd"}),
)
_SETTINGS_COUNTED = ("image_detail", "tool_search", "openai_reasoning_context")
# S57's reasons: an extra attempt's target, not a cheaper model the tenant chose.
_ATTEMPT_REASONS = (
    "fallback",
    "overflow",
    "format_retry",
    "canary_fallback",
    "degrade",
)
_NOTES = {lever.name: lever.note for lever in LEVERS}
_ORDER = {lever.name: index for index, lever in enumerate(LEVERS)}


@dataclass(frozen=True, slots=True)
class SavingsRow:
    lever: str
    method: Method
    requests: int
    usd: str | None = None
    tokens: int | None = None
    chars: int | None = None
    bytes: int | None = None
    unpriced: int = 0

    @property
    def note(self) -> str:
        return _NOTES[self.lever]


def estimate_route_saving(
    origin: ModelPrice | None,
    target: ModelPrice | None,
    prompt_tokens: int,
    completion_tokens: int,
) -> Decimal | None:
    """The same tokens priced at both models, without a cache split; None when unpriced."""
    if origin is None or target is None:
        return None
    return origin.cost(prompt_tokens, completion_tokens) - target.cost(
        prompt_tokens, completion_tokens
    )


async def model_prices(
    session: AsyncSession, tenant_id: UUID, names: Iterable[str]
) -> dict[str, ModelPrice | None]:
    """Each name's price: a tenant alias's own price, else its upstream model's
    catalog price; a name that is no alias, its catalog price; None when unknown."""
    wanted = set(names)
    deployments = {
        row.alias: row
        for row in await session.scalars(
            select(ModelDeployment).where(
                ModelDeployment.organization_id == tenant_id,
                ModelDeployment.alias.in_(wanted),
            )
        )
    }
    prices: dict[str, ModelPrice | None] = {}
    for name in wanted:
        deployment = deployments.get(name)
        if deployment is not None and deployment.input_price_per_million is not None:
            assert deployment.output_price_per_million is not None
            prices[name] = ModelPrice(
                deployment.input_price_per_million, deployment.output_price_per_million
            )
            continue
        model = (
            (deployment.price_model or deployment.upstream_model)
            if deployment is not None
            else name
        )
        providers = (
            (deployment.provider,)
            if deployment is not None
            else ("openai", "anthropic", "google")
        )
        prices[name] = next(
            (
                price
                for provider in providers
                if (price := DEFAULT_PRICE_BOOK.exact(model, provider)) is not None
            ),
            None,
        )
    return prices


async def tenant_savings(
    session: AsyncSession,
    tenant_id: UUID,
    start: datetime,
    end: datetime,
    api_key_id: UUID | None = None,
) -> list[SavingsRow]:
    """The window's lever rows, in `LEVERS` order, only those with requests."""
    window = [
        RequestLifecycle.organization_id == tenant_id,
        RequestLifecycle.started_at >= start,
        RequestLifecycle.started_at <= end,
        RequestLifecycle.status == "completed",
        *([RequestLifecycle.api_key_id == api_key_id] if api_key_id else []),
    ]
    metadata = RequestLifecycle.lifecycle_metadata
    columns: list[Any] = []
    for lever, _, section, fields in _RECORDED:
        row = metadata[("savings", section, lever)]
        columns += [
            func.count().filter(row.isnot(None)),
            func.count().filter(row["unpriced"].astext == "true"),
            *(func.sum(row[field].astext.cast(Numeric)) for field in fields.values()),
        ]
    counted = [
        *(
            metadata["settings_applied"].contains([{"id": name}])
            for name in _SETTINGS_COUNTED
        ),
        func.jsonb_path_exists(
            metadata["settings_applied"],
            cast(literal('$[*] ? (@.id starts with "parameter_pin.")'), JSONPATH),
        ),
    ]
    columns += [func.count().filter(condition) for condition in counted]
    values = list((await session.execute(select(*columns).where(*window))).one())
    rows: list[SavingsRow] = []
    for lever, method, _, fields in _RECORDED:
        requests, unpriced, *sums = values[: 2 + len(fields)]
        values = values[2 + len(fields) :]
        if not requests:
            continue
        found = dict(zip(fields, sums))
        rows.append(
            SavingsRow(
                lever,
                method,
                requests,
                usd=None if found.get("usd") is None else usd(found["usd"]),
                tokens=None if found.get("tokens") is None else int(found["tokens"]),
                chars=None if found.get("chars") is None else int(found["chars"]),
                bytes=None if found.get("bytes") is None else int(found["bytes"]),
                unpriced=unpriced,
            )
        )
    for name, requests in zip((*_SETTINGS_COUNTED, "parameter_pin"), values):
        if requests:
            rows.append(SavingsRow(name, "counted", requests))
    rows += await _routing(session, tenant_id, window)
    return sorted(rows, key=lambda row: _ORDER[row.lever])


async def _routing(
    session: AsyncSession, tenant_id: UUID, window: list[Any]
) -> list[SavingsRow]:
    # A target chosen after privacy is recorded over the one admission chose.
    decision = type_coerce(
        func.coalesce(
            RequestLifecycle.lifecycle_metadata["route_decision"],
            RequestLifecycle.route_decision,
        ),
        JSONB,
    )
    joined = and_(
        RequestLog.organization_id == RequestLifecycle.organization_id,
        RequestLog.request_id == RequestLifecycle.request_id,
    )
    decisions = union_all(
        *(
            select(
                part.op("->>")("from").label("origin"),
                part.op("->>")("to").label("target"),
                part.op("->>")("outcome").label("outcome"),
                part.op("->>")("reason").label("reason"),
                RequestLog.prompt_tokens.label("prompt_tokens"),
                RequestLog.completion_tokens.label("completion_tokens"),
            )
            .select_from(RequestLifecycle)
            .join(RequestLog, joined)
            .where(*window, part.isnot(None))
            for part in (decision, decision.op("->", return_type=JSONB)("previous"))
        )
    ).subquery()
    groups = (
        await session.execute(
            select(
                decisions.c.origin,
                decisions.c.target,
                decisions.c.outcome,
                func.count(),
                func.sum(decisions.c.prompt_tokens),
                func.sum(decisions.c.completion_tokens),
            )
            .where(
                decisions.c.outcome.in_(("routed", "would_route")),
                or_(
                    decisions.c.reason.is_(None),
                    decisions.c.reason.notin_(_ATTEMPT_REASONS),
                ),
            )
            .group_by(decisions.c.origin, decisions.c.target, decisions.c.outcome)
        )
    ).all()
    prices = await model_prices(
        session, tenant_id, {name for group in groups for name in group[:2] if name}
    )
    totals: dict[str, list[Any]] = {}
    for origin, target, outcome, requests, prompt, completion in groups:
        saving = estimate_route_saving(
            prices.get(origin),
            prices.get(target),
            int(prompt or 0),
            int(completion or 0),
        )
        lever = "routing" if outcome == "routed" else "routing_monitor"
        total = totals.setdefault(lever, [0, Decimal(0), 0, 0])
        total[0] += requests
        total[2] += int(prompt or 0) + int(completion or 0)
        if saving is None:
            total[3] += requests
        else:
            total[1] += saving
    return [
        SavingsRow(
            lever,
            "estimated",
            requests,
            usd=usd(amount) if unpriced < requests else None,
            tokens=tokens,
            unpriced=unpriced,
        )
        for lever, (requests, amount, tokens, unpriced) in totals.items()
    ]


def measured_usd(rows: Iterable[SavingsRow]) -> str:
    return usd(
        sum(
            (Decimal(row.usd) for row in rows if row.method == "measured" and row.usd),
            Decimal(0),
        )
    )
