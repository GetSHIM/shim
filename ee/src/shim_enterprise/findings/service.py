"""The gateway rules, their evaluation, and the OCSF form of a finding."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import (
    ARRAY,
    Text,
    and_,
    case,
    cast,
    func,
    not_,
    or_,
    select,
    text,
    type_coerce,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB, aggregate_order_by, insert
from sqlalchemy.orm import aliased
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.findings.models import Finding
from shim_enterprise.observability.outcomes import OUTCOMES
from shim_enterprise.observability.model_inventory import (
    byok_request,
    catalog_traffic,
    registry_traffic,
    shown_model,
)
from shim_enterprise.tenants.models import ModelDeployment, Organization, ProviderSecret


logger = logging.getLogger(__name__)

RETRY_STORM = "gateway.retry_storm"
REPEAT_SPEND = "gateway.repeat_spend"
UNUSED_DEPLOYMENT = "gateway.unused_deployment"
ANSWER_QUALITY = "gateway.answer_quality"
IDLE_INTERNAL_DEPLOYMENT = "gateway.idle_internal_deployment"
UNREGISTERED_MODEL = "gateway.unregistered_model"
BYOK_USAGE = "gateway.byok_usage"
TRUNCATION_RATE = "gateway.truncation_rate"
REFUSAL_RATE = "gateway.refusal_rate"
RULE_VERSION = 1
RULE_VERSIONS = {RETRY_STORM: 2, REPEAT_SPEND: 2, UNUSED_DEPLOYMENT: 2}

RETRY_BUCKET = timedelta(minutes=15)
RETRY_BUCKETS = 4
RETRY_STORM_MIN_REQUESTS = 20
REPEAT_SPEND_MIN_SHARE = Decimal("0.10")
REPEAT_SPEND_MIN_USD = Decimal("1")
ANSWER_QUALITY_WINDOW = timedelta(hours=24)
ANSWER_QUALITY_MIN_REQUESTS = 50
ANSWER_QUALITY_MIN_RATE = Decimal("0.05")
AUTO_RESOLVE_AFTER = timedelta(days=7)
# Covers the pinned SDKs' 600 s timeout plus backoff; a longer client timeout is not linked.
REPEAT_LINK_WINDOW_SECONDS = 900
# A deployment at least this old is judged on its traffic over this many days.
DEPLOYMENT_WINDOW_DAYS = 30
IDLE_DEPLOYMENT_MAX_REQUESTS = 300
UNREGISTERED_MODEL_WINDOW_DAYS = 7
UNREGISTERED_MODEL_MIN_REQUESTS = 5
BYOK_USAGE_WINDOW_DAYS = 7
BYOK_USAGE_MIN_REQUESTS = 5
OUTCOME_RATE_WINDOW_HOURS = 24
OUTCOME_RATE_MIN_SETTLED = 50
TRUNCATION_RATE_THRESHOLD = Decimal("0.05")
REFUSAL_RATE_THRESHOLD = Decimal("0.05")
EVIDENCE_KEY_IDS = 10
EVIDENCE_MODELS = 10
EVIDENCE_MODELS_PER_KEY = 5
EVIDENCE_REQUEST_IDS = 20

STATUS_IDS = {"new": 1, "in_progress": 2, "suppressed": 3, "resolved": 4}
STATUS_RESOLVED = STATUS_IDS["resolved"]
OCSF_VERSION = "1.3.0"

# Rule id: (title, OCSF severity_id, remediation text). Every fix is reversible,
# and its doc is the rule's section of ee/docs/FINDINGS.md.
RULES: dict[str, tuple[str, int, str]] = {
    RETRY_STORM: (
        "Retry storm from one API key",
        3,
        "Find the client behind this key and make it back off: honour "
        "Retry-After, add jittered exponential backoff and cap retries. When "
        "abandoned requests co-occur, raise the client's timeout above the "
        "model's answer time instead of retrying.",
    ),
    REPEAT_SPEND: (
        "Repeated requests are a large share of a key's spend",
        3,
        "Stop resending identical requests from this key: retry only on "
        "retryable errors, deduplicate in the client, or cache the answer.",
    ),
    UNUSED_DEPLOYMENT: (
        "Registered deployment receives no traffic",
        2,
        "Disable or delete the deployment if nobody uses it, or point callers "
        "at its alias.",
    ),
    ANSWER_QUALITY: (
        "A model often truncates, refuses or returns empty answers",
        2,
        "For truncation, raise the output token limit or shorten the expected "
        "answer; for empty or refused answers, review the prompt and the "
        "model choice.",
    ),
    UNREGISTERED_MODEL: (
        "A model outside the registry serves requests",
        3,
        "Register the model as a deployment, or limit the keys that use it with "
        "allowed_models; an operator can make the registry mandatory with "
        "MODEL_DEPLOYMENT_REQUIRED=true.",
    ),
    BYOK_USAGE: (
        "An API key sends its own provider key past a stored one",
        3,
        "Give the app the managed key path (no x-provider-key header), or route "
        "it through a registry deployment, whose stored secret always wins.",
    ),
    TRUNCATION_RATE: (
        "An API key's answers often stop at the output limit",
        2,
        "The answers hit the output limit: raise the max output tokens the app "
        "sends, or check the model's output limit. The request list filtered by "
        "completion_outcome=truncated and this api_key_id shows them.",
    ),
    REFUSAL_RATE: (
        "An API key's answers are often refused, filtered or empty",
        2,
        "Read the refused and filtered requests (the request list filtered by "
        "completion_outcome and this api_key_id): a provider content filter, a "
        "model refusal and an empty answer have different fixes.",
    ),
    IDLE_INTERNAL_DEPLOYMENT: (
        "Internal deployment is almost unused",
        2,
        "Disable the deployment or move its few callers to another deployment; "
        "it can be enabled again in one write.",
    ),
}
# A retry storm's fix follows the class most of its repeats belong to.
STORM_FIXES = {
    "after_timeout": "The client's timeout is shorter than the answers take: raise "
    "the timeout or ask for fewer output tokens instead of sending the request again.",
    "after_error": "The SDK retries after errors: honour Retry-After, lower "
    "max_retries and add jittered backoff.",
    "after_success": "The app sends the same request again after a successful "
    "answer: deduplicate it in the app.",
}
REPEAT_CLASSES = ("after_timeout", "after_error", "after_success", "pending")
_TIMED_OUT = ("client_disconnected", "timeout")
_FAILED = ("provider_error", "failed", "rejected", "internal_error", "cancelled")

_EPOCH = datetime(2000, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class Detection:
    rule_id: str
    subject_key: str
    subject: dict[str, Any]
    summary: str
    evidence: dict[str, Any]
    impact: dict[str, Any] | None = None
    remediation: str | None = None


def _request_ids(
    condition: Any,
    request_id: Any = RequestLifecycle.request_id,
    started_at: Any = RequestLifecycle.started_at,
) -> Any:
    ordered = func.array_agg(aggregate_order_by(request_id, started_at)).filter(
        condition
    )
    return type_coerce(ordered, ARRAY(Text))[1:EVIDENCE_REQUEST_IDS]


def _priced_settlement(request_id: Any, tenant_id: UUID) -> Any:
    # One settlement per request at most, so this join never repeats a row.
    return (
        (UsageLedger.organization_id == tenant_id)
        & (UsageLedger.request_id == request_id)
        & (UsageLedger.event_type == "spend_settlement")
        & UsageLedger.event_metadata["pricing"]["pricing_resolution"]
        .as_string()
        .is_distinct_from("unknown")
    )


def _repeats(tenant_id: UUID, start: datetime, end: datetime) -> Any:
    """Each request of the window with its settlement and the request before it."""
    metadata = RequestLifecycle.lifecycle_metadata
    # Narrow columns only: the window sorts these rows, and the metadata they come
    # from is many times wider. MATERIALIZED stops Postgres folding the projection
    # back into the scan and carrying the metadata through the join and the sort.
    requests = (
        select(
            RequestLifecycle.id,
            RequestLifecycle.request_id,
            RequestLifecycle.api_key_id,
            RequestLifecycle.started_at,
            RequestLifecycle.status,
            # Null without prompt material, before digests, and (JSON null) with
            # personal data.
            metadata["repeat_digest"].as_string().label("digest"),
            metadata["repeat_chain_length"].as_integer().label("chain"),
        )
        .where(
            RequestLifecycle.organization_id == tenant_id,
            # The link window before start lets a repeat at the window's edge find
            # its predecessor.
            RequestLifecycle.started_at
            >= start - timedelta(seconds=REPEAT_LINK_WINDOW_SECONDS),
            RequestLifecycle.started_at < end,
            RequestLifecycle.api_key_id.is_not(None),
        )
        .cte("requests")
        .prefix_with("MATERIALIZED")
    )
    # One settlement per request at most, so this join never repeats a row.
    settlement = aliased(UsageLedger)
    billed = settlement.id.is_not(None)

    def previous(column: Any) -> Any:
        return func.lag(column).over(
            partition_by=(requests.c.api_key_id, requests.c.digest),
            order_by=(requests.c.started_at, requests.c.id),
        )

    return (
        select(
            requests.c.request_id,
            requests.c.api_key_id,
            requests.c.started_at,
            requests.c.status,
            requests.c.chain,
            case(
                (
                    settlement.event_metadata["pricing"]["pricing_resolution"]
                    .as_string()
                    .is_distinct_from("unknown"),
                    settlement.cost_usd,
                )
            ).label("cost"),
            requests.c.digest.is_not(None).label("digested"),
            (requests.c.chain >= 2).label("chained"),
            previous(requests.c.chain).label("previous_chain"),
            previous(billed).label("previous_billed"),
            previous(requests.c.request_id).label("previous_id"),
            previous(requests.c.started_at).label("previous_at"),
            previous(requests.c.status).label("previous_status"),
        )
        .select_from(requests)
        .outerjoin(
            settlement,
            (settlement.organization_id == tenant_id)
            & (settlement.request_id == requests.c.request_id)
            & (settlement.event_type == "spend_settlement"),
        )
        .subquery("repeats")
    )


def _repeat_terms(rows: Any) -> SimpleNamespace:
    link = timedelta(seconds=REPEAT_LINK_WINDOW_SECONDS)
    linked = and_(
        rows.c.digested,
        rows.c.previous_id.is_not(None),
        rows.c.started_at - rows.c.previous_at <= link,
    )
    kind = case(
        (rows.c.previous_status.in_(_TIMED_OUT), "after_timeout"),
        (rows.c.previous_status.in_(_FAILED), "after_error"),
        (rows.c.previous_status == "completed", "after_success"),
        else_="pending",
    )
    gap = func.extract("epoch", rows.c.started_at - rows.c.previous_at)
    pair = func.jsonb_build_object(
        "repeat",
        rows.c.request_id,
        "previous",
        rows.c.previous_id,
        "class",
        kind,
        "gap_seconds",
        func.round(gap),
    )
    unlinked = and_(not_(rows.c.digested), rows.c.chained)
    return SimpleNamespace(
        rows=rows,
        linked=linked,
        repeat=or_(linked, unlinked),
        # A chain without a digest has no link, but when the key's previous such
        # request carries one repeat less and was refunded, this is its retry.
        legacy=and_(
            unlinked,
            not_(
                and_(
                    rows.c.previous_chain.is_not_distinct_from(rows.c.chain - 1),
                    rows.c.started_at - rows.c.previous_at <= link,
                    not_(rows.c.previous_billed),
                )
            ),
        ),
        kind=kind,
        gap=gap,
        billed=func.coalesce(rows.c.previous_billed, False),
        pairs=func.array_to_json(
            type_coerce(
                func.array_agg(aggregate_order_by(pair, rows.c.started_at)).filter(
                    linked
                ),
                ARRAY(JSONB),
            )[1:EVIDENCE_REQUEST_IDS],
            type_=JSONB,
        ),
        classes=[
            func.count().filter(linked, kind == name).label(name)
            for name in REPEAT_CLASSES
        ],
    )


async def linked_repeats(
    session: AsyncSession, tenant_id: UUID, start: datetime, end: datetime
) -> list[Any]:
    """Every repeat started in [start, end) linked to the request it repeats."""
    terms = _repeat_terms(_repeats(tenant_id, start, end))
    rows = terms.rows
    return list(
        await session.execute(
            select(
                rows.c.request_id,
                rows.c.previous_id,
                rows.c.api_key_id,
                terms.gap.label("gap_seconds"),
                rows.c.previous_status,
                terms.kind.label("repeat_class"),
                terms.billed.label("previous_billed"),
                rows.c.cost.label("cost_usd"),
            )
            .where(rows.c.started_at >= start, terms.linked)
            .order_by(rows.c.started_at, rows.c.request_id)
        )
    )


def _classes(row: Any) -> dict[str, int]:
    return {name: getattr(row, name) for name in REPEAT_CLASSES}


async def _retry_storms(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    current = _EPOCH + (now - _EPOCH) // RETRY_BUCKET * RETRY_BUCKET
    start = current - RETRY_BUCKET * (RETRY_BUCKETS - 1)
    terms = _repeat_terms(_repeats(tenant_id, start, now))
    rows = terms.rows
    bucket = func.date_bin(RETRY_BUCKET, rows.c.started_at, _EPOCH)
    count = func.count().filter(terms.repeat)
    result = await session.execute(
        select(
            rows.c.api_key_id,
            bucket.label("bucket"),
            count.label("repeated"),
            func.count().filter(rows.c.status.in_(_TIMED_OUT)).label("abandoned"),
            func.coalesce(
                func.sum(rows.c.cost).filter(terms.repeat), Decimal("0")
            ).label("cost"),
            _request_ids(terms.repeat, rows.c.request_id, rows.c.started_at).label(
                "request_ids"
            ),
            terms.pairs.label("pairs"),
            *terms.classes,
        )
        .where(rows.c.started_at >= start)
        .group_by(rows.c.api_key_id, bucket)
        .having(count >= RETRY_STORM_MIN_REQUESTS)
        .order_by(rows.c.api_key_id, count.desc(), bucket.desc())
    )
    worst: dict[UUID, Any] = {}
    for row in result:
        worst.setdefault(row.api_key_id, row)
    detections = []
    for key_id, row in worst.items():
        classes = _classes(row)
        cause = max(STORM_FIXES, key=lambda name: classes[name])
        detections.append(
            Detection(
                rule_id=RETRY_STORM,
                subject_key=f"api_key:{key_id}",
                subject={"api_key_id": str(key_id)},
                summary=(
                    f"One API key sent {row.repeated} repeated requests in the 15 "
                    f"minutes from {row.bucket:%Y-%m-%d %H:%M} UTC."
                ),
                evidence={
                    "window_start": row.bucket.isoformat(),
                    "window_minutes": 15,
                    "repeated_requests": row.repeated,
                    "threshold": RETRY_STORM_MIN_REQUESTS,
                    "abandoned_requests": row.abandoned,
                    "request_ids": list(row.request_ids or []),
                    "classes": classes,
                    "pairs": row.pairs or [],
                },
                impact={"cost_usd": str(row.cost), "requests": row.repeated},
                remediation=STORM_FIXES[cause] if classes[cause] else None,
            )
        )
    return detections


async def _repeat_spend(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    month_start = now.astimezone(timezone.utc).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    terms = _repeat_terms(_repeats(tenant_id, month_start, now))
    rows = terms.rows
    # A repeat of a refunded request did not double the bill.
    counted = or_(and_(terms.linked, terms.billed), terms.legacy)
    known = func.coalesce(func.sum(rows.c.cost), Decimal("0"))
    repeated_cost = func.coalesce(func.sum(rows.c.cost).filter(counted), Decimal("0"))
    # The window sort of a busy month needs more than the 4MB default to stay in memory.
    await session.execute(text("SET LOCAL work_mem = '32MB'"))
    result = await session.execute(
        select(
            rows.c.api_key_id,
            known.label("known"),
            repeated_cost.label("repeated_cost"),
            func.count().filter(counted).label("repeated"),
            func.count().filter(terms.linked, terms.billed).label("billed"),
            func.count()
            .filter(terms.linked, not_(terms.billed), terms.kind != "pending")
            .label("unbilled"),
            _request_ids(counted, rows.c.request_id, rows.c.started_at).label(
                "request_ids"
            ),
            terms.pairs.label("pairs"),
            *terms.classes,
        )
        .where(rows.c.started_at >= month_start)
        .group_by(rows.c.api_key_id)
        .having(
            repeated_cost >= REPEAT_SPEND_MIN_USD,
            repeated_cost >= known * REPEAT_SPEND_MIN_SHARE,
        )
        .order_by(rows.c.api_key_id)
    )
    return [
        Detection(
            rule_id=REPEAT_SPEND,
            subject_key=f"api_key:{row.api_key_id}",
            subject={"api_key_id": str(row.api_key_id)},
            summary=(
                f"Repeated requests cost {row.repeated_cost:.2f} USD of this API "
                f"key's {row.known:.2f} USD known spend this month."
            ),
            evidence={
                "period_start": month_start.isoformat(),
                "repeated_cost_usd": str(row.repeated_cost),
                "known_spend_usd": str(row.known),
                "share": str(round(row.repeated_cost / row.known, 4)),
                "repeated_requests": row.repeated,
                "request_ids": list(row.request_ids or []),
                "classes": _classes(row),
                "billed_repeats": row.billed,
                "unbilled_repeats": row.unbilled,
                "pairs": row.pairs or [],
            },
            impact={"cost_usd": str(row.repeated_cost), "requests": row.repeated},
        )
        for row in result
    ]


async def _deployments(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    """Unused and idle internal deployments, from one read of their traffic."""
    window = timedelta(days=DEPLOYMENT_WINDOW_DAYS)
    deployments = (
        await session.execute(
            select(
                ModelDeployment.id,
                ModelDeployment.alias,
                ModelDeployment.deployment_kind,
                ModelDeployment.created_at,
            )
            .where(
                ModelDeployment.organization_id == tenant_id,
                ModelDeployment.enabled.is_(True),
                ModelDeployment.created_at <= now - window,
            )
            .order_by(ModelDeployment.alias)
        )
    ).all()
    if not deployments:
        return []
    joined, target = registry_traffic(tenant_id)
    traffic = {
        row.deployment_id: row
        for row in await session.execute(
            select(
                target.label("deployment_id"),
                func.count().label("requests"),
                func.count(
                    func.distinct(
                        func.date(func.timezone("UTC", RequestLifecycle.started_at))
                    )
                ).label("active_days"),
                func.max(RequestLifecycle.started_at).label("last_request_at"),
                func.count(func.distinct(RequestLifecycle.api_key_id)).label(
                    "api_keys"
                ),
                _request_ids(True).label("request_ids"),
            )
            .select_from(joined)
            .where(
                RequestLifecycle.organization_id == tenant_id,
                RequestLifecycle.started_at >= now - window,
                RequestLifecycle.started_at <= now,
                target.in_([str(row.id) for row in deployments]),
            )
            .group_by(target)
        )
    }
    detections = []
    for row in deployments:
        used = traffic.get(str(row.id))
        if used is None:
            detections.append(
                Detection(
                    rule_id=UNUSED_DEPLOYMENT,
                    subject_key=f"deployment:{row.alias}",
                    subject={"deployment_id": str(row.id), "alias": row.alias},
                    summary=(
                        f"Deployment {row.alias} has had no requests in "
                        f"{DEPLOYMENT_WINDOW_DAYS} days."
                    ),
                    evidence={
                        "created_at": row.created_at.isoformat(),
                        "window_days": DEPLOYMENT_WINDOW_DAYS,
                        "requests": 0,
                    },
                )
            )
        # External deployments hold no hardware of the tenant.
        elif (
            row.deployment_kind == "internal"
            and used.requests < IDLE_DEPLOYMENT_MAX_REQUESTS
        ):
            detections.append(
                Detection(
                    rule_id=IDLE_INTERNAL_DEPLOYMENT,
                    subject_key=str(row.id),
                    subject={"deployment_id": str(row.id), "alias": row.alias},
                    summary=(
                        f"Internal deployment {row.alias} served {used.requests} "
                        f"requests in {DEPLOYMENT_WINDOW_DAYS} days."
                    ),
                    evidence={
                        "window_days": DEPLOYMENT_WINDOW_DAYS,
                        "requests": used.requests,
                        "threshold": IDLE_DEPLOYMENT_MAX_REQUESTS,
                        "active_days": used.active_days,
                        "last_request_at": used.last_request_at.isoformat(),
                        "api_keys": used.api_keys,
                        "request_ids": list(used.request_ids or []),
                        "hardware_cost": "not recorded",
                    },
                    impact={"cost_usd": None, "requests": used.requests},
                )
            )
    return detections


async def _unregistered_models(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    # A tenant without a registry routes by catalog on purpose.
    if not await session.scalar(
        select(ModelDeployment.id)
        .where(
            ModelDeployment.organization_id == tenant_id,
            ModelDeployment.enabled.is_(True),
        )
        .limit(1)
    ):
        return []
    window = (
        RequestLifecycle.organization_id == tenant_id,
        RequestLifecycle.started_at
        >= now - timedelta(days=UNREGISTERED_MODEL_WINDOW_DAYS),
        RequestLifecycle.started_at <= now,
    )
    catalog, model = catalog_traffic(*window)
    count = func.count()
    rows = await session.execute(
        select(
            RequestLifecycle.provider,
            model.label("model"),
            count.label("requests"),
            func.count(func.distinct(RequestLifecycle.api_key_id)).label("keys"),
            type_coerce(
                func.array_agg(func.distinct(cast(RequestLifecycle.api_key_id, Text))),
                ARRAY(Text),
            )[1:EVIDENCE_KEY_IDS].label("key_ids"),
            func.count(
                func.distinct(
                    RequestLifecycle.lifecycle_metadata["team_id"].as_string()
                )
            ).label("teams"),
            func.min(RequestLifecycle.started_at).label("first_seen"),
            func.max(RequestLifecycle.started_at).label("last_seen"),
            _request_ids(True).label("request_ids"),
            func.count().filter(byok_request()).label("byok"),
            func.coalesce(func.sum(UsageLedger.cost_usd), Decimal("0")).label("cost"),
        )
        .select_from(
            catalog.outerjoin(
                UsageLedger, _priced_settlement(RequestLifecycle.request_id, tenant_id)
            )
        )
        .where(*window)
        .group_by(RequestLifecycle.provider, model)
        .having(count >= UNREGISTERED_MODEL_MIN_REQUESTS)
        .order_by(RequestLifecycle.provider, model)
    )
    return [
        Detection(
            rule_id=UNREGISTERED_MODEL,
            subject_key=f"{row.provider}:{row.model}",
            subject={"provider": row.provider, "model": row.model},
            summary=(
                f"{row.requests} requests in 7 days used {row.model} "
                f"through {row.provider}'s public endpoint, outside the registry."
            ),
            evidence={
                "window_days": UNREGISTERED_MODEL_WINDOW_DAYS,
                "requests": row.requests,
                "threshold": UNREGISTERED_MODEL_MIN_REQUESTS,
                "api_keys": row.keys,
                "api_key_ids": sorted(row.key_ids or []),
                "teams": row.teams,
                "first_seen": row.first_seen.isoformat(),
                "last_seen": row.last_seen.isoformat(),
                "request_ids": list(row.request_ids or []),
                "byok_requests": row.byok,
            },
            impact={"cost_usd": str(row.cost), "requests": row.requests},
        )
        for row in rows
    ]


async def _byok_usage(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    # A tenant that never stored a provider key uses its own keys as its only mode.
    managed = select(ProviderSecret.provider).where(
        ProviderSecret.organization_id == tenant_id
    )
    window = (
        RequestLifecycle.organization_id == tenant_id,
        RequestLifecycle.started_at >= now - timedelta(days=BYOK_USAGE_WINDOW_DAYS),
        RequestLifecycle.started_at <= now,
    )
    # A caller's own provider key is honoured on catalog routes only.
    catalog, model = catalog_traffic(*window)
    rows = await session.execute(
        select(
            RequestLifecycle.api_key_id,
            RequestLifecycle.provider,
            func.count().label("requests"),
            type_coerce(func.array_agg(func.distinct(model)), ARRAY(Text))[
                1:EVIDENCE_MODELS
            ].label("models"),
            _request_ids(True).label("request_ids"),
            func.coalesce(func.sum(UsageLedger.cost_usd), Decimal("0")).label("cost"),
        )
        .select_from(
            catalog.outerjoin(
                UsageLedger, _priced_settlement(RequestLifecycle.request_id, tenant_id)
            )
        )
        .where(
            *window,
            RequestLifecycle.api_key_id.is_not(None),
            RequestLifecycle.provider.in_(managed),
            byok_request(),
        )
        .group_by(RequestLifecycle.api_key_id, RequestLifecycle.provider)
        .order_by(RequestLifecycle.api_key_id, RequestLifecycle.provider)
    )
    by_key: dict[UUID, list[Any]] = {}
    for row in rows:
        by_key.setdefault(row.api_key_id, []).append(row)
    detections = []
    for key_id, providers in by_key.items():
        requests = sum(row.requests for row in providers)
        if requests < BYOK_USAGE_MIN_REQUESTS:
            continue
        cost = sum((row.cost for row in providers), Decimal("0"))
        detections.append(
            Detection(
                rule_id=BYOK_USAGE,
                subject_key=f"api_key:{key_id}",
                subject={"api_key_id": str(key_id)},
                summary=(
                    f"One API key sent {requests} requests with its own provider key "
                    "in 7 days, past the provider spend limit."
                ),
                evidence={
                    "window_days": BYOK_USAGE_WINDOW_DAYS,
                    "requests": {row.provider: row.requests for row in providers},
                    "threshold": BYOK_USAGE_MIN_REQUESTS,
                    "models": sorted(
                        {model for row in providers for model in row.models or []}
                    )[:EVIDENCE_MODELS],
                    "request_ids": [
                        request
                        for row in providers
                        for request in row.request_ids or []
                    ][:EVIDENCE_REQUEST_IDS],
                    "cost_usd": str(cost),
                    "note": "These requests skipped the provider spend limit and the "
                    "tenant's stored provider key.",
                },
                impact={"cost_usd": str(cost), "requests": requests},
            )
        )
    return detections


def _outcome_counts() -> tuple[Any, Any, tuple[Any, ...]]:
    """The answer's outcome, the settled count, and the settled and per-outcome columns."""
    outcome = RequestLifecycle.lifecycle_metadata["completion_outcome"].as_string()
    settled = func.count().filter(outcome.is_not(None))
    return (
        outcome,
        settled,
        (
            settled.label("settled"),
            *(func.count().filter(outcome == name).label(name) for name in OUTCOMES),
        ),
    )


async def _answer_quality(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    model = shown_model(
        func.coalesce(RequestLifecycle.provider_model, RequestLifecycle.requested_model)
    )
    outcome, settled, counts = _outcome_counts()
    rows = await session.execute(
        select(
            model.label("model"),
            *counts,
            _request_ids(outcome.in_(("truncated", "empty", "refused"))).label(
                "request_ids"
            ),
        )
        .where(
            RequestLifecycle.organization_id == tenant_id,
            RequestLifecycle.started_at >= now - ANSWER_QUALITY_WINDOW,
            RequestLifecycle.started_at <= now,
        )
        .group_by(model)
        .having(settled >= ANSWER_QUALITY_MIN_REQUESTS)
        .order_by(model)
    )
    detections = []
    for row in rows:
        truncated_rate = Decimal(row.truncated) / row.settled
        unanswered_rate = Decimal(row.empty + row.refused) / row.settled
        if max(truncated_rate, unanswered_rate) < ANSWER_QUALITY_MIN_RATE:
            continue
        detections.append(
            Detection(
                rule_id=ANSWER_QUALITY,
                subject_key=f"model:{row.model}",
                subject={"model": row.model},
                summary=(
                    f"In the last 24 hours {row.model} truncated {row.truncated} and "
                    f"left empty or refused {row.empty + row.refused} of "
                    f"{row.settled} answers."
                ),
                evidence={
                    "window_hours": 24,
                    "settled_requests": row.settled,
                    "truncated": row.truncated,
                    "empty": row.empty,
                    "refused": row.refused,
                    "truncated_rate": str(round(truncated_rate, 4)),
                    "empty_or_refused_rate": str(round(unanswered_rate, 4)),
                    "threshold_rate": str(ANSWER_QUALITY_MIN_RATE),
                    "request_ids": list(row.request_ids or []),
                },
            )
        )
    return detections


async def _outcome_rates(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    outcome, settled, counts = _outcome_counts()
    unanswered = outcome.in_(("refused", "filtered", "empty"))
    window = (
        RequestLifecycle.organization_id == tenant_id,
        RequestLifecycle.started_at >= now - timedelta(hours=OUTCOME_RATE_WINDOW_HOURS),
        RequestLifecycle.started_at <= now,
        RequestLifecycle.api_key_id.is_not(None),
    )
    keys = {
        row.api_key_id: row
        for row in await session.execute(
            select(
                RequestLifecycle.api_key_id,
                *counts,
                _request_ids(outcome == "truncated").label("truncated_ids"),
                _request_ids(unanswered).label("unanswered_ids"),
            )
            .where(*window)
            .group_by(RequestLifecycle.api_key_id)
            .having(settled >= OUTCOME_RATE_MIN_SETTLED)
        )
    }
    if not keys:
        return []
    models: dict[UUID, list[Any]] = {}
    model = shown_model(RequestLifecycle.requested_model)
    for row in await session.execute(
        select(RequestLifecycle.api_key_id, model.label("model"), *counts)
        .where(*window, RequestLifecycle.api_key_id.in_(list(keys)))
        .group_by(RequestLifecycle.api_key_id, model)
        .order_by(RequestLifecycle.api_key_id, settled.desc(), model)
    ):
        models.setdefault(row.api_key_id, []).append(row)
    detections = []
    for key_id, row in sorted(keys.items()):
        top = models[key_id][:EVIDENCE_MODELS_PER_KEY]
        unanswered_count = row.refused + row.filtered + row.empty
        for rule_id, count, threshold, ids, fields, ended in (
            (
                TRUNCATION_RATE,
                row.truncated,
                TRUNCATION_RATE_THRESHOLD,
                row.truncated_ids,
                ("truncated",),
                "stopped at the output limit",
            ),
            (
                REFUSAL_RATE,
                unanswered_count,
                REFUSAL_RATE_THRESHOLD,
                row.unanswered_ids,
                ("refused", "filtered", "empty"),
                "were refused, filtered or empty",
            ),
        ):
            rate = Decimal(count) / row.settled
            if rate < threshold:
                continue
            detections.append(
                Detection(
                    rule_id=rule_id,
                    subject_key=f"api_key:{key_id}",
                    subject={"api_key_id": str(key_id)},
                    summary=(
                        f"{count} of {row.settled} answers to this API key in "
                        f"{OUTCOME_RATE_WINDOW_HOURS} hours {ended}."
                    ),
                    evidence={
                        "window_hours": OUTCOME_RATE_WINDOW_HOURS,
                        "settled_requests": row.settled,
                        **{field: getattr(row, field) for field in fields},
                        "rate": str(round(rate, 4)),
                        "threshold_rate": str(threshold),
                        "models": [
                            {
                                "model": item.model,
                                "settled": item.settled,
                                **{field: getattr(item, field) for field in fields},
                            }
                            for item in top
                        ],
                        "request_ids": list(ids or []),
                    },
                    impact={"cost_usd": None, "requests": count},
                )
            )
    return detections


async def evaluate_organization(
    session: AsyncSession, tenant_id: UUID, *, now: datetime
) -> list[Detection]:
    # Each rule and the rule ids it raises. A rule that fails is rolled back alone
    # and leaves its open findings as they are; the other rules still run.
    rules = (
        (_retry_storms, (RETRY_STORM,)),
        (_repeat_spend, (REPEAT_SPEND,)),
        (_deployments, (UNUSED_DEPLOYMENT, IDLE_INTERNAL_DEPLOYMENT)),
        (_unregistered_models, (UNREGISTERED_MODEL,)),
        (_byok_usage, (BYOK_USAGE,)),
        (_answer_quality, (ANSWER_QUALITY,)),
        (_outcome_rates, (TRUNCATION_RATE, REFUSAL_RATE)),
    )
    detections: list[Detection] = []
    failed: list[str] = []
    for rule, rule_ids in rules:
        try:
            async with session.begin_nested():
                found = await rule(session, tenant_id, now)
                for detection in found:
                    title, severity_id, fix = RULES[detection.rule_id]
                    statement = insert(Finding).values(
                        organization_id=tenant_id,
                        rule_id=detection.rule_id,
                        rule_version=RULE_VERSIONS.get(detection.rule_id, RULE_VERSION),
                        subject_key=detection.subject_key,
                        subject=detection.subject,
                        title=title,
                        summary=detection.summary,
                        severity_id=severity_id,
                        first_seen_at=now,
                        last_seen_at=now,
                        evidence=detection.evidence,
                        impact=detection.impact,
                        remediation={
                            "text": detection.remediation or fix,
                            "reversible": True,
                            "doc": "ee/docs/FINDINGS.md#"
                            + detection.rule_id.replace(".", ""),
                        },
                    )
                    await session.execute(
                        statement.on_conflict_do_update(
                            index_elements=[
                                "organization_id",
                                "rule_id",
                                "subject_key",
                            ],
                            index_where=Finding.status_id != STATUS_RESOLVED,
                            set_={
                                "last_seen_at": now,
                                "occurrences": Finding.occurrences + 1,
                                "summary": statement.excluded.summary,
                                "evidence": statement.excluded.evidence,
                                "impact": statement.excluded.impact,
                                "rule_version": statement.excluded.rule_version,
                                "remediation": statement.excluded.remediation,
                                "updated_at": func.now(),
                            },
                        )
                    )
        except Exception as exc:
            failed += rule_ids
            logger.error(
                "Findings rule failed organization_id=%s rules=%s type=%s",
                tenant_id,
                ",".join(rule_ids),
                type(exc).__name__,
            )
        else:
            detections += found
    await session.execute(
        update(Finding)
        .where(
            Finding.organization_id == tenant_id,
            Finding.status_id != STATUS_RESOLVED,
            Finding.last_seen_at < now - AUTO_RESOLVE_AFTER,
            Finding.rule_id.not_in(failed),
        )
        .values(status_id=STATUS_RESOLVED, resolved_at=now, resolved_by="system")
    )
    return detections


async def evaluate_findings(
    session_factory: Callable[[], Any], *, now: datetime
) -> None:
    """Evaluate every rule for every active organization, one transaction each."""
    async with session_factory() as session:
        tenant_ids = (
            await session.scalars(
                select(Organization.id).where(Organization.archived_at.is_(None))
            )
        ).all()
    for tenant_id in tenant_ids:
        async with session_factory() as session:
            try:
                await evaluate_organization(session, tenant_id, now=now)
                await session.commit()
            except Exception as exc:
                await session.rollback()
                logger.error(
                    "Findings evaluation failed organization_id=%s type=%s",
                    tenant_id,
                    type(exc).__name__,
                )


def ocsf_detection_finding(finding: Finding) -> dict[str, Any]:
    if finding.status_id == STATUS_RESOLVED:
        activity_id = 3
    elif finding.occurrences > 1 or finding.status_id != STATUS_IDS["new"]:
        activity_id = 2
    else:
        activity_id = 1
    return {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": activity_id,
        "type_uid": 200400 + activity_id,
        "time": _epoch_ms(finding.resolved_at or finding.last_seen_at),
        "severity_id": finding.severity_id,
        "status_id": finding.status_id,
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "shim", "vendor_name": "shim"},
        },
        "finding_info": {
            "uid": str(finding.id),
            "title": finding.title,
            "desc": finding.summary,
            "first_seen_time": _epoch_ms(finding.first_seen_at),
            "last_seen_time": _epoch_ms(finding.last_seen_at),
        },
        "unmapped": {
            "rule_id": finding.rule_id,
            "rule_version": finding.rule_version,
            "subject": finding.subject,
            "occurrences": finding.occurrences,
            "evidence": finding.evidence,
            "impact": finding.impact,
            "remediation": finding.remediation,
        },
    }


def _epoch_ms(value: datetime) -> int:
    return int(value.timestamp() * 1000)
