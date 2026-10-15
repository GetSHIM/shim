"""Preview estimators for destination rules and request caps, from stored metadata.

Each counts the requests of a window a new rule would have matched, from what the
record already holds: detected entity types, the target's kind, the admission byte
estimate, the settled price-tier warning and the `shape` analyzer's counts. No
content is stored, so none is read; a note names labels, never values.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import (
    ColumnElement,
    Float,
    and_,
    case,
    exists,
    func,
    not_,
    or_,
    select,
)
from sqlalchemy.dialects.postgresql import array
from sqlalchemy.ext.asyncio import AsyncSession

from shim.billing.pricing import DATE_SUFFIX, DEFAULT_PRICE_BOOK
from shim.privacy.policies import PII_CONFIG_DEFAULTS, effective_entity_actions
from shim.rules import Rule, RuleScope
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.rules.preview import (
    PREVIEW_ESTIMATORS,
    PreviewCount,
    count_matching,
)
from shim_enterprise.rules.route_triggers import ShadowMatch
from shim_enterprise.tenants.models import ModelDeployment, OrganizationPIIConfig

# A scope's protocol name to the record's `source_endpoint`, as the kernel maps it.
ENDPOINT_SOURCE = {
    "chat": "chat.completions",
    "responses": "responses",
    "messages": "messages",
    "count_tokens": "messages.count_tokens",
    "generate_content": "generateContent",
}
SHAPE_FIELDS = {
    "max_tools": "tool_count",
    "max_documents": "document_count",
    "max_history": "message_count",
}
COUNT_TOKENS_NOTE = (
    "count_tokens requests never reach the record and are exempt from request caps"
)
SHAPE_DEFINITIONS_NOTE = (
    "shape counts follow the analyzer's definitions (S37): Gemini audio and video "
    "parts count as documents and documents inside Anthropic tool results are not "
    "counted"
)
PRICE_TIER_NOTE = (
    "requests whose settled input crossed the tier; an enforced block refuses the "
    "subset that is certain before the call"
)

_metadata = RequestLifecycle.lifecycle_metadata


def scope_conditions(scope: RuleScope) -> list[ColumnElement[bool]]:
    """The rule's scope as conditions on the record, with the gateway's semantics."""
    conditions: list[ColumnElement[bool]] = []
    if scope.api_key_ids:
        conditions.append(
            RequestLifecycle.api_key_id.in_([UUID(key) for key in scope.api_key_ids])
        )
    if scope.team_ids:
        conditions.append(_metadata["team_id"].astext.in_(scope.team_ids))
    if scope.tags:
        conditions.append(_metadata["tags"].has_any(array(scope.tags)))
    if scope.models:
        # The model the request reached, never the alias the caller named; the
        # gateway stores it as `provider_model` before the provider call.
        reached = func.lower(RequestLifecycle.provider_model)
        wanted = [model.casefold() for model in scope.models]
        conditions.append(
            or_(
                reached.in_(wanted),
                func.regexp_replace(reached, DATE_SUFFIX.pattern, "").in_(wanted),
            )
        )
    if scope.deployment_kinds:
        # An unclassified target is treated as external.
        kinds = [*scope.deployment_kinds]
        if "external" in kinds:
            kinds.append("unknown")
        conditions.append(_metadata["deployment_kind"].astext.in_(kinds))
    if scope.endpoints:
        conditions.append(
            RequestLifecycle.source_endpoint.in_(
                [ENDPOINT_SOURCE[endpoint] for endpoint in scope.endpoints]
            )
        )
    return conditions


def _notes(rule: Rule, *notes: str | None) -> str | None:
    named = [
        *([COUNT_TOKENS_NOTE] if rule.scope.endpoints == ("count_tokens",) else []),
        *(note for note in notes if note),
    ]
    return "; ".join(named) or None


async def _counted(
    session: AsyncSession,
    organization_id: UUID,
    rule: Rule,
    start: datetime,
    end: datetime,
    condition: ColumnElement[bool],
    *notes: str | None,
) -> PreviewCount:
    requests, _, by_scope = await count_matching(
        session,
        organization_id,
        start,
        end,
        and_(condition, *scope_conditions(rule.scope)),
    )
    return {"requests": requests, "by_scope": by_scope, "note": _notes(rule, *notes)}


async def estimate_destination(
    session: AsyncSession,
    organization_id: UUID,
    rule: Rule,
    start: datetime,
    end: datetime,
) -> PreviewCount:
    """Requests whose record shows a named type detected, masked or monitored.

    Only a request that reached the privacy stage carries those keys, which is where
    the rule is evaluated; a type the base action blocked is not counted.
    """
    types = list(rule.match["entity_types"])
    config = await session.scalar(
        select(OrganizationPIIConfig).where(
            OrganizationPIIConfig.organization_id == organization_id
        )
    )
    actions = (
        effective_entity_actions()
        if config is None
        else effective_entity_actions(
            {name: getattr(config, name) for name in PII_CONFIG_DEFAULTS},
            config.entity_actions,
        )
    )
    off = [entity_type for entity_type in types if actions.get(entity_type) == "off"]
    return await _counted(
        session,
        organization_id,
        rule,
        start,
        end,
        or_(
            _metadata["pii_entities"].has_any(array(types)),
            _metadata["monitored_entities"].has_any(array(types)),
        ),
        f"types {', '.join(off)} have base action off; they were not detected in "
        "the window and are not counted (S43 enables their detection once the rule "
        "exists)"
        if off
        else None,
    )


async def estimate_request_limit(
    session: AsyncSession,
    organization_id: UUID,
    rule: Rule,
    start: datetime,
    end: datetime,
) -> PreviewCount | None:
    """Requests that crossed any of the rule's caps, each counted once.

    None when a shape cap is asked for and no request of the window carries the
    `shape` analyzer's counts: such a rule starts in monitor.
    """
    match: dict[str, Any] = rule.match
    window = (
        RequestLifecycle.organization_id == organization_id,
        RequestLifecycle.started_at >= start,
        RequestLifecycle.started_at < end,
    )
    shaped = _metadata["response_analysis"].has_key("shape")
    media = _metadata.has_key("media_parts")
    crossed: list[ColumnElement[bool]] = []
    notes: list[str | None] = []
    shape_caps = {
        cap: field for cap, field in SHAPE_FIELDS.items() if match.get(cap) is not None
    }
    if shape_caps:
        if not await session.scalar(select(exists().where(*window, shaped))):
            return None
        for cap, field in shape_caps.items():
            value = _metadata["response_analysis"]["shape"][field]
            # A count that is not a number is never counted; CASE keeps the cast safe.
            crossed.append(
                case(
                    (func.jsonb_typeof(value) == "number", value.astext.cast(Float)),
                    else_=None,
                )
                > match[cap]
            )
    if match.get("max_input_bytes") is not None:
        # The admission byte estimate is reserved as is; a media request reserves
        # text bytes plus media tokens, so it is left out and named in the note.
        crossed.append(
            and_(
                exists().where(
                    UsageLedger.organization_id == RequestLifecycle.organization_id,
                    UsageLedger.request_id == RequestLifecycle.request_id,
                    UsageLedger.event_type == "quota_reservation",
                    UsageLedger.prompt_tokens > match["max_input_bytes"],
                ),
                not_(media),
            )
        )
    if match.get("below_price_tier"):
        crossed.append(_metadata["warnings"].contains(["LARGE_CONTEXT_PRICE"]))
        notes.append(PRICE_TIER_NOTE)
    if shape_caps or match.get("max_input_bytes") is not None:
        carrying, total, with_media = (
            await session.execute(
                select(
                    func.count().filter(shaped),
                    func.count(),
                    func.count().filter(media),
                ).where(*window, *scope_conditions(rule.scope))
            )
        ).one()
        if shape_caps:
            notes.append(
                f"tools, documents and history counted on {carrying} of {total} "
                "requests that carry shape analysis"
            )
            notes.append(SHAPE_DEFINITIONS_NOTE)
        if match.get("max_input_bytes") is not None and with_media:
            notes.append(f"{with_media} requests with media parts not counted")
    return await _counted(
        session,
        organization_id,
        rule,
        start,
        end,
        or_(*crossed),
        *notes,
    )


async def change_test_estimate(
    session: AsyncSession,
    organization_id: UUID,
    rule: Rule,
    start: datetime,
    end: datetime,
) -> dict[str, Any]:
    """What a `shadow` rule would have copied over the window, and what it would have
    cost at the candidate's price: the share of completed requests to `from`."""

    match = ShadowMatch.model_validate(rule.match)
    # The scope fields the record carries; the reached model is `from` by definition.
    scope = rule.scope.model_copy(update={"models": (), "deployment_kinds": ()})
    completed = and_(
        RequestLifecycle.requested_model == match.from_,
        RequestLifecycle.status == "completed",
        *scope_conditions(scope),
    )
    requests, _, by_scope = await count_matching(
        session, organization_id, start, end, completed
    )
    prompt, completion = (
        await session.execute(
            select(
                func.coalesce(func.sum(UsageLedger.prompt_tokens), 0),
                func.coalesce(func.sum(UsageLedger.completion_tokens), 0),
            )
            .join(
                RequestLifecycle,
                and_(
                    RequestLifecycle.organization_id == UsageLedger.organization_id,
                    RequestLifecycle.request_id == UsageLedger.request_id,
                ),
            )
            .where(
                UsageLedger.organization_id == organization_id,
                UsageLedger.event_type == "quota_settlement",
                RequestLifecycle.started_at >= start,
                RequestLifecycle.started_at < end,
                completed,
            )
        )
    ).one()
    candidate = await session.scalar(
        select(ModelDeployment).where(
            ModelDeployment.organization_id == organization_id,
            ModelDeployment.alias == match.to,
        )
    )
    prices = None
    if candidate is not None and candidate.input_price_per_million is not None:
        prices = (
            candidate.input_price_per_million,
            candidate.output_price_per_million,
        )
    elif candidate is not None and DEFAULT_PRICE_BOOK.supports(
        candidate.upstream_model, candidate.provider
    ):
        price = DEFAULT_PRICE_BOOK.resolve(candidate.upstream_model, candidate.provider)
        prices = (price.input_per_million, price.output_per_million)
    share = Decimal(str(match.share_percent)) / 100
    extra = (
        None
        if prices is None
        else (prompt * prices[0] + completion * (prices[1] or 0)) * share / 1_000_000
    )
    return {
        "requests": requests,
        "would_copy": min(int(requests * share), match.max_requests),
        "extra_cost_usd": None if extra is None else str(round(extra, 6)),
        "priced": extra is not None,
        "by_scope": by_scope,
    }


async def estimate_change_test(
    session: AsyncSession,
    organization_id: UUID,
    rule: Rule,
    start: datetime,
    end: datetime,
) -> PreviewCount:
    estimate = await change_test_estimate(session, organization_id, rule, start, end)
    return {
        "requests": estimate["would_copy"],
        "by_scope": estimate["by_scope"],
        "note": f"estimated extra cost USD {estimate['extra_cost_usd']}"
        if estimate["priced"]
        else "candidate unpriced",
    }


PREVIEW_ESTIMATORS.update(
    {
        "destination": estimate_destination,
        "request_limit": estimate_request_limit,
        "route:shadow": estimate_change_test,
    }
)
