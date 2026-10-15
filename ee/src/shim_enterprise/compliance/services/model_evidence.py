"""Model evidence documents: why this model, and where requests went and what it saved.

Measurement only: every number is read from the organization's own gateway records
for the document's window, and the document says what it does not prove.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from decimal import ROUND_HALF_EVEN, Decimal
from hashlib import sha256
import json
from typing import Any
from uuid import UUID

from sqlalchemy import (
    ColumnElement,
    Float,
    and_,
    case,
    cast,
    func,
    literal,
    not_,
    or_,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession

from shim.billing.pricing import DEFAULT_PRICE_BOOK, ModelPrice
from shim.rules import Rule, RuleSet
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.compliance.reporting import (
    build_pdf,
    evidence_table,
    report_styles,
)
from shim_enterprise.observability.analytics_projection import RequestLog
from shim_enterprise.observability.language_cost import (
    LANGUAGE_COST_MIN_REQUESTS,
    language_cost,
)
from shim_enterprise.observability.outcomes import OUTCOMES
from shim_enterprise.rules.canaries import canary_sides
from shim_enterprise.rules.change_tests import change_test_results
from shim_enterprise.tenants.models import ModelDeployment

FORMAT = "shim.model_evidence"
VERSION = 1
NOT_RECORDED = "not recorded in this version"
COVER = (
    "This document is a measurement of gateway traffic shim recorded for this "
    "organization. It is not an audit, an assessment or a certification, and it "
    "contains no prompt, answer or detected value."
)
LIMITS = {
    "no_answer_review": "No person and no model read the answers. Matching outcome "
    "classes, schema validity and lengths do not show that an answer was correct.",
    "different_populations": "Routed requests were chosen by the rule's conditions; "
    "comparing them with requests that were not routed compares different kinds of "
    "requests.",
    "copy_timing": "Shadow copies were sent after the primary answer, under different "
    "load; latency differences are indicative.",
    "token_estimate": "Counterfactual costs reuse the tokens the other model billed; "
    "another tokenizer bills differently, and the language adjustment covers output "
    "tokens only.",
    "prices_in_force": "Costs use the prices recorded at settlement; list prices change.",
    "window_only": "The numbers describe this organization's traffic in this window. "
    "They are not a benchmark.",
    "masked_input": "Candidates received the payload after masking, as the primary did.",
}
# Extra attempts S57 adds are not routing decisions a rule's savings count.
ATTEMPT_REASONS = ("fallback", "overflow", "format_retry", "canary_fallback", "degrade")
_QUANTUM = Decimal("1e-10")


def money(value: Decimal | None) -> str | None:
    return None if value is None else str(value.quantize(_QUANTUM, ROUND_HALF_EVEN))


def facts_digest(facts: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        facts, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )
    return sha256(canonical.encode()).hexdigest()


async def _deployment(
    session: AsyncSession, tenant_id: UUID, name: str
) -> ModelDeployment | None:
    return await session.scalar(
        select(ModelDeployment).where(
            ModelDeployment.organization_id == tenant_id, ModelDeployment.alias == name
        )
    )


async def route_price(
    session: AsyncSession, tenant_id: UUID, name: str, provider: str
) -> ModelPrice | None:
    """A registry alias by its deployment price, else the catalog price of its upstream
    model (or of the name), else None."""
    deployment = await _deployment(session, tenant_id, name)
    if deployment is not None and deployment.input_price_per_million is not None:
        return ModelPrice(
            deployment.input_price_per_million,
            deployment.output_price_per_million or Decimal(0),
        )
    model = deployment.upstream_model if deployment is not None else name
    if DEFAULT_PRICE_BOOK.supports(model, provider):
        return DEFAULT_PRICE_BOOK.resolve(model, provider)
    return None


async def _models(
    session: AsyncSession, tenant_id: UUID, names: Sequence[str]
) -> list[dict[str, Any]]:
    models = []
    for name in names:
        deployment = await _deployment(session, tenant_id, name)
        provider = deployment.provider if deployment is not None else _provider(name)
        upstream = deployment.upstream_model if deployment is not None else name
        if deployment is not None and deployment.input_price_per_million is not None:
            source = "deployment"
            prices = (
                deployment.input_price_per_million,
                deployment.output_price_per_million,
            )
        elif provider is not None and DEFAULT_PRICE_BOOK.supports(upstream, provider):
            source = "catalog"
            price = DEFAULT_PRICE_BOOK.resolve(upstream, provider)
            prices = (price.input_per_million, price.output_per_million)
        else:
            source, prices = "unpriced", (None, None)
        models.append(
            {
                "name": name,
                "provider": provider,
                "upstream_model": upstream,
                "deployment_kind": deployment.deployment_kind
                if deployment is not None
                else "external",
                "input_per_million": None if prices[0] is None else str(prices[0]),
                "output_per_million": None if prices[1] is None else str(prices[1]),
                "price_source": source,
            }
        )
    return models


def _provider(model: str) -> str | None:
    return next(
        (
            provider
            for provider in ("openai", "anthropic", "google")
            if DEFAULT_PRICE_BOOK.supports(model, provider)
        ),
        None,
    )


def _window(tenant_id: UUID, start: datetime, end: datetime) -> tuple[Any, ...]:
    return (
        RequestLifecycle.organization_id == tenant_id,
        RequestLifecycle.started_at >= start,
        RequestLifecycle.started_at < end,
    )


def _spend(tenant_id: UUID) -> Any:
    return (
        select(func.sum(UsageLedger.cost_usd))
        .where(
            UsageLedger.organization_id == tenant_id,
            UsageLedger.request_id == RequestLifecycle.request_id,
            UsageLedger.event_type == "spend_settlement",
        )
        .correlate(RequestLifecycle)
        .scalar_subquery()
    )


def _unpriced(tenant_id: UUID) -> Any:
    return (
        select(UsageLedger.id)
        .where(
            UsageLedger.organization_id == tenant_id,
            UsageLedger.request_id == RequestLifecycle.request_id,
            UsageLedger.event_type == "spend_settlement",
            UsageLedger.event_metadata["pricing"]["pricing_resolution"].as_string()
            == "unknown",
        )
        .correlate(RequestLifecycle)
        .exists()
    )


async def traffic(
    session: AsyncSession,
    tenant_id: UUID,
    start: datetime,
    end: datetime,
    condition: ColumnElement[bool],
    group: Any = None,
) -> list[dict[str, Any]]:
    """Requests, outcomes, failures, latency, cost and analysed rates, per `group`."""
    metadata = RequestLifecycle.lifecycle_metadata
    analysis = metadata["response_analysis"]
    latency = cast(metadata["provider_latency_ms"].as_string(), Float)
    valid = analysis["schema"]["valid"].as_string()
    refused = analysis["refusal"]["soft_refusal"].as_string()
    spend = _spend(tenant_id)
    priced = and_(spend.isnot(None), not_(_unpriced(tenant_id)))
    key = (group if group is not None else literal("all")).label("key")
    rows = await session.execute(
        select(
            key,
            func.count().label("requests"),
            *(
                func.count()
                .filter(metadata["completion_outcome"].as_string() == outcome)
                .label(outcome)
                for outcome in OUTCOMES
            ),
            func.count()
            .filter(
                RequestLifecycle.status.in_(("provider_error", "timeout", "failed"))
            )
            .label("failed"),
            func.percentile_cont(0.5).within_group(latency).label("latency_p50"),
            func.percentile_cont(0.95).within_group(latency).label("latency_p95"),
            func.sum(spend).filter(priced).label("cost"),
            func.count().filter(priced).label("priced"),
            func.count().filter(valid.in_(("true", "false"))).label("schema_checked"),
            func.count().filter(valid == "false").label("schema_invalid"),
            func.count()
            .filter(refused.in_(("true", "false")))
            .label("refusal_checked"),
            func.count().filter(refused == "true").label("soft_refused"),
        )
        .where(*_window(tenant_id, start, end), condition)
        .group_by(key)
        .order_by(key)
    )
    return [
        {
            "model": row.key,
            "requests": row.requests,
            "completion_outcomes": {
                outcome: getattr(row, outcome) for outcome in OUTCOMES
            },
            "failed": row.failed,
            "provider_latency_ms_p50": row.latency_p50,
            "provider_latency_ms_p95": row.latency_p95,
            "cost_usd": money(row.cost) if row.cost is not None else None,
            "cost_usd_per_request": money(row.cost / row.priced)
            if row.priced
            else None,
            "priced_requests": row.priced,
            "schema_invalid_rate": row.schema_invalid / row.schema_checked
            if row.schema_checked
            else None,
            "schema_analysed": row.schema_checked,
            "soft_refusal_rate": row.soft_refused / row.refusal_checked
            if row.refusal_checked
            else None,
            "refusal_analysed": row.refusal_checked,
        }
        for row in rows
    ]


def _decision(rule_id: str) -> Any:
    """This rule's decision on a row: the current one, or the one an attempt replaced."""
    route = RequestLifecycle.lifecycle_metadata["route_decision"]
    return case(
        (route["rule_id"].as_string() == rule_id, route),
        else_=route["previous"],
    )


def _decided(rule_id: str) -> ColumnElement[bool]:
    route = RequestLifecycle.lifecycle_metadata["route_decision"]
    return or_(
        route["rule_id"].as_string() == rule_id,
        route["previous"]["rule_id"].as_string() == rule_id,
    )


async def _language_ratios(
    session: AsyncSession, tenant_id: UUID, start: datetime, end: datetime
) -> dict[tuple[str, str], tuple[float, int]]:
    measured = await language_cost(
        session, tenant_id, start=start, end=end, group_by="model"
    )
    return {
        (str(item["group"]["id"]), item["language"]): (
            item["tokens_per_1000_characters"],
            item["requests"],
        )
        for item in measured["items"]
    }


async def _savings(
    session: AsyncSession,
    tenant_id: UUID,
    rule_id: str,
    start: datetime,
    end: datetime,
    outcome: str,
    ratios: Mapping[tuple[str, str], tuple[float, int]],
) -> list[dict[str, Any]]:
    """The routed (or would-route) rows' settled tokens priced at both sides."""
    decision = _decision(rule_id)
    language = RequestLifecycle.lifecycle_metadata["response_analysis"]["language"][
        "answer"
    ].as_string()
    rows = await session.execute(
        select(
            decision["from"].as_string().label("source"),
            decision["to"].as_string().label("target"),
            RequestLifecycle.provider,
            language.label("language"),
            func.coalesce(func.sum(RequestLog.prompt_tokens), 0).label("prompt"),
            func.coalesce(func.sum(RequestLog.completion_tokens), 0).label(
                "completion"
            ),
            func.coalesce(func.sum(_spend(tenant_id)), 0).label("actual"),
            func.count().label("requests"),
        )
        .join(
            RequestLog,
            and_(
                RequestLog.organization_id == RequestLifecycle.organization_id,
                RequestLog.request_id == RequestLifecycle.request_id,
            ),
        )
        .where(
            *_window(tenant_id, start, end),
            _decided(rule_id),
            decision["outcome"].as_string() == outcome,
            decision["reason"].as_string().notin_(ATTEMPT_REASONS),
        )
        .group_by("source", "target", RequestLifecycle.provider, "language")
    )
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        group = groups.setdefault(
            (row.source, row.target, row.provider),
            {
                "prompt": 0,
                "completion": 0,
                "actual": Decimal(0),
                "requests": 0,
                "by_language": {},
            },
        )
        group["prompt"] += row.prompt
        group["completion"] += row.completion
        group["actual"] += Decimal(row.actual)
        group["requests"] += row.requests
        group["by_language"][row.language] = (
            group["by_language"].get(row.language, 0) + row.completion
        )
    priced = []
    for (source, target, provider), group in sorted(groups.items()):
        at_from = await route_price(session, tenant_id, source, provider)
        at_to = await route_price(session, tenant_id, target, provider)
        item: dict[str, Any] = {
            "from": source,
            "to": target,
            "requests": group["requests"],
            "tokens": {"prompt": group["prompt"], "completion": group["completion"]},
            "actual_usd": money(group["actual"]),
        }
        if at_from is None or at_to is None:
            priced.append({**item, "priced": False})
            continue
        from_cost = at_from.cost(group["prompt"], group["completion"])
        to_cost = at_to.cost(group["prompt"], group["completion"])
        difference = "savings_usd" if outcome == "routed" else "potential_savings_usd"
        item |= {
            "priced": True,
            "cost_at_from_usd": money(from_cost),
            "cost_at_to_usd": money(to_cost),
            difference: money(from_cost - to_cost),
        }
        adjusted, reason = await _adjusted(
            session, tenant_id, source, target, provider, group, at_from, ratios
        )
        if adjusted is None:
            item["adjustment_unavailable_reason"] = reason
        else:
            item["adjusted_cost_at_from_usd"] = money(adjusted)
        priced.append(item)
    return priced


async def _adjusted(
    session: AsyncSession,
    tenant_id: UUID,
    source: str,
    target: str,
    provider: str,
    group: Mapping[str, Any],
    at_from: ModelPrice,
    ratios: Mapping[tuple[str, str], tuple[float, int]],
) -> tuple[Decimal | None, str | None]:
    """The from side with its own output tokens per character, by answer language."""
    models = []
    for name in (source, target):
        deployment = await _deployment(session, tenant_id, name)
        models.append(deployment.upstream_model if deployment is not None else name)
    completion = Decimal(0)
    for language, tokens in group["by_language"].items():
        if language not in ("tr", "en"):
            return None, "answer_language_not_measured"
        measured = [ratios.get((model, language)) for model in models]
        if any(
            side is None or side[1] < LANGUAGE_COST_MIN_REQUESTS for side in measured
        ):
            return None, "not_enough_answers"
        from_ratio, to_ratio = (side[0] for side in measured if side is not None)
        completion += (
            Decimal(tokens) * Decimal(str(from_ratio)) / Decimal(str(to_ratio))
        )
    return at_from.cost(group["prompt"], int(completion.to_integral_value())), None


async def routing_section(
    session: AsyncSession,
    tenant_id: UUID,
    rule_id: str,
    rule_set: RuleSet | None,
    start: datetime,
    end: datetime,
    listed_tests: Iterable[str],
    ratios: Mapping[tuple[str, str], tuple[float, int]],
) -> dict[str, Any]:
    current = {rule.id: rule for rule in (rule_set.rules if rule_set else ())}
    rule: Rule | None = current.get(rule_id)
    decision = _decision(rule_id)
    keys = (
        decision["state"].as_string().label("state"),
        decision["reason"].as_string().label("reason"),
        decision["outcome"].as_string().label("outcome"),
    )
    counts = await session.execute(
        select(*keys, func.count())
        .where(*_window(tenant_id, start, end), _decided(rule_id))
        .group_by(*keys)
        .order_by(*keys)
    )
    # A monitor rule never moved the request, whatever its `to` says.
    served = case(
        (
            or_(
                decision["outcome"].as_string() == "routed",
                and_(
                    decision["outcome"].as_string().is_(None),
                    decision["state"].as_string() == "enforced",
                ),
            ),
            decision["to"].as_string(),
        ),
        else_=decision["from"].as_string(),
    )
    by_alias = await session.execute(
        select(served, func.count())
        .where(*_window(tenant_id, start, end), _decided(rule_id))
        .group_by(served)
        .order_by(served)
    )
    # A retargeted request (a fallback) names deployment ids; the document names aliases.
    aliases = {
        str(deployment_id): alias
        for deployment_id, alias in await session.execute(
            select(ModelDeployment.id, ModelDeployment.alias).where(
                ModelDeployment.organization_id == tenant_id
            )
        )
    }
    by_served: Counter[str] = Counter()
    for alias, requests in by_alias:
        by_served[aliases.get(str(alias), str(alias))] += requests
    conversations = await session.scalar(
        select(
            func.count(func.distinct(decision["conversation_id"].as_string()))
        ).where(*_window(tenant_id, start, end), _decided(rule_id))
    )
    decisions = [
        {"state": state, "reason": reason, "outcome": outcome, "requests": requests}
        for state, reason, outcome, requests in counts
    ]
    section: dict[str, Any] = {
        "rule_id": rule_id,
        "definition": _definition(rule),
        "decisions": {
            "by_state_reason_outcome": decisions,
            "routed": sum(d["requests"] for d in decisions if d["outcome"] == "routed"),
            "conversations": conversations or 0,
            "served": dict(sorted(by_served.items())),
        },
        "savings": await _savings(
            session, tenant_id, rule_id, start, end, "routed", ratios
        ),
        "potential_savings": await _savings(
            session, tenant_id, rule_id, start, end, "would_route", ratios
        ),
    }
    routed = and_(_decided(rule_id), decision["outcome"].as_string() == "routed")
    sources = _sources(rule)
    section["quality"] = {
        "routed": await traffic(session, tenant_id, start, end, routed),
        "not_routed": await traffic(
            session,
            tenant_id,
            start,
            end,
            # Rows without a decision compare as NULL: count them as not routed.
            and_(
                RequestLifecycle.requested_model.in_(sources),
                not_(func.coalesce(routed, False)),
            ),
        )
        if sources
        else [],
    }
    tests = list(dict.fromkeys(listed_tests))
    if rule is not None and rule.match.get("to") is not None:
        tests += [
            other.id
            for other in current.values()
            if other.kind == "route"
            and other.match.get("on") == "shadow"
            and other.match.get("from") in sources
            and other.match.get("to") == rule.match.get("to")
            and other.id not in tests
        ]
    section["change_tests"] = {
        test: await change_test_results(session, tenant_id, test, start, end)
        for test in tests
    }
    return section


def _sources(rule: Rule | None) -> list[str]:
    if rule is None:
        return []
    source = rule.match.get("from")
    return list(source) if isinstance(source, list) else [source] if source else []


def _definition(rule: Rule | None) -> dict[str, Any] | str:
    if rule is None:
        return "not in the current rule set"
    when = rule.match.get("when") or {}
    return {
        "from": rule.match.get("from"),
        "to": rule.match.get("to"),
        "on": rule.match.get("on"),
        "when": sorted(when),
        "state": rule.state,
    }


async def collect(
    session: AsyncSession,
    tenant_id: UUID,
    *,
    kind: str,
    title: str,
    note: str | None,
    start: datetime,
    end: datetime,
    sources: Mapping[str, Any],
    rule_set: RuleSet | None,
    generated_at: datetime,
    generator_version: str,
) -> dict[str, Any]:
    """The document's facts object: ids, labels, counts, sums, ratios, percentiles."""
    sections: dict[str, Any] = {}
    ratios = await _language_ratios(session, tenant_id, start, end)
    tests = {
        test: await change_test_results(session, tenant_id, test, start, end)
        for test in sources["change_tests"]
    }
    canaries = {
        canary: await canary_sides(session, tenant_id, canary, start, end)
        for canary in sources["canaries"]
    }
    if kind == "model_selection":
        names = [sources["current"], *sources["candidates"]]
        models = await _models(session, tenant_id, names)
        served = [model["upstream_model"] for model in models]
        sections["models"] = models
        sections["change_tests"] = tests
        sections["canaries"] = canaries
        sections["live_traffic"] = await traffic(
            session,
            tenant_id,
            start,
            end,
            RequestLifecycle.provider_model.in_(served),
            RequestLifecycle.provider_model,
        )
        measured = [
            {
                "model": model,
                "language": language,
                "tokens_per_1000_characters": ratio[0],
                "requests": ratio[1],
            }
            for (model, language), ratio in sorted(ratios.items())
            if model in served
        ]
        sections["language_cost"] = measured or NOT_RECORDED
    else:
        sections["routing"] = [
            await routing_section(
                session,
                tenant_id,
                rule_id,
                rule_set,
                start,
                end,
                sources["change_tests"],
                ratios,
            )
            for rule_id in sources["route_rules"]
        ]
        sections["canaries"] = canaries
    limits = ["no_answer_review", "prices_in_force", "window_only"]
    if any(test["copies"] for test in tests.values()) or kind == "routing":
        limits += ["copy_timing", "masked_input"]
    if kind == "routing":
        limits += ["different_populations", "token_estimate"]
    facts = {
        "format": FORMAT,
        "version": VERSION,
        "kind": kind,
        "title": title,
        "note": note,
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "generated_at": generated_at.isoformat(),
        "generator_version": generator_version,
        "sources": dict(sources),
        "sections": sections,
        "limits": [limit for limit in LIMITS if limit in limits],
    }
    # As stored: dates and decimals as strings, so the digest is over what is kept.
    return json.loads(json.dumps(facts, default=str))


def _rows(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    """A nested facts value as (path, text) lines."""
    if isinstance(value, Mapping):
        return [
            row for key, item in value.items() for row in _rows(item, f"{prefix}{key}.")
        ]
    if isinstance(value, list) and value and isinstance(value[0], Mapping):
        return [
            row
            for index, item in enumerate(value)
            for row in _rows(item, f"{prefix}{index}.")
        ]
    text = (
        NOT_RECORDED
        if value is None
        else json.dumps(value, ensure_ascii=False)
        if isinstance(value, list)
        else str(value)
    )
    return [(prefix.rstrip("."), text)]


def story(
    facts: Mapping[str, Any], audit_event_id: str, document_id: str, styles: Any
) -> list[Any]:
    from reportlab.platypus import Paragraph, Spacer

    window = f"{facts['window']['start']} to {facts['window']['end']}"
    parts: list[Any] = [
        Paragraph(_escape(facts["title"]), styles["Title"]),
        Paragraph(f"Kind: {facts['kind']}. Window: {window}.", styles["Normal"]),
        Paragraph(f"Generator: {facts['generator_version']}.", styles["Normal"]),
        Paragraph(COVER, styles["Normal"]),
        Paragraph(f"Document id: {document_id}.", styles["Normal"]),
        Paragraph(
            "Integrity: SHA-256 of this file is recorded in the audit chain entry "
            f"{audit_event_id}.",
            styles["Normal"],
        ),
    ]
    if facts.get("note"):
        parts.append(Paragraph(f"Note: {_escape(facts['note'])}", styles["Normal"]))
    for name, section in facts["sections"].items():
        parts += [
            Spacer(1, 8),
            Paragraph(name.replace("_", " ").capitalize(), styles["Heading2"]),
            Paragraph(
                f"Source: request_lifecycle, usage_ledger and request_logs of this "
                f"organization, {window}.",
                styles["Normal"],
            ),
            evidence_table(
                [
                    [
                        Paragraph(_escape(path), styles["Normal"]),
                        Paragraph(_escape(text), styles["Normal"]),
                    ]
                    for path, text in _rows(section)
                ]
                or [[NOT_RECORDED, ""]],
                ["Measure", "Value"],
                col_widths=[95 * 2.8346, 79 * 2.8346],
            ),
        ]
    parts += [
        Spacer(1, 8),
        Paragraph("What this document does not prove", styles["Heading2"]),
    ]
    parts += [
        Paragraph(f"{limit}: {LIMITS[limit]}", styles["Normal"])
        for limit in facts["limits"]
    ]
    return parts


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


async def render_model_evidence_pdf(
    facts: Mapping[str, Any], audit_event_id: str, document_id: str
) -> bytes:
    def render() -> bytes:
        return build_pdf(
            story(facts, audit_event_id, document_id, report_styles()),
            str(facts["title"]),
        )

    return await asyncio.to_thread(render)
