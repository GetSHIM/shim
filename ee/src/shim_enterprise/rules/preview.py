"""What a rule would have hit: its own monitor history, or a kind's metadata estimator."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from typing import Any, Literal, Protocol, TypedDict
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import exists, func, literal_column, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from shim.rules import Rule, RuleSet, RuleSetError, load_rule_set, validate_rule_set
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import QUERY_CANCELED, bound_statements
from shim_enterprise.rules.models import (
    OrganizationRuleSet,
    RuleDefinition,
    RulePreview,
)

RULE_PREVIEW_DEFAULT_DAYS = 7
RULE_PREVIEW_MIN_DAYS = 7
PREVIEW_LIFETIME = timedelta(hours=24)
_SCOPE_ENTRIES = 20
NO_HISTORY = (
    "no history for this rule and its kind cannot be counted from stored metadata; "
    "start in monitor"
)
_TOO_SLOW = "preview took too long; start in monitor"
_TRUNCATED = (
    "{} requests in the window matched more rules than were recorded, so this "
    "count is a lower bound"
)

Basis = Literal["metadata", "monitor_history", "none"]


class ByScope(TypedDict):
    api_keys: list[dict[str, Any]]
    teams: list[dict[str, Any]]
    models: list[dict[str, Any]]
    truncated_rows: int


class PreviewCount(TypedDict):
    requests: int
    by_scope: ByScope
    note: str | None


class RuleEstimator(Protocol):
    async def __call__(
        self,
        session: AsyncSession,
        organization_id: UUID,
        rule: Rule,
        start: datetime,
        end: datetime,
    ) -> PreviewCount | None: ...


# Keyed "<kind>" or "<kind>:<match.on>"; a kind whose rules can be counted from
# stored request metadata registers here. Content kinds (term, pattern) cannot.
PREVIEW_ESTIMATORS: dict[str, RuleEstimator] = {}


def _digest(label: bytes, value: dict[str, Any]) -> str:
    base = (settings.COMPLIANCE_HASH_SALT or settings.SECRET_KEY).encode("utf-8")
    # Keyed, so a short term list cannot be guessed back from the digest.
    key = hmac.new(base, label, hashlib.sha256).digest()
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def definition_digest(rule: Rule) -> str:
    """What the rule matches: name, action and state do not change it."""
    return _digest(
        b"shim-rule-definition-v1",
        rule.model_dump(mode="json", include={"kind", "scope", "match"}),
    )


def preview_digest(rule: Rule) -> str:
    return _digest(
        b"shim-rule-preview-v1",
        rule.model_dump(mode="json", include={"kind", "action", "scope", "match"}),
    )


def checked_set(revision: int, rules: list[dict[str, Any]]) -> RuleSet:
    try:
        return validate_rule_set(
            {"revision": revision, "rules": rules}, approval_available=True
        )
    except RuleSetError as error:
        raise HTTPException(
            status_code=422,
            detail={"code": error.code, "path": error.path, "message": str(error)},
        ) from None


def stored_rules(row: OrganizationRuleSet | None) -> RuleSet | None:
    return (
        load_rule_set(row.revision, row.rules)
        if row is not None and row.rules
        else None
    )


async def has_preview(session: AsyncSession, organization_id: UUID, rule: Rule) -> bool:
    return bool(
        await session.scalar(
            select(
                exists().where(
                    RulePreview.organization_id == organization_id,
                    RulePreview.rule_id == rule.id,
                    RulePreview.preview_digest == preview_digest(rule),
                    RulePreview.expires_at > datetime.now(timezone.utc),
                )
            )
        )
    )


def estimator_for(rule: Rule) -> RuleEstimator | None:
    """The `<kind>:<match.on>` estimator first, then the kind's."""
    on = rule.match.get("on")
    variant = PREVIEW_ESTIMATORS.get(f"{rule.kind}:{on}") if on is not None else None
    return variant or PREVIEW_ESTIMATORS.get(rule.kind)


def _top(counts: dict[Any, int], key: str) -> list[dict[str, Any]]:
    ranked = sorted(counts.items(), key=lambda item: (-item[1], str(item[0])))
    return [
        {key: value, "requests": requests}
        for value, requests in ranked[:_SCOPE_ENTRIES]
    ]


async def _monitor_history(
    session: AsyncSession,
    organization_id: UUID,
    rule_id: str,
    start: datetime,
    end: datetime,
) -> tuple[int, int, ByScope]:
    metadata = RequestLifecycle.lifecycle_metadata
    matched = metadata.contains({"rule_matches": [{"rule_id": rule_id}]})
    errored = metadata.contains({"rule_matches": [{"rule_id": rule_id, "error": True}]})
    truncated = metadata.contains({"rule_matches_truncated": True})
    # A literal, so the select list and GROUP BY hold the same expression.
    team = literal_column("request_lifecycle.metadata ->> 'team_id'")
    key, model = RequestLifecycle.api_key_id, RequestLifecycle.requested_model
    rows = await session.execute(
        select(
            func.grouping(key, team, model),
            key,
            team,
            model,
            func.count().filter(matched),
            func.count().filter(errored),
            func.count().filter(truncated),
        )
        .where(
            RequestLifecycle.organization_id == organization_id,
            RequestLifecycle.started_at >= start,
            RequestLifecycle.started_at < end,
            matched | truncated,
        )
        .group_by(func.grouping_sets(key, team, model, text("()")))
    )
    keys: dict[Any, int] = {}
    teams: dict[Any, int] = {}
    models: dict[Any, int] = {}
    total = errors = truncated_rows = 0
    for grouping, key_id, team_id, model_name, count, error_count, cut in rows:
        # grouping() sets a bit for every column a row is not grouped by.
        if grouping == 0b111:
            total, errors, truncated_rows = count, error_count, cut
        elif count and grouping == 0b011 and key_id is not None:
            keys[str(key_id)] = count
        elif count and grouping == 0b101 and team_id is not None:
            teams[team_id] = count
        elif count and grouping == 0b110 and model_name is not None:
            models[model_name] = count
    return (
        total,
        errors,
        {
            "api_keys": _top(keys, "id"),
            "teams": _top(teams, "id"),
            "models": _top(models, "model"),
            "truncated_rows": truncated_rows,
        },
    )


def _empty_scope() -> ByScope:
    return {"api_keys": [], "teams": [], "models": [], "truncated_rows": 0}


async def preview_rule(
    session: AsyncSession,
    organization_id: UUID,
    proposed: dict[str, Any],
    window_days: int,
    *,
    others: list[dict[str, Any]] | None = None,
) -> tuple[Rule, dict[str, Any]]:
    """The validated rule and what it would have hit; nothing is written.

    The rule is checked within `others`, the rest of the set it will belong to;
    by default the stored set.
    """
    row = await session.get(OrganizationRuleSet, organization_id)
    stored = stored_rules(row)
    current = {rule.id: rule for rule in stored.rules} if stored is not None else {}
    rule_id = proposed.get("id")
    if others is None:
        others = [
            rule.model_dump(mode="json")
            for rule in current.values()
            if rule.id != rule_id
        ]
    candidate = checked_set(1, [*others, proposed])
    rule = next(rule for rule in candidate.rules if rule.id == rule_id)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=window_days)
    basis: Basis = "none"
    covered_start, requests, errors = start, None, None
    by_scope, note = _empty_scope(), NO_HISTORY
    await bound_statements(session)
    try:
        # A savepoint, so a statement timeout leaves the caller's transaction usable.
        async with session.begin_nested():
            known = current.get(rule.id)
            digest = definition_digest(rule)
            estimator = estimator_for(rule)
            if known is not None and definition_digest(known) == digest:
                assert row is not None
                defined = await session.get(RuleDefinition, (organization_id, rule.id))
                # Without a current definition row, the set's last write bounds it.
                defined_at = (
                    defined.defined_at
                    if defined is not None and defined.definition_digest == digest
                    else row.updated_at
                )
                covered_start = max(start, defined_at)
                requests, errors, by_scope = await _monitor_history(
                    session, organization_id, rule.id, covered_start, end
                )
                basis = "monitor_history"
                note = (
                    _TRUNCATED.format(by_scope["truncated_rows"])
                    if by_scope["truncated_rows"]
                    else None
                )
            elif estimator is not None and (
                counted := await estimator(session, organization_id, rule, start, end)
            ):
                basis, requests, errors = "metadata", counted["requests"], 0
                by_scope, note = counted["by_scope"], counted["note"]
    except DBAPIError as error:
        if getattr(error.orig, "pgcode", None) != QUERY_CANCELED:
            raise
        basis, covered_start, requests, errors = "none", start, None, None
        by_scope, note = _empty_scope(), _TOO_SLOW
    covered_days = (end - covered_start).days if basis != "none" else 0
    return rule, {
        "rule_id": rule.id,
        "basis": basis,
        "requests": requests,
        "errors": errors,
        "window": {
            "start": start,
            "end": end,
            "days": window_days,
            "covered_days": covered_days,
        },
        "by_scope": by_scope,
        "note": note,
        # Only a new rule, and only on a whole window of at least seven days.
        "enforce_on_create": rule.id not in current
        and basis != "none"
        and window_days >= RULE_PREVIEW_MIN_DAYS
        and covered_days == window_days,
        "preview_expires_at": None,
    }
