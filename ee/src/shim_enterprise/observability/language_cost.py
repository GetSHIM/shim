"""Tokens per 1,000 characters of answer, per model or API key and answer language.

Only the output side is measured: the provider's billed completion tokens over the
answer's characters, for answers whose tokens are all answer text. The input side
mixes system prompts, tools, history and cached prefixes and is not shown.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

LanguageCostGroup = Literal["model", "api_key"]
LANGUAGE_COST_MIN_ANSWER_CHARACTERS = 200
LANGUAGE_COST_MIN_REQUESTS = 30
MAX_GROUPS = 200
EXCLUSIONS = (
    "estimated_usage",
    "tool_calls",
    "reasoning",
    "short",
    "not_analysed",
    "language_unknown",
)

# Settled complete answers with their exclusion reason (the first that applies, in
# EXCLUSIONS order) or none, and the output price per token their settlement used:
# the large-context price once the prompt crossed its threshold; none if unpriced.
_ANSWERS = """
    answers AS (
        SELECT l.request_id,
               {group} AS grp,
               {name} AS grp_name,
               (l.metadata ->> 'answer_characters')::int AS characters,
               s.completion_tokens AS tokens,
               l.metadata -> 'response_analysis' -> 'language' ->> 'answer' AS language,
               CASE
                   WHEN s.estimated THEN 'estimated_usage'
                   WHEN jsonb_typeof(l.metadata -> 'tool_call_names') = 'array'
                        AND jsonb_array_length(l.metadata -> 'tool_call_names') > 0
                       THEN 'tool_calls'
                   WHEN (l.metadata ->> 'reasoning_seen')::boolean THEN 'reasoning'
                   WHEN coalesce((l.metadata ->> 'answer_characters')::int, 0)
                        < :min_characters THEN 'short'
                   WHEN NOT coalesce(l.metadata -> 'response_analysis', '{{}}'::jsonb)
                        ? 'language' THEN 'not_analysed'
                   WHEN coalesce(
                            l.metadata -> 'response_analysis' -> 'language' ->> 'answer',
                            ''
                        ) NOT IN ('tr', 'en') THEN 'language_unknown'
               END AS excluded,
               CASE
                   WHEN s.metadata -> 'pricing' ->> 'pricing_resolution' = 'unknown'
                       THEN NULL
                   WHEN s.prompt_tokens > (
                            s.metadata -> 'pricing' ->> 'large_context_threshold'
                        )::int
                       THEN (s.metadata -> 'pricing'
                             ->> 'large_context_output_per_million')::numeric / 1000000
                   ELSE (s.metadata -> 'pricing' ->> 'output_per_million')::numeric
                        / 1000000
               END AS price
        FROM request_lifecycle l
        JOIN usage_ledger s
          ON s.organization_id = l.organization_id
         AND s.request_id = l.request_id
         AND s.event_type = 'spend_settlement'
        {key_join}
        WHERE l.organization_id = :tenant_id
          AND l.started_at >= CAST(:start AS timestamptz)
          AND l.started_at < CAST(:end AS timestamptz)
          AND l.metadata ->> 'completion_outcome' = 'complete'
          AND s.completion_tokens > 0
    )
"""
# The provider model the settlement billed, so a registry alias shows what it called.
_GROUPS: dict[LanguageCostGroup, tuple[str, str, str]] = {
    "model": ("coalesce(s.provider_model, s.requested_model)", "NULL::text", ""),
    "api_key": (
        "l.api_key_id::text",
        "k.name",
        "LEFT JOIN api_keys k ON k.organization_id = l.organization_id"
        " AND k.id = l.api_key_id",
    ),
}

_EXCLUDED_SQL = """
    WITH {answers}
    SELECT excluded, count(*) AS requests FROM answers GROUP BY excluded
"""
_RATIOS_SQL = """
    WITH {answers}
    SELECT grp, max(grp_name) AS name, language,
           count(*) AS requests,
           sum(characters) AS characters,
           sum(tokens) AS tokens,
           percentile_cont(0.25) WITHIN GROUP (ORDER BY 1000.0 * tokens / characters)
               AS ratio_p25,
           percentile_cont(0.75) WITHIN GROUP (ORDER BY 1000.0 * tokens / characters)
               AS ratio_p75,
           sum(tokens * price) AS usd,
           sum(characters) FILTER (WHERE price IS NOT NULL) AS priced_characters,
           count(price) AS priced_requests
    FROM answers
    WHERE excluded IS NULL
    GROUP BY grp, language
"""


def _ratio(numerator: Decimal | int, denominator: Decimal | int) -> float:
    return round(float(Decimal(1000) * Decimal(numerator) / Decimal(denominator)), 4)


async def language_cost(
    session: AsyncSession,
    organization_id: UUID,
    *,
    start: datetime,
    end: datetime,
    group_by: LanguageCostGroup,
) -> dict[str, Any]:
    group, name, key_join = _GROUPS[group_by]
    answers = _ANSWERS.format(group=group, name=name, key_join=key_join)
    params = {
        "tenant_id": organization_id,
        "start": start,
        "end": end,
        "min_characters": LANGUAGE_COST_MIN_ANSWER_CHARACTERS,
    }
    counted = {
        row.excluded: row.requests
        for row in await session.execute(
            text(_EXCLUDED_SQL.format(answers=answers)), params
        )
    }
    rows = (
        await session.execute(text(_RATIOS_SQL.format(answers=answers)), params)
    ).all()
    totals: dict[Any, int] = {}
    for row in rows:
        totals[row.grp] = totals.get(row.grp, 0) + row.requests
    kept = sorted(totals, key=lambda grp: (-totals[grp], grp or ""))[:MAX_GROUPS]
    ratios = {(row.grp, row.language): row for row in rows}
    items = []
    for grp in kept:
        tr, en = ratios.get((grp, "tr")), ratios.get((grp, "en"))
        enough = all(
            side is not None and side.requests >= LANGUAGE_COST_MIN_REQUESTS
            for side in (tr, en)
        )
        compared = (
            round(
                float(
                    (Decimal(tr.tokens) / tr.characters)
                    / (Decimal(en.tokens) / en.characters)
                ),
                4,
            )
            if enough and tr is not None and en is not None
            else None
        )
        for row in (tr, en):
            if row is None:
                continue
            items.append(
                {
                    "group": {"id": grp, "name": row.name},
                    "language": row.language,
                    "requests": row.requests,
                    "answer_characters": row.characters,
                    "completion_tokens": row.tokens,
                    "tokens_per_1000_characters": _ratio(row.tokens, row.characters),
                    "ratio_p25": round(row.ratio_p25, 4),
                    "ratio_p75": round(row.ratio_p75, 4),
                    "output_usd_per_1000_characters": None
                    if not row.priced_characters
                    else str(round(Decimal(1000) * row.usd / row.priced_characters, 8)),
                    "priced_requests": row.priced_requests,
                    "tr_vs_en": compared,
                    "comparison_unavailable_reason": None
                    if compared is not None
                    else "not_enough_answers",
                }
            )
    eligible = counted.get(None, 0)
    settled = sum(counted.values())
    return {
        "start": start,
        "end": end,
        "group_by": group_by,
        "items": items,
        "truncated": len(totals) > MAX_GROUPS,
        "excluded": {reason: counted.get(reason, 0) for reason in EXCLUSIONS},
        "analysed_share": round(eligible / settled, 4) if settled else None,
    }
