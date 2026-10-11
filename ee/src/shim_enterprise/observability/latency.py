"""Latency per team, app, tag, model or deployment, read from the request timestamps.

Computed on demand over a bounded window on the indexed `started_at`; there is no
rollup table to drift from the rows.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from shim.gateway.kernel.result import UNSPECIFIED_PROVIDER_MODEL
from shim_enterprise.observability.model_inventory import UNSPECIFIED_MODEL

LatencyGroup = Literal["team", "api_key", "tag", "model", "deployment"]
LatencyBucket = Literal["hour", "day"]
MAX_GROUPS = 20
HEAD_OF_LINE_SHORT_PROMPT_TOKENS = 2_000
HEAD_OF_LINE_LONG_PROMPT_TOKENS = 20_000
HEAD_OF_LINE_MAX_WINDOW_HOURS = 48

# The first byte of an answer: a stream's TTFT, a JSON answer's provider latency.
FIRST_BYTE_SQL = (
    "CASE WHEN {t}stream THEN ({t}metadata ->> 'ttft_ms')::float"
    " ELSE ({t}metadata ->> 'provider_latency_ms')::float END"
)
# The most requests in flight at once, from `clipped(grp, bucket, s, e)` (each
# request's [provider start, completion] clipped to its bucket): +1 at a start and
# -1 at an end, summed in time order with an end before a start at the same
# instant, the maximum per group and bucket as `peaks(grp, bucket, peak)`.
SWEEP_SQL = """
    events AS (
        SELECT grp, bucket, s AS at, 1 AS delta FROM clipped
        UNION ALL
        SELECT grp, bucket, e AS at, -1 AS delta FROM clipped
    ),
    peaks AS (
        SELECT grp, bucket, max(running) AS peak FROM (
            SELECT grp, bucket,
                   sum(delta) OVER (PARTITION BY grp, bucket ORDER BY at, delta
                                    ROWS UNBOUNDED PRECEDING) AS running
            FROM events
        ) swept
        GROUP BY grp, bucket
    )
"""

# The group expression and how a group's name is found, per grouping. Fixed SQL:
# nothing a caller sends is interpolated.
_GROUPS: dict[LatencyGroup, tuple[str, str]] = {
    "team": (
        "l.metadata ->> 'team_id'",
        "(SELECT t.name FROM teams t WHERE t.organization_id = :tenant_id"
        " AND t.id::text = groups.grp)",
    ),
    "api_key": (
        "l.api_key_id::text",
        "(SELECT k.name FROM api_keys k WHERE k.organization_id = :tenant_id"
        " AND k.id::text = groups.grp)",
    ),
    "tag": ("tag.value", "groups.grp"),
    "model": (
        "CASE WHEN l.requested_model = CAST(:unspecified AS text)"
        " THEN CAST(:unspecified_name AS text) ELSE l.requested_model END",
        "groups.grp",
    ),
    "deployment": (
        "l.metadata ->> 'deployment_id'",
        "(SELECT d.alias FROM model_deployments d WHERE d.organization_id = :tenant_id"
        " AND d.id::text = groups.grp)",
    ),
}

# One row per request (per tag for group_by=tag), with the derived measurements:
# - first_byte: FIRST_BYTE_SQL;
# - queue_ms: admission, privacy and the reservation commits before the provider call;
# - tokens_per_second: settled output tokens over the stream's duration, which
#   includes the terminal commit; not for estimated usage, reasoning or under 1 s.
_BASE = """
    base AS (
        SELECT {group} AS grp,
               l.request_id, l.started_at, l.stream, l.status,
               l.provider_started_at, l.completed_at,
               date_trunc(CAST(:bucket AS text), l.started_at AT TIME ZONE 'UTC') AS bucket,
               r.prompt_tokens,
               {first_byte} AS first_byte,
               EXTRACT(EPOCH FROM l.provider_started_at - l.started_at) * 1000
                   AS queue_ms,
               CASE WHEN l.stream
                         AND (r.details ->> 'usage_estimated')::boolean IS NOT TRUE
                         AND (l.metadata ->> 'reasoning_seen')::boolean IS NOT TRUE
                         AND l.completed_at - l.stream_started_at >= interval '1 second'
                    THEN r.completion_tokens
                         / EXTRACT(EPOCH FROM l.completed_at - l.stream_started_at)
               END AS tokens_per_second
        FROM request_lifecycle l
        LEFT JOIN request_logs r
               ON r.organization_id = l.organization_id AND r.request_id = l.request_id
        {tag_join}
        WHERE l.organization_id = :tenant_id
          AND l.started_at >= CAST(:start AS timestamptz)
          AND l.started_at < CAST(:end AS timestamptz)
    )
"""
_TAG_JOIN = (
    "LEFT JOIN LATERAL jsonb_array_elements_text("
    "CASE WHEN jsonb_typeof(l.metadata -> 'tags') = 'array'"
    " THEN l.metadata -> 'tags' ELSE '[]'::jsonb END) AS tag ON true"
)
_CHOSEN = "(grp = ANY(CAST(:groups AS text[])) OR (grp IS NULL AND CAST(:with_null AS boolean)))"

_GROUPS_SQL = """
    WITH {base},
    groups AS (
        SELECT grp, count(*) AS requests FROM base GROUP BY grp
        ORDER BY count(*) DESC, grp NULLS LAST LIMIT :limit
    )
    SELECT groups.grp, groups.requests, {name} AS name FROM groups
    ORDER BY groups.requests DESC, groups.grp NULLS LAST
"""

_BUCKETS_SQL = """
    WITH {base}
    SELECT grp, bucket,
           count(*) AS requests,
           count(*) FILTER (WHERE stream) AS streams,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY first_byte) FILTER (WHERE stream)
               AS stream_first_byte_p50,
           percentile_cont(0.95) WITHIN GROUP (ORDER BY first_byte) FILTER (WHERE stream)
               AS stream_first_byte_p95,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY first_byte)
               FILTER (WHERE NOT stream) AS json_first_byte_p50,
           percentile_cont(0.95) WITHIN GROUP (ORDER BY first_byte)
               FILTER (WHERE NOT stream) AS json_first_byte_p95,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY queue_ms) AS queue_p50,
           percentile_cont(0.95) WITHIN GROUP (ORDER BY queue_ms) AS queue_p95,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY tokens_per_second)
               AS tokens_per_second_p50,
           count(tokens_per_second) AS tokens_per_second_count,
           count(*) FILTER (WHERE status = 'timeout') AS timeouts,
           count(*) FILTER (WHERE status = 'provider_error') AS provider_errors
    FROM base
    WHERE {chosen}
    GROUP BY grp, bucket
"""

# Peak concurrency per group and bucket; a request still open runs to the window's end.
_PEAK_SQL = """
    WITH {base},
    spans AS (
        SELECT grp, provider_started_at AS s,
               coalesce(completed_at, CAST(:end AS timestamptz)) AS e
        FROM base WHERE {chosen} AND provider_started_at IS NOT NULL
    ),
    buckets AS (
        SELECT generate_series(
            date_trunc(CAST(:bucket AS text), CAST(:start AS timestamptz) AT TIME ZONE 'UTC'),
            CAST(:end AS timestamptz) AT TIME ZONE 'UTC',
            CAST(:step AS interval)
        ) AS bucket
    ),
    clipped AS (
        SELECT spans.grp, buckets.bucket,
               greatest(spans.s AT TIME ZONE 'UTC', buckets.bucket) AS s,
               least(spans.e AT TIME ZONE 'UTC',
                     buckets.bucket + CAST(:step AS interval)) AS e
        FROM spans JOIN buckets
          ON spans.s AT TIME ZONE 'UTC' < buckets.bucket + CAST(:step AS interval)
         AND spans.e AT TIME ZONE 'UTC' > buckets.bucket
    ),
    {sweep}
    SELECT grp, bucket, peak FROM peaks
"""

# Short streams that started while a long request of the same group was in flight,
# against short streams that started with none.
_HEAD_OF_LINE_SQL = """
    WITH {base},
    long AS (
        SELECT grp, provider_started_at AS s,
               coalesce(completed_at, CAST(:end AS timestamptz)) AS e
        FROM base
        WHERE {chosen} AND prompt_tokens >= :long_tokens
          AND provider_started_at IS NOT NULL
    ),
    short AS (
        SELECT b.grp, b.first_byte,
               EXISTS (SELECT 1 FROM long
                       WHERE long.grp IS NOT DISTINCT FROM b.grp
                         AND long.s <= b.started_at AND b.started_at < long.e) AS behind
        FROM base b
        WHERE {chosen} AND b.stream AND b.prompt_tokens <= :short_tokens
          AND b.first_byte IS NOT NULL
    )
    SELECT grp, behind,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY first_byte) AS ttft_p50,
           count(*) AS streams
    FROM short GROUP BY grp, behind
"""


def _rounded(value: float | None) -> float | None:
    return None if value is None else round(value, 1)


def _no_head_of_line() -> dict[str, dict[str, Any]]:
    return {
        "behind_long": {"ttft_ms_p50": None, "streams": 0},
        "alone": {"ttft_ms_p50": None, "streams": 0},
    }


def _empty_bucket(start: datetime) -> dict[str, Any]:
    nothing = {"p50": None, "p95": None}
    return {
        "start": start,
        "requests": 0,
        "streams": 0,
        "first_byte_ms": {"stream": nothing, "json": nothing},
        "shim_queue_ms": nothing,
        "output_tokens_per_second": {"p50": None, "count": 0},
        "peak_concurrency": 0,
        "timeouts": 0,
        "provider_errors": 0,
    }


async def latency_by_group(
    session: AsyncSession,
    organization_id: UUID,
    *,
    start: datetime,
    end: datetime,
    group_by: LatencyGroup,
    bucket: LatencyBucket,
) -> dict[str, Any]:
    group, name = _GROUPS[group_by]
    base = _BASE.format(
        group=group,
        tag_join=_TAG_JOIN if group_by == "tag" else "",
        first_byte=FIRST_BYTE_SQL.format(t="l."),
    )
    params: dict[str, Any] = {
        "tenant_id": organization_id,
        "start": start,
        "end": end,
        "bucket": bucket,
        "step": timedelta(hours=1) if bucket == "hour" else timedelta(days=1),
        "unspecified": UNSPECIFIED_PROVIDER_MODEL,
        "unspecified_name": UNSPECIFIED_MODEL,
    }
    ranked = (
        await session.execute(
            text(_GROUPS_SQL.format(base=base, name=name)),
            {**params, "limit": MAX_GROUPS + 1},
        )
    ).all()
    chosen = ranked[:MAX_GROUPS]
    params |= {
        "groups": [row.grp for row in chosen if row.grp is not None],
        "with_null": any(row.grp is None for row in chosen),
    }
    buckets: dict[Any, dict[datetime, dict[str, Any]]] = {}
    for row in await session.execute(
        text(_BUCKETS_SQL.format(base=base, chosen=_CHOSEN)), params
    ):
        buckets.setdefault(row.grp, {})[row.bucket] = {
            "start": row.bucket.replace(tzinfo=timezone.utc),
            "requests": row.requests,
            "streams": row.streams,
            "first_byte_ms": {
                "stream": {
                    "p50": _rounded(row.stream_first_byte_p50),
                    "p95": _rounded(row.stream_first_byte_p95),
                },
                "json": {
                    "p50": _rounded(row.json_first_byte_p50),
                    "p95": _rounded(row.json_first_byte_p95),
                },
            },
            "shim_queue_ms": {
                "p50": _rounded(row.queue_p50),
                "p95": _rounded(row.queue_p95),
            },
            "output_tokens_per_second": {
                "p50": _rounded(row.tokens_per_second_p50),
                "count": row.tokens_per_second_count,
            },
            "peak_concurrency": 0,
            "timeouts": row.timeouts,
            "provider_errors": row.provider_errors,
        }
    for row in await session.execute(
        text(_PEAK_SQL.format(base=base, chosen=_CHOSEN, sweep=SWEEP_SQL)), params
    ):
        # A request still running counts in a bucket where no request started.
        entry = buckets.setdefault(row.grp, {}).setdefault(
            row.bucket, _empty_bucket(row.bucket.replace(tzinfo=timezone.utc))
        )
        entry["peak_concurrency"] = row.peak
    head_of_line: dict[Any, dict[str, Any]] = {}
    reason = None
    if group_by not in ("model", "deployment"):
        reason = "group_by"
    elif end - start > timedelta(hours=HEAD_OF_LINE_MAX_WINDOW_HOURS):
        reason = "window_over_48h"
    else:
        for row in await session.execute(
            text(_HEAD_OF_LINE_SQL.format(base=base, chosen=_CHOSEN)),
            {
                **params,
                "short_tokens": HEAD_OF_LINE_SHORT_PROMPT_TOKENS,
                "long_tokens": HEAD_OF_LINE_LONG_PROMPT_TOKENS,
            },
        ):
            side = "behind_long" if row.behind else "alone"
            head_of_line.setdefault(row.grp, _no_head_of_line())[side] = {
                "ttft_ms_p50": _rounded(row.ttft_p50),
                "streams": row.streams,
            }
    return {
        "start": start,
        "end": end,
        "group_by": group_by,
        "bucket": bucket,
        "truncated": len(ranked) > MAX_GROUPS,
        "groups": [
            {
                "id": row.grp,
                "name": row.name,
                "requests": row.requests,
                "buckets": [
                    item for _, item in sorted(buckets.get(row.grp, {}).items())
                ],
                "head_of_line": None
                if reason
                else head_of_line.get(row.grp, _no_head_of_line()),
                "head_of_line_unavailable_reason": reason,
            }
            for row in chosen
        ],
    }
