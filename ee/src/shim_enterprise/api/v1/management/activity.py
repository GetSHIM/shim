"""Request activity, its export, and prompt versions."""

from __future__ import annotations

from collections.abc import AsyncIterator
import csv
from datetime import datetime, timezone
from decimal import Decimal
import io
import json
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import and_, case, cast as sql_cast, distinct, func, or_, select, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from shim_enterprise.api.enterprise_deps import (
    READER_REQUIRED,
    get_current_user,
    require,
)
from shim.billing.attribution import normalize_attribution
from shim.gateway.kernel.result import ResponseWarning
from shim_enterprise.billing.models import AuditIntent, RequestLifecycle, UsageLedger
from shim_enterprise.compliance.reporting import safe_csv
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim_enterprise.gateway.pipeline.outbox import _DIAGNOSTIC_FIELDS
from shim_enterprise.observability.analytics_projection import RequestLog
from shim_enterprise.observability.model_inventory import shown_model
from shim_enterprise.observability.outcomes import OUTCOMES, CompletionOutcome
from shim_enterprise.observability.overview import _spend_denied
from shim_enterprise.tenants.audit import (
    export_details,
    record_management_action as _audit,
)
from shim_enterprise.tenants.models import ApiKey, User
from shim_enterprise.tenants.permissions import user_permissions
from shim_enterprise.api.v1.management._common import (
    _ATTACHMENT,
    _aware,
    _BINARY,
    _MAX_SYNC_REQUEST_EXPORT_ROWS,
    _own_or_administered_key,
    _sync_window,
    _tenant_id,
    BillingPeriodView,
)


router = APIRouter()


_CSV_EXPORT_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {
        "description": "CSV attachment.",
        "content": {"text/csv": _BINARY},
        "headers": _ATTACHMENT,
    }
}


_MAX_PROMPT_VERSIONS = 200
_SYSTEM_PROMPT_HASH_PATTERN = r"^hmac-sha256:v1:[0-9a-f]{64}$"
_RuleIdFilter = Annotated[
    str | None,
    Query(
        pattern=r"^[a-z][a-z0-9_]{0,47}$",
        description="Only requests a tenant rule with this id matched.",
    ),
]
_TECHNICAL_FAILURES = ("provider_error", "timeout", "internal_error", "failed")


class PromptVersionOutcomes(BaseModel):
    complete: int
    truncated: int
    empty: int
    refused: int
    filtered: int


class PromptVersionView(BaseModel):
    system_prompt_hash: str | None
    first_seen: datetime
    last_seen: datetime
    requests: int
    api_keys: list[UUID] = Field(max_length=10)
    models: list[str] = Field(max_length=10)
    outcomes: PromptVersionOutcomes
    failed: int
    p95_shim_latency_ms: int | None


class PromptVersionPage(BaseModel):
    period: BillingPeriodView
    items: list[PromptVersionView]
    truncated: bool


KNOWN_REQUEST_ACTIVITY_STATUSES = (
    "completed",
    "provider_error",
    "client_disconnected",
    "timeout",
    "cancelled",
    "internal_error",
    "rejected",
    "failed",
)

RequestActivityStatus = Literal[
    "completed",
    "provider_error",
    "client_disconnected",
    "timeout",
    "cancelled",
    "internal_error",
    "rejected",
    "failed",
    "unknown",
]
CompletionOutcomeFilter = Literal[CompletionOutcome, "none"]


# Query filters the request and prompt-version routes share.
_ModelFilter = Annotated[
    str | None,
    Query(
        min_length=1, max_length=255, description="Case-insensitive model substring."
    ),
]
_TagFilter = Annotated[
    str | None,
    Query(
        min_length=1,
        max_length=settings.COST_TAG_MAX_LENGTH,
        description="Case-insensitive substring of any request tag.",
    ),
]
_CostCenterFilter = Annotated[
    str | None,
    Query(
        min_length=1,
        max_length=settings.COST_TAG_MAX_LENGTH,
        description="Case-insensitive cost center substring.",
    ),
]
_WarningFilter = Annotated[
    ResponseWarning | None,
    Query(description="Only requests that carried this warning code."),
]
_SystemPromptHashFilter = Annotated[
    str | None, Query(pattern=_SYSTEM_PROMPT_HASH_PATTERN)
]
_ApprovalFilter = Annotated[
    UUID | None, Query(description="Only requests this request approval decided.")
]
_AttemptGroupFilter = Annotated[
    str | None,
    Query(
        min_length=1,
        max_length=255,
        description="Only the attempts of one client request: the first attempt's "
        "request id.",
    ),
]
_OutcomeFilter = Annotated[
    CompletionOutcomeFilter | None,
    Query(
        description="How the answer ended; none is a request without a "
        "recorded outcome (failed, rejected or older rows)."
    ),
]
_RouteOutcomeFilter = Annotated[
    Literal["routed", "would_route", "not_allowed_for_key", "target_unavailable"]
    | None,
    Query(description="What a route rule decided at the conversation start."),
]
_SoftRefusalFilter = Annotated[
    bool | None,
    Query(
        description="Whether the refusal analyzer found a text refusal in the "
        "answer. The field exists only when the tenant enabled the refusal "
        "analyzer; answers it did not read match neither value."
    ),
]


class RequestActivityView(BaseModel):
    request_id: str
    created_at: datetime
    endpoint: str | None
    model: str | None
    status: RequestActivityStatus
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    usage_estimated: bool
    cost_usd: Decimal | None = Field(ge=0)
    cost_complete: bool
    shim_latency_ms: int | None = Field(
        default=None,
        ge=0,
        title="shim latency (ms)",
        description="shim processing time excluding provider waiting; null when unmeasured.",
    )
    pii_detected: bool
    tags: list[str] = Field(default_factory=list)
    cost_center: str | None
    provider: str | None
    team: str | None
    provider_finish_reasons: dict[str, str] | None = None
    completion_outcome: (
        Literal["complete", "truncated", "empty", "refused", "filtered"] | None
    ) = None
    repeat_chain_length: int | None = Field(default=None, ge=1)
    ttft_ms: float | None = Field(default=None, ge=0)
    provider_latency_ms: int | None = Field(
        default=None,
        ge=0,
        description=(
            "JSON answers: milliseconds from before the provider call to the parsed "
            "answer; null for streams and older rows."
        ),
    )
    warnings: list[ResponseWarning] | None = Field(
        default=None,
        description="X-Shim-Warnings codes the request carried; null on older rows.",
    )
    cached_input_tokens: int | None = Field(
        default=None,
        ge=0,
        description=(
            "Input tokens read from or written to the provider's prompt cache; "
            "null when the provider did not report the split."
        ),
    )
    system_prompt_hash: str | None = None
    deployment_kind: Literal["internal", "external", "unknown"] | None = None
    pii_entities: dict[str, int] | None = Field(
        default=None, description="Masked values by entity type; null on older rows."
    )
    monitored_entities: dict[str, int] | None = Field(
        default=None,
        description="Values sent unchanged under a monitor action, by entity type.",
    )
    blocked_entities: dict[str, int] | None = Field(
        default=None,
        description="Values that stopped the request under a block action, by entity type.",
    )
    bulk_disclosure: dict[str, int] | None = Field(
        default=None,
        description=(
            "distinct_values and threshold when the request carried at least the "
            "tenant's bulk threshold of distinct detected values; null otherwise."
        ),
    )
    injection_markers: dict[str, int | bool] | None = Field(
        default=None,
        description=(
            "Tool results and documents carrying each hidden-instruction marker; "
            '{"error": true} when the scan failed; null when the tenant\'s scan was off.'
        ),
    )
    restore_withheld: dict[str, int] | None = Field(
        default=None,
        description=(
            "Placeholders left in the answer, by type, because the caller's key and "
            "team may not see the value; null when nothing was withheld for this caller."
        ),
    )
    response_entities: dict[str, int] | None = Field(
        default=None,
        description=(
            "Distinct values the answer carried that the request did not, by "
            "entity type; null when the response scan was off or has not finished."
        ),
    )
    rule_matches: list[dict[str, Any]] | None = Field(
        default=None,
        description=(
            "Tenant rules that matched, by id, kind, action, state and count; [] when "
            "the rule set was evaluated and nothing matched, null without rules."
        ),
    )
    rule_matches_truncated: bool | None = None
    settings_applied: list[dict[str, Any]] | None = Field(
        default=None,
        description=(
            "Settings band steps that set a provider parameter, by id and version; "
            "[] when the band ran and set nothing, null when it did not run."
        ),
    )
    attempt_group_id: str | None = Field(
        default=None,
        description="On an extra attempt a tenant rule asked for: the request id of "
        "the client request's first attempt; null on a first attempt.",
    )
    attempt_number: int | None = Field(default=None, ge=2)
    attempt_reason: str | None = None
    attempt_rule_id: str | None = None
    shadow_of: str | None = Field(
        default=None,
        description="On a copy of a finished request sent to a candidate model: "
        "the primary request's id; null otherwise.",
    )
    route_decision: dict[str, Any] | None = Field(
        default=None,
        description="Where a route rule sent, or would have sent, the request: "
        "rule_id, state, from, to, reason, conversation_id and outcome (routed, "
        "would_route, not_allowed_for_key, target_unavailable), with the earlier "
        "decision under previous when a rule moved it again after privacy; null "
        "when no rule decided.",
    )
    transforms_applied: list[dict[str, Any]] | None = Field(
        default=None,
        description=(
            "Transform band steps that changed the request, by id and version, with "
            "characters before and after and the strings changed; [] when the band "
            "ran and changed nothing, null when it did not run."
        ),
    )
    approval_id: UUID | None = Field(
        default=None,
        description="The request approval this request created, was refused under "
        "or consumed; null when no approval gate decided it.",
    )
    content_archived: bool = Field(
        default=False,
        description="The self-hosted request archive kept this request's content; "
        "an admin can open it, and every opening is listed.",
    )
    response_analysis: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Results of the after-answer analyzers by name, with their versions; "
            "null when no analyzer ran or the pass has not finished."
        ),
    )


class RequestActivityStatusCountsView(BaseModel):
    completed: int = Field(ge=0)
    provider_error: int = Field(ge=0)
    client_disconnected: int = Field(ge=0)
    timeout: int = Field(ge=0)
    cancelled: int = Field(ge=0)
    internal_error: int = Field(ge=0)
    rejected: int = Field(ge=0)
    failed: int = Field(ge=0)
    unknown: int = Field(ge=0)


class RequestOutcomeCountsView(BaseModel):
    complete: int = Field(ge=0)
    truncated: int = Field(ge=0)
    empty: int = Field(ge=0)
    refused: int = Field(ge=0)
    filtered: int = Field(ge=0)
    none: int = Field(ge=0, description="Requests without a recorded outcome.")


class RequestActivitySummaryView(BaseModel):
    requests: int = Field(ge=0)
    technical_success_rate: float | None = Field(ge=0, le=1)
    p95_completed_shim_latency_ms: int | None = Field(
        ge=0, title="p95 completed shim latency (ms)"
    )
    settled_spend_usd: Decimal = Field(ge=0)
    cost_complete: bool
    unpriced_requests: int = Field(ge=0)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    pii_detected_requests: int = Field(ge=0)
    technical_failures: int = Field(ge=0)
    policy_rejections: int = Field(ge=0)
    status_counts: RequestActivityStatusCountsView
    outcome_counts: RequestOutcomeCountsView


class RequestActivityPage(BaseModel):
    generated_at: datetime
    summary: RequestActivitySummaryView
    items: list[RequestActivityView]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


@router.get("/requests", response_model=RequestActivityPage)
async def list_requests(
    start: datetime | None = Query(
        default=None,
        description="Inclusive timestamp; values without an offset are UTC.",
    ),
    end: datetime | None = Query(
        default=None,
        description="Inclusive timestamp; values without an offset are UTC.",
    ),
    status_filter: RequestActivityStatus | None = Query(
        default=None,
        alias="status",
    ),
    model: _ModelFilter = None,
    request_id: str | None = Query(default=None, min_length=1, max_length=255),
    api_key_id: Annotated[UUID | None, Query()] = None,
    pii_detected: bool | None = Query(default=None),
    tag: _TagFilter = None,
    cost_center: _CostCenterFilter = None,
    warning: _WarningFilter = None,
    system_prompt_hash: _SystemPromptHashFilter = None,
    rule_id: _RuleIdFilter = None,
    approval_id: _ApprovalFilter = None,
    attempt_group_id: _AttemptGroupFilter = None,
    completion_outcome: _OutcomeFilter = None,
    route_outcome: _RouteOutcomeFilter = None,
    soft_refusal: _SoftRefusalFilter = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> RequestActivityPage:
    generated_at = datetime.now(timezone.utc)
    tenant_id = _tenant_id(user)
    filters = await _request_filters(
        session,
        user,
        start=start,
        end=end,
        status_filter=status_filter,
        model=model,
        request_id=request_id,
        api_key_id=api_key_id,
        pii_detected=pii_detected,
        tag=tag,
        cost_center=cost_center,
        warning=warning,
        system_prompt_hash=system_prompt_hash,
        rule_id=rule_id,
        approval_id=approval_id,
        attempt_group_id=attempt_group_id,
        completion_outcome=completion_outcome,
        route_outcome=route_outcome,
        soft_refusal=soft_refusal,
    )
    summary_row = (
        await session.execute(_request_summary_statement(tenant_id, filters))
    ).one()
    summary = _request_activity_summary(summary_row)
    rows = (
        await session.execute(
            _request_rows_statement(tenant_id, filters).limit(limit).offset(offset)
        )
    ).all()
    return RequestActivityPage(
        generated_at=generated_at,
        summary=summary,
        items=[
            RequestActivityView(
                request_id=row.request_id,
                created_at=row.timestamp,
                endpoint=row.path,
                model=row.model,
                status=_request_activity_status(row.details),
                prompt_tokens=row.prompt_tokens,
                completion_tokens=row.completion_tokens,
                usage_estimated=_request_usage_estimated(row.details),
                cost_usd=Decimal(str(cost_usd)) if cost_usd is not None else None,
                cost_complete=cost_usd is not None,
                pii_detected=row.pii_detected,
                tags=list(row.tags or []),
                cost_center=row.cost_center,
                provider=_request_provider(row),
                team=row.team,
                **{
                    field: (row.details or {}).get(field)
                    for field in _DIAGNOSTIC_FIELDS
                },
                content_archived=(row.details or {}).get("request_archive") == "stored",
                response_entities=response_entities,
                response_analysis=response_analysis,
            )
            for row, cost_usd, response_entities, response_analysis in rows
        ],
        total=summary.requests,
        limit=limit,
        offset=offset,
    )


@router.get("/prompt-versions", response_model=PromptVersionPage)
async def list_prompt_versions(
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    api_key_id: UUID | None = Query(default=None),
    model: _ModelFilter = None,
    user: User = Depends(require("usage.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> PromptVersionPage:
    start_at, end_at = _sync_window(start, end, days=7)
    metadata = RequestLifecycle.lifecycle_metadata
    prompt_hash = metadata["system_prompt_hash"].as_string()
    outcome = metadata["completion_outcome"].as_string()
    tenant_id = _tenant_id(user)
    filters = [
        RequestLifecycle.organization_id == tenant_id,
        RequestLifecycle.started_at >= start_at,
        RequestLifecycle.started_at <= end_at,
        RequestLifecycle.source_endpoint != "scan",
    ]
    if api_key_id is not None:
        filters.append(RequestLifecycle.api_key_id == api_key_id)
    if model is not None:
        filters.append(
            RequestLifecycle.requested_model.icontains(model, autoescape=True)
        )
    # Narrow columns only: the grouping sorts these rows, and the whole lifecycle
    # row (its metadata jsonb) is several times wider. MATERIALIZED stops
    # Postgres folding the projection back into the scan.
    versions = (
        select(
            prompt_hash.label("system_prompt_hash"),
            RequestLifecycle.started_at,
            RequestLifecycle.api_key_id,
            shown_model(RequestLifecycle.requested_model).label("model"),
            RequestLifecycle.status,
            outcome.label("outcome"),
            metadata["shim_latency_ms"].as_integer().label("latency"),
            # A budget denial ends `failed` but is a policy rejection.
            and_(RequestLifecycle.status == "failed", _spend_denied(tenant_id)).label(
                "spend_denied"
            ),
        )
        .where(*filters)
        .cte("versions")
        .prefix_with("MATERIALIZED")
    )
    first_seen = func.min(versions.c.started_at)
    # Sorts of ~100k narrow rows fit in 32MB; the 4MB default spills to disk.
    await session.execute(text("SET LOCAL work_mem = '32MB'"))
    rows = (
        await session.execute(
            select(
                versions.c.system_prompt_hash,
                first_seen.label("first_seen"),
                func.max(versions.c.started_at).label("last_seen"),
                func.count().label("requests"),
                func.array_agg(distinct(versions.c.api_key_id)).label("api_keys"),
                func.array_agg(distinct(versions.c.model)).label("models"),
                *(
                    func.count().filter(versions.c.outcome == name).label(name)
                    for name in OUTCOMES
                ),
                func.count()
                .filter(
                    versions.c.status.in_(_TECHNICAL_FAILURES),
                    ~versions.c.spend_denied,
                )
                .label("failed"),
                func.percentile_cont(0.95)
                .within_group(versions.c.latency)
                .filter(versions.c.status == "completed")
                .label("p95"),
            )
            .group_by(versions.c.system_prompt_hash)
            .order_by(first_seen.desc())
            .limit(_MAX_PROMPT_VERSIONS + 1)
        )
    ).all()
    return PromptVersionPage(
        period=BillingPeriodView(start=start_at, end=end_at),
        items=[
            PromptVersionView(
                system_prompt_hash=row.system_prompt_hash,
                first_seen=row.first_seen,
                last_seen=row.last_seen,
                requests=row.requests,
                api_keys=[key for key in row.api_keys if key is not None][:10],
                models=row.models[:10],
                outcomes=PromptVersionOutcomes(
                    **{name: getattr(row, name) for name in OUTCOMES}
                ),
                failed=row.failed,
                p95_shim_latency_ms=round(row.p95) if row.p95 is not None else None,
            )
            for row in rows[:_MAX_PROMPT_VERSIONS]
        ],
        truncated=len(rows) > _MAX_PROMPT_VERSIONS,
    )


@router.get(
    "/requests/export",
    response_class=StreamingResponse,
    responses=_CSV_EXPORT_RESPONSES,
)
async def export_requests(
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    status_filter: RequestActivityStatus | None = Query(default=None, alias="status"),
    model: _ModelFilter = None,
    request_id: str | None = Query(default=None, min_length=1, max_length=255),
    api_key_id: Annotated[UUID | None, Query()] = None,
    pii_detected: bool | None = Query(default=None),
    tag: _TagFilter = None,
    cost_center: _CostCenterFilter = None,
    warning: _WarningFilter = None,
    system_prompt_hash: _SystemPromptHashFilter = None,
    rule_id: _RuleIdFilter = None,
    approval_id: _ApprovalFilter = None,
    attempt_group_id: _AttemptGroupFilter = None,
    completion_outcome: _OutcomeFilter = None,
    route_outcome: _RouteOutcomeFilter = None,
    soft_refusal: _SoftRefusalFilter = None,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    tenant_id = _tenant_id(user)
    start_at, end_at = _sync_window(start, end, days=30)
    filters = await _request_filters(
        session,
        user,
        start=start_at,
        end=end_at,
        status_filter=status_filter,
        model=model,
        request_id=request_id,
        api_key_id=api_key_id,
        pii_detected=pii_detected,
        tag=tag,
        cost_center=cost_center,
        warning=warning,
        system_prompt_hash=system_prompt_hash,
        rule_id=rule_id,
        approval_id=approval_id,
        attempt_group_id=attempt_group_id,
        completion_outcome=completion_outcome,
        route_outcome=route_outcome,
        soft_refusal=soft_refusal,
    )
    rows_statement = _request_rows_statement(tenant_id, filters)
    bounded_count = int(
        await session.scalar(
            select(func.count()).select_from(
                select(RequestLog.id)
                .where(*filters)
                .limit(_MAX_SYNC_REQUEST_EXPORT_ROWS + 1)
                .subquery()
            )
        )
        or 0
    )
    if bounded_count > _MAX_SYNC_REQUEST_EXPORT_ROWS:
        raise HTTPException(
            status_code=422,
            detail=(
                "synchronous request exports are limited to "
                f"{_MAX_SYNC_REQUEST_EXPORT_ROWS} rows"
            ),
        )

    # Buffered, not session.stream(): server-side cursors break on the
    # statement_cache_size=0 engine (core/database.py). The cap bounds memory.
    rows = (
        await session.execute(rows_statement.limit(_MAX_SYNC_REQUEST_EXPORT_ROWS))
    ).all()
    # Recorded after the rows are read, so the export never contains its own event.
    await _audit(
        session,
        user,
        "tenant.requests_exported",
        str(tenant_id),
        details=export_details(start_at, end_at, rows=len(rows)),
    )
    await session.commit()

    async def content() -> AsyncIterator[bytes]:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            (
                "request_id",
                "created_at",
                "endpoint",
                "model",
                "provider",
                "status",
                "prompt_tokens",
                "completion_tokens",
                "cost_usd",
                "shim_latency_ms",
                "pii_detected",
                "tags",
                "cost_center",
                "team",
                "provider_finish_reasons",
                "completion_outcome",
                "repeat_chain_length",
                "ttft_ms",
                "provider_latency_ms",
                "cached_input_tokens",
                "warnings",
                "system_prompt_hash",
                "deployment_kind",
                "cost_complete",
                "pii_entities",
                "monitored_entities",
                "blocked_entities",
                "bulk_disclosure",
                "response_entities",
                "response_analysis",
                "rule_matches",
                "settings_applied",
                "transforms_applied",
                "attempt_group_id",
                "attempt_number",
                "attempt_reason",
                "attempt_rule_id",
                "route_decision",
                "shadow_of",
                "injection_markers",
                "restore_withheld",
                "approval_id",
                "content_archived",
            )
        )
        yield output.getvalue().encode("utf-8-sig")
        for row, cost_usd, response_entities, response_analysis in rows:
            details = row.details or {}
            output.seek(0)
            output.truncate(0)
            writer.writerow(
                safe_csv(value)
                for value in (
                    row.request_id,
                    row.timestamp.isoformat(),
                    row.path,
                    row.model,
                    _request_provider(row),
                    _request_activity_status(row.details),
                    row.prompt_tokens,
                    row.completion_tokens,
                    Decimal(str(cost_usd)) if cost_usd is not None else None,
                    details.get("shim_latency_ms"),
                    row.pii_detected,
                    ",".join(row.tags or []),
                    row.cost_center,
                    row.team,
                    _json(details.get("provider_finish_reasons")),
                    details.get("completion_outcome"),
                    details.get("repeat_chain_length"),
                    details.get("ttft_ms"),
                    details.get("provider_latency_ms"),
                    details.get("cached_input_tokens"),
                    ",".join(details.get("warnings") or []),
                    details.get("system_prompt_hash"),
                    details.get("deployment_kind"),
                    cost_usd is not None,
                    *(
                        _json(details.get(field))
                        for field in (
                            "pii_entities",
                            "monitored_entities",
                            "blocked_entities",
                            "bulk_disclosure",
                        )
                    ),
                    _json(response_entities),
                    json.dumps(response_analysis, sort_keys=True, separators=(",", ":"))
                    if response_analysis is not None
                    else None,
                    _json(details.get("rule_matches")),
                    _json(details.get("settings_applied")),
                    _json(details.get("transforms_applied")),
                    details.get("attempt_group_id"),
                    details.get("attempt_number"),
                    details.get("attempt_reason"),
                    details.get("attempt_rule_id"),
                    _json(details.get("route_decision")),
                    details.get("shadow_of"),
                    _json(details.get("injection_markers")),
                    _json(details.get("restore_withheld")),
                    details.get("approval_id"),
                    details.get("request_archive") == "stored",
                )
            )
            yield output.getvalue().encode("utf-8")

    return StreamingResponse(
        content(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="shim_requests.csv"'},
    )


async def _request_filters(
    session: AsyncSession,
    user: User,
    *,
    start: datetime | None,
    end: datetime | None,
    status_filter: RequestActivityStatus | None,
    model: str | None,
    request_id: str | None,
    pii_detected: bool | None,
    tag: str | None,
    cost_center: str | None,
    warning: ResponseWarning | None = None,
    system_prompt_hash: str | None = None,
    api_key_id: UUID | None = None,
    rule_id: str | None = None,
    approval_id: UUID | None = None,
    attempt_group_id: str | None = None,
    completion_outcome: CompletionOutcomeFilter | None = None,
    route_outcome: str | None = None,
    soft_refusal: bool | None = None,
) -> list[Any]:
    start_at = _aware(start) if start is not None else None
    end_at = _aware(end) if end is not None else None
    if start_at is not None and end_at is not None and start_at > end_at:
        raise HTTPException(status_code=422, detail="start must not be after end")
    try:
        normalized_tag = (
            normalize_attribution(tag, maximum_length=settings.COST_TAG_MAX_LENGTH)
            if tag is not None
            else None
        )
        normalized_cost_center = (
            normalize_attribution(
                cost_center,
                maximum_length=settings.COST_TAG_MAX_LENGTH,
            )
            if cost_center is not None
            else None
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    tenant_id = _tenant_id(user)
    filters = [RequestLog.organization_id == tenant_id]
    if "usage.read" not in await user_permissions(session, user):
        filters.append(
            RequestLog.api_key_id.in_(
                select(ApiKey.id).where(
                    ApiKey.organization_id == tenant_id, _own_or_administered_key(user)
                )
            )
        )
    if start_at is not None:
        filters.append(RequestLog.timestamp >= start_at)
    if end_at is not None:
        filters.append(RequestLog.timestamp <= end_at)
    if status_filter is not None:
        lifecycle_status = _request_lifecycle_status_expression()
        filters.append(
            or_(
                lifecycle_status.is_(None),
                lifecycle_status.not_in(KNOWN_REQUEST_ACTIVITY_STATUSES),
            )
            if status_filter == "unknown"
            else lifecycle_status == status_filter
        )
    if model is not None:
        filters.append(RequestLog.model.icontains(model, autoescape=True))
    if request_id is not None:
        filters.append(RequestLog.request_id == request_id)
    if api_key_id is not None:
        filters.append(RequestLog.api_key_id == api_key_id)
    if pii_detected is not None:
        filters.append(RequestLog.pii_detected == pii_detected)
    if system_prompt_hash is not None:
        filters.append(
            RequestLog.details["system_prompt_hash"].as_string() == system_prompt_hash
        )
    if normalized_tag is not None:
        tag_values = func.jsonb_array_elements_text(
            func.coalesce(RequestLog.tags, sql_cast([], JSONB))
        ).table_valued("value")
        filters.append(
            select(1)
            .select_from(tag_values)
            .where(tag_values.c.value.icontains(normalized_tag, autoescape=True))
            .correlate(RequestLog)
            .exists()
        )
    if normalized_cost_center is not None:
        filters.append(
            RequestLog.cost_center.icontains(
                normalized_cost_center,
                autoescape=True,
            )
        )
    if warning is not None:
        filters.append(RequestLog.details.contains({"warnings": [warning]}))
    if rule_id is not None:
        filters.append(
            RequestLog.details.contains({"rule_matches": [{"rule_id": rule_id}]})
        )
    if approval_id is not None:
        filters.append(RequestLog.details.contains({"approval_id": str(approval_id)}))
    if attempt_group_id is not None:
        filters.append(
            or_(
                RequestLog.request_id == attempt_group_id,
                RequestLog.details.contains({"attempt_group_id": attempt_group_id}),
            )
        )
    if completion_outcome is not None:
        outcome = RequestLog.details["completion_outcome"].as_string()
        filters.append(
            outcome.is_(None)
            if completion_outcome == "none"
            else outcome == completion_outcome
        )
    if route_outcome is not None:
        filters.append(
            RequestLog.details.contains({"route_decision": {"outcome": route_outcome}})
        )
    if soft_refusal is not None:
        lifecycle = aliased(RequestLifecycle)
        filters.append(
            select(1)
            .where(
                lifecycle.organization_id == tenant_id,
                lifecycle.request_id == RequestLog.request_id,
                lifecycle.lifecycle_metadata["response_analysis"]["refusal"][
                    "soft_refusal"
                ].as_string()
                == str(soft_refusal).lower(),
            )
            .correlate(RequestLog)
            .exists()
        )
    return filters


def _request_settled_spend(tenant_id: UUID):
    return (
        select(func.sum(UsageLedger.cost_usd))
        .where(
            UsageLedger.organization_id == tenant_id,
            UsageLedger.request_id == RequestLog.request_id,
            UsageLedger.event_type == "spend_settlement",
            UsageLedger.event_metadata["pricing"]["pricing_resolution"]
            .as_string()
            .is_distinct_from("unknown"),
        )
        .correlate(RequestLog)
        .scalar_subquery()
    )


def _request_unpriced_spend(tenant_id: UUID):
    return (
        select(UsageLedger.id)
        .where(
            UsageLedger.organization_id == tenant_id,
            UsageLedger.request_id == RequestLog.request_id,
            UsageLedger.event_type == "spend_settlement",
            UsageLedger.event_metadata["pricing"]["pricing_resolution"].as_string()
            == "unknown",
        )
        .correlate(RequestLog)
        .exists()
    )


def _request_summary_statement(tenant_id: UUID, filters: list[Any]):
    lifecycle_status = _request_lifecycle_status_expression()
    outcome = RequestLog.details["completion_outcome"].as_string()
    usage_estimated = RequestLog.details["usage_estimated"].as_boolean().is_(True)
    spend = _request_settled_spend(tenant_id)
    spend_denied = (
        select(AuditIntent.id)
        .where(
            AuditIntent.organization_id == tenant_id,
            AuditIntent.request_id == RequestLog.request_id,
            AuditIntent.event_type == "preflight",
            AuditIntent.usage_summary["spend_denied"].as_integer() == 1,
        )
        .correlate(RequestLog)
        .exists()
    )
    return (
        select(
            func.count(RequestLog.id).label("requests"),
            func.count(RequestLog.id)
            .filter(_request_unpriced_spend(tenant_id))
            .label("unpriced_requests"),
            *(
                func.count(RequestLog.id)
                .filter(lifecycle_status == status_name)
                .label(status_name)
                for status_name in KNOWN_REQUEST_ACTIVITY_STATUSES
            ),
            func.count(RequestLog.id)
            .filter(
                or_(
                    lifecycle_status.is_(None),
                    lifecycle_status.not_in(KNOWN_REQUEST_ACTIVITY_STATUSES),
                )
            )
            .label("unknown"),
            *(
                func.count(RequestLog.id)
                .filter(outcome == name)
                .label(f"outcome_{name}")
                for name in OUTCOMES
            ),
            func.count(RequestLog.id).filter(outcome.is_(None)).label("outcome_none"),
            func.coalesce(
                func.sum(case((usage_estimated, 0), else_=RequestLog.prompt_tokens)),
                0,
            ).label("prompt_tokens"),
            func.coalesce(
                func.sum(
                    case((usage_estimated, 0), else_=RequestLog.completion_tokens)
                ),
                0,
            ).label("completion_tokens"),
            func.count(RequestLog.id)
            .filter(RequestLog.pii_detected.is_(True))
            .label("pii_detected_requests"),
            func.count(RequestLog.id)
            .filter(lifecycle_status == "failed", spend_denied)
            .label("policy_failed"),
            func.percentile_cont(0.95)
            .within_group(RequestLog.details["shim_latency_ms"].as_integer())
            .filter(lifecycle_status == "completed")
            .label("p95_completed_shim_latency_ms"),
            func.coalesce(
                func.sum(func.coalesce(spend, Decimal("0"))), Decimal("0")
            ).label("settled_spend_usd"),
        )
        .select_from(RequestLog)
        .where(*filters)
    )


def _request_activity_summary(row: Any) -> RequestActivitySummaryView:
    status_counts = {
        status_name: int(getattr(row, status_name) or 0)
        for status_name in (*KNOWN_REQUEST_ACTIVITY_STATUSES, "unknown")
    }
    technical_failures = sum(
        status_counts[status_name] for status_name in _TECHNICAL_FAILURES
    ) - int(row.policy_failed or 0)
    technical_requests = status_counts["completed"] + technical_failures
    p95 = row.p95_completed_shim_latency_ms
    return RequestActivitySummaryView(
        requests=int(row.requests or 0),
        technical_success_rate=(
            status_counts["completed"] / technical_requests
            if technical_requests
            else None
        ),
        p95_completed_shim_latency_ms=round(float(p95)) if p95 is not None else None,
        settled_spend_usd=Decimal(str(row.settled_spend_usd or 0)),
        cost_complete=not row.unpriced_requests,
        unpriced_requests=int(row.unpriced_requests or 0),
        prompt_tokens=int(row.prompt_tokens or 0),
        completion_tokens=int(row.completion_tokens or 0),
        pii_detected_requests=int(row.pii_detected_requests or 0),
        technical_failures=technical_failures,
        policy_rejections=status_counts["rejected"] + int(row.policy_failed or 0),
        status_counts=RequestActivityStatusCountsView(**status_counts),
        outcome_counts=RequestOutcomeCountsView(
            **{
                name: int(getattr(row, f"outcome_{name}") or 0)
                for name in (*OUTCOMES, "none")
            }
        ),
    )


def _request_rows_statement(tenant_id: UUID, filters: list[Any]):
    # Correlate spend to bounded request rows; never aggregate all tenant history.
    spend = _request_settled_spend(tenant_id)
    return (
        select(
            RequestLog,
            case(
                (_request_unpriced_spend(tenant_id), None),
                else_=func.coalesce(spend, Decimal("0")),
            ).label("cost_usd"),
            # The response scan finishes after the analytics row is projected.
            RequestLifecycle.lifecycle_metadata["response_entities"].label(
                "response_entities"
            ),
            RequestLifecycle.lifecycle_metadata["response_analysis"].label(
                "response_analysis"
            ),
        )
        .outerjoin(
            RequestLifecycle,
            (RequestLifecycle.organization_id == RequestLog.organization_id)
            & (RequestLifecycle.request_id == RequestLog.request_id),
        )
        .where(*filters)
        .order_by(RequestLog.timestamp.desc(), RequestLog.id.desc())
    )


def _json(value: Any) -> str | None:
    return None if value is None else json.dumps(value, sort_keys=True)


def _request_provider(row: RequestLog) -> str | None:
    provider = (row.details or {}).get("provider")
    return provider if isinstance(provider, str) else None


def _request_activity_status(details: dict[str, Any] | None) -> RequestActivityStatus:
    value = (details or {}).get("lifecycle_status")
    return value if value in KNOWN_REQUEST_ACTIVITY_STATUSES else "unknown"


def _request_usage_estimated(details: dict[str, Any] | None) -> bool:
    return (details or {}).get("usage_estimated") is True


def _request_lifecycle_status_expression() -> Any:
    return RequestLog.details["lifecycle_status"].as_string()
