"""The semantic review loop: archived requests read against the tenant's questions.

Runs inside the enterprise gateway process, only with REQUEST_ARCHIVE_ENABLED, after
the requests are long answered. It reads the masked payload, never the original
values and never the answer, and its only effects are review rows, a finding and the
review calls' own cost. Several processes may run it: the unique key decides which
one reviews an item.
"""

from __future__ import annotations

import asyncio
import contextvars
from datetime import datetime, time, timedelta, timezone
from decimal import Decimal
import json
import logging
from typing import Any
from uuid import UUID, uuid4

from cryptography.fernet import Fernet
from sqlalchemy import delete, exists, func, literal, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim.gateway.contracts.ids import CURRENT_REQUEST_ID, TenantId
from shim_enterprise.archive.models import RequestArchive
from shim_enterprise.billing.models import UsageLedger
from shim_enterprise.core.config import settings
from shim_enterprise.observability.enterprise_metrics import SEMANTIC_REVIEWS_TOTAL
from shim_enterprise.outbox.publisher import OutboxWriter
from shim_enterprise.semantic.call import (
    REVIEW_TAG,
    SemanticTarget,
    request_text,
    run_semantic_call,
    semantic_target,
)
from shim_enterprise.semantic.models import (
    OrganizationSemanticQuestions,
    SemanticReview,
)
from shim_enterprise.tenants.gateway_settings import (
    SemanticReviewSettings,
    stored_settings,
)
from shim_enterprise.tenants.models import OrganizationGatewaySettings

logger = logging.getLogger(__name__)
STALE_CLAIM = timedelta(minutes=10)
# A tenant's pass ends well before its claims go stale, so another process never
# claims an item this one is still reviewing; one slow model holds the others back
# at most this long.
PASS_SECONDS = STALE_CLAIM.total_seconds() / 2
ITEM_SECONDS = 120
# An item still failing this long after its first claim (about 144 tries, one per
# stale claim) is not a temporary refusal: it ends `failed` with its last error code.
GIVE_UP_AFTER = timedelta(days=1)
ACTOR = "system:semantic_review"


async def run_review_loop(kernel: Any, session_factory: async_sessionmaker) -> None:
    """Review every SEMANTIC_REVIEW_INTERVAL_SECONDS until cancelled; a failing pass
    is logged by type and the next one runs."""
    while True:
        try:
            await review_once(kernel, session_factory)
        except Exception as exc:
            logger.warning("Semantic review pass failed type=%s", type(exc).__name__)
        await asyncio.sleep(settings.SEMANTIC_REVIEW_INTERVAL_SECONDS)


async def review_once(kernel: Any, session_factory: async_sessionmaker) -> None:
    async with session_factory() as session:
        rows = (
            await session.execute(
                select(
                    OrganizationGatewaySettings.organization_id,
                    OrganizationGatewaySettings.settings,
                ).where(
                    OrganizationGatewaySettings.settings["semantic_review"][
                        "enabled"
                    ].as_boolean()
                )
            )
        ).all()
    for organization_id, stored in rows:
        try:
            review = stored_settings(stored).semantic_review
        except ValueError as exc:
            logger.warning(
                "Semantic review settings skipped type=%s", type(exc).__name__
            )
            continue
        try:
            # Each tenant's claims carry the time they are made.
            await review_tenant(
                kernel,
                session_factory,
                organization_id,
                review,
                datetime.now(timezone.utc),
            )
        except Exception as exc:
            logger.warning(
                "Semantic review of a tenant failed type=%s", type(exc).__name__
            )


async def review_tenant(
    kernel: Any,
    session_factory: async_sessionmaker,
    organization_id: UUID,
    review: SemanticReviewSettings,
    now: datetime,
) -> None:
    async with session_factory() as session:
        claims, questions, target = await _claim(session, organization_id, review, now)
        await session.commit()
    if target is None:
        # Nothing was claimed.
        return
    done: set[UUID] = set()
    try:
        async with asyncio.timeout(PASS_SECONDS):
            for claim in claims:
                if done and not await _within_cost(
                    session_factory, organization_id, review, now
                ):
                    break
                status = await _review_item(
                    kernel,
                    session_factory,
                    organization_id,
                    review,
                    questions,
                    target,
                    claim,
                    now,
                )
                SEMANTIC_REVIEWS_TOTAL.labels(status=status).inc()
                done.add(claim.id)
                if status == "pending":
                    # A temporary refusal: likely the next item's too.
                    break
    except TimeoutError:
        logger.warning("Semantic review pass reached its time bound")
    left = [claim.id for claim in claims if claim.id not in done]
    if left:
        # Not reviewed in this pass: back to the pool, unclaimed. An item cut off
        # mid-call keeps its row: its spend counts toward the day's cap.
        async with session_factory() as session:
            await session.execute(
                delete(SemanticReview).where(
                    SemanticReview.id.in_(left),
                    SemanticReview.status == "pending",
                    SemanticReview.cost_usd.is_(None),
                )
            )
            await session.commit()


async def _spent(
    session: AsyncSession, organization_id: UUID, now: datetime
) -> Decimal:
    spent = await session.scalar(
        select(func.coalesce(func.sum(SemanticReview.cost_usd), 0)).where(
            SemanticReview.organization_id == organization_id,
            SemanticReview.created_at
            >= datetime.combine(now.date(), time(), tzinfo=timezone.utc),
        )
    )
    return Decimal(spent or 0)


async def _within_cost(
    session_factory: async_sessionmaker,
    organization_id: UUID,
    review: SemanticReviewSettings,
    now: datetime,
) -> bool:
    """Read before every call: the day's cap can be passed by one call only."""
    async with session_factory() as session:
        return await _spent(session, organization_id, now) < review.max_cost_usd_per_day


async def _claim(
    session: AsyncSession,
    organization_id: UUID,
    review: SemanticReviewSettings,
    now: datetime,
) -> tuple[list[Any], list[dict[str, Any]], SemanticTarget | None]:
    """The reviews this pass makes, claimed under the hourly and daily caps."""
    row = await session.get(OrganizationSemanticQuestions, organization_id)
    if row is None or row.revision < 1 or not row.questions:
        return [], [], None
    owned = SemanticReview.organization_id == organization_id
    target = await semantic_target(session, organization_id, review.model)
    if target is None or not target.internal:
        # Only an internal model reads archived requests (the settings refuse any
        # other); a deployment edited since then waits, and nothing is claimed.
        return [], [], None
    claimed_hour = await session.scalar(
        select(func.count()).where(
            owned, SemanticReview.claimed_at >= now - timedelta(hours=1)
        )
    )
    left = review.max_items_per_hour - (claimed_hour or 0)
    if left <= 0 or await _spent(session, organization_id, now) >= (
        review.max_cost_usd_per_day
    ):
        return [], [], None
    allowance = min(left, settings.SEMANTIC_REVIEW_BATCH)
    # A stale claim of older questions is dropped: the item is claimed again below,
    # at the current revision.
    await session.execute(
        delete(SemanticReview).where(
            owned,
            SemanticReview.status == "pending",
            SemanticReview.claimed_at < now - STALE_CLAIM,
            SemanticReview.questions_revision != row.revision,
        )
    )
    stale = (
        select(SemanticReview.id)
        .where(
            owned,
            SemanticReview.status == "pending",
            SemanticReview.claimed_at < now - STALE_CLAIM,
        )
        .limit(allowance)
        .with_for_update(skip_locked=True)
    )
    reclaimed = (
        await session.execute(
            update(SemanticReview)
            .where(SemanticReview.id.in_(stale))
            .values(claimed_at=now)
            .returning(
                SemanticReview.id,
                SemanticReview.archive_id,
                SemanticReview.request_id,
                SemanticReview.created_at,
            )
        )
    ).all()
    fresh = (
        select(
            func.gen_random_uuid(),
            RequestArchive.organization_id,
            RequestArchive.id,
            RequestArchive.request_id,
            RequestArchive.api_key_id,
            literal(row.revision),
            literal("pending"),
            literal(now),
        )
        .where(
            RequestArchive.organization_id == organization_id,
            RequestArchive.expires_at > now,
            # A request made with the review key is never reviewed by it.
            RequestArchive.api_key_id.is_distinct_from(review.api_key_id),
            ~exists().where(
                SemanticReview.archive_id == RequestArchive.id,
                SemanticReview.questions_revision == row.revision,
            ),
        )
        .order_by(RequestArchive.created_at.desc())
        .limit(max(0, allowance - len(reclaimed)))
    )
    inserted = (
        await session.execute(
            insert(SemanticReview)
            .from_select(
                [
                    "id",
                    "organization_id",
                    "archive_id",
                    "request_id",
                    "api_key_id",
                    "questions_revision",
                    "status",
                    "claimed_at",
                ],
                fresh,
            )
            .on_conflict_do_nothing()
            .returning(
                SemanticReview.id,
                SemanticReview.archive_id,
                SemanticReview.request_id,
                SemanticReview.created_at,
            )
        )
    ).all()
    # Fresh items first: an item that keeps failing never ends a pass before them.
    claims = [*inserted, *reclaimed]
    if claims:
        await _audit_scan(
            session,
            organization_id,
            [claim.request_id for claim in claims],
            row.revision,
            review,
        )
    return claims, list(row.questions), target


async def _audit_scan(
    session: AsyncSession,
    organization_id: UUID,
    request_ids: list[str],
    revision: int,
    review: SemanticReviewSettings,
) -> None:
    """One audit intent per claim batch: the request ids read, never their content."""
    event_id = f"management:{uuid4()}"
    await OutboxWriter().append(
        session,
        organization_id=TenantId(organization_id),
        values={
            "event_type": "audit.chain_append_requested",
            "aggregate_type": "management",
            "aggregate_id": event_id,
            "idempotency_key": f"{event_id}:audit",
            "payload": {
                "organization_id": str(organization_id),
                "request_id": event_id,
                "event_type": "management_action",
                "actor": ACTOR,
                "endpoint": "tenant.request_content_scanned",
                "extra": {
                    "subject_id": str(organization_id),
                    "request_ids": request_ids,
                    "questions_revision": revision,
                    "model": review.model,
                    "actor_type": "internal",
                },
            },
            "status": "pending",
            "next_attempt_at": datetime.now(timezone.utc),
        },
    )


def masked_payload(ciphertext: bytes) -> Any:
    """The archived masked payload; the edit map with the original values is never read."""
    return json.loads(Fernet(str(settings.ENCRYPTION_KEY).encode()).decrypt(ciphertext))


async def _review_item(
    kernel: Any,
    session_factory: async_sessionmaker,
    organization_id: UUID,
    review: SemanticReviewSettings,
    questions: list[dict[str, Any]],
    target: SemanticTarget,
    claim: Any,
    now: datetime,
) -> str:
    """The item's new status; `pending` after a temporary refusal, which the next
    pass that re-claims it tries again."""
    values: dict[str, Any] = {"completed_at": datetime.now(timezone.utc)}
    # The call's request id lands here even when the call is cut off.
    context = contextvars.copy_context()
    context.run(CURRENT_REQUEST_ID.set, None)
    try:
        async with session_factory() as session:
            archive = await session.get(RequestArchive, claim.archive_id)
        if archive is None:
            values |= {"status": "failed", "error_code": "TARGET_UNAVAILABLE"}
        else:
            payload = await asyncio.to_thread(masked_payload, archive.masked_payload)
            text = request_text(payload, archive.protocol)
            if not text.strip():
                values["status"] = "skipped_empty"
            else:
                # GatewaySettings refuses an enabled review without both.
                assert review.api_key_id is not None and review.model is not None
                async with asyncio.timeout(ITEM_SECONDS):
                    result = await run_semantic_call(
                        kernel,
                        api_key_id=review.api_key_id,
                        alias=review.model,
                        provider=target.provider,
                        text=text,
                        questions=questions,
                        tag=REVIEW_TAG,
                        context=context,
                    )
                values |= {
                    "status": "pending" if result.retryable else result.outcome,
                    "matched_question_ids": list(result.matched_ids),
                    "review_request_id": result.request_id,
                    "error_code": result.error_code,
                }
    except TimeoutError:
        values |= {"status": "pending", "error_code": "TIMEOUT"}
    except asyncio.CancelledError:
        # The pass's bound: the call may already be billed.
        await _store(session_factory, organization_id, claim, context, {})
        raise
    except Exception as exc:
        logger.warning("Semantic review item failed type=%s", type(exc).__name__)
        values |= {"status": "pending", "error_code": "INTERNAL"}
    if values["status"] == "pending":
        values["completed_at"] = None
        if claim.created_at <= now - GIVE_UP_AFTER:
            values |= {"status": "failed", "completed_at": datetime.now(timezone.utc)}
    await _store(session_factory, organization_id, claim, context, values)
    return values["status"]


async def _store(
    session_factory: async_sessionmaker,
    organization_id: UUID,
    claim: Any,
    context: contextvars.Context,
    values: dict[str, Any],
) -> None:
    """The item's new values, with the call's spend added to what earlier tries spent."""
    async with session_factory() as session:
        request_id = values.get("review_request_id") or context.get(CURRENT_REQUEST_ID)
        spent = await _call_spend(session, organization_id, request_id)
        if spent is not None:
            values = {
                **values,
                "cost_usd": func.coalesce(SemanticReview.cost_usd, 0) + spent,
            }
        if values:
            await session.execute(
                update(SemanticReview)
                .where(SemanticReview.id == claim.id)
                .values(**values)
            )
            await session.commit()


async def _call_spend(
    session: AsyncSession, organization_id: UUID, request_id: str | None
) -> Decimal | None:
    """A review call's settled spend; refunded, none; cut off before either, its
    reservation, the upper bound the gateway held for it."""
    if request_id is None:
        return None
    totals: dict[str, Decimal] = {
        event_type: total
        for event_type, total in (
            await session.execute(
                select(UsageLedger.event_type, func.sum(UsageLedger.cost_usd))
                .where(
                    UsageLedger.organization_id == organization_id,
                    UsageLedger.request_id == request_id,
                    UsageLedger.event_type.in_(
                        ("spend_settlement", "spend_refund", "spend_reservation")
                    ),
                )
                .group_by(UsageLedger.event_type)
            )
        ).tuples()
    }
    if "spend_settlement" in totals:
        return totals["spend_settlement"]
    if "spend_refund" in totals:
        return None
    return totals.get("spend_reservation")
