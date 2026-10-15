"""The change test: a share of live requests is also sent to a candidate model, and
the two answers are compared in memory, never stored."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
import logging
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim.gateway.analyzers import ANALYZERS
from shim.gateway.contracts.ids import RequestId, TenantId
from shim.gateway.kernel.result import PreparedInference
from shim.gateway.kernel.shadow import (
    ShadowCandidate,
    ShadowObservation,
    ShadowSelection,
)
from shim.gateway.pipeline.analysis import AnalysisContext, run_analyzers
from shim.rules import Rule, in_scope
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.cache.circuit_breaker import RedisResource
from shim_enterprise.observability.enterprise_metrics import (
    CHANGE_TEST_COMPARISONS_TOTAL,
    CHANGE_TEST_SKIPS_TOTAL,
)
from shim_enterprise.observability.lifecycle import RequestLifecycleRepository
from shim_enterprise.rules.route_triggers import ShadowMatch
from shim_enterprise.tenants.deployments import alias_target

logger = logging.getLogger(__name__)
COMPARISON_VERSION = 1
# The answer-reading analyzers a comparison may run; `schema` always.
_OPTIONAL_ANALYZERS = frozenset({"language", "refusal"})


def shadow_rules(prepared: PreparedInference) -> list[tuple[Rule, ShadowMatch]]:
    """The enforced `shadow` rules for the request's alias, in rule-set order."""
    found = []
    for rule in prepared.rules.rules if prepared.rules is not None else ():
        if (
            rule.kind != "route"
            or rule.state != "enforced"
            or rule.match.get("on") != "shadow"
            or rule.match.get("from") != prepared.model
        ):
            continue
        try:
            found.append((rule, ShadowMatch.model_validate(rule.match)))
        except ValueError:
            logger.warning("Change test rule skipped reason=invalid_match")
    return found


def counter_key(tenant_id: object, rule_id: str, starts_at: datetime) -> str:
    # The tenant id stays out of Redis keys in clear.
    digest = sha256(f"{tenant_id}|{rule_id}|{starts_at.isoformat()}".encode())
    return f"ct:{digest.hexdigest()[:40]}"


def sampled(rule_id: str, request_id: str, share_percent: float) -> bool:
    bucket = int(sha256(f"{rule_id}|{request_id}".encode()).hexdigest()[:8], 16)
    return bucket % 1000 < round(share_percent * 10)


def _side(
    observation: ShadowObservation, results: Mapping[str, Any] | None
) -> dict[str, Any]:
    answered = observation.answer_text is not None
    schema = (results or {}).get("schema") or {}
    language = (results or {}).get("language") or {}
    refusal = (results or {}).get("refusal") or {}
    side = {
        "status": observation.status,
        "outcome": observation.completion_outcome if answered else "failed",
        "schema_valid": schema.get("valid"),
        "language": language.get("answer"),
        "soft_refusal": refusal.get("soft_refusal"),
        "answer_chars": len(observation.answer_text) if answered else None,
        "prompt_tokens": observation.prompt_tokens,
        "completion_tokens": observation.completion_tokens,
        "provider_latency_ms": observation.provider_latency_ms,
        "ttft_ms": observation.ttft_ms,
        "cost_usd": None if observation.cost_usd is None else str(observation.cost_usd),
        "error_code": observation.error_code,
    }
    if observation.answer_truncated:
        side["answer_truncated"] = True
    return side


class ChangeTestSender:
    """S58's shadow sender for the tenant's `shadow` rules."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        cache: RedisResource | None,
    ) -> None:
        self.session_factory = session_factory
        self.cache = cache
        # (rule id, starts_at) of tests that reached a cap in this process.
        self.ended: set[tuple[str, datetime]] = set()

    def select(self, prepared: PreparedInference) -> ShadowSelection | None:
        if prepared.rules is None or not any(
            rule.state == "enforced" and rule.match.get("on") == "shadow"
            for rule in prepared.rules.rules
        ):
            return None
        now = datetime.now(timezone.utc)
        tags = prepared.admission.tags if prepared.admission is not None else ()
        for rule, match in shadow_rules(prepared):
            if (
                in_scope(rule, prepared, tags)
                and match.starts_at <= now < match.ends_at
                and (rule.id, match.starts_at) not in self.ended
            ):
                # Only the first test that holds samples: one copy per request at most.
                if not sampled(rule.id, str(prepared.request_id), match.share_percent):
                    return None
                return ShadowSelection(
                    rule_id=rule.id, candidate=match.to, keep_answer=True
                )
        return None

    def _match(self, prepared: PreparedInference, rule_id: str) -> ShadowMatch:
        return next(
            match for rule, match in shadow_rules(prepared) if rule.id == rule_id
        )

    def _skip(self, reason: str) -> None:
        CHANGE_TEST_SKIPS_TOTAL.labels(reason=reason).inc()

    async def candidate(
        self, prepared: PreparedInference, selection: ShadowSelection
    ) -> ShadowCandidate | None:
        match = self._match(prepared, selection.rule_id)
        try:
            async with self.session_factory() as session:
                found = await alias_target(session, prepared, selection.candidate)
                # A copy that cannot be sent is never counted.
                reason = (
                    (
                        "target_not_allowed"
                        if found == "not_allowed"
                        else "target_unavailable"
                    )
                    if isinstance(found, str)
                    else await self._left(session, prepared, selection.rule_id, match)
                )
        except Exception as exc:
            logger.warning("Change test candidate failed type=%s", type(exc).__name__)
            reason = "target_unavailable"
        if reason is not None or isinstance(found, str):
            self._skip(reason or "target_unavailable")
            return None
        target, kind = found
        return ShadowCandidate(provider_target=target, deployment_kind=kind)

    async def _left(
        self,
        session: AsyncSession,
        prepared: PreparedInference,
        rule_id: str,
        match: ShadowMatch,
    ) -> str | None:
        """The skip reason when the test's caps are reached. A copy is counted when it
        was sent (`compare`), after the core guards that may still drop it.
        ponytail: copies in flight are not counted yet, so a test can pass
        `max_requests` by at most SHADOW_MAX_IN_FLIGHT per process, as its cost cap."""
        redis = self.cache.redis if self.cache is not None else None
        if redis is None:
            return "counter_unavailable"
        key = counter_key(prepared.tenant_id, rule_id, match.starts_at)
        expiry = max(
            1,
            int(
                (
                    match.ends_at + timedelta(days=7) - datetime.now(timezone.utc)
                ).total_seconds()
            ),
        )
        try:
            if not await redis.exists(f"{key}:n"):
                copies, cost = await copies_so_far(
                    session, prepared.tenant_id, rule_id, match.starts_at
                )
                await redis.set(f"{key}:n", copies, nx=True, ex=expiry)
                await redis.set(f"{key}:usd", str(cost), nx=True, ex=expiry)
            copies = int(await redis.get(f"{key}:n") or 0)
            spent = Decimal(await redis.get(f"{key}:usd") or "0")
        except Exception as exc:
            # No copy when its spend cannot be counted.
            logger.warning("Change test counter failed type=%s", type(exc).__name__)
            return "counter_unavailable"
        reason = (
            "cap_requests"
            if copies >= match.max_requests
            else "cap_cost"
            if spent >= match.max_cost_usd
            else None
        )
        if reason is not None:
            self.ended.add((rule_id, match.starts_at))
        return reason

    async def compare(
        self,
        prepared: PreparedInference,
        selection: ShadowSelection,
        primary: ShadowObservation,
        shadow: ShadowObservation,
    ) -> None:
        try:
            match = self._match(prepared, selection.rule_id)
            redis = self.cache.redis if self.cache is not None else None
            if redis is not None:
                # The copy was sent: it counts toward the test's caps.
                key = counter_key(
                    prepared.tenant_id, selection.rule_id, match.starts_at
                )
                await redis.incr(f"{key}:n")
                if shadow.cost_usd is not None:
                    await redis.incrbyfloat(f"{key}:usd", float(shadow.cost_usd))
            primary_results, shadow_results = await asyncio.to_thread(
                self._analyse, prepared, primary, shadow
            )
            schema = (primary_results or {}).get("schema") or {}
            record = {
                "rule_id": selection.rule_id,
                "starts_at": match.starts_at.isoformat(),
                "version": COMPARISON_VERSION,
                "schema_expected": schema.get("expected"),
                "primary": _side(primary, primary_results),
                "candidate": _side(shadow, shadow_results),
            }
            async with self.session_factory() as session:
                await RequestLifecycleRepository.update(
                    session,
                    organization_id=TenantId(prepared.tenant_id),
                    request_id=RequestId(shadow.request_id),
                    values={
                        "lifecycle_metadata": RequestLifecycle.lifecycle_metadata.op(
                            "||"
                        )({"shadow_comparison": record})
                    },
                )
                await session.commit()
        except Exception as exc:
            logger.warning("Change test comparison failed type=%s", type(exc).__name__)
            CHANGE_TEST_COMPARISONS_TOTAL.labels(result="failed").inc()
            return
        CHANGE_TEST_COMPARISONS_TOTAL.labels(result="ok").inc()

    def _analyse(
        self,
        prepared: PreparedInference,
        primary: ShadowObservation,
        shadow: ShadowObservation,
    ) -> tuple[dict | None, dict | None]:
        # Legal: nothing derived from the answer to a request with personal data is kept.
        if prepared.privacy is not None and prepared.privacy.pii_detected:
            return None, None
        wanted = {"schema"} | (_OPTIONAL_ANALYZERS & set(prepared.response_analysis))
        analyzers = [analyzer for analyzer in ANALYZERS if analyzer.name in wanted]
        payload = prepared.pre_band_payload or prepared.payload

        def run(side: ShadowObservation) -> dict | None:
            if side.answer_text is None:
                return None
            return run_analyzers(
                analyzers,
                AnalysisContext(
                    request_id=side.request_id,
                    protocol=prepared.protocol,
                    model=prepared.model,
                    payload=payload,
                    answer_text=side.answer_text,
                    answer_truncated=side.answer_truncated,
                    tool_calls=side.tool_calls,
                    completion_outcome=side.completion_outcome,
                    # Nothing was detected, so nothing was masked to restore.
                    restore=lambda text: text,
                ),
            )

        return run(primary), run(shadow)


async def copies_so_far(
    session: AsyncSession, tenant_id: object, rule_id: str, starts_at: datetime
) -> tuple[int, Decimal]:
    """The test's copies and their settled cost, from the ledger."""
    copies, cost = (
        await session.execute(
            select(
                func.count(func.distinct(RequestLifecycle.request_id)),
                func.coalesce(func.sum(UsageLedger.cost_usd), 0),
            )
            .select_from(RequestLifecycle)
            .outerjoin(
                UsageLedger,
                (UsageLedger.organization_id == RequestLifecycle.organization_id)
                & (UsageLedger.request_id == RequestLifecycle.request_id)
                & (UsageLedger.event_type == "spend_settlement"),
            )
            .where(
                RequestLifecycle.organization_id == tenant_id,
                RequestLifecycle.started_at >= starts_at,
                RequestLifecycle.lifecycle_metadata["shadow_rule_id"].astext == rule_id,
            )
        )
    ).one()
    return int(copies), Decimal(cost)
