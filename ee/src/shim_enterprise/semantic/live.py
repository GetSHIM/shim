"""The live semantic check on a tenant-marked endpoint: before the provider call, bounded
by the tenant's timeout, and it only ever warns."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256
import logging
from time import monotonic
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim.gateway.contracts.ids import RequestId, TenantId
from shim.gateway.kernel.attempts import AttemptOutcome, protects_less
from shim.gateway.kernel.result import PreparedInference
from shim.rules import KINDS
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.cache.circuit_breaker import RedisResource
from shim_enterprise.gateway.attempts import AttemptCandidate
from shim_enterprise.observability.enterprise_metrics import SEMANTIC_CHECKS_TOTAL
from shim_enterprise.observability.lifecycle import RequestLifecycleRepository
from shim_enterprise.semantic.call import (
    CHECK_TAG,
    PROMPT_VERSION,
    PROTOCOLS,
    SemanticTarget,
    request_text,
    run_semantic_call,
    semantic_call,
    semantic_target,
)
from shim_enterprise.semantic.models import OrganizationSemanticQuestions
from shim_enterprise.tenants.gateway_settings import (
    GatewaySettings,
    SemanticCheckSettings,
)

logger = logging.getLogger(__name__)
QUESTIONS_TTL_SECONDS = 60
MAX_CACHED_TENANTS = 1_024
COUNTER_EXPIRY_SECONDS = 2 * 86_400
MAX_MATCHED = 20


def counter_key(tenant_id: Any, now: datetime) -> str:
    # The tenant id stays out of Redis keys in clear.
    digest = sha256(str(tenant_id).encode()).hexdigest()[:40]
    return f"semchk:{digest}:{now.strftime('%Y%m%d')}"


def protects_less_at(prepared: PreparedInference, check: SemanticTarget) -> bool:
    """Privacy ran for the caller's target only: an enforced caller rule that would act
    at the check model and not there never saw the text (core `protects_less`)."""
    if prepared.rules is None:
        return False
    if check.target is None:
        return True
    return protects_less(
        prepared,
        replace(
            prepared,
            target=check.target,
            deployment_kind="internal" if check.internal else "external",
            protocol=PROTOCOLS[check.provider][0],
        ),
    )


def in_check_scope(check: SemanticCheckSettings, prepared: PreparedInference) -> bool:
    """Every non-empty scope list holds the request's value."""
    tags = prepared.admission.tags if prepared.admission is not None else ()
    scope = check.scope
    return (
        (not scope.api_key_ids or prepared.api_key_id in scope.api_key_ids)
        and (not scope.tags or not set(scope.tags).isdisjoint(tags))
        and (not scope.models or prepared.model in scope.models)
    )


class SemanticPreCheck:
    """First of the attempt strategies; it never chooses a target."""

    name = "semantic_check"

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        cache: RedisResource | None,
    ) -> None:
        self.session_factory = session_factory
        self.cache = cache
        # Handed over once the kernel this strategy belongs to exists.
        self.kernel: Any = None
        self.questions: OrderedDict[Any, tuple[float, int, list[dict[str, Any]]]] = (
            OrderedDict()
        )

    async def after_outcome(self, outcome: AttemptOutcome) -> AttemptCandidate | None:
        return None

    async def after_privacy(
        self, prepared: PreparedInference
    ) -> AttemptCandidate | None:
        gateway = prepared.tenant_gateway_settings
        if (
            not isinstance(gateway, GatewaySettings)
            or not gateway.semantic_check.enabled
        ):
            return None
        check = gateway.semantic_check
        if (
            prepared.protocol not in check.endpoints
            or not in_check_scope(check, prepared)
            or semantic_call(prepared, gateway)
            or prepared.api_key_id == check.api_key_id
        ):
            return None
        started = monotonic()
        try:
            # Everything before the answer counts: the reads, the counter, the call.
            async with asyncio.timeout(check.timeout_ms / 1_000):
                record = await self._check(prepared, check)
        except TimeoutError:
            record = {"outcome": "timeout"}
        except Exception as exc:
            logger.warning("Semantic check failed type=%s", type(exc).__name__)
            record: dict[str, Any] = {"outcome": "failed"}
        record = {
            **record,
            "latency_ms": round((monotonic() - started) * 1_000),
            "prompt_version": PROMPT_VERSION,
        }
        if record["outcome"] == "matched" and check.warn_header:
            prepared.warn("SEMANTIC_WARN")
        SEMANTIC_CHECKS_TOTAL.labels(outcome=record["outcome"]).inc()
        await self._record(prepared, record)
        return None

    async def _check(
        self, prepared: PreparedInference, check: SemanticCheckSettings
    ) -> dict[str, Any]:
        assert check.model is not None and check.api_key_id is not None
        async with self.session_factory() as session:
            target = await semantic_target(session, prepared.tenant_id, check.model)
            detected = (
                prepared.privacy is not None and prepared.privacy.pii_detected
            ) or any(
                match.kind in KINDS and KINDS[match.kind].point == "privacy"
                for match in prepared.rule_matches
            )
            if target is None:
                return {"outcome": "failed"}
            # What a move to another target would need: nothing detected leaves
            # inside, and no caller rule protects more at the check model.
            if (
                prepared.deployment_kind == "internal"
                and not target.internal
                and detected
            ) or protects_less_at(prepared, target):
                return {"outcome": "skipped_guard"}
            if not await self._count(prepared, check):
                return {"outcome": "skipped_cap"}
            revision, questions = await self._questions(session, prepared.tenant_id)
        if check.question_ids:
            questions = [q for q in questions if q["id"] in check.question_ids]
        text = request_text(prepared.payload, prepared.protocol)
        if not questions or not text.strip():
            return {"outcome": "skipped_empty", "questions_revision": revision}
        result = await run_semantic_call(
            self.kernel,
            api_key_id=check.api_key_id,
            alias=check.model,
            provider=target.provider,
            text=text,
            questions=questions,
            tag=CHECK_TAG,
        )
        record: dict[str, Any] = {
            "outcome": result.outcome,
            "questions_revision": revision,
            "check_request_id": result.request_id,
        }
        # Legal: of a request that carried personal data, only the outcome is kept.
        if prepared.privacy is None or not prepared.privacy.pii_detected:
            record["matched"] = list(result.matched_ids[:MAX_MATCHED])
        return record

    async def _count(
        self, prepared: PreparedInference, check: SemanticCheckSettings
    ) -> bool:
        """One check off today's cap; no check when it cannot be counted."""
        redis = self.cache.redis if self.cache is not None else None
        if redis is None:
            return False
        key = counter_key(prepared.tenant_id, datetime.now(timezone.utc))
        try:
            count = int(await redis.incr(key))
            if count == 1:
                await redis.expire(key, COUNTER_EXPIRY_SECONDS)
        except Exception as exc:
            logger.warning("Semantic check counter failed type=%s", type(exc).__name__)
            return False
        return count <= check.max_checks_per_day

    async def _questions(
        self, session: AsyncSession, tenant_id: Any
    ) -> tuple[int, list[dict[str, Any]]]:
        """The tenant's questions, read at most once a minute per process; never Redis."""
        cached = self.questions.get(tenant_id)
        if cached is not None and monotonic() - cached[0] < QUESTIONS_TTL_SECONDS:
            self.questions.move_to_end(tenant_id)
            return cached[1], cached[2]
        row = await session.get(OrganizationSemanticQuestions, tenant_id)
        revision, questions = (row.revision, list(row.questions)) if row else (0, [])
        self.questions[tenant_id] = (monotonic(), revision, questions)
        self.questions.move_to_end(tenant_id)
        while len(self.questions) > MAX_CACHED_TENANTS:
            self.questions.popitem(last=False)
        return revision, questions

    async def _record(
        self, prepared: PreparedInference, record: dict[str, Any]
    ) -> None:
        try:
            async with self.session_factory() as session:
                await RequestLifecycleRepository.update(
                    session,
                    organization_id=TenantId(prepared.tenant_id),
                    request_id=RequestId(str(prepared.request_id)),
                    values={
                        "lifecycle_metadata": RequestLifecycle.lifecycle_metadata.op(
                            "||"
                        )({"semantic_check": record})
                    },
                )
                await session.commit()
        except Exception as exc:
            logger.warning("Semantic check record failed type=%s", type(exc).__name__)
