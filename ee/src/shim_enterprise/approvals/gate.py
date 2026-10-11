"""The enterprise approval gate: a request a tenant rule holds goes out only once approved."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from functools import cache
import hashlib
import hmac
import json
from typing import Any
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim.gateway.kernel.result import PreparedInference
from shim.rules.approval import ApprovalDecision, ApprovalRequest
from shim_enterprise.approvals.models import RequestApproval
from shim_enterprise.core.config import settings
from shim_enterprise.observability.enterprise_metrics import REQUEST_APPROVALS_TOTAL
from shim_enterprise.outbox.handlers import APPROVAL_REQUESTED
from shim_enterprise.outbox.publisher import OutboxWriter
from shim_enterprise.tenants.models import ApiKey

APPROVAL_PENDING_TTL = timedelta(hours=24)
APPROVAL_USE_TTL = timedelta(minutes=60)
APPROVAL_PENDING_LIMIT = 200


@cache
def _approval_key(base_key: bytes) -> bytes:
    return hmac.new(base_key, b"shim-request-approval-v1", hashlib.sha256).digest()


def request_digest(
    base_key: bytes,
    *,
    tenant_id: str,
    api_key_id: str,
    protocol: str,
    model: str,
    stream: bool,
    payload: Mapping[str, Any],
) -> tuple[str, int]:
    """A keyed digest of the request as it entered privacy, and its size in bytes.

    The unmasked payload: random placeholders make every masked payload unique.
    """
    material = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    head = f"{tenant_id}\n{api_key_id}\n{protocol}\n{model}\n{int(stream)}\n"
    digest = hmac.new(
        _approval_key(base_key), head.encode("utf-8") + material, hashlib.sha256
    ).hexdigest()
    return digest, len(material)


async def expire_overdue(session: AsyncSession, tenant: UUID, *where: Any) -> None:
    """Lazy expiry: a pending row past its lifetime, an approval past its use-by."""
    await session.execute(
        update(RequestApproval)
        .where(
            RequestApproval.organization_id == tenant,
            (
                (RequestApproval.status == "pending")
                & (RequestApproval.expires_at <= func.now())
            )
            | (
                (RequestApproval.status == "approved")
                & (RequestApproval.use_by <= func.now())
            ),
            *where,
        )
        .values(status="expired")
    )


class EnterpriseApprovalGate:
    def __init__(self, session_factory: Callable[[], AsyncSession]) -> None:
        self._session_factory = session_factory

    async def check(
        self, prepared: PreparedInference, request: ApprovalRequest
    ) -> ApprovalDecision:
        try:
            decision = await self._check(prepared, request)
        except Exception:
            REQUEST_APPROVALS_TOTAL.labels(outcome="unavailable").inc()
            raise
        REQUEST_APPROVALS_TOTAL.labels(outcome=decision.outcome).inc()
        return decision

    async def _check(
        self, prepared: PreparedInference, request: ApprovalRequest
    ) -> ApprovalDecision:
        base = (settings.COMPLIANCE_HASH_SALT or settings.SECRET_KEY).encode("utf-8")
        digest, size = await asyncio.to_thread(
            request_digest,
            base,
            tenant_id=str(prepared.tenant_id),
            api_key_id=str(prepared.api_key_id),
            protocol=prepared.protocol,
            model=prepared.model,
            stream=prepared.stream,
            payload=request.admitted_payload,
        )
        tenant = prepared.tenant_id
        same = (
            RequestApproval.organization_id == tenant,
            RequestApproval.request_digest == digest,
        )
        async with self._session_factory() as session, session.begin():
            presented = _uuid(request.presented_id)
            if presented is not None:
                presented_row = (
                    *same,
                    RequestApproval.id == presented,
                    RequestApproval.api_key_id == prepared.api_key_id,
                )
                used = await session.scalar(
                    update(RequestApproval)
                    .where(
                        *presented_row,
                        RequestApproval.status == "approved",
                        RequestApproval.use_by > func.now(),
                    )
                    .values(
                        status="used",
                        used_at=func.now(),
                        used_request_id=str(prepared.request_id),
                    )
                    .returning(RequestApproval.id)
                )
                if used is not None:
                    return ApprovalDecision("approved", str(used))
                rejected = await session.scalar(
                    select(RequestApproval.id).where(
                        *presented_row, RequestApproval.status == "rejected"
                    )
                )
                if rejected is not None:
                    return ApprovalDecision("rejected", str(rejected))
            await expire_overdue(
                session, tenant, RequestApproval.request_digest == digest
            )
            pending = await session.scalar(
                select(RequestApproval.id).where(
                    *same, RequestApproval.status == "pending"
                )
            )
            if pending is not None:
                return ApprovalDecision("required", str(pending))
            waiting = await session.scalar(
                select(func.count()).where(
                    RequestApproval.organization_id == tenant,
                    RequestApproval.status == "pending",
                    RequestApproval.expires_at > func.now(),
                )
            )
            if (waiting or 0) >= APPROVAL_PENDING_LIMIT:
                return ApprovalDecision("queue_full", None)
            return ApprovalDecision(
                "required",
                await _hold(session, prepared, request, tenant, digest, size),
            )


async def _hold(
    session: AsyncSession,
    prepared: PreparedInference,
    request: ApprovalRequest,
    tenant: UUID,
    digest: str,
    size: int,
) -> str:
    rule_ids = sorted(request.rule_ids)
    admission = prepared.admission
    team = prepared.policy.team_id
    created = (
        await session.execute(
            insert(RequestApproval)
            .values(
                organization_id=tenant,
                api_key_id=prepared.api_key_id,
                requested_by=select(ApiKey.user_id)
                .where(ApiKey.id == prepared.api_key_id)
                .scalar_subquery(),
                team_id=None if team is None else UUID(team),
                request_digest=digest,
                request_id=str(prepared.request_id),
                protocol=prepared.protocol,
                provider=str(prepared.provider),
                model=prepared.model[:255],
                stream=prepared.stream,
                rule_ids=rule_ids,
                detected=_detected(prepared),
                input_bytes=size,
                estimated_input_tokens=None
                if admission is None
                else admission.estimated_input_tokens,
                expires_at=func.now() + APPROVAL_PENDING_TTL,
            )
            .on_conflict_do_nothing(
                index_elements=["organization_id", "request_digest"],
                index_where=RequestApproval.status == "pending",
            )
            .returning(RequestApproval.id, RequestApproval.expires_at)
        )
    ).first()
    if created is None:
        # A concurrent twin was held first: one row, one notification.
        twin = await session.scalar(
            select(RequestApproval.id).where(
                RequestApproval.organization_id == tenant,
                RequestApproval.request_digest == digest,
                RequestApproval.status == "pending",
            )
        )
        return str(twin)
    approval_id, expires_at = created
    now = datetime.now(timezone.utc)
    await OutboxWriter().append(
        session,
        organization_id=prepared.tenant_id,
        values={
            "event_type": APPROVAL_REQUESTED,
            "aggregate_type": "request_approval",
            "aggregate_id": str(approval_id),
            "idempotency_key": f"request_approval:{approval_id}",
            "payload": {
                "organization_id": str(tenant),
                "approval_id": str(approval_id),
                "rule_ids": rule_ids,
                "api_key_id": str(prepared.api_key_id),
                "provider": str(prepared.provider),
                "model": prepared.model[:255],
                "expires_at": expires_at.isoformat(),
                "occurred_at": now.isoformat(),
            },
            "status": "pending",
            "next_attempt_at": now,
        },
    )
    return str(approval_id)


def _detected(prepared: PreparedInference) -> dict[str, Any]:
    entities: dict[str, int] = {}
    if prepared.privacy is not None:
        for counts in (
            prepared.privacy.pii_entities,
            prepared.privacy.monitored_entities,
            prepared.privacy.blocked_entities,
        ):
            for entity, count in counts.items():
                entities[entity] = entities.get(entity, 0) + count
    rules: dict[str, int] = {}
    for match in prepared.rule_matches:
        rules[match.rule_id] = rules.get(match.rule_id, 0) + match.count
    return {
        "entities": dict(sorted(entities.items())),
        "rules": dict(sorted(rules.items())),
    }


def _uuid(value: str | None) -> UUID | None:
    try:
        return None if value is None else UUID(value)
    except ValueError:
        return None
