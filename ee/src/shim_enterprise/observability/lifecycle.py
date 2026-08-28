"""Durable request lifecycle transitions."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.billing.models import (
    REQUEST_LIFECYCLE_NONTERMINAL_STATUSES,
    REQUEST_LIFECYCLE_STATUSES,
    RequestLifecycle,
)
from shim.gateway.contracts.ids import RequestId, TenantId

_STATUS_PREDECESSORS: dict[str, frozenset[str]] = {
    "routing_pending": frozenset({"accepted"}),
    "routing_rejected": frozenset({"accepted"}),
    "provider_pending": frozenset({"accepted", "routing_pending"}),
    "provider_started": frozenset({"provider_pending"}),
    "streaming": frozenset({"provider_started"}),
    "completed": REQUEST_LIFECYCLE_NONTERMINAL_STATUSES,
    "provider_error": REQUEST_LIFECYCLE_NONTERMINAL_STATUSES,
    "client_disconnected": REQUEST_LIFECYCLE_NONTERMINAL_STATUSES,
    "timeout": REQUEST_LIFECYCLE_NONTERMINAL_STATUSES,
    "cancelled": REQUEST_LIFECYCLE_NONTERMINAL_STATUSES,
    "internal_error": REQUEST_LIFECYCLE_NONTERMINAL_STATUSES,
    "rejected": frozenset({"accepted", "routing_rejected"}),
    "failed": REQUEST_LIFECYCLE_NONTERMINAL_STATUSES,
}
_IMMUTABLE_FIELDS = frozenset(
    {
        "id",
        "organization_id",
        "request_id",
        "actor_type",
        "api_key_id",
        "user_id",
        "source_endpoint",
        "requested_model",
        "stream",
        "started_at",
        "created_at",
    }
)


class PersistenceConflictError(RuntimeError):
    """A durable identity is already owned by a different record."""


class RequestLifecycleRepository:
    """Tenant-scoped writes for the canonical request lifecycle."""

    @staticmethod
    async def create(
        session: AsyncSession,
        *,
        organization_id: TenantId,
        values: Mapping[str, Any],
    ) -> RequestLifecycle:
        payload = dict(values)
        payload["organization_id"] = organization_id
        status = payload.get("status")
        if status not in REQUEST_LIFECYCLE_STATUSES:
            raise ValueError("unsupported request lifecycle status")
        request_id = payload["request_id"]
        statement = (
            insert(RequestLifecycle)
            .values(**payload)
            .on_conflict_do_nothing(index_elements=[RequestLifecycle.request_id])
            .returning(RequestLifecycle)
        )
        lifecycle = (await session.execute(statement)).scalar_one_or_none()
        if lifecycle is not None:
            return lifecycle
        lifecycle = await RequestLifecycleRepository.get(
            session,
            organization_id=organization_id,
            request_id=request_id,
        )
        if lifecycle is None:
            raise PersistenceConflictError("request lifecycle identity conflict")
        if any(
            getattr(lifecycle, field) != payload[field]
            for field in _IMMUTABLE_FIELDS
            if field in payload
        ):
            raise PersistenceConflictError("request lifecycle identity conflict")
        return lifecycle

    @staticmethod
    async def get(
        session: AsyncSession,
        *,
        organization_id: TenantId,
        request_id: RequestId,
    ) -> RequestLifecycle | None:
        statement = (
            select(RequestLifecycle)
            .where(
                RequestLifecycle.organization_id == organization_id,
                RequestLifecycle.request_id == request_id,
            )
            .execution_options(populate_existing=True)
        )
        return (await session.execute(statement)).scalar_one_or_none()

    @staticmethod
    async def update(
        session: AsyncSession,
        *,
        organization_id: TenantId,
        request_id: RequestId,
        values: Mapping[str, Any],
    ) -> RequestLifecycle | None:
        payload = {
            key: value for key, value in values.items() if key not in _IMMUTABLE_FIELDS
        }
        if "status" in payload:
            target_status = payload.pop("status")
            expected_statuses = _STATUS_PREDECESSORS.get(target_status)
            if expected_statuses is None:
                raise ValueError("unsupported request lifecycle transition")
            return await RequestLifecycleRepository.transition(
                session,
                organization_id=organization_id,
                request_id=request_id,
                target_status=target_status,
                expected_statuses=expected_statuses,
                values=payload,
            )
        if not payload:
            return await RequestLifecycleRepository.get(
                session,
                organization_id=organization_id,
                request_id=request_id,
            )
        statement = (
            update(RequestLifecycle)
            .where(
                RequestLifecycle.organization_id == organization_id,
                RequestLifecycle.request_id == request_id,
            )
            .values(**payload)
            .returning(RequestLifecycle)
        )
        return (await session.execute(statement)).scalar_one_or_none()

    @staticmethod
    async def transition(
        session: AsyncSession,
        *,
        organization_id: TenantId,
        request_id: RequestId,
        target_status: str,
        expected_statuses: Collection[str],
        values: Mapping[str, Any] | None = None,
    ) -> RequestLifecycle | None:
        if target_status not in REQUEST_LIFECYCLE_STATUSES:
            raise ValueError("unsupported request lifecycle status")
        expected = frozenset(expected_statuses)
        if not expected or not expected <= REQUEST_LIFECYCLE_STATUSES:
            raise ValueError("unsupported request lifecycle predecessor")
        payload = dict(values or {})
        if "status" in payload:
            raise ValueError("transition status must use target_status")
        payload = {
            key: value for key, value in payload.items() if key not in _IMMUTABLE_FIELDS
        }
        payload["status"] = target_status
        statement = (
            update(RequestLifecycle)
            .where(
                RequestLifecycle.organization_id == organization_id,
                RequestLifecycle.request_id == request_id,
                RequestLifecycle.status.in_(tuple(expected)),
                RequestLifecycle.reconciled_at.is_(None),
            )
            .values(**payload)
            .returning(RequestLifecycle)
        )
        lifecycle = (await session.execute(statement)).scalar_one_or_none()
        if lifecycle is not None:
            return lifecycle
        lifecycle = await RequestLifecycleRepository.get(
            session,
            organization_id=organization_id,
            request_id=request_id,
        )
        if lifecycle is not None and lifecycle.status == target_status:
            return lifecycle
        return None
