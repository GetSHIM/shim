"""Transactional outbox append and post-commit event dispatch."""

from __future__ import annotations

from collections.abc import Awaitable, Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Protocol
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim.gateway.contracts.ids import TenantId
from shim_enterprise.core.errors import IdentityConflictError
from shim.observability.metrics import bounded_label
from shim.observability.tracing import start_span
from shim_enterprise.outbox.models import OutboxEvent


@dataclass(frozen=True, slots=True)
class OutboxMessage:
    id: UUID
    organization_id: UUID
    event_type: str
    aggregate_type: str
    aggregate_id: str
    idempotency_key: str
    payload: Mapping[str, Any]
    attempt_count: int
    created_at: datetime

    @classmethod
    def from_event(cls, event: OutboxEvent) -> OutboxMessage:
        return cls(
            id=event.id,
            organization_id=event.organization_id,
            event_type=event.event_type,
            aggregate_type=event.aggregate_type,
            aggregate_id=event.aggregate_id,
            idempotency_key=event.idempotency_key,
            payload=MappingProxyType(dict(event.payload)),
            attempt_count=event.attempt_count,
            created_at=event.created_at,
        )


class OutboxHandler(Protocol):
    def __call__(self, message: OutboxMessage) -> Awaitable[None]: ...


class UnknownEventTypeError(LookupError):
    """No delivery handler owns an outbox event type."""


class OutboxPublisher:
    """Dispatch every event type to exactly one registered handler."""

    def __init__(self) -> None:
        self._handlers: dict[str, OutboxHandler] = {}

    def register(self, event_type: str, handler: OutboxHandler) -> None:
        if not event_type.strip():
            raise ValueError("outbox event type cannot be empty")
        if event_type in self._handlers:
            raise ValueError(f"outbox handler already registered: {event_type}")
        self._handlers[event_type] = handler

    async def publish(self, message: OutboxMessage) -> None:
        handler = self._handlers.get(message.event_type)
        if handler is None:
            raise UnknownEventTypeError(message.event_type)
        await handler(message)


class OutboxIdentityConflict(IdentityConflictError):
    """An idempotency key is missing or owns different immutable intent."""


class OutboxWriter:
    """Append an idempotent side-effect intent inside the caller transaction."""

    async def append(
        self,
        session: AsyncSession,
        *,
        organization_id: TenantId,
        values: Mapping[str, Any],
    ) -> OutboxEvent:
        payload = dict(values)
        payload["organization_id"] = organization_id
        idempotency_key = str(payload["idempotency_key"])
        with start_span(
            "gateway.outbox_append",
            event_type=bounded_label("event_type", str(payload["event_type"])),
        ):
            statement = (
                insert(OutboxEvent)
                .values(**payload)
                .on_conflict_do_nothing(
                    index_elements=[
                        OutboxEvent.organization_id,
                        OutboxEvent.idempotency_key,
                    ]
                )
                .returning(OutboxEvent)
            )
            event = (await session.execute(statement)).scalar_one_or_none()
            if event is not None:
                return event
            existing = await self.fetch(
                session,
                organization_id=organization_id,
                idempotency_key=idempotency_key,
            )
            if existing is None:
                raise OutboxIdentityConflict("outbox identity conflict")
            immutable_intent = (
                existing.event_type,
                existing.aggregate_type,
                existing.aggregate_id,
                existing.payload,
            )
            requested_intent = (
                payload["event_type"],
                payload["aggregate_type"],
                payload["aggregate_id"],
                payload["payload"],
            )
            if immutable_intent != requested_intent:
                raise OutboxIdentityConflict("outbox identity conflict")
            return existing

    async def fetch(
        self,
        session: AsyncSession,
        *,
        organization_id: TenantId,
        idempotency_key: str,
    ) -> OutboxEvent | None:
        statement = select(OutboxEvent).where(
            OutboxEvent.organization_id == organization_id,
            OutboxEvent.idempotency_key == idempotency_key,
        )
        return (await session.execute(statement)).scalar_one_or_none()
