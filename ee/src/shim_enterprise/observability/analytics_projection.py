"""Analytics read-model projection driven only by durable outbox events."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as SQLUUID
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Mapped, mapped_column

from shim_enterprise.core.database import AsyncSessionLocal, Base
from shim_enterprise.outbox.publisher import OutboxMessage, OutboxPublisher


COMPLETED_EVENT = "analytics.request_completed"
FAILED_EVENT = "analytics.request_failed"


class RequestLog(Base):
    """Tenant-scoped analytics projection; never authoritative for billing."""

    __tablename__ = "request_logs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "api_key_id"],
            ["api_keys.organization_id", "api_keys.id"],
            name="fk_request_logs_org_api_key",
        ),
        Index("ix_request_logs_org_timestamp", "organization_id", "timestamp"),
        UniqueConstraint(
            "organization_id",
            "request_id",
            name="uq_request_logs_org_request_id",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SQLUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    request_id: Mapped[str] = mapped_column(String, nullable=False)
    api_key_id: Mapped[UUID] = mapped_column(
        SQLUUID(as_uuid=True),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        SQLUUID(as_uuid=True),
        ForeignKey("organizations.id", name="fk_request_logs_organization_id"),
        nullable=False,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    prompt_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cost_saved: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_cache_hit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    pii_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    path: Mapped[str | None] = mapped_column(String, nullable=True)
    method: Mapped[str | None] = mapped_column(String, nullable=True)
    model: Mapped[str | None] = mapped_column(String, nullable=True)
    tokens_saved: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    flags: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    cost_usd: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0,
        server_default="0",
    )
    cost_center: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    team: Mapped[str | None] = mapped_column(String, nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)


def _projection_values(message: OutboxMessage) -> dict:
    payload = dict(message.payload)
    request_id = payload.get("request_id")
    if str(payload.get("organization_id")) != str(message.organization_id):
        raise ValueError("analytics projection tenant mismatch")
    if (
        message.aggregate_type != "request"
        or not isinstance(request_id, str)
        or request_id != message.aggregate_id
    ):
        raise ValueError("analytics projection request identity mismatch")
    try:
        api_key_id = UUID(str(payload["api_key_id"]))
        timestamp = datetime.fromisoformat(str(payload["timestamp"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("analytics projection has invalid identity or time") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("analytics projection timestamp must be timezone-aware")
    return {
        "organization_id": message.organization_id,
        "request_id": request_id,
        "api_key_id": api_key_id,
        "timestamp": timestamp,
        "prompt_tokens": max(0, int(payload.get("prompt_tokens") or 0)),
        "completion_tokens": max(0, int(payload.get("completion_tokens") or 0)),
        "latency_ms": max(0, int(payload.get("latency_ms") or 0)),
        "is_cache_hit": bool(payload.get("is_cache_hit")),
        "pii_detected": bool(payload.get("pii_detected")),
        "path": payload.get("path"),
        "method": "POST",
        "model": payload.get("model"),
        "cost_usd": max(0.0, float(payload.get("cost_usd") or 0.0)),
        "details": {
            "provider": payload.get("provider"),
            "lifecycle_status": payload.get("lifecycle_status"),
            "usage_estimated": bool(payload.get("usage_estimated")),
        },
        "cost_center": payload.get("cost_center"),
        "team": payload.get("team"),
        "tags": list(payload.get("tags") or []),
    }


async def project_request(message: OutboxMessage) -> None:
    values = _projection_values(message)
    statement = insert(RequestLog).values(**values)
    statement = statement.on_conflict_do_update(
        constraint="uq_request_logs_org_request_id",
        set_={key: value for key, value in values.items() if key != "request_id"},
    )
    async with AsyncSessionLocal() as session:
        await session.execute(statement)
        await session.commit()


def register_analytics_handlers(publisher: OutboxPublisher) -> None:
    for event_type in (COMPLETED_EVENT, FAILED_EVENT):
        publisher.register(event_type, project_request)
