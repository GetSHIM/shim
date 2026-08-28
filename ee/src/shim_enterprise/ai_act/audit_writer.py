"""Serialized, metadata-only audit-chain append operations."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import time
from typing import Any
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act.hashing import compute_row_hash, genesis_hash
from shim_enterprise.ai_act.models import AIActAuditLog
from shim_enterprise.core.config import settings


LOCK_MAX_WAIT_SECONDS = 5.0
LOCK_RETRY_SECONDS = 0.05
CANONICAL_KEYS = (
    "seq",
    "organization_id",
    "created_at",
    "event_type",
    "request_id",
    "api_key_id",
    "actor",
    "model",
    "provider",
    "gateway_version",
    "endpoint",
    "input_hash",
    "output_hash",
    "prompt_tokens",
    "completion_tokens",
    "pii_detected",
    "pii_entities",
    "policy_verdicts",
    "is_cache_hit",
    "latency_ms",
    "cost_usd",
    "extra",
)
PROVIDER_PREFIXES = (
    ("claude", "anthropic"),
    ("gemini", "google"),
    ("gpt", "openai"),
    ("llama", "ollama"),
    ("mistral", "ollama"),
)
SENSITIVE_METADATA_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "content",
        "credential",
        "input",
        "message",
        "output",
        "password",
        "prompt",
        "response",
        "secret",
        "token",
    }
)


def audit_salt() -> str:
    return settings.COMPLIANCE_HASH_SALT or settings.SECRET_KEY


def gateway_version() -> str:
    return f"shim-gateway/{settings.VERSION}"


def derive_provider(model: str | None) -> str | None:
    normalized = (model or "").strip().casefold()
    return next(
        (
            provider
            for prefix, provider in PROVIDER_PREFIXES
            if normalized.startswith(prefix)
        ),
        None,
    )


def canonical_fields_from_values(values: Mapping[str, Any]) -> dict[str, Any]:
    return {key: values.get(key) for key in CANONICAL_KEYS}


def row_to_values(row: AIActAuditLog) -> dict[str, Any]:
    return {key: getattr(row, key) for key in CANONICAL_KEYS}


def _bounded_text(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    return str(value)[:limit]


def _nonnegative_integer(value: Any) -> int:
    parsed = int(value or 0)
    if parsed < 0:
        raise ValueError("audit counters must be non-negative")
    return parsed


def _cost(value: Any) -> Decimal:
    try:
        parsed = Decimal(str(value or 0))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("audit cost is invalid") from exc
    if not parsed.is_finite() or parsed < 0:
        raise ValueError("audit cost must be finite and non-negative")
    return parsed.quantize(Decimal("0.00000001"))


def _metadata(value: Any, *, depth: int = 0) -> Any:
    if depth > 4:
        return None
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for raw_key, child in value.items():
            key = str(raw_key)[:64]
            normalized = key.casefold().replace("-", "_")
            if normalized in SENSITIVE_METADATA_KEYS or normalized.endswith(
                ("_key", "_password", "_secret", "_token")
            ):
                continue
            output[key] = _metadata(child, depth=depth + 1)
        return output
    if isinstance(value, (list, tuple)):
        return [_metadata(child, depth=depth + 1) for child in value[:64]]
    if isinstance(value, str):
        return value[:512]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:512]


def _policy_verdicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    verdicts: list[dict[str, Any]] = []
    for item in value[:64]:
        normalized = _metadata(item)
        verdicts.append(
            normalized if isinstance(normalized, dict) else {"code": str(normalized)}
        )
    return verdicts


def _normalized_context(
    context: Mapping[str, Any],
    *,
    created_at: datetime,
    version: str,
) -> dict[str, Any]:
    organization_id = UUID(str(context["organization_id"]))
    api_key = context.get("api_key_id")
    pii_entities = context.get("pii_entities")
    entities = (
        {
            str(key)[:128]: _nonnegative_integer(count)
            for key, count in pii_entities.items()
        }
        if isinstance(pii_entities, Mapping)
        else {}
    )
    model = _bounded_text(context.get("model"), 255)
    return {
        "organization_id": organization_id,
        "event_type": _bounded_text(context.get("event_type") or "ai_request", 64),
        "request_id": _bounded_text(context.get("request_id"), 255),
        "api_key_id": UUID(str(api_key)) if api_key else None,
        "actor": _bounded_text(context.get("actor"), 320),
        "model": model,
        "provider": _bounded_text(
            context.get("provider") or derive_provider(model),
            64,
        ),
        "gateway_version": version[:64],
        "endpoint": _bounded_text(context.get("endpoint"), 255),
        "input_hash": _bounded_text(context.get("input_hash"), 128),
        "output_hash": _bounded_text(context.get("output_hash"), 128),
        "prompt_tokens": _nonnegative_integer(context.get("prompt_tokens")),
        "completion_tokens": _nonnegative_integer(context.get("completion_tokens")),
        "pii_detected": bool(context.get("pii_detected")),
        "pii_entities": dict(sorted(entities.items())),
        "policy_verdicts": _policy_verdicts(context.get("policy_verdicts")),
        "is_cache_hit": bool(context.get("is_cache_hit")),
        "latency_ms": _nonnegative_integer(context.get("latency_ms")),
        "cost_usd": _cost(context.get("cost_usd")),
        "extra": _metadata(context.get("extra") or {}),
        "created_at": created_at,
    }


def next_link(
    tip: tuple[int, str] | None,
    context: Mapping[str, Any],
    *,
    salt: str,
    now: datetime,
    gateway_version: str,
) -> dict[str, Any]:
    sequence = 1 if tip is None else tip[0] + 1
    organization_id = UUID(str(context["organization_id"]))
    previous_hash = genesis_hash(salt, str(organization_id)) if tip is None else tip[1]
    values = _normalized_context(
        context,
        created_at=now,
        version=gateway_version,
    )
    values["seq"] = sequence
    values["prev_hash"] = previous_hash
    values["row_hash"] = compute_row_hash(
        previous_hash,
        canonical_fields_from_values(values),
    )
    return values


async def _read_tip(
    session: AsyncSession,
    organization_id: UUID,
) -> tuple[int, str] | None:
    row = (
        await session.execute(
            select(AIActAuditLog.seq, AIActAuditLog.row_hash)
            .where(AIActAuditLog.organization_id == organization_id)
            .order_by(AIActAuditLog.seq.desc())
            .limit(1)
        )
    ).first()
    return (row.seq, row.row_hash) if row else None


async def _existing_event(
    session: AsyncSession,
    organization_id: UUID,
    request_id: str,
    event_type: str,
) -> AIActAuditLog | None:
    rows = list(
        (
            await session.execute(
                select(AIActAuditLog).where(
                    AIActAuditLog.organization_id == organization_id,
                    AIActAuditLog.request_id == request_id,
                    AIActAuditLog.event_type == event_type,
                )
            )
        ).scalars()
    )
    if len(rows) > 1:
        raise RuntimeError("duplicate audit request event")
    return rows[0] if rows else None


async def _acquire_tenant_lock(
    session: AsyncSession,
    organization_id: UUID,
) -> None:
    deadline = time.monotonic() + LOCK_MAX_WAIT_SECONDS
    while True:
        acquired = await session.scalar(
            text("SELECT pg_try_advisory_xact_lock(hashtextextended(:tenant, 0))"),
            {"tenant": str(organization_id)},
        )
        if acquired:
            return
        if time.monotonic() >= deadline:
            raise TimeoutError("tenant audit lock timed out")
        await asyncio.sleep(LOCK_RETRY_SECONDS)


async def write_audit_row(
    context: Mapping[str, Any],
    session: AsyncSession,
    *,
    deduplicate: bool = False,
) -> AIActAuditLog:
    if context.get("organization_id") is None:
        raise ValueError("audit event requires organization_id")
    organization_id = UUID(str(context["organization_id"]))
    await _acquire_tenant_lock(session, organization_id)
    request_id = _bounded_text(context.get("request_id"), 255)
    event_type = _bounded_text(context.get("event_type") or "ai_request", 64)
    assert event_type is not None
    if deduplicate and request_id:
        existing = await _existing_event(
            session,
            organization_id,
            request_id,
            event_type,
        )
        if existing is not None:
            return existing
    values = next_link(
        await _read_tip(session, organization_id),
        context,
        salt=audit_salt(),
        now=datetime.now(timezone.utc),
        gateway_version=gateway_version(),
    )
    row = AIActAuditLog(**values)
    session.add(row)
    await session.flush()
    return row


async def append_audit_row_deduplicated(
    context: Mapping[str, Any],
) -> AIActAuditLog:
    from shim_enterprise.core.database import AsyncSessionLocal

    async with AsyncSessionLocal.begin() as session:
        return await write_audit_row(context, session, deduplicate=True)
