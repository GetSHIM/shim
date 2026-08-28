"""Deterministic SHA-256 primitives for tenant audit chains."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
import hashlib
import json
from typing import Any
from uuid import UUID


def _json_default(value: Any) -> str:
    if isinstance(value, (date, datetime, Decimal, UUID)):
        return (
            str(value) if not isinstance(value, (date, datetime)) else value.isoformat()
        )
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def canonical_row(fields: dict[str, Any]) -> bytes:
    return json.dumps(
        fields,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=_json_default,
    ).encode()


def chain_hash(previous_hash: str, canonical: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(previous_hash.encode())
    digest.update(b"\x1f")
    digest.update(canonical)
    return digest.hexdigest()


def compute_row_hash(previous_hash: str, fields: dict[str, Any]) -> str:
    return chain_hash(previous_hash, canonical_row(fields))


def genesis_hash(salt: str, organization_id: str) -> str:
    digest = hashlib.sha256()
    digest.update(salt.encode())
    digest.update(b"\x1faudit-genesis\x1f")
    digest.update(organization_id.encode())
    return digest.hexdigest()
