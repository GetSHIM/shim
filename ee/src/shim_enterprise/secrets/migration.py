"""Canonical reference assignment shared by secret-owning persistence models."""

from __future__ import annotations

from typing import Protocol

from shim.gateway.contracts.ids import SecretRef
from shim_enterprise.secrets.store import parse_secret_ref


class SecretReferenceRow(Protocol):
    secret_ref: str
    secret_backend: str
    secret_version: str


def assign_secret_reference(row: SecretReferenceRow, secret_ref: SecretRef) -> None:
    """Assign a validated opaque reference and its indexed metadata together."""

    parsed = parse_secret_ref(secret_ref)
    row.secret_ref = str(secret_ref)
    row.secret_backend = parsed.backend
    row.secret_version = parsed.version
