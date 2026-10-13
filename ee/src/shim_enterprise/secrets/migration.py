"""Canonical reference assignment shared by secret-owning persistence models."""

from __future__ import annotations

from typing import Protocol

from shim.gateway.contracts.ids import SecretRef
from shim_enterprise.secrets.store import parse_secret_ref


class SecretReferenceRow(Protocol):
    # Properties, so a row whose reference may be absent (an AWS role) fits too.
    @property
    def secret_ref(self) -> str | None: ...
    @secret_ref.setter
    def secret_ref(self, value: str) -> None: ...
    @property
    def secret_backend(self) -> str | None: ...
    @secret_backend.setter
    def secret_backend(self, value: str) -> None: ...
    @property
    def secret_version(self) -> str | None: ...
    @secret_version.setter
    def secret_version(self, value: str) -> None: ...


def assign_secret_reference(row: SecretReferenceRow, secret_ref: SecretRef) -> None:
    """Assign a validated opaque reference and its indexed metadata together."""

    parsed = parse_secret_ref(secret_ref)
    row.secret_ref = str(secret_ref)
    row.secret_backend = parsed.backend
    row.secret_version = parsed.version
