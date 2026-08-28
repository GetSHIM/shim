"""Gateway authentication port and strict credential selection."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from fastapi import HTTPException, status

from shim.gateway.contracts.principal import AuthenticatedPrincipal


class GatewayAuthenticator(Protocol):
    async def resolve(self, candidate: str | None) -> AuthenticatedPrincipal: ...


def select_gateway_credential(
    headers: Mapping[str, str],
    *,
    accept_anthropic_key: bool = False,
) -> str | None:
    folded = {name.casefold(): value for name, value in headers.items()}
    if "x-shim-key" in folded:
        return folded["x-shim-key"]
    if "authorization" in folded:
        scheme, separator, credential = folded["authorization"].partition(" ")
        return credential if separator and scheme.casefold() == "bearer" else ""
    if accept_anthropic_key and "x-api-key" in folded:
        return folded["x-api-key"]
    return None


def authentication_error(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )
