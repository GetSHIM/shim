"""The approval gate port: a tenant rule can hold a request until an administrator decides."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from shim.gateway.kernel.result import PreparedInference


@dataclass(frozen=True)
class ApprovalRequest:
    # Enforced, in-scope require_approval matches, sorted.
    rule_ids: tuple[str, ...]
    # X-Shim-Approval-Id, stripped, at most 64 characters, else None.
    presented_id: str | None
    # The payload object as it entered the privacy stage (a reference, never a copy).
    admitted_payload: Mapping[str, Any]


@dataclass(frozen=True)
class ApprovalDecision:
    outcome: Literal["approved", "required", "rejected", "queue_full"]
    approval_id: str | None


class ApprovalGate(Protocol):
    async def check(
        self, prepared: PreparedInference, request: ApprovalRequest
    ) -> ApprovalDecision: ...
