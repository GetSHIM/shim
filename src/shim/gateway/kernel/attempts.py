"""Extra provider attempts a tenant rule asks for: the policy port and its guards."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal, Protocol
from uuid import uuid4

from shim.gateway.contracts.ids import RequestId
from shim.gateway.kernel.result import AttemptInfo, AttemptReason, ProviderTarget
from shim.observability.metrics import EXTRA_ATTEMPTS_TOTAL

if TYPE_CHECKING:
    from shim.gateway.kernel.result import PreparedInference
    from shim.gateway.pipeline.provider_execution import ProviderCallError

# Attempts per client request, the first included.
MAX_ATTEMPTS = 3


@dataclass(frozen=True)
class Target:
    # None: the catalog route the request already uses.
    provider_target: ProviderTarget | None
    deployment_kind: Literal["internal", "external", "unknown"]
    reason: AttemptReason
    rule_id: str

    def __post_init__(self) -> None:
        if not 0 < len(self.rule_id) <= 128:
            raise ValueError("a target names the tenant rule that chose it")


@dataclass(frozen=True)
class AttemptOutcome:
    prepared: PreparedInference
    attempts: int
    error: ProviderCallError | None
    provider_started: bool
    # The restored native JSON body of an answered non-stream attempt, in memory only.
    answer: Mapping[str, Any] | None


class AttemptPolicy(Protocol):
    async def choose_target_after_privacy(
        self, prepared: PreparedInference
    ) -> Target | None: ...

    async def next_attempt(self, outcome: AttemptOutcome) -> Target | None: ...


def _deployment(target: ProviderTarget | None) -> str | None:
    return target.deployment_id if target is not None else None


def guarded(
    prepared: PreparedInference,
    target: Target | None,
    *,
    attempts: int,
    byok: bool,
) -> Target | None:
    """`target` when every core guard lets it through, else None with a skip verdict."""

    if target is None:
        return None
    payload = prepared.payload
    privacy = prepared.privacy
    reason = None
    if attempts >= MAX_ATTEMPTS:
        reason = "ATTEMPT_LIMIT_REACHED"
    elif (
        prepared.deployment_kind == "internal"
        and target.deployment_kind != "internal"
        and ((privacy is not None and privacy.pii_detected) or prepared.rule_matches)
    ):
        reason = "ATTEMPT_WOULD_LEAVE_INTERNAL"
    elif (
        prepared.protocol == "responses"
        and (payload.get("previous_response_id") or payload.get("conversation"))
        and _deployment(target.provider_target) != _deployment(prepared.target)
    ):
        reason = "ATTEMPT_CONTINUATION_PINNED"
    elif byok and target.provider_target is None:
        reason = "ATTEMPT_NEEDS_STORED_CREDENTIAL"
    if reason is None:
        return target
    skip_attempt(prepared, target.reason, target.rule_id, reason)
    return None


def skip_attempt(
    prepared: PreparedInference,
    reason: AttemptReason,
    rule_id: str,
    code: str,
    *,
    outcome: Literal["skipped", "not_admitted"] = "skipped",
) -> None:
    """Record why an attempt a rule asked for did not run: `gateway.attempt`, skip."""
    prepared.record_verdict(
        "gateway.attempt",
        stage="attempt",
        outcome="skip",
        reason_code=code,
        policy={"reason": reason, "rule_id": rule_id},
    )
    EXTRA_ATTEMPTS_TOTAL.labels(reason=reason, outcome=outcome).inc()


def _sent_to(
    prepared: PreparedInference, target: Target, payload: dict[str, Any]
) -> PreparedInference:
    destination = target.provider_target
    if destination is not None and "model" in payload:
        payload = {**payload, "model": destination.upstream_model}
    return replace(
        prepared,
        payload=payload,
        pre_band_payload=payload,
        target=destination,
        deployment_kind=target.deployment_kind,
    )


def retargeted(prepared: PreparedInference, target: Target) -> PreparedInference:
    """The request on the same row sent to `target`, chosen after privacy."""

    previous = prepared.route_decision
    decision: dict[str, Any] = {
        "rule_id": target.rule_id,
        "state": "enforced",
        "from": _deployment(prepared.target) or "catalog",
        "to": _deployment(target.provider_target) or "catalog",
        "reason": target.reason,
        "conversation_id": None,
        "outcome": "routed",
    }
    if previous is not None:
        decision["previous"] = {
            key: value for key, value in previous.items() if key != "previous"
        }
    return replace(
        _sent_to(prepared, target, prepared.payload), route_decision=decision
    )


def next_attempt(
    prepared: PreparedInference, target: Target, *, number: int
) -> PreparedInference:
    """Attempt `number`: a new request id and start, the same privacy and admission."""

    assert prepared.pre_band_payload is not None
    group = prepared.attempt.group_id if prepared.attempt else str(prepared.request_id)
    return replace(
        _sent_to(prepared, target, prepared.pre_band_payload),
        context=prepared.context.model_copy(
            update={
                "request_id": RequestId(f"req_{uuid4().hex}"),
                "started_at": datetime.now(timezone.utc),
            }
        ),
        attempt=AttemptInfo(
            group_id=group, number=number, reason=target.reason, rule_id=target.rule_id
        ),
        route_decision=None,
        settings_applied=None,
        transforms_applied=None,
        provider_betas=(),
    )
