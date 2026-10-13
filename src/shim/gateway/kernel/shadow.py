"""A copy of a finished request sent to a candidate target, never seen by the caller."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Literal, Protocol
from uuid import uuid4

from shim.gateway.contracts.ids import RequestId
from shim.gateway.kernel.result import InferenceTiming, ProviderTarget, ShadowInfo
from shim.gateway.pipeline.analysis import AnalysisToolCall

if TYPE_CHECKING:
    from shim.gateway.kernel.result import PreparedInference
    from shim.gateway.streaming.finalization import StreamFinalization


@dataclass(frozen=True)
class ShadowSelection:
    rule_id: str
    # An alias the enterprise side resolves.
    candidate: str
    # The comparison needs the answer text.
    keep_answer: bool


@dataclass(frozen=True)
class ShadowCandidate:
    provider_target: ProviderTarget
    deployment_kind: Literal["internal", "external"]


@dataclass(frozen=True)
class ShadowObservation:
    """One side of a comparison, in memory only."""

    request_id: str
    status: str
    completion_outcome: str | None
    answer_text: str | None
    prompt_tokens: int
    completion_tokens: int
    cost_usd: Decimal | None
    provider_latency_ms: int | None
    ttft_ms: int | None
    error_code: str | None
    tool_calls: tuple[AnalysisToolCall, ...] = ()
    answer_truncated: bool = False


class ShadowSender(Protocol):
    def select(self, prepared: PreparedInference) -> ShadowSelection | None: ...

    async def candidate(
        self, prepared: PreparedInference, selection: ShadowSelection
    ) -> ShadowCandidate | None: ...

    async def compare(
        self,
        prepared: PreparedInference,
        selection: ShadowSelection,
        primary: ShadowObservation,
        shadow: ShadowObservation,
    ) -> None: ...


def selectable(prepared: PreparedInference) -> bool:
    """A request a copy may be made of: no token count, no continuation, no stored response."""
    payload: Mapping[str, Any] = prepared.payload
    if prepared.protocol == "count_tokens":
        return False
    if prepared.protocol == "responses":
        # A stored copy would leave provider-side state the tenant never asked for.
        return (
            not payload.get("previous_response_id")
            and not payload.get("conversation")
            and payload.get("store") is False
        )
    return True


def observation(
    prepared: PreparedInference,
    terminal: StreamFinalization,
    text: str | None,
    tool_calls: tuple[AnalysisToolCall, ...],
    truncated: bool,
) -> ShadowObservation:
    usage = terminal.usage
    ttft = usage.ttft_ms
    return ShadowObservation(
        request_id=str(prepared.request_id),
        status=terminal.terminal_status,
        completion_outcome=usage.completion_outcome,
        answer_text=text,
        prompt_tokens=usage.prompt_tokens,
        completion_tokens=usage.completion_tokens,
        cost_usd=usage.settlement_cost_usd,
        provider_latency_ms=usage.provider_latency_ms,
        ttft_ms=round(ttft) if ttft is not None else None,
        error_code=terminal.error_code,
        tool_calls=tool_calls,
        answer_truncated=truncated,
    )


def shadow_of(
    primary: PreparedInference,
    selection: ShadowSelection,
    candidate: ShadowCandidate,
) -> PreparedInference:
    """The copy: its own request id and start, the primary's masked payload before the
    bands with the candidate's model, the same privacy outcome and admission."""

    assert primary.pre_band_payload is not None
    target = candidate.provider_target
    payload = primary.pre_band_payload
    if "model" in payload:
        payload = {**payload, "model": target.upstream_model}
    return replace(
        primary,
        context=primary.context.model_copy(
            update={
                "request_id": RequestId(f"req_{uuid4().hex}"),
                "started_at": datetime.now(timezone.utc),
            }
        ),
        payload=payload,
        pre_band_payload=payload,
        target=target,
        deployment_kind=candidate.deployment_kind,
        shadow=ShadowInfo(of=str(primary.request_id), rule_id=selection.rule_id),
        attempt=None,
        route_decision=None,
        settings_applied=None,
        transforms_applied=None,
        provider_betas=(),
        concurrency_lease=None,
        # Its own verdicts and warnings: the primary's records stay as they were.
        policy_verdicts=list(primary.policy_verdicts),
        warnings=list(primary.warnings),
        rule_matches=list(primary.rule_matches),
        timing=InferenceTiming(),
    )
