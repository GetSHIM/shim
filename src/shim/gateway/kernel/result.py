"""Typed values passed between gateway-kernel stages."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
from time import perf_counter
from typing import Any, Literal, TypeVar

from pydantic import AwareDatetime, Field

from shim.billing.pricing import (
    DEFAULT_PRICE_BOOK,
    UNSPECIFIED_PROVIDER_MODEL as UNSPECIFIED_PROVIDER_MODEL,
)
from shim.gateway.contracts.context import GatewayContext
from shim.gateway.contracts import FrozenContractModel
from shim.gateway.contracts.ids import ProviderId
from shim.gateway.request_policy import RequestPolicyContext as _RequestPolicyContext
from shim.privacy.policies import EntityAction, PrivacyOutcome


StreamItem = TypeVar("StreamItem")


@dataclass
class InferenceTiming:
    started_at: float = field(default_factory=perf_counter)
    excluded_seconds: float = 0.0
    _paused_at: float | None = None
    _pause_depth: int = 0

    def pause(self) -> None:
        if self._pause_depth == 0:
            self._paused_at = perf_counter()
        self._pause_depth += 1

    def resume(self) -> None:
        if self._pause_depth == 0:
            return
        self._pause_depth -= 1
        if self._pause_depth == 0:
            assert self._paused_at is not None
            self.excluded_seconds += perf_counter() - self._paused_at
            self._paused_at = None

    @contextmanager
    def exclude(self) -> Iterator[None]:
        self.pause()
        try:
            yield
        finally:
            self.resume()

    async def iterate(
        self, stream: AsyncIterator[StreamItem]
    ) -> AsyncIterator[StreamItem]:
        iterator = aiter(stream)
        while True:
            try:
                with self.exclude():
                    item = await anext(iterator)
            except StopAsyncIteration:
                return
            yield item

    @property
    def shim_latency_ms(self) -> int:
        measured_until = (
            self._paused_at if self._paused_at is not None else perf_counter()
        )
        return max(
            0, round((measured_until - self.started_at - self.excluded_seconds) * 1_000)
        )


class PolicyVerdict(FrozenContractModel):
    """Content-free evidence of one evaluated gateway rule, scoped by its envelope."""

    schema_version: Literal[1] = 1
    rule_id: str = Field(pattern=r"^[a-z][a-z0-9_.]{0,95}$")
    rule_version: Literal[1] = 1
    policy_version: str = Field(min_length=1, max_length=128)
    stage: Literal["authentication", "admission", "privacy", "provider_spend"]
    outcome: Literal["allow", "mask", "deny", "error", "skip"]
    reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,95}$")
    effective_at: AwareDatetime


@dataclass(frozen=True)
class ProviderTarget:
    """Operator-approved invocation destination; never populated from request JSON."""

    deployment_id: str
    base_url: str
    upstream_model: str
    credential_reference: str
    timeout_seconds: float
    declared_version: str


@dataclass(frozen=True)
class AdmissionState:
    estimated_input_tokens: int
    maximum_output_tokens: int
    cost_center: str
    tags: tuple[str, ...]
    repeat_chain_length: int | None = None


@dataclass(frozen=True)
class PreparedInference:
    """One validated native provider request plus trusted gateway state."""

    context: GatewayContext
    payload: dict[str, Any]
    provider: ProviderId
    protocol: Literal[
        "chat", "responses", "messages", "count_tokens", "generate_content"
    ]
    model: str
    stream: bool
    policy: _RequestPolicyContext
    pii_config: dict[str, bool] | None
    admission: AdmissionState | None = None
    entity_actions: Mapping[str, EntityAction] | None = None
    privacy: PrivacyOutcome | None = None
    deployment_kind: Literal["internal", "external", "unknown"] = "unknown"
    target: ProviderTarget | None = None
    policy_verdicts: list[PolicyVerdict] = field(default_factory=list)
    timing: InferenceTiming = field(default_factory=InferenceTiming, compare=False)

    def record_verdict(
        self,
        rule_id: str,
        *,
        stage: Literal["authentication", "admission", "privacy", "provider_spend"],
        outcome: Literal["allow", "mask", "deny", "error", "skip"],
        reason_code: str,
        policy: object = None,
        policy_version: str | None = None,
    ) -> None:
        # The request-local list survives immutable stage replacements and exceptions.
        self.policy_verdicts[:] = [
            verdict for verdict in self.policy_verdicts if verdict.rule_id != rule_id
        ]
        self.policy_verdicts.append(
            PolicyVerdict(
                rule_id=rule_id,
                policy_version=policy_version
                or sha256(
                    json.dumps(policy, sort_keys=True, default=str).encode()
                ).hexdigest(),
                stage=stage,
                outcome=outcome,
                reason_code=reason_code,
                effective_at=datetime.now(timezone.utc),
            )
        )

    @property
    def pricing_model(self) -> str:
        return self.target.upstream_model if self.target is not None else self.model

    @property
    def unpriced(self) -> bool:
        return self.target is not None and not DEFAULT_PRICE_BOOK.supports(
            self.pricing_model, str(self.provider)
        )

    @property
    def request_id(self):
        return self.context.request_id

    @property
    def tenant_id(self):
        return self.context.tenant_id

    @property
    def api_key_id(self):
        return self.context.api_key_id

    @property
    def source_endpoint(self) -> str:
        return {
            "chat": "chat.completions",
            "responses": "responses",
            "messages": "messages",
            "count_tokens": "messages.count_tokens",
            "generate_content": "generateContent",
        }[self.protocol]
