"""Provider-neutral inference orchestration."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import replace
import logging
from typing import Any

from fastapi import HTTPException
from opentelemetry import trace
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from starlette.responses import JSONResponse, Response, StreamingResponse

from shim.billing.lifecycle import ModelLifecycle, load_lifecycle
from shim.core.middleware import AsyncRateLimiter
from shim.gateway.admission import (
    InFlightEntry,
    InFlightRegistry,
    InMemoryTaskCounter,
    LoopDetector,
    TaskCounter,
)
from shim.gateway.contracts.ids import CURRENT_REQUEST_ID
from shim.gateway.pipeline.admission import AdmissionStage, rule_blocked
from shim.gateway.pipeline.authenticate import AuthenticateStage, GatewayInvocation
from shim.gateway.pipeline.postprocess import PostprocessStage, ResponsePostprocessor
from shim.gateway.pipeline.privacy import PrivacyStage
from shim.gateway.pipeline.provider_spend import ProviderSpendStage
from shim.gateway.pipeline.settings_band import SettingsBandStage, pins_in_scope
from shim.gateway.pipeline.transform_band import TransformBandStage
from shim.gateway.pipeline.provider_execution import (
    ProviderCallError,
    ProviderNonStream,
    ProviderExecutionStage,
    ProviderStream,
)
from shim.gateway.streaming import StreamSession
from shim.gateway.usage import (
    UsageAuditPersistenceError,
    UsageFailureReason,
    UsageLifecycle,
    UsageLimitExceeded,
)
from shim.observability.metrics import (
    INFLIGHT_DUPLICATES_TOTAL,
    REQUESTS_IN_FLIGHT,
    REQUESTS_TOTAL,
    bounded_label,
)
from shim.observability.tracing import safe_attributes, start_span
from shim.privacy.continuation import PrivacyContinuationStore
from shim.rules.approval import ApprovalGate, ApprovalRequest
from shim.rules.evaluate import record_rule_verdicts, settle_matches

from .runtime import run_stage
from .result import PreparedInference


logger = logging.getLogger(__name__)
_PROVIDERS = frozenset({"openai", "anthropic", "google"})


# OpenTelemetry GenAI names at schema 1.44.0 (tracing.SCHEMA_URL); a token count is no operation.
_GENAI_OPERATIONS = {
    "chat": "chat",
    "responses": "chat",
    "messages": "chat",
    "generate_content": "generate_content",
    "embeddings": "embeddings",
    "embed_content": "embeddings",
}
_GENAI_PROVIDERS = {
    "openai": "openai",
    "anthropic": "anthropic",
    "google": "gcp.gemini",
}


class GatewayKernel:
    def __init__(
        self,
        executions: Mapping[str, Any],
        *,
        chain_store: PrivacyContinuationStore,
        policy_resolver,
        rate_limiter: AsyncRateLimiter,
        loop_detector: LoopDetector,
        loop_repeat_limit: int,
        loop_window_seconds: int,
        cost_tag_max_length: int,
        usage: UsageLifecycle,
        heartbeat_interval_seconds: float = 30,
        output_hash_salt: str | None = None,
        prepare_inference: Callable[[PreparedInference], Awaitable[PreparedInference]]
        | None = None,
        approval_gate: ApprovalGate | None = None,
        honor_trace_parent: bool = False,
        task_counter: TaskCounter | None = None,
        model_lifecycle: ModelLifecycle | None = None,
    ) -> None:
        self.executions = dict(executions)
        if not self.executions or not set(self.executions) <= _PROVIDERS:
            raise ValueError("executions must configure supported native providers")
        self.usage = usage
        self.rate_limiter = rate_limiter
        self.loop_detector = loop_detector
        self.loop_repeat_limit = loop_repeat_limit
        self.loop_window_seconds = loop_window_seconds
        self.cost_tag_max_length = cost_tag_max_length
        self.task_counter = task_counter or InMemoryTaskCounter()
        self.model_lifecycle = model_lifecycle or load_lifecycle()
        # Per process in both editions: a duplicate on another replica is not seen.
        self.inflight = InFlightRegistry()
        self.postprocessor = ResponsePostprocessor(
            usage,
            heartbeat_interval_seconds=heartbeat_interval_seconds,
            output_hash_salt=output_hash_salt,
            task_counter=self.task_counter,
        )
        self.chain_store = chain_store
        self.policy_resolver = policy_resolver
        self.prepare_inference = prepare_inference
        self.approval_gate = approval_gate
        self.honor_trace_parent = honor_trace_parent

    async def execute(self, invocation: GatewayInvocation) -> Response:
        endpoint = bounded_label("endpoint", invocation.metadata.endpoint)
        tenant_tier = "default"
        outcome = "server_error"
        request_id: str | None = None

        def observe_prepared(prepared: PreparedInference) -> None:
            nonlocal tenant_tier, request_id
            tenant_tier = bounded_label("tenant_tier", prepared.policy.tier)
            request_id = str(prepared.request_id)
            CURRENT_REQUEST_ID.set(request_id)

        with start_span(
            "gateway.request",
            # A missing or invalid traceparent extracts an empty context: a new trace.
            context=TraceContextTextMapPropagator().extract(invocation.headers)
            if self.honor_trace_parent
            else None,
            endpoint=endpoint,
            method=invocation.metadata.method,
            protocol=invocation.protocol,
        ) as span:
            try:
                result = await self._execute(
                    invocation,
                    prepared_observer=observe_prepared,
                )
            except UsageLimitExceeded:
                outcome = "rejected"
                raise
            except HTTPException as exc:
                outcome = "client_error" if exc.status_code < 500 else "server_error"
                if request_id is not None:
                    exc.headers = {
                        **(exc.headers or {}),
                        "X-Shim-Request-Id": request_id,
                    }
                raise
            except ProviderCallError as exc:
                exc.shim_request_id = request_id
                raise
            else:
                outcome = "success"
                span.set_attribute("tenant_tier", tenant_tier)
                return result
            finally:
                REQUESTS_TOTAL.labels(
                    endpoint=endpoint,
                    status=outcome,
                    tenant_tier=tenant_tier,
                ).inc()
                span.set_attribute("status", outcome)

    async def _execute(
        self,
        invocation: GatewayInvocation,
        *,
        prepared_observer: Callable[[PreparedInference], None] | None = None,
    ) -> Response:
        execution = self.executions.get(invocation.provider)
        if execution is None:
            raise ProviderCallError(
                status_code=503,
                error_code="PROVIDER_UNAVAILABLE",
                retryable=True,
                provider=invocation.provider,
            )
        authenticate_stage = AuthenticateStage(self.policy_resolver)
        try:
            prepared = await run_stage(authenticate_stage, invocation)
        except BaseException:
            if authenticate_stage.prepared is not None:
                if prepared_observer is not None:
                    prepared_observer(authenticate_stage.prepared)
                await self.usage.reject(authenticate_stage.prepared)
            raise
        if prepared_observer is not None:
            prepared_observer(prepared)
        if self.prepare_inference is not None:
            try:
                prepared = await self.prepare_inference(prepared)
            except BaseException:
                if not any(
                    verdict.outcome in {"deny", "error"}
                    for verdict in prepared.policy_verdicts
                ):
                    prepared.record_verdict(
                        "deployment.registry",
                        stage="admission",
                        outcome="error",
                        reason_code="DEPLOYMENT_REGISTRY_UNAVAILABLE",
                    )
                await self.usage.reject(prepared)
                raise

        admission_stage = AdmissionStage(
            invocation,
            self.usage,
            rate_limiter=self.rate_limiter,
            loop_detector=self.loop_detector,
            loop_repeat_limit=self.loop_repeat_limit,
            loop_window_seconds=self.loop_window_seconds,
            cost_tag_max_length=self.cost_tag_max_length,
            task_counter=self.task_counter,
            inflight=self.inflight,
            model_lifecycle=self.model_lifecycle,
        )
        try:
            prepared = await run_stage(admission_stage, prepared)
        except BaseException as error:
            if admission_stage.reserved:
                await self._fail_safely(prepared, reason="admission_aborted")
            else:
                if not any(
                    verdict.outcome in {"deny", "error"}
                    for verdict in prepared.policy_verdicts
                ):
                    prepared.record_verdict(
                        "gateway.admission",
                        stage="admission",
                        outcome="deny"
                        if isinstance(error, HTTPException) and error.status_code < 500
                        else "error",
                        reason_code="INVALID_REQUEST"
                        if isinstance(error, HTTPException) and error.status_code < 500
                        else "ADMISSION_UNAVAILABLE",
                    )
                await self.usage.reject(prepared)
            raise
        assert prepared.admission is not None
        trace.get_current_span().set_attributes(
            safe_attributes(
                {
                    "gen_ai.operation.name": _GENAI_OPERATIONS.get(prepared.protocol),
                    "gen_ai.provider.name": _GENAI_PROVIDERS[str(prepared.provider)],
                    "shim.task_id": prepared.admission.task_id,
                }
            )
        )

        stream_session: StreamSession | None = None
        # A reference, not a copy: the approval gate digests what entered privacy.
        admitted_payload = prepared.payload
        admission = prepared.admission
        inflight_key = (
            str(prepared.tenant_id),
            str(admission.request_digest),
            str(prepared.request_id),
        )
        leader = admission_stage.leader
        shared = handed_off = False
        try:
            prepared = await run_stage(
                PrivacyStage(
                    execution.pii_scrubber,
                    self.chain_store,
                ),
                prepared,
            )
            assert prepared.privacy is not None
            if prepared.privacy.block_code is not None:
                if prepared.protocol != "count_tokens":
                    await self.usage.record_privacy(prepared)
                raise HTTPException(
                    status_code=400,
                    detail={
                        "code": prepared.privacy.block_code,
                        "message": "Request blocked by privacy policy: "
                        f"{', '.join(sorted(prepared.privacy.blocked_entities))}.",
                    },
                )
            if prepared.rules is not None:
                prepared, refusal = await self._decide_rules(
                    prepared, invocation, admitted_payload
                )
                if refusal is not None:
                    raise refusal
            if prepared.protocol == "count_tokens":
                await self.usage.record_token_count(prepared, None)

                async def token_count_started() -> None:
                    pass

                counted = await execution.execute(
                    invocation=invocation,
                    prepared=prepared,
                    provider_start_callback=token_count_started,
                )
                assert isinstance(counted, ProviderNonStream)
                input_tokens = counted.payload.get("input_tokens")
                if (
                    not isinstance(input_tokens, int)
                    or isinstance(input_tokens, bool)
                    or input_tokens < 0
                ):
                    raise ProviderCallError(
                        502, "PROVIDER_UNAVAILABLE", False, provider="anthropic"
                    )
                await self.usage.record_token_count(prepared, input_tokens)
                headers = {"X-Shim-Request-Id": str(prepared.request_id)}
                if counted.request_id:
                    headers["request-id"] = counted.request_id
                return JSONResponse(content=counted.payload, headers=headers)
            pins = pins_in_scope(prepared)
            if pins or prepared.band.on:
                prepared, blocked = await run_stage(SettingsBandStage(pins), prepared)
                if blocked is not None:
                    await self.usage.record_privacy(prepared)
                    raise rule_blocked(blocked)
            if prepared.band.json_compaction:
                prepared = await run_stage(TransformBandStage(), prepared)
            await self.usage.record_privacy(prepared)
            if leader is not None and (
                answer := await self._leader_answer(prepared, leader)
            ):
                response = await self.postprocessor.finalize_shared(
                    prepared, answer, leader.request_id
                )
                if response is not None:
                    shared = True
                    return response
            prepared = await run_stage(
                ProviderSpendStage(invocation, self.usage),
                prepared,
            )
            if prepared.stream:
                stream_session = self.postprocessor.create_stream_session(
                    prepared,
                    on_terminal=lambda: self.inflight.leave(*inflight_key),
                )
            # A stream's session releases its own call at its terminal state.
            in_flight = REQUESTS_IN_FLIGHT.labels(
                provider=bounded_label("provider", invocation.provider)
            )
            in_flight.inc()
            try:
                provider_output = await run_stage(
                    ProviderExecutionStage(
                        invocation,
                        execution,
                        self.usage,
                    ),
                    prepared,
                )
            except BaseException:
                in_flight.dec()
                raise
            if not isinstance(provider_output, ProviderStream):
                in_flight.dec()
                # Before this request's own postprocess, so followers do not wait on it.
                self.inflight.publish(*inflight_key, provider_output)
            try:
                response = await run_stage(
                    PostprocessStage(
                        self.postprocessor,
                        prepared,
                        stream_session=stream_session,
                    ),
                    provider_output,
                )
                # A stream leaves at its terminal state, through its session.
                handed_off = isinstance(response, StreamingResponse)
                return response
            except BaseException:
                if isinstance(provider_output, ProviderStream):
                    in_flight.dec()
                raise
        except BaseException as error:
            reason = (
                "provider_rejected_without_usage"
                if isinstance(error, ProviderCallError)
                and error.status_code < 500
                and error.error_code != "PROVIDER_TIMEOUT"
                else "request_aborted"
            )
            if prepared.protocol != "count_tokens":
                await self._fail_safely(prepared, reason=reason)
            elif not isinstance(error, UsageAuditPersistenceError):
                if not any(
                    verdict.outcome in {"deny", "error"}
                    for verdict in prepared.policy_verdicts
                ):
                    prepared.record_verdict(
                        "gateway.token_count",
                        stage="privacy",
                        outcome="error",
                        reason_code="TOKEN_COUNT_UNAVAILABLE",
                    )
                await self.usage.reject(prepared)
            raise
        finally:
            if not handed_off:
                self.inflight.leave(*inflight_key)
            if admission.inflight_duplicate_of is not None:
                INFLIGHT_DUPLICATES_TOTAL.labels(shared=str(shared).lower()).inc()

    async def _leader_answer(
        self, prepared: PreparedInference, leader: InFlightEntry
    ) -> ProviderNonStream | None:
        """The leader's answer, or None once it ends without one or its entry expires."""
        assert leader.outcome is not None
        try:
            # Provider time, like the call it replaces. Shielded: a follower that stops
            # waiting must not cancel the leader's answer.
            with prepared.timing.exclude():
                async with asyncio.timeout(leader.expires_at - self.inflight.clock()):
                    answer = await asyncio.shield(leader.outcome)
        except TimeoutError:
            return None
        return answer if isinstance(answer, ProviderNonStream) else None

    async def _decide_rules(
        self,
        prepared: PreparedInference,
        invocation: GatewayInvocation,
        admitted_payload: Mapping[str, Any],
    ) -> tuple[PreparedInference, HTTPException | None]:
        """The decision point: a tenant rule block, then the approval gate."""

        blocked, approval = settle_matches(prepared)
        counting = prepared.protocol == "count_tokens"
        if approval and not blocked and not counting and self.approval_gate is None:
            # A cached set can still hold such a rule after the gate went away: fail closed.
            blocked = approval
            record_rule_verdicts(
                prepared, dict.fromkeys(approval, ("deny", "RULE_BLOCKED"))
            )
        if blocked:
            if not counting:
                await self.usage.record_privacy(prepared)
            return prepared, rule_blocked(blocked[0])
        if not approval:
            return prepared, None
        first = approval[0]
        if counting:
            record_rule_verdicts(
                prepared, dict.fromkeys(approval, ("deny", "APPROVAL_REQUIRED"))
            )
            return prepared, HTTPException(
                status_code=403,
                detail={
                    "code": "APPROVAL_REQUIRED",
                    "message": "Token counting is not available for content that "
                    f"needs approval under tenant rule {first}.",
                },
                headers={"X-Shim-Rule-Id": first, "x-should-retry": "false"},
            )
        assert self.approval_gate is not None
        presented = (invocation.headers.get("x-shim-approval-id") or "").strip()
        request = ApprovalRequest(
            rule_ids=tuple(approval),
            presented_id=presented if 0 < len(presented) <= 64 else None,
            admitted_payload=admitted_payload,
        )
        try:
            decision = await self.approval_gate.check(prepared, request)
        except Exception as exc:
            logger.warning("Approval gate failed type=%s", type(exc).__name__)
            record_rule_verdicts(
                prepared, dict.fromkeys(approval, ("error", "APPROVAL_UNAVAILABLE"))
            )
            await self.usage.record_privacy(prepared)
            return prepared, HTTPException(
                status_code=503,
                detail={
                    "code": "APPROVAL_UNAVAILABLE",
                    "message": "The approval store could not be reached.",
                },
                headers={"Retry-After": "5", "X-Shim-Rule-Id": first},
            )
        prepared = replace(prepared, approval_id=decision.approval_id)
        if decision.outcome == "approved":
            record_rule_verdicts(
                prepared, dict.fromkeys(approval, ("allow", "RULE_APPROVED"))
            )
            return prepared, None
        code, message = {
            "required": (
                "APPROVAL_REQUIRED",
                f"Request needs approval under tenant rule {first}. After an "
                f"administrator approves {decision.approval_id}, send the same "
                f"request again with X-Shim-Approval-Id: {decision.approval_id}.",
            ),
            "rejected": (
                "APPROVAL_REJECTED",
                f"Request {decision.approval_id} was rejected by an administrator.",
            ),
            "queue_full": (
                "APPROVAL_QUEUE_FULL",
                "Too many requests are waiting for approval.",
            ),
        }[decision.outcome]
        record_rule_verdicts(prepared, dict.fromkeys(approval, ("deny", code)))
        await self.usage.record_privacy(prepared)
        headers = {"X-Shim-Rule-Id": first, "x-should-retry": "false"}
        detail: dict[str, Any] = {"code": code, "message": message}
        if decision.approval_id is not None and decision.outcome != "queue_full":
            headers["X-Shim-Approval-Id"] = decision.approval_id
            detail["param"] = decision.approval_id
        return prepared, HTTPException(status_code=403, detail=detail, headers=headers)

    async def _fail_safely(
        self,
        prepared: PreparedInference,
        *,
        reason: UsageFailureReason,
    ) -> None:
        try:
            await self.usage.fail(prepared, reason=reason)
        except UsageAuditPersistenceError:
            raise
        except Exception as exc:
            logger.error("Usage recovery failed type=%s", type(exc).__name__)
