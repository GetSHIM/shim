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
from shim.gateway.concurrency import (
    ConcurrencyLimiter,
    ConcurrencyRefused,
    concurrency_target,
    work_tokens,
)
from shim.gateway.contracts.ids import CURRENT_REQUEST_ID
from shim.gateway.kernel.shadow import (
    ShadowObservation,
    ShadowSelection,
    ShadowSender,
    observation,
    selectable,
    shadow_of,
)
from shim.gateway.kernel.attempts import (
    AttemptOutcome,
    AttemptPolicy,
    Target,
    guarded,
    next_attempt,
    retargeted,
    skip_attempt,
)
from shim.gateway.pipeline.admission import AdmissionStage, rule_blocked
from shim.gateway.pipeline.authenticate import AuthenticateStage, GatewayInvocation
from shim.gateway.pipeline.analysis import AnalysisToolCall
from shim.gateway.pipeline.postprocess import (
    OnSettled,
    PostprocessStage,
    ResponsePostprocessor,
)
from shim.gateway.streaming.finalization import StreamFinalization
from shim.gateway.streaming.meter import (
    KEPT_ANSWER_CHARACTERS,
    KEPT_TOOL_CALLS,
    answer_text,
    answer_tool_calls,
)
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
    EXTRA_ATTEMPTS_TOTAL,
    SHADOW_COPIES_TOTAL,
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


def _failure_reason(error: BaseException) -> UsageFailureReason:
    if (
        isinstance(error, ProviderCallError)
        and error.status_code < 500
        and error.error_code != "PROVIDER_TIMEOUT"
    ):
        return "provider_rejected_without_usage"
    return "request_aborted"


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
        prepare_inference: Callable[
            [PreparedInference, Mapping[str, str]], Awaitable[PreparedInference]
        ]
        | None = None,
        approval_gate: ApprovalGate | None = None,
        honor_trace_parent: bool = False,
        task_counter: TaskCounter | None = None,
        model_lifecycle: ModelLifecycle | None = None,
        attempt_policy: AttemptPolicy | None = None,
        concurrency_limiter: ConcurrencyLimiter | None = None,
        concurrency_wait_ms: int = 0,
        shadow_sender: ShadowSender | None = None,
        shadow_max_in_flight: int = 4,
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
        self.attempt_policy = attempt_policy
        self.concurrency_limiter = concurrency_limiter
        self.concurrency_wait_ms = concurrency_wait_ms
        self.shadow_sender = shadow_sender
        self.shadow_max_in_flight = shadow_max_in_flight
        # Per process; a copy beyond the bound is dropped, never queued.
        self._shadow_in_flight = 0

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
                prepared = await self.prepare_inference(prepared, invocation.headers)
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
            concurrency_limiter=self.concurrency_limiter,
            concurrency_wait_ms=self.concurrency_wait_ms,
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
        shared = handed_off = settled = False
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
            # Only an extra attempt reads it: a BYOK key is consumed by the first one.
            byok = (
                self.attempt_policy is not None
                and invocation.provider_credential is not None
            )
            if self.attempt_policy is not None:
                target = guarded(
                    prepared,
                    await self.attempt_policy.choose_target_after_privacy(prepared),
                    attempts=1,
                    byok=byok,
                )
                if target is not None:
                    prepared = (
                        await self._leased(
                            prepared, retargeted(prepared, target), target
                        )
                        or prepared
                    )
            if (
                self.attempt_policy is not None or self.shadow_sender is not None
            ) and prepared.pre_band_payload is None:
                # Kept by reference: an extra attempt or a copy runs the bands again from here.
                prepared = replace(prepared, pre_band_payload=prepared.payload)
            prepared, blocked = await self._bands(prepared)
            await self.usage.record_privacy(prepared)
            if blocked is not None:
                raise rule_blocked(blocked)
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
            selection = self._shadow_selection(prepared)
            attempts = 1
            while True:
                on_settled = (
                    None
                    if selection is None
                    else self._shadow_copy(invocation, execution, prepared, selection)
                )
                keep = selection is not None and selection.keep_answer
                stream_session = None
                if prepared.stream:
                    stream_session = self.postprocessor.create_stream_session(
                        prepared,
                        on_terminal=lambda: self.inflight.leave(*inflight_key),
                        on_settled=on_settled,
                        keep_answer=keep,
                    )
                # A stream's session releases its own call at its terminal state.
                in_flight = REQUESTS_IN_FLIGHT.labels(
                    provider=bounded_label("provider", invocation.provider)
                )
                in_flight.inc()
                execution_stage = ProviderExecutionStage(
                    invocation, execution, self.usage
                )
                try:
                    provider_output = await run_stage(execution_stage, prepared)
                except ProviderCallError as error:
                    in_flight.dec()
                    if self.attempt_policy is None:
                        raise
                    target = guarded(
                        prepared,
                        await self.attempt_policy.next_attempt(
                            AttemptOutcome(
                                prepared,
                                attempts,
                                error,
                                execution_stage.provider_started,
                                None,
                            )
                        ),
                        attempts=attempts,
                        byok=byok,
                    )
                    following = (
                        None
                        if target is None
                        else await self._start_attempt(
                            invocation, prepared, target, attempts + 1
                        )
                    )
                    # Settled after the next attempt's start, so a skip that start
                    # records lands on this attempt's row too.
                    await self._fail_safely(prepared, reason=_failure_reason(error))
                    settled = True
                    if following is None:
                        raise
                    prepared, attempts, settled = following, attempts + 1, False
                    if prepared_observer is not None:
                        prepared_observer(prepared)
                    continue
                except BaseException:
                    in_flight.dec()
                    raise
                target = None
                if not isinstance(provider_output, ProviderStream):
                    in_flight.dec()
                    if self.attempt_policy is not None:
                        target = guarded(
                            prepared,
                            await self.attempt_policy.next_attempt(
                                AttemptOutcome(
                                    prepared,
                                    attempts,
                                    None,
                                    True,
                                    provider_output.payload,
                                )
                            ),
                            attempts=attempts,
                            byok=byok,
                        )
                    if target is None:
                        # Before this request's own postprocess, so followers do not wait on it.
                        self.inflight.publish(*inflight_key, provider_output)
                try:
                    response = await run_stage(
                        PostprocessStage(
                            self.postprocessor,
                            prepared,
                            stream_session=stream_session,
                            # Only the attempt that serves is copied.
                            on_settled=on_settled if target is None else None,
                            keep_answer=keep,
                        ),
                        provider_output,
                    )
                except BaseException:
                    if isinstance(provider_output, ProviderStream):
                        in_flight.dec()
                    raise
                if target is not None:
                    # The settled answer is kept aside: it serves only if no next attempt starts.
                    settled = True
                    following = await self._start_attempt(
                        invocation, prepared, target, attempts + 1
                    )
                    if following is not None:
                        prepared, attempts, settled = following, attempts + 1, False
                        if prepared_observer is not None:
                            prepared_observer(prepared)
                        continue
                    self.inflight.publish(*inflight_key, provider_output)
                # A stream leaves at its terminal state, through its session.
                handed_off = isinstance(response, StreamingResponse)
                if attempts > 1:
                    response.headers["X-Shim-Attempts"] = str(attempts)
                return response
        except BaseException as error:
            if prepared.protocol != "count_tokens":
                if not settled:
                    await self._fail_safely(prepared, reason=_failure_reason(error))
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
                # A stream releases its lease when it finalizes.
                if prepared.concurrency_lease is not None:
                    await prepared.concurrency_lease.release()
            if admission.inflight_duplicate_of is not None:
                INFLIGHT_DUPLICATES_TOTAL.labels(shared=str(shared).lower()).inc()

    def _shadow_selection(self, prepared: PreparedInference) -> ShadowSelection | None:
        if self.shadow_sender is None or not selectable(prepared):
            return None
        try:
            return self.shadow_sender.select(prepared)
        except Exception as exc:
            logger.warning("Shadow selection failed type=%s", type(exc).__name__)
            SHADOW_COPIES_TOTAL.labels(outcome="failed").inc()
            return None

    def _shadow_copy(
        self,
        invocation: GatewayInvocation,
        execution: Any,
        primary: PreparedInference,
        selection: ShadowSelection,
    ) -> OnSettled:
        # Runs after the caller's answer is complete, as the postprocessor's
        # settled hook: it never touches the caller and never raises.
        async def copy(
            terminal: StreamFinalization,
            text: str | None,
            tool_calls: tuple[AnalysisToolCall, ...],
            truncated: bool,
        ) -> None:
            assert self.shadow_sender is not None
            if terminal.terminal_status != "completed":
                return
            if self._shadow_in_flight >= self.shadow_max_in_flight:
                SHADOW_COPIES_TOTAL.labels(outcome="dropped_saturated").inc()
                return
            self._shadow_in_flight += 1
            lease = None
            try:
                candidate = await self.shadow_sender.candidate(primary, selection)
                if candidate is None:
                    SHADOW_COPIES_TOTAL.labels(outcome="no_candidate").inc()
                    return
                if (
                    candidate.deployment_kind != "internal"
                    and candidate.deployment_kind != primary.deployment_kind
                ) or not candidate.provider_target.credential_reference:
                    SHADOW_COPIES_TOTAL.labels(outcome="skipped_guard").inc()
                    return
                shadow = shadow_of(primary, selection, candidate)
                if self.concurrency_limiter is not None and primary.admission:
                    try:
                        lease = await self.concurrency_limiter.acquire(
                            concurrency_target(shadow),
                            work_tokens(primary.admission),
                            "low",
                            0,
                        )
                    except ConcurrencyRefused:
                        SHADOW_COPIES_TOTAL.labels(outcome="dropped_saturated").inc()
                        return
                shadow, blocked = await self._bands(
                    replace(shadow, concurrency_lease=lease)
                )
                if blocked is not None:
                    SHADOW_COPIES_TOTAL.labels(outcome="skipped_guard").inc()
                    return
                observed = await self._run_shadow(
                    replace(invocation, provider_credential=None),
                    execution,
                    shadow,
                    keep_answer=selection.keep_answer,
                )
                SHADOW_COPIES_TOTAL.labels(outcome="sent").inc()
                await self.shadow_sender.compare(
                    primary,
                    selection,
                    observation(primary, terminal, text, tool_calls, truncated),
                    observed,
                )
            except Exception as exc:
                logger.warning("Shadow copy failed type=%s", type(exc).__name__)
                SHADOW_COPIES_TOTAL.labels(outcome="failed").inc()
            finally:
                self._shadow_in_flight -= 1
                if lease is not None:
                    await lease.release()

        return copy

    async def _run_shadow(
        self,
        invocation: GatewayInvocation,
        execution: Any,
        shadow: PreparedInference,
        *,
        keep_answer: bool,
    ) -> ShadowObservation:
        # The copy is its own request: no rate limit, repeat or task counter sees it.
        assert shadow.admission is not None
        try:
            await self.usage.admit(shadow, shadow.admission)
        except BaseException:
            await self.usage.reject(shadow)
            raise
        settled: asyncio.Future[ShadowObservation] = (
            asyncio.get_running_loop().create_future()
        )

        async def observe(
            terminal: StreamFinalization,
            text: str | None,
            tool_calls: tuple[AnalysisToolCall, ...],
            truncated: bool,
        ) -> None:
            settled.set_result(
                observation(shadow, terminal, text, tool_calls, truncated)
            )

        try:
            await self.usage.record_privacy(shadow)
            shadow = await run_stage(ProviderSpendStage(invocation, self.usage), shadow)
            output = await ProviderExecutionStage(
                invocation, execution, self.usage
            ).run(shadow)
        except ProviderCallError as error:
            await self._fail_safely(shadow, reason=_failure_reason(error))
            return ShadowObservation(
                request_id=str(shadow.request_id),
                status="provider_error",
                completion_outcome=None,
                answer_text=None,
                prompt_tokens=0,
                completion_tokens=0,
                cost_usd=None,
                provider_latency_ms=None,
                ttft_ms=None,
                error_code=error.error_code,
            )
        except BaseException:
            # A copy cancelled at shutdown, or one that failed, is settled here.
            await self._fail_safely(shadow, reason="request_aborted")
            raise
        if isinstance(output, ProviderNonStream):
            _, terminal = await self.postprocessor.settle_json(shadow, output)
            text = answer_text(output.payload) if keep_answer else None
            calls = answer_tool_calls(output.payload) if keep_answer else ()
            return observation(
                shadow,
                terminal,
                text[:KEPT_ANSWER_CHARACTERS] if text is not None else None,
                calls[:KEPT_TOOL_CALLS],
                (text is not None and len(text) > KEPT_ANSWER_CHARACTERS)
                or len(calls) > KEPT_TOOL_CALLS,
            )
        session = self.postprocessor.create_stream_session(
            shadow, on_settled=observe, keep_answer=keep_answer
        )
        await self.postprocessor.finalize(shadow, output, stream_session=session)
        async for _ in session:
            pass
        return await settled

    async def _bands(
        self, prepared: PreparedInference
    ) -> tuple[PreparedInference, str | None]:
        # The settings band, then the transform band; the id of a pin that blocks.
        pins = pins_in_scope(prepared)
        if pins or prepared.band.on:
            prepared, blocked = await run_stage(SettingsBandStage(pins), prepared)
            if blocked is not None:
                return prepared, blocked
        if prepared.band.json_compaction:
            prepared = await run_stage(TransformBandStage(), prepared)
        return prepared, None

    async def _start_attempt(
        self,
        invocation: GatewayInvocation,
        prepared: PreparedInference,
        target: Target,
        number: int,
    ) -> PreparedInference | None:
        # Attempt `number`, admitted and reserved, or None. Admission is the usage
        # reservation only: rate limits and the repeat detector never see it.
        following, blocked = await self._bands(
            next_attempt(prepared, target, number=number)
        )
        moved = (
            None
            if blocked is not None
            else await self._leased(prepared, following, target)
        )
        if moved is None:
            if blocked is not None:
                skip_attempt(
                    following,
                    target.reason,
                    target.rule_id,
                    "ATTEMPT_NOT_ADMITTED",
                    outcome="not_admitted",
                )
            return None
        following = moved
        assert following.admission is not None
        admitted = False
        try:
            await self.usage.admit(following, following.admission)
            admitted = True
            await self.usage.record_privacy(following)
            following = await run_stage(
                ProviderSpendStage(invocation, self.usage), following
            )
        except Exception:
            skip_attempt(
                following,
                target.reason,
                target.rule_id,
                "ATTEMPT_NOT_ADMITTED",
                outcome="not_admitted",
            )
            if admitted:
                await self._fail_safely(following, reason="admission_aborted")
            else:
                await self.usage.reject(following)
            if following.concurrency_lease is not None:
                await following.concurrency_lease.release()
            return None
        EXTRA_ATTEMPTS_TOTAL.labels(reason=target.reason, outcome="started").inc()
        return following

    async def _leased(
        self, current: PreparedInference, moved: PreparedInference, target: Target
    ) -> PreparedInference | None:
        # A request moving to another target takes room there first, without waiting,
        # and then gives back its room on the current one.
        if self.concurrency_limiter is None or current.admission is None:
            return moved
        try:
            lease = await self.concurrency_limiter.acquire(
                concurrency_target(moved), work_tokens(current.admission), "normal", 0
            )
        except ConcurrencyRefused:
            skip_attempt(
                current, target.reason, target.rule_id, "ATTEMPT_TARGET_SATURATED"
            )
            return None
        if current.concurrency_lease is not None:
            await current.concurrency_lease.release()
        return replace(moved, concurrency_lease=lease)

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
