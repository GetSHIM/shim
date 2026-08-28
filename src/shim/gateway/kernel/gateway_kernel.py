"""Provider-neutral inference orchestration."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import logging
from typing import Any

from fastapi import HTTPException
from starlette.responses import Response

from shim.core.middleware import AsyncRateLimiter
from shim.gateway.admission import LoopDetector
from shim.gateway.pipeline.admission import AdmissionStage
from shim.gateway.pipeline.authenticate import AuthenticateStage, GatewayInvocation
from shim.gateway.pipeline.postprocess import PostprocessStage, ResponsePostprocessor
from shim.gateway.pipeline.privacy import PrivacyStage
from shim.gateway.pipeline.provider_spend import ProviderSpendStage
from shim.gateway.pipeline.provider_execution import (
    ProviderCallError,
    ProviderExecutionStage,
)
from shim.gateway.streaming import StreamSession
from shim.gateway.usage import UsageFailureReason, UsageLifecycle, UsageLimitExceeded
from shim.observability.metrics import REQUESTS_TOTAL, bounded_label
from shim.observability.tracing import start_span
from shim.privacy.continuation import PrivacyContinuationStore

from .runtime import run_stage
from .result import PreparedInference


logger = logging.getLogger(__name__)
_PROVIDERS = frozenset({"openai", "anthropic", "google"})


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
        self.postprocessor = ResponsePostprocessor(
            usage,
            heartbeat_interval_seconds=heartbeat_interval_seconds,
            output_hash_salt=output_hash_salt,
        )
        self.chain_store = chain_store
        self.policy_resolver = policy_resolver

    async def execute(self, invocation: GatewayInvocation) -> Response:
        endpoint = bounded_label("endpoint", invocation.metadata.endpoint)
        tenant_tier = "default"
        outcome = "server_error"

        def observe_prepared(prepared: PreparedInference) -> None:
            nonlocal tenant_tier
            tenant_tier = bounded_label("tenant_tier", prepared.policy.tier)

        with start_span(
            "gateway.request",
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
        prepared = await run_stage(
            AuthenticateStage(self.policy_resolver),
            invocation,
        )
        if prepared_observer is not None:
            prepared_observer(prepared)
        admission_stage = AdmissionStage(
            invocation,
            self.usage,
            rate_limiter=self.rate_limiter,
            loop_detector=self.loop_detector,
            loop_repeat_limit=self.loop_repeat_limit,
            loop_window_seconds=self.loop_window_seconds,
            cost_tag_max_length=self.cost_tag_max_length,
        )
        try:
            prepared = await run_stage(admission_stage, prepared)
        except BaseException:
            if admission_stage.reserved:
                await self._fail_safely(prepared, reason="admission_aborted")
            raise

        stream_session: StreamSession | None = None
        try:
            prepared = await run_stage(
                PrivacyStage(
                    execution.pii_scrubber,
                    self.chain_store,
                ),
                prepared,
            )
            await self.usage.record_privacy(prepared)
            prepared = await run_stage(
                ProviderSpendStage(invocation, self.usage),
                prepared,
            )
            if prepared.stream:
                stream_session = self.postprocessor.create_stream_session(
                    prepared,
                )
            provider_output = await run_stage(
                ProviderExecutionStage(
                    invocation,
                    execution,
                    self.usage,
                ),
                prepared,
            )
            return await run_stage(
                PostprocessStage(
                    self.postprocessor,
                    prepared,
                    stream_session=stream_session,
                ),
                provider_output,
            )
        except BaseException as error:
            reason = (
                "provider_rejected_without_usage"
                if isinstance(error, ProviderCallError)
                and error.error_code == "PROVIDER_UNAVAILABLE"
                and error.status_code < 500
                else "request_aborted"
            )
            await self._fail_safely(prepared, reason=reason)
            raise

    async def _fail_safely(
        self,
        prepared: PreparedInference,
        *,
        reason: UsageFailureReason,
    ) -> None:
        try:
            await self.usage.fail(prepared, reason=reason)
        except Exception as exc:
            logger.error("Usage recovery failed type=%s", type(exc).__name__)
