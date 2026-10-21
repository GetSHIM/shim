"""Best-effort admission before authoritative usage reservation."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import replace
from decimal import ROUND_CEILING, Decimal
import hashlib
import json
import re
from typing import TYPE_CHECKING
import unicodedata

from fastapi import HTTPException
from opentelemetry import trace
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from shim.billing.attribution import CostAttribution
from shim.billing.lifecycle import ModelLifecycle, load_lifecycle
from shim.billing.pricing import DEFAULT_PRICE_BOOK, ModelPrice
from shim.core.middleware import AsyncRateLimiter
from shim.gateway.admission import (
    InFlightEntry,
    InFlightRegistry,
    InMemoryTaskCounter,
    LoopDetectionResult,
    LoopDetector,
    TaskCounter,
)

from shim.gateway.concurrency import (
    ConcurrencyLimiter,
    ConcurrencyRefused,
    Lease,
    concurrency_target,
    work_tokens,
)
from shim.gateway.kernel.result import (
    EMBEDDINGS_PROTOCOLS,
    AdmissionState,
    PreparedInference,
    UNSPECIFIED_PROVIDER_MODEL,
)
from shim.gateway.kernel.stage import TraceValue
from shim.gateway.media import (
    MEDIA_MARKERS,
    MediaPart,
    classify_media,
    media_tokens,
    pdf_page_count,
    value_at,
)
from shim.gateway.image_rules import image_detail
from shim.gateway.pipeline.privacy import media_refused
from shim.observability.metrics import (
    AGENT_LOOP_SIGNALS_TOTAL,
    TASK_ID_REJECTED_TOTAL,
    TASK_COUNTER_UNAVAILABLE_TOTAL,
    TASK_LIMIT_REFUSALS_TOTAL,
)
from shim.privacy.documents import is_document
from shim.privacy.policies import is_protocol_field
from shim.rules.evaluate import in_scope, settle_matches
from shim.rules.request_limit import request_measures

if TYPE_CHECKING:
    from shim.gateway.pipeline.authenticate import GatewayInvocation
    from shim.gateway.usage import UsageLifecycle


_WHITESPACE = re.compile(r"\s+")
_TASK_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
_MAX_CANDIDATES = 10_000
# A word never shares a token with its neighbour in a whitespace-splitting tokenizer.
_WORD = re.compile(r"[^ \t\r\n]+")
_PROMPT_FIELDS = (
    "messages",
    "input",
    "instructions",
    "system",
    "contents",
    "systemInstruction",
    "prompt",
)
_CATALOG_MODALITIES = frozenset({"image", "audio", "pdf"})
# Earlier turns' reasoning, which a provider may drop from the window.
_UNCOUNTED_BLOCKS = frozenset({"thinking", "redacted_thinking", "reasoning"})


class AdmissionStage:
    """Apply RPM/TPM and repeat admission, then reserve authoritative usage."""

    name = "admission"

    def __init__(
        self,
        invocation: GatewayInvocation,
        usage: UsageLifecycle,
        *,
        rate_limiter: AsyncRateLimiter,
        loop_detector: LoopDetector,
        loop_repeat_limit: int,
        loop_window_seconds: int,
        cost_tag_max_length: int,
        task_counter: TaskCounter | None = None,
        inflight: InFlightRegistry | None = None,
        model_lifecycle: ModelLifecycle | None = None,
        concurrency_limiter: ConcurrencyLimiter | None = None,
        concurrency_wait_ms: int = 0,
    ) -> None:
        if loop_repeat_limit < 2 or loop_window_seconds < 1:
            raise ValueError("loop-detection bounds are invalid")
        if cost_tag_max_length < 1:
            raise ValueError("cost_tag_max_length must be positive")
        self.invocation = invocation
        self.usage = usage
        self.rate_limiter = rate_limiter
        self.loop_detector = loop_detector
        self.loop_repeat_limit = loop_repeat_limit
        self.loop_window_seconds = loop_window_seconds
        self.cost_tag_max_length = cost_tag_max_length
        self.task_counter = task_counter or InMemoryTaskCounter()
        self.inflight = inflight or InFlightRegistry()
        self.model_lifecycle = model_lifecycle or load_lifecycle()
        self.concurrency_limiter = concurrency_limiter
        self.concurrency_wait_ms = concurrency_wait_ms
        # The shareable leader of this request's key whose answer it may receive.
        self.leader: InFlightEntry | None = None
        self.loop_result = LoopDetectionResult("SAFE", 0)
        self.reserved = False

    async def run(self, value: PreparedInference) -> PreparedInference:
        unspecified_openai_response_model = (
            value.provider == "openai"
            and value.protocol == "responses"
            and value.model == UNSPECIFIED_PROVIDER_MODEL
        )
        embeddings = value.protocol in EMBEDDINGS_PROTOCOLS
        # An embeddings model answers only the embeddings routes, and only them.
        model_denied = (
            value.target is None
            and not unspecified_openai_response_model
            and (
                not DEFAULT_PRICE_BOOK.supports(value.model, str(value.provider))
                or (
                    DEFAULT_PRICE_BOOK.resolve(value.model, str(value.provider)).kind
                    == "embedding"
                )
                != embeddings
            )
        )
        value.record_verdict(
            "gateway.model_catalog",
            stage="admission",
            outcome="skip"
            if value.target is not None
            else ("deny" if model_denied else "allow"),
            reason_code="DEPLOYMENT_AUTHORIZED"
            if value.target is not None
            else ("MODEL_NOT_PRICED" if model_denied else "MODEL_SUPPORTED"),
            policy_version=DEFAULT_PRICE_BOOK.version,
        )
        if model_denied:
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "MODEL_NOT_PRICED",
                    "message": "The requested model is not in this gateway's supported model catalog. Use a supported model.",
                },
            )
        # A warning only: the provider's own error stays the truth after the date.
        retirement = self.model_lifecycle.retirement(
            value.pricing_model,
            str(value.provider),
            value.model if value.target is not None else None,
        )
        if retirement is not None and (
            code := retirement.warning(value.context.started_at.date())
        ):
            value.warn(code)
        payload = value.payload
        generation_config = payload.get("generationConfig")
        gemini_max = (
            generation_config.get("maxOutputTokens")
            if isinstance(generation_config, Mapping)
            else None
        )
        model_output_limit = DEFAULT_PRICE_BOOK.maximum_output_tokens(
            value.pricing_model,
            str(value.provider),
        )
        # Reserve the ceiling when omitted without changing provider defaults.
        output_token_field, per_candidate_output_tokens = next(
            (
                candidate
                for candidate in (
                    ("max_output_tokens", payload.get("max_output_tokens")),
                    ("max_completion_tokens", payload.get("max_completion_tokens")),
                    ("max_tokens", payload.get("max_tokens")),
                    ("maxOutputTokens", gemini_max),
                )
                if candidate[1] is not None
            ),
            ("provider_default", model_output_limit),
        )
        if value.protocol == "count_tokens" or embeddings:
            per_candidate_output_tokens = 0
        minimum_output_tokens = (
            0
            if value.protocol == "count_tokens"
            or embeddings
            or (
                value.provider == "anthropic"
                and value.protocol == "messages"
                and output_token_field == "max_tokens"
            )
            else 1
        )
        if (
            not isinstance(per_candidate_output_tokens, int)
            or isinstance(per_candidate_output_tokens, bool)
            or not (
                minimum_output_tokens
                <= per_candidate_output_tokens
                <= model_output_limit
            )
        ):
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "INVALID_REQUEST",
                    "message": (
                        "Maximum output tokens must be between "
                        f"{minimum_output_tokens} and "
                        f"{model_output_limit}."
                    ),
                },
            )
        input_tokens, request_digest, serialized = _estimate_input_tokens(
            payload,
            f"{value.provider}|{value.protocol}|{value.model}|{value.stream}",
        )
        media = classify_media(payload) if MEDIA_MARKERS.search(serialized) else ()
        # A byte cap measures the body as sent, whatever its parts are estimated at.
        body_bytes = input_tokens
        candidates = candidate_count(value)
        output_tokens = per_candidate_output_tokens * candidates
        tier = value.context.tier_policy
        key_hash = value.policy.rate_limit_key_hash
        # The byte count stays the reservation bound; the rate unit is four bytes a token.
        approximate_tokens = -(-input_tokens // 4)
        attribution = CostAttribution.resolve(
            self.invocation.headers.get("x-shim-tag"),
            api_key_cost_center=value.policy.cost_center,
            maximum_length=self.cost_tag_max_length,
        )
        # Media that privacy will refuse is sized as bytes, so its refusal is unchanged;
        # inline documents it reads pass when clean.
        if media and (
            not media_refused(value, attribution.tags)
            or (
                value.documents != "as_media"
                and all(is_document(part) and part.source == "inline" for part in media)
            )
        ):
            input_tokens, approximate_tokens = await _sized_by_parts(
                value, media, input_tokens
            )
        # The provider answers an oversized embeddings input natively.
        if (
            value.protocol != "count_tokens"
            and not embeddings
            and (
                value.target is None
                or value.target.context_window
                or value.target.price_model
            )
        ):
            _check_catalog_limits(
                value,
                media,
                input_bytes=input_tokens,
                approximate_tokens=approximate_tokens,
                requested_output=0
                if output_token_field == "provider_default"
                else per_candidate_output_tokens,
            )
        elif embeddings and value.target is None:
            entry = DEFAULT_PRICE_BOOK.exact(value.pricing_model, str(value.provider))
            if entry is not None and entry.status == "deprecated":
                value.warn("MODEL_DEPRECATED")
        # Before the rate limits, so a refused request consumes none of them.
        limited = value.protocol != "count_tokens" and _request_limits(
            value,
            attribution.tags,
            input_bytes=body_bytes,
            approximate_tokens=approximate_tokens,
        )
        token_limit = tier.rate_limit_tpm
        if token_limit is not None and approximate_tokens > token_limit:
            value.record_verdict(
                "rate.tokens",
                stage="admission",
                outcome="deny",
                reason_code="RATE_LIMIT_EXCEEDED",
                policy={
                    "limit": token_limit,
                    "window_seconds": 60,
                    "unit": "approximate_tokens",
                },
            )
            # Checked before any window is charged: it can never be admitted, so SDKs must not wait.
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "RATE_LIMIT_EXCEEDED",
                    "dimension": "tokens",
                    "message": (
                        f"This request is about {approximate_tokens} tokens, more than "
                        f"the limit of {token_limit} tokens per minute."
                    ),
                    "hint": "Send a smaller request or ask for a higher tokens-per-minute limit; retrying it unchanged fails again.",
                },
                headers={"x-should-retry": "false"},
            )
        for dimension, limit, key, amount, unit in (
            ("requests", tier.rate_limit_rpm, key_hash, 1, {}),
            (
                "tokens",
                tier.rate_limit_tpm,
                f"tpm:{key_hash}",
                approximate_tokens,
                {"unit": "approximate_tokens"},
            ),
        ):
            denied = limit is not None and not await self.rate_limiter.allow(
                key,
                limit=limit,
                window_seconds=60,
                amount=amount,
            )
            value.record_verdict(
                f"rate.{dimension}",
                stage="admission",
                outcome="deny" if denied else "allow" if limit is not None else "skip",
                reason_code="RATE_LIMIT_EXCEEDED"
                if denied
                else "RATE_LIMIT_PASSED"
                if limit is not None
                else "RATE_LIMIT_UNLIMITED",
                policy={"limit": limit, "window_seconds": 60, **unit},
            )
            if denied:
                raise HTTPException(
                    status_code=429,
                    detail={"code": "RATE_LIMIT_EXCEEDED", "dimension": dimension},
                    headers={"Retry-After": "60"},
                )
        repeat_material = _repeat_material(
            {
                **payload,
                "model": value.model,
                "provider": str(value.provider),
                "protocol": value.protocol,
            }
        )
        task_id, trace_id = _task_identity(self.invocation.headers)
        # A token count is neither an agent turn nor one of the task's calls.
        counted = value.protocol != "count_tokens"
        signature = (
            _tool_signature(payload, value.protocol)
            if counted and value.agent_loop.action != "off"
            else None
        )
        turn_key = (
            hashlib.sha256(
                f"{task_id or value.api_key_id}|{signature}".encode()
            ).hexdigest()
            if signature is not None
            else None
        )
        self.loop_result = await self.loop_detector.check_exact_repeat(
            str(value.tenant_id),
            repeat_material,
            limit=self.loop_repeat_limit,
            window_seconds=self.loop_window_seconds,
            turn_key=turn_key,
        )
        repeated = self.loop_result.status == "BLOCKED"
        value.record_verdict(
            "rate.repeated_requests",
            stage="admission",
            outcome="deny" if repeated else "allow",
            reason_code="REPEATED_REQUEST_LIMIT_EXCEEDED"
            if repeated
            else "REPEAT_CHECK_PASSED",
            policy={
                "limit": self.loop_repeat_limit,
                "window_seconds": self.loop_window_seconds,
            },
        )
        if repeated:
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "RATE_LIMIT_EXCEEDED",
                    "dimension": "repeated_requests",
                },
                headers={"Retry-After": str(self.loop_window_seconds)},
            )
        tool_call_repeats = self.loop_result.turn_repeats if turn_key else None
        if tool_call_repeats is not None and tool_call_repeats >= (
            repeats := value.agent_loop.repeats
        ):
            block = value.agent_loop.action == "block" and tool_call_repeats > repeats
            AGENT_LOOP_SIGNALS_TOTAL.labels(action="block" if block else "count").inc()
            value.record_verdict(
                "task.agent_loop",
                stage="admission",
                outcome="deny" if block else "allow",
                reason_code="AGENT_LOOP_DETECTED" if block else "AGENT_LOOP_SUSPECTED",
                policy=value.agent_loop.model_dump(),
            )
            if block:
                raise HTTPException(
                    status_code=429,
                    detail={
                        "code": "AGENT_LOOP_DETECTED",
                        "message": f"The same tool call was repeated {tool_call_repeats} "
                        f"times within {self.loop_window_seconds} seconds.",
                    },
                    headers={"x-should-retry": "false"},
                )
        task_calls = await self._admit_task_call(value, task_id) if counted else None
        shareable = _shareable(value, candidates)
        earlier = (
            None
            if value.protocol == "count_tokens"
            else self.inflight.enter(
                str(value.tenant_id),
                request_digest,
                str(value.request_id),
                str(value.api_key_id),
                shareable,
            )
        )
        # An answer never crosses keys, and one already published belongs to a call
        # that was finishing, not one this request waited on.
        if (
            shareable
            and earlier is not None
            and earlier.shareable
            and earlier.api_key_id == str(value.api_key_id)
            and not (earlier.outcome is not None and earlier.outcome.done())
        ):
            self.leader = earlier
        admission = AdmissionState(
            estimated_input_tokens=input_tokens,
            maximum_output_tokens=output_tokens,
            cost_center=attribution.cost_center,
            tags=attribution.tags,
            repeat_chain_length=self.loop_result.chain_length or None,
            task_id=task_id,
            trace_id=trace_id,
            tool_call_repeats=tool_call_repeats,
            task_calls=task_calls,
            request_digest=request_digest,
            inflight_duplicate_of=earlier.request_id if earlier is not None else None,
        )
        lease = None
        if value.protocol != "count_tokens":
            try:
                if self.concurrency_limiter is not None:
                    # The approximate input unit TPM uses, plus the output resolved above.
                    lease = await self._acquire(value, work_tokens(admission))
                    admission = replace(admission, queue_wait_ms=lease.waited_ms)
                await self.usage.admit(value, admission)
            except BaseException:
                if lease is not None:
                    await lease.release()
                self.inflight.leave(
                    str(value.tenant_id), request_digest, str(value.request_id)
                )
                # A call the quota refused is not one of the task's calls.
                if task_calls and task_id is not None:
                    await self.task_counter.release_call(
                        str(value.tenant_id), _task_key(task_id)
                    )
                raise
            self.reserved = True
        return replace(
            value,
            admission=admission,
            media=media,
            rules_evaluated=value.rules_evaluated or limited,
            concurrency_lease=lease,
        )

    async def _acquire(self, value: PreparedInference, tokens: int) -> Lease:
        assert self.concurrency_limiter is not None
        policy = {"tokens": tokens, "wait_ms": self.concurrency_wait_ms}
        try:
            lease = await self.concurrency_limiter.acquire(
                concurrency_target(value), tokens, "normal", self.concurrency_wait_ms
            )
        except ConcurrencyRefused as refused:
            value.record_verdict(
                "admission.concurrency",
                stage="admission",
                outcome="deny",
                reason_code="CONCURRENCY_LIMITED",
                policy=policy,
            )
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "CONCURRENCY_LIMITED",
                    "message": "The model target is running all the work it allows.",
                },
                headers={"x-should-retry": "false"}
                if refused.never_fits
                else {"Retry-After": str(refused.retry_after_seconds)},
            ) from None
        value.record_verdict(
            "admission.concurrency",
            stage="admission",
            outcome="allow",
            reason_code="CONCURRENCY_ADMITTED",
            policy=policy,
        )
        return lease

    async def _admit_task_call(
        self, value: PreparedInference, task_id: str | None
    ) -> int | None:
        """The task's calls after this one, or None while no cap is set."""
        caps = value.task_caps
        if task_id is None or (caps.max_calls is None and caps.max_cost_usd is None):
            return None
        task = await self.task_counter.admit_call(
            str(value.tenant_id),
            _task_key(task_id),
            max_calls=caps.max_calls,
            max_cost_micro_usd=micro_usd(caps.max_cost_usd),
            window_seconds=caps.window_seconds,
        )
        refused = not task.allowed
        if task.unavailable:
            # Caps are advisory: an outage admits the call, never silently (the
            # counter logs why).
            TASK_COUNTER_UNAVAILABLE_TOTAL.inc()
        value.record_verdict(
            "task.limit",
            stage="admission",
            outcome="error" if task.unavailable else "deny" if refused else "allow",
            reason_code="TASK_COUNTER_UNAVAILABLE"
            if task.unavailable
            else "TASK_LIMIT_EXCEEDED"
            if refused
            else "TASK_LIMIT_PASSED",
            policy=caps.model_dump(mode="json"),
        )
        if refused:
            cap = (
                "calls"
                if caps.max_calls is not None and task.calls >= caps.max_calls
                else "cost"
            )
            TASK_LIMIT_REFUSALS_TOTAL.labels(cap=cap).inc()
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "TASK_LIMIT_EXCEEDED",
                    "message": (
                        f"This task reached its limit of {caps.max_calls} calls"
                        if cap == "calls"
                        else f"This task reached its cost limit of {caps.max_cost_usd} USD"
                    )
                    + f" within {caps.window_seconds} seconds.",
                },
                headers={"x-should-retry": "false"},
            )
        return task.calls

    def trace_metadata(self, output: PreparedInference) -> Mapping[str, TraceValue]:
        assert output.admission is not None
        return {
            "estimated_input_tokens": output.admission.estimated_input_tokens,
            "maximum_output_tokens": output.admission.maximum_output_tokens,
            "repeat_status": self.loop_result.status.casefold(),
            "repeat_chain_length": self.loop_result.chain_length,
        }


def _check_catalog_limits(
    value: PreparedInference,
    media: Sequence[MediaPart],
    *,
    input_bytes: int,
    approximate_tokens: int,
    requested_output: int,
) -> None:
    payload = value.payload
    if value.target is None:
        # A dated snapshot may differ from its base entry, so only its own entry counts.
        entry = DEFAULT_PRICE_BOOK.exact(value.pricing_model, str(value.provider))
        if entry is None:
            return
        if entry.status == "deprecated":
            value.warn("MODEL_DEPRECATED")
        missing = _missing_capability(payload, entry, media)
        if missing is not None:
            _refuse(
                value,
                "admission.capability",
                "MODEL_CAPABILITY_UNSUPPORTED",
                f"The model does not support {missing}.",
            )
        window, input_limit = entry.context_window, entry.input_limit
        # Gemini's output limit is separate; Claude 4.5 and later accept input plus
        # max_tokens above the window and stop at it.
        output = requested_output if value.provider == "openai" else 0
    else:
        # A deployment's own window, else its price model's: never the upstream name's.
        entry = (
            DEFAULT_PRICE_BOOK.exact(value.target.price_model, str(value.provider))
            if value.target.price_model and not value.target.context_window
            else None
        )
        window = value.target.context_window or (
            entry.context_window if entry is not None else None
        )
        input_limit = entry.input_limit if entry is not None else None
        output = requested_output
    if window is None:
        return
    limit = min(input_limit or window, window - output)
    # A word takes at least two bytes, so a small request skips the count.
    if input_bytes // 2 > limit and not _overflow_is_managed(payload):
        words = _lower_bound_input(payload)
        if words > limit:
            _refuse(
                value,
                "admission.context",
                "MODEL_CONTEXT_EXCEEDED",
                f"The input is at least {words} tokens; with a context window of "
                f"{window} tokens the model accepts at most {limit} input tokens"
                + (f" when {output} output tokens are requested." if output else "."),
            )
    if approximate_tokens + output > window:
        value.warn("CONTEXT_MAY_EXCEED")


def micro_usd(amount: Decimal | None) -> int | None:
    return (
        None
        if amount is None
        else int((amount * 1_000_000).to_integral_value(ROUND_CEILING))
    )


def _arguments(value: object) -> object:
    """Chat and Responses send arguments as a JSON string; parsed when valid.

    Nesting too deep to parse is hashed as the text it is.
    """
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, RecursionError):
            return value
    return value


def _turn_calls(
    turn: Mapping[str, object], protocol: str
) -> list[tuple[object, object]]:
    """The tool calls of one assistant (or model) turn."""
    if protocol == "chat":
        return [
            (
                call["function"].get("name"),
                _arguments(call["function"].get("arguments")),
            )
            for call in _listed(turn.get("tool_calls"))
            if isinstance(call, Mapping) and isinstance(call.get("function"), Mapping)
        ]
    if protocol == "generate_content":
        return [
            (part["functionCall"].get("name"), part["functionCall"].get("args"))
            for part in _listed(turn.get("parts"))
            if isinstance(part, Mapping)
            and isinstance(part.get("functionCall"), Mapping)
        ]
    return [
        (block.get("name"), block.get("input"))
        for block in _listed(turn.get("content"))
        if isinstance(block, Mapping) and block.get("type") == "tool_use"
    ]


def _tool_signature(payload: Mapping[str, object], protocol: str) -> str | None:
    """A digest of the latest assistant turn's tool calls: names and canonical arguments.

    Read from the end, so a long history costs one turn; a latest turn without
    calls has no signature.
    """
    calls: list[tuple[object, object]] = []
    if protocol == "responses":
        # Calls of one turn sit next to each other; anything else ends the turn,
        # and an assistant message after them is a later turn.
        for item in reversed(_listed(payload.get("input"))):
            if isinstance(item, Mapping) and item.get("type") == "function_call":
                calls.append((item.get("name"), _arguments(item.get("arguments"))))
            elif calls or (
                isinstance(item, Mapping) and item.get("role") == "assistant"
            ):
                break
        calls.reverse()
    else:
        turns = payload.get(
            "contents" if protocol == "generate_content" else "messages"
        )
        role = "model" if protocol == "generate_content" else "assistant"
        for turn in reversed(_listed(turns)):
            if isinstance(turn, Mapping) and turn.get("role") == role:
                calls = _turn_calls(turn, protocol)
                break
    if not calls:
        return None
    canonical = json.dumps(
        [protocol, calls], sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _task_key(task_id: str) -> str:
    """Counters hold a digest, never the task id itself."""
    return hashlib.sha256(task_id.encode()).hexdigest()


def _listed(value: object) -> list:
    return value if isinstance(value, list) else []


def _task_identity(headers: Mapping[str, str]) -> tuple[str | None, str | None]:
    """X-Shim-Task-Id when it is one, else the incoming W3C trace id; and that trace id."""

    trace_id = None
    if "traceparent" in headers:
        context = trace.get_current_span(
            TraceContextTextMapPropagator().extract(
                {"traceparent": headers["traceparent"]}
            )
        ).get_span_context()
        trace_id = format(context.trace_id, "032x") if context.is_valid else None
    task_id = (headers.get("x-shim-task-id") or "").strip()
    # Ten digits or more alone are shaped like a national id or a phone number.
    if task_id and (
        not _TASK_ID.fullmatch(task_id) or (task_id.isdigit() and len(task_id) >= 10)
    ):
        TASK_ID_REJECTED_TOTAL.inc()
        task_id = ""
    return task_id or trace_id, trace_id


def _request_limits(
    value: PreparedInference,
    tags: tuple[str, ...],
    *,
    input_bytes: int,
    approximate_tokens: int,
) -> bool:
    """The price-tier warning and the request-limit rules in scope; True when a rule ran.

    An enforced block refuses here, before the rate limits. A request that only may cross
    the price tier is warned, never refused.
    """

    rules = [
        rule
        for rule in (value.rules.rules if value.rules is not None else ())
        if rule.kind == "request_limit" and in_scope(rule, value, tags)
    ]
    entry = (
        DEFAULT_PRICE_BOOK.exact(value.pricing_model, str(value.provider))
        if value.target is None
        and (
            value.price_tier_warning
            or any(rule.match["below_price_tier"] for rule in rules)
        )
        else None
    )
    threshold = entry.large_context_threshold if entry is not None else None
    if threshold is not None and value.price_tier_warning:
        if approximate_tokens > threshold:
            value.warn("PRICE_TIER_CROSSED")
    if not rules:
        return False
    tools, documents, history = request_measures(value.payload, value.protocol)
    # A word takes at least two bytes, so a small request skips the count.
    words = (
        _lower_bound_input(value.payload)
        if threshold is not None and input_bytes // 2 > threshold
        else 0
    )
    for rule in rules:
        caps = rule.match
        over = any(
            cap is not None and measure > cap
            for cap, measure in (
                (caps["max_tools"], tools),
                (caps["max_documents"], documents),
                (caps["max_history"], history),
                (caps["max_input_bytes"], input_bytes),
            )
        )
        tiered = caps["below_price_tier"] and threshold is not None
        if over or (tiered and words > threshold):
            value.record_rule_match(rule, 1)
        elif tiered and approximate_tokens > threshold:
            value.record_rule_match(rule.model_copy(update={"action": "warn"}), 1)
    if any(
        (match.kind, match.state, match.action)
        == ("request_limit", "enforced", "block")
        for match in value.rule_matches
    ):
        blocked, _ = settle_matches(value)
        raise rule_blocked(blocked[0])
    return True


def rule_blocked(rule_id: str) -> HTTPException:
    """The refusal of a request an enforced tenant rule blocks."""
    return HTTPException(
        status_code=400,
        detail={
            "code": "RULE_BLOCKED",
            "message": f"Request blocked by tenant rule {rule_id}.",
            "param": rule_id,
        },
        headers={"X-Shim-Rule-Id": rule_id},
    )


def _overflow_is_managed(payload: Mapping[str, object]) -> bool:
    """The provider truncates or compacts the context itself, so overflow is not certain."""

    return (
        payload.get("truncation") == "auto"
        or "context_management" in payload
        or "compaction" in payload
        or any(_has_compaction(payload.get(field)) for field in ("messages", "input"))
    )


def _has_compaction(value: object) -> bool:
    if isinstance(value, list):
        return any(_has_compaction(item) for item in value)
    if isinstance(value, Mapping):
        return value.get("type") == "compaction" or any(
            _has_compaction(item) for item in value.values()
        )
    return False


def _refuse(value: PreparedInference, rule_id: str, code: str, message: str) -> None:
    value.record_verdict(
        rule_id,
        stage="admission",
        outcome="deny",
        reason_code=code,
        policy_version=DEFAULT_PRICE_BOOK.version,
    )
    raise HTTPException(status_code=400, detail={"code": code, "message": message})


def _missing_capability(
    payload: Mapping[str, object], entry: ModelPrice, media: Sequence[MediaPart]
) -> str | None:
    if entry.tools is False and payload.get("tools"):
        return "tools"
    response_format = payload.get("response_format")
    text = payload.get("text")
    text_format = text.get("format") if isinstance(text, Mapping) else None
    generation_config = payload.get("generationConfig")
    structured = (
        (
            isinstance(response_format, Mapping)
            and response_format.get("type") == "json_schema"
        )
        or (
            isinstance(text_format, Mapping)
            and text_format.get("type") == "json_schema"
        )
        or (
            isinstance(generation_config, Mapping)
            and any(
                generation_config.get(key) is not None
                for key in ("responseSchema", "responseJsonSchema")
            )
        )
    )
    if entry.structured_output is False and structured:
        return "structured_output"
    if entry.input_modalities is not None:
        missing = {
            part.kind
            for part in media
            if part.kind in _CATALOG_MODALITIES
            and part.path
            and part.path[0] in _PROMPT_FIELDS
            and not _openai_file(value_at(payload, part.path))
        } - set(entry.input_modalities)
        if missing:
            return min(missing)
    return None


def _openai_file(part: Mapping[str, object]) -> bool:
    # It need not be a PDF, and the catalog's OpenAI pdf flag is unreliable.
    return part.get("type") == "input_file" or (
        part.get("type") == "file" and "file" in part
    )


async def _sized_by_parts(
    value: PreparedInference, media: Sequence[MediaPart], input_bytes: int
) -> tuple[int, int]:
    """The reservation bound and the rate amount of a request whose media is forwarded:
    its text by bytes, each part by the tokens a provider reads it as."""
    text_bytes, tokens = input_bytes, 0
    for part in media:
        data = value_at(value.payload, part.data_path) if part.data_path else None
        pages = (
            await asyncio.to_thread(pdf_page_count, data)
            if part.kind == "pdf" and data is not None
            else None
        )
        detail = (
            image_detail(value.protocol, value_at(value.payload, part.path))
            if part.kind == "image"
            else None
        )
        part_tokens = media_tokens(
            part,
            pages,
            provider=str(value.provider),
            model=value.pricing_model,
            detail=detail if isinstance(detail, str) else None,
        )
        if part_tokens is None:
            continue
        tokens += part_tokens
        if data is not None:
            # Base64 and data URLs are ASCII with nothing JSON escapes.
            text_bytes -= len(data)
    window = _context_window(value)
    if window is not None:
        tokens = min(tokens, window)
    return text_bytes + tokens, -(-text_bytes // 4) + tokens


def _context_window(value: PreparedInference) -> int | None:
    target = value.target
    if target is not None and target.context_window:
        return target.context_window
    entry = (
        DEFAULT_PRICE_BOOK.exact(value.pricing_model, str(value.provider))
        if target is None
        else DEFAULT_PRICE_BOOK.exact(target.price_model, str(value.provider))
        if target.price_model
        else None
    )
    return entry.context_window if entry is not None else None


def _lower_bound_input(payload: Mapping[str, object]) -> int:
    def words(value: object) -> int:
        if isinstance(value, str):
            return len(_WORD.findall(value))
        if isinstance(value, list):
            return sum(words(item) for item in value)
        if isinstance(value, Mapping):
            if value.get("type") in _UNCOUNTED_BLOCKS:
                return 0
            return sum(
                words(item)
                for key, item in value.items()
                if key != "cache_control" and not is_protocol_field(key)
            )
        return 0

    return sum(words(payload.get(field)) for field in _PROMPT_FIELDS)


def _estimate_input_tokens(
    payload: Mapping[str, object], identity: str
) -> tuple[int, str, str]:
    """The byte bound, the request digest (SHA-256 over the identity and those
    bytes) and the compact JSON they were taken from.

    Keys hash in the order the client sent them, so a reordered body is another request.
    """
    serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    try:
        encoded = serialized.encode("utf-8")
    except UnicodeEncodeError:
        # A lone surrogate ("\ud800" in the JSON) is no text: refused before privacy
        # could miss it, never rewritten into something the provider would get.
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_REQUEST",
                "message": "The request contains an unpaired UTF-16 surrogate.",
            },
        ) from None
    # One token per UTF-8 byte bounds tokenizer-hostile provider payloads.
    return (
        max(1, len(encoded)),
        hashlib.sha256(identity.encode() + b"\n" + encoded).hexdigest(),
        serialized,
    )


def _shareable(value: PreparedInference, candidates: int) -> bool:
    """One JSON answer that another identical request of the key may receive as is."""
    if not value.inflight_sharing or value.stream or candidates != 1:
        return False
    if value.protocol == "generate_content":
        config = value.payload.get("generationConfig")
        temperature = config.get("temperature") if isinstance(config, Mapping) else None
    elif value.protocol in {"chat", "messages"}:
        temperature = value.payload.get("temperature")
    else:
        # Responses carries provider-side conversation state; a count is no answer.
        return False
    return not (
        isinstance(temperature, int | float)
        and not isinstance(temperature, bool)
        and temperature > 0
    )


def candidate_count(prepared: PreparedInference) -> int:
    if prepared.provider == "google":
        config = prepared.payload.get("generationConfig")
        candidate = (
            config.get("candidateCount", 1) if isinstance(config, Mapping) else 1
        )
    elif prepared.provider == "openai" and prepared.protocol == "chat":
        candidate = prepared.payload.get("n", 1)
    else:
        candidate = 1
    count = (
        candidate
        if isinstance(candidate, int) and not isinstance(candidate, bool)
        else 1
    )
    if count < 1 or count > _MAX_CANDIDATES:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_REQUEST",
                "message": f"Candidate count must be between 1 and {_MAX_CANDIDATES}.",
            },
        )
    return count


def _repeat_material(payload: Mapping[str, object]) -> str:
    """Hash only prompt-bearing fields so client metadata cannot mask a repeat."""
    material = {
        key: payload[key]
        for key in (
            "contents",
            "input",
            "instructions",
            "messages",
            "model",
            "protocol",
            "provider",
            "system",
            "systemInstruction",
        )
        if key in payload
    }
    normalized = unicodedata.normalize(
        "NFKC",
        json.dumps(material, sort_keys=True, separators=(",", ":")),
    )
    return _WHITESPACE.sub(" ", normalized.strip())
