"""Best-effort admission before authoritative usage reservation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
import json
import re
from typing import TYPE_CHECKING
import unicodedata

from fastapi import HTTPException

from shim.billing.attribution import CostAttribution
from shim.billing.pricing import DEFAULT_PRICE_BOOK
from shim.core.middleware import AsyncRateLimiter
from shim.gateway.admission import LoopDetectionResult, LoopDetector

from shim.gateway.kernel.result import (
    AdmissionState,
    PreparedInference,
    UNSPECIFIED_PROVIDER_MODEL,
)
from shim.gateway.kernel.stage import TraceValue

if TYPE_CHECKING:
    from shim.gateway.pipeline.authenticate import GatewayInvocation
    from shim.gateway.usage import UsageLifecycle


_WHITESPACE = re.compile(r"\s+")
_MAX_CANDIDATES = 10_000


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
        self.loop_result = LoopDetectionResult("SAFE", 0)
        self.reserved = False

    async def run(self, value: PreparedInference) -> PreparedInference:
        unspecified_openai_response_model = (
            value.provider == "openai"
            and value.protocol == "responses"
            and value.model == UNSPECIFIED_PROVIDER_MODEL
        )
        model_denied = (
            value.target is None
            and not unspecified_openai_response_model
            and not DEFAULT_PRICE_BOOK.supports(value.model, str(value.provider))
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
        if value.protocol == "count_tokens":
            per_candidate_output_tokens = 0
        minimum_output_tokens = (
            0
            if value.protocol == "count_tokens"
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
        input_tokens = _estimate_input_tokens(payload)
        output_tokens = per_candidate_output_tokens * candidate_count(value)
        tier = value.context.tier_policy
        key_hash = value.policy.rate_limit_key_hash
        for dimension, limit, key, amount in (
            ("requests", tier.rate_limit_rpm, key_hash, 1),
            ("tokens", tier.rate_limit_tpm, f"tpm:{key_hash}", input_tokens),
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
                policy={"limit": limit, "window_seconds": 60},
            )
            if denied:
                raise HTTPException(
                    status_code=429,
                    detail={"code": "RATE_LIMIT_EXCEEDED", "dimension": dimension},
                )
        repeat_material = _repeat_material(
            {
                **payload,
                "model": value.model,
                "provider": str(value.provider),
                "protocol": value.protocol,
            }
        )
        self.loop_result = await self.loop_detector.check_exact_repeat(
            str(value.tenant_id),
            repeat_material,
            limit=self.loop_repeat_limit,
            window_seconds=self.loop_window_seconds,
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
            )
        attribution = CostAttribution.resolve(
            self.invocation.headers.get("x-shim-tag"),
            api_key_cost_center=value.policy.cost_center,
            maximum_length=self.cost_tag_max_length,
        )
        admission = AdmissionState(
            estimated_input_tokens=input_tokens,
            maximum_output_tokens=output_tokens,
            cost_center=attribution.cost_center,
            tags=attribution.tags,
            repeat_chain_length=self.loop_result.chain_length or None,
        )
        if value.protocol != "count_tokens":
            await self.usage.admit(value, admission)
            self.reserved = True
        return replace(value, admission=admission)

    def trace_metadata(self, output: PreparedInference) -> Mapping[str, TraceValue]:
        assert output.admission is not None
        return {
            "estimated_input_tokens": output.admission.estimated_input_tokens,
            "maximum_output_tokens": output.admission.maximum_output_tokens,
            "repeat_status": self.loop_result.status.casefold(),
            "repeat_chain_length": self.loop_result.chain_length,
        }


def _estimate_input_tokens(payload: Mapping[str, object]) -> int:
    serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    # One token per UTF-8 byte bounds tokenizer-hostile provider payloads.
    return max(1, len(serialized.encode("utf-8", errors="backslashreplace")))


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
    """Build a stable, prompt-only identity without trusted request metadata."""

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
