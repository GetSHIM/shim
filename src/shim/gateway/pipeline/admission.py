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
        if not unspecified_openai_response_model and not DEFAULT_PRICE_BOOK.supports(
            value.model, str(value.provider)
        ):
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
            value.model,
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
        minimum_output_tokens = (
            0
            if value.provider == "anthropic"
            and value.protocol == "messages"
            and output_token_field == "max_tokens"
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
        candidate_count = _candidate_count(payload)
        output_tokens = per_candidate_output_tokens * candidate_count
        tier = value.context.tier_policy
        key_hash = value.policy.rate_limit_key_hash
        if tier.rate_limit_rpm is not None and not await self.rate_limiter.allow(
            key_hash,
            limit=tier.rate_limit_rpm,
            window_seconds=60,
        ):
            raise HTTPException(
                status_code=429,
                detail={"code": "RATE_LIMIT_EXCEEDED", "dimension": "requests"},
            )
        if tier.rate_limit_tpm is not None and not await self.rate_limiter.allow(
            f"tpm:{key_hash}",
            limit=tier.rate_limit_tpm,
            window_seconds=60,
            amount=input_tokens,
        ):
            raise HTTPException(
                status_code=429,
                detail={"code": "RATE_LIMIT_EXCEEDED", "dimension": "tokens"},
            )
        repeat_material = _repeat_material(
            {
                **payload,
                "model": value.model,
                "provider": str(value.provider),
            }
        )
        self.loop_result = await self.loop_detector.check_exact_repeat(
            str(value.tenant_id),
            repeat_material,
            limit=self.loop_repeat_limit,
            window_seconds=self.loop_window_seconds,
        )
        if self.loop_result.status == "BLOCKED":
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
        )
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


def _candidate_count(payload: Mapping[str, object]) -> int:
    generation_config = payload.get("generationConfig")
    candidate = (
        generation_config.get("candidateCount")
        if isinstance(generation_config, Mapping)
        else payload.get("n", 1)
    )
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
