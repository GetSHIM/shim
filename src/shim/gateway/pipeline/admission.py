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
from shim.billing.pricing import DEFAULT_PRICE_BOOK, ModelPrice
from shim.core.middleware import AsyncRateLimiter
from shim.gateway.admission import LoopDetectionResult, LoopDetector

from shim.gateway.kernel.result import (
    AdmissionState,
    PreparedInference,
    UNSPECIFIED_PROVIDER_MODEL,
)
from shim.gateway.kernel.stage import TraceValue
from shim.gateway.pipeline.privacy import _is_protocol_field

if TYPE_CHECKING:
    from shim.gateway.pipeline.authenticate import GatewayInvocation
    from shim.gateway.usage import UsageLifecycle


_WHITESPACE = re.compile(r"\s+")
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
# OpenAI file parts are absent: they need not be PDFs, and the catalog's OpenAI pdf flag is unreliable.
_MEDIA_PART_TYPES = {
    "image": "image",
    "image_url": "image",
    "input_image": "image",
    "input_audio": "audio",
    "document": "pdf",
}
_MEDIA_MIME_TYPES = (
    ("image/", "image"),
    ("audio/", "audio"),
    ("application/pdf", "pdf"),
)
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
        # The byte count stays the reservation bound; the rate unit is four bytes a token.
        approximate_tokens = -(-input_tokens // 4)
        if value.protocol != "count_tokens" and (
            value.target is None or value.target.context_window
        ):
            _check_catalog_limits(
                value,
                input_bytes=input_tokens,
                approximate_tokens=approximate_tokens,
                requested_output=0
                if output_token_field == "provider_default"
                else per_candidate_output_tokens,
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
                headers={"Retry-After": str(self.loop_window_seconds)},
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


def _check_catalog_limits(
    value: PreparedInference,
    *,
    input_bytes: int,
    approximate_tokens: int,
    requested_output: int,
) -> None:
    payload = value.payload
    if value.target is None:
        # A prefix match describes another model, so only the model's own entry counts.
        entry = DEFAULT_PRICE_BOOK.exact(value.pricing_model, str(value.provider))
        if entry is None:
            return
        if entry.status == "deprecated":
            value.warn("MODEL_DEPRECATED")
        missing = _missing_capability(payload, entry)
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
        # A deployment is checked against its own window only, never the catalog.
        window, input_limit = value.target.context_window, None
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


def _missing_capability(payload: Mapping[str, object], entry: ModelPrice) -> str | None:
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
        missing = _input_media([payload.get(field) for field in _PROMPT_FIELDS]) - set(
            entry.input_modalities
        )
        if missing:
            return min(missing)
    return None


def _input_media(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, list):
        for item in value:
            found |= _input_media(item)
    elif isinstance(value, Mapping):
        part_type = value.get("type")
        source = value.get("source")
        if (
            isinstance(part_type, str)
            and part_type in _MEDIA_PART_TYPES
            and not (
                part_type == "document"
                and isinstance(source, Mapping)
                and source.get("type") in {"text", "content"}
            )
        ):
            found.add(_MEDIA_PART_TYPES[part_type])
        for key in ("inlineData", "inline_data", "fileData", "file_data"):
            blob = value.get(key)
            mime = (
                blob.get("mimeType", blob.get("mime_type"))
                if isinstance(blob, Mapping)
                else None
            )
            if isinstance(mime, str):
                found |= {
                    modality
                    for prefix, modality in _MEDIA_MIME_TYPES
                    if mime.startswith(prefix)
                }
        for item in value.values():
            found |= _input_media(item)
    return found


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
                if key != "cache_control" and not _is_protocol_field(key)
            )
        return 0

    return sum(words(payload.get(field)) for field in _PROMPT_FIELDS)


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
