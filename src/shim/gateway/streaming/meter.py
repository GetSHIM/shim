"""Provider-aware usage metering for native streamed responses."""

from __future__ import annotations

import json
import hashlib
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from time import perf_counter
from typing import Any, Literal

from shim.billing.pricing import (
    DEFAULT_PRICE_BOOK,
    UNSPECIFIED_PROVIDER_MODEL,
    compute_cost_usd,
)
from shim.gateway.streaming.sse import data_payload, pop_event


StreamTerminalHint = Literal[
    "completed",
    "provider_error",
    "timeout",
    "cancelled",
    "internal_error",
]

_TEXT_RESPONSE_DELTA_TYPES = (
    "audio.transcript",
    "code_interpreter_call_code",
    "custom_tool_call_input",
    "function_call_arguments",
    "mcp_call_arguments",
    "output_text",
    "reasoning",
    "refusal",
)


@dataclass(frozen=True, slots=True)
class StreamUsageSnapshot:
    """Final usage values used by the one durable terminal transition."""

    prompt_tokens: int
    completion_tokens: int
    settlement_cost_usd: Decimal
    provider_model: str
    pricing_metadata: dict[str, str | int]
    estimated: bool
    output_hash: str | None
    provider_finish_reasons: dict[str, str] | None = None
    ttft_ms: float | None = None


class StreamMeter:
    """Capture provider usage and estimate output from emitted deltas.

    Provider-reported counts remain authoritative when present. If either side
    is missing, settlement deterministically falls back to the request's prompt
    estimate and approximately one token per four emitted output characters.
    """

    def __init__(
        self,
        *,
        provider: str,
        requested_model: str,
        prompt_tokens_estimated: int,
        expected_candidates: int = 1,
        output_hash_salt: str | None = None,
        started_at_monotonic: float | None = None,
        monotonic_clock: Callable[[], float] = perf_counter,
    ) -> None:
        if prompt_tokens_estimated < 0:
            raise ValueError("stream token estimates must be nonnegative")
        if expected_candidates < 1:
            raise ValueError("expected stream candidates must be positive")
        self.provider = provider
        self.requested_model = requested_model
        self.prompt_tokens_estimated = prompt_tokens_estimated
        self.expected_candidates = expected_candidates
        self.prompt_tokens_actual: int | None = None
        self.completion_tokens_actual: int | None = None
        self.response_model: str | None = None
        self.emitted_output_characters = 0
        self.terminal_hint: StreamTerminalHint | None = None
        self.provider_finish_reasons: dict[str, str] = {}
        self.started_at_monotonic = started_at_monotonic
        self._monotonic_clock = monotonic_clock
        self.ttft_ms: float | None = None
        self._finished_candidates: set[int] = set()
        self._sse_buffer = b""
        self._output_hasher = hashlib.sha256() if output_hash_salt is not None else None
        if self._output_hasher is not None:
            assert output_hash_salt is not None
            self._output_hasher.update(output_hash_salt.encode("utf-8"))
            self._output_hasher.update(b"\x1f")
        self._emitted_wire_bytes = 0

    def observe_sse(self, chunk: bytes) -> None:
        """Observe arbitrary chunk boundaries without mutating wire bytes."""

        self._sse_buffer += chunk
        while True:
            event, remainder = pop_event(self._sse_buffer)
            if event is None:
                break
            self._sse_buffer = remainder
            self._observe_sse_event(event.decode("utf-8", errors="replace"))

    def finish(self) -> None:
        """Meter a final unterminated SSE fragment, if the provider emitted one."""

        if not self._sse_buffer:
            return
        event = self._sse_buffer
        self._sse_buffer = b""
        self._observe_sse_event(event.decode("utf-8", errors="replace"))

    def observe_emitted_output(self, chunk: bytes) -> None:
        """Hash final client-visible bytes without buffering streamed content."""

        if self._output_hasher is None:
            return
        self._output_hasher.update(chunk)
        self._emitted_wire_bytes += len(chunk)

    def snapshot(self) -> StreamUsageSnapshot:
        """Return immutable actual-or-estimated usage for final settlement."""

        completion_estimate = self._estimated_completion_tokens()
        prompt = (
            self.prompt_tokens_estimated
            if self.prompt_tokens_actual is None
            else self.prompt_tokens_actual
        )
        completion = (
            completion_estimate
            if self.completion_tokens_actual is None
            else self.completion_tokens_actual
        )
        estimated = (
            self.prompt_tokens_actual is None or self.completion_tokens_actual is None
        )
        settlement_model = (
            self.response_model
            if self.requested_model == UNSPECIFIED_PROVIDER_MODEL
            and self.terminal_hint == "completed"
            and self.response_model is not None
            and DEFAULT_PRICE_BOOK.supports(self.response_model, self.provider)
            else self.requested_model
        )
        settlement_cost = compute_cost_usd(
            settlement_model,
            prompt,
            completion,
            provider=self.provider,
        )
        return StreamUsageSnapshot(
            prompt_tokens=prompt,
            completion_tokens=completion,
            settlement_cost_usd=settlement_cost,
            provider_model=settlement_model,
            pricing_metadata=DEFAULT_PRICE_BOOK.resolved_price_metadata(
                settlement_model,
                self.provider,
                input_tokens=prompt,
                output_tokens=completion,
            ),
            estimated=estimated,
            output_hash=(
                self._output_hasher.hexdigest()
                if self._output_hasher is not None and self._emitted_wire_bytes > 0
                else None
            ),
            provider_finish_reasons=dict(self.provider_finish_reasons) or None,
            ttft_ms=self.ttft_ms,
        )

    def _observe_sse_event(self, event_text: str) -> None:
        event_name: str | None = None
        data_lines: list[str] = []
        for raw_line in event_text.split("\n"):
            line = raw_line.strip()
            if line.startswith("event:"):
                event_name = line[6:].strip()
            else:
                data = data_payload(line)
                if data is not None:
                    data_lines.append(data)
        if not data_lines:
            return
        data = "\n".join(data_lines)
        if data == "[DONE]":
            self._set_terminal_hint("completed")
            return
        try:
            payload = json.loads(data)
        except json.JSONDecodeError:
            return
        if not isinstance(payload, dict):
            return

        payload_type = str(payload.get("type") or event_name or "")
        self._capture_terminal_hint(payload_type, payload)
        self._capture_response_model(payload)
        self._capture_usage(payload)
        self.provider_finish_reasons.update(
            native_finish_reasons(payload, provider=self.provider) or {}
        )
        output_characters = self._output_delta_characters(
            payload_type,
            payload,
        )
        self.emitted_output_characters += output_characters
        if (
            self.ttft_ms is None
            and self.started_at_monotonic is not None
            and (
                output_characters > 0
                or _initial_or_media_content(payload_type, payload)
            )
        ):
            self.ttft_ms = max(
                0.0, (self._monotonic_clock() - self.started_at_monotonic) * 1_000
            )

    def _capture_response_model(self, payload: dict[str, Any]) -> None:
        candidates = [payload]
        candidates.extend(
            value
            for value in (payload.get("response"), payload.get("message"))
            if isinstance(value, dict)
        )
        for candidate in candidates:
            model = candidate.get("model")
            if isinstance(model, str):
                self.response_model = model
                return

    def _capture_terminal_hint(self, event_type: str, payload: dict[str, Any]) -> None:
        lowered = event_type.lower()
        if payload.get("code") == "PRIVACY_STATE_UNAVAILABLE":
            self._set_terminal_hint("internal_error")
            return
        error = payload.get("error")
        error_fields = error if isinstance(error, dict) else {}
        codes = {
            str(payload.get("code", "")).casefold(),
            str(error_fields.get("code", "")).casefold(),
            str(error_fields.get("type", "")).casefold(),
            str(error_fields.get("status", "")).casefold(),
        }
        if (
            codes
            & {"provider_timeout", "timeout", "timeout_error", "deadline_exceeded"}
            or "timeout" in lowered
        ):
            self._set_terminal_hint("timeout")
            return
        if "cancel" in lowered:
            self._set_terminal_hint("cancelled")
            return
        if lowered in {
            "error",
            "message_failed",
            "message_incomplete",
            "response.failed",
        } or isinstance(payload.get("error"), dict):
            if codes & {"cancelled", "canceled", "stream_cancelled"}:
                self._set_terminal_hint("cancelled")
            else:
                self._set_terminal_hint("provider_error")
            return

        prompt_feedback = payload.get("promptFeedback")
        if (
            self.provider == "google"
            and isinstance(prompt_feedback, dict)
            and prompt_feedback.get("blockReason")
        ):
            self._set_terminal_hint("provider_error")
            return

        if self.provider == "anthropic" and lowered == "message_stop":
            self._set_terminal_hint("completed")
        elif self.provider == "google" and (
            payload.get("done") is True or self._all_google_candidates_finished(payload)
        ):
            self._set_terminal_hint("completed")
        elif lowered in {"response.completed", "response.incomplete"}:
            self._set_terminal_hint("completed")

    def _capture_usage(self, payload: dict[str, Any]) -> None:
        candidates: list[Any] = [payload.get("usage")]
        response = payload.get("response")
        if isinstance(response, dict):
            candidates.append(response.get("usage"))
        message = payload.get("message")
        if isinstance(message, dict):
            candidates.append(message.get("usage"))
        candidates.append(payload.get("usageMetadata"))
        for usage in candidates:
            if not isinstance(usage, dict):
                continue
            prompt = self._first_token_count(
                usage,
                "prompt_tokens",
                "input_tokens",
                "promptTokenCount",
            )
            completion = self._first_token_count(
                usage,
                "completion_tokens",
                "output_tokens",
                "candidatesTokenCount",
            )
            if self.provider == "anthropic" and payload.get("type") == "message_start":
                completion = None
            total = self._first_token_count(
                usage,
                "total_tokens",
                "totalTokenCount",
            )
            if self.provider == "anthropic":
                prompt = _sum_optional_counts(
                    prompt,
                    self._first_token_count(
                        usage,
                        "cache_creation_input_tokens",
                    ),
                    self._first_token_count(
                        usage,
                        "cache_read_input_tokens",
                    ),
                )
            elif self.provider == "google":
                prompt = _sum_optional_counts(
                    prompt,
                    self._first_token_count(usage, "toolUsePromptTokenCount"),
                )
                completion = _sum_optional_counts(
                    completion,
                    self._first_token_count(usage, "thoughtsTokenCount"),
                )
            if prompt is None and completion is not None and total is not None:
                prompt = total - completion if total >= completion else None
            if completion is None and prompt is not None and total is not None:
                completion = total - prompt if total >= prompt else None
            if prompt is not None:
                self.prompt_tokens_actual = prompt
            if completion is not None:
                self.completion_tokens_actual = completion

    @staticmethod
    def _output_delta_characters(
        event_type: str,
        payload: dict[str, Any],
    ) -> int:
        fragments: list[str] = []
        choices = payload.get("choices")
        if isinstance(choices, list):
            for choice in choices:
                if not isinstance(choice, dict):
                    continue
                delta = choice.get("delta")
                if not isinstance(delta, dict):
                    continue
                for field in ("content", "refusal"):
                    content = delta.get(field)
                    if isinstance(content, str):
                        fragments.append(content)
                function_call = delta.get("function_call")
                if isinstance(function_call, dict) and isinstance(
                    function_call.get("arguments"), str
                ):
                    fragments.append(function_call["arguments"])
                tool_calls = delta.get("tool_calls")
                if isinstance(tool_calls, list):
                    for call in tool_calls:
                        if not isinstance(call, dict):
                            continue
                        function = call.get("function")
                        if isinstance(function, dict) and isinstance(
                            function.get("arguments"), str
                        ):
                            fragments.append(function["arguments"])

        delta = payload.get("delta")
        if isinstance(delta, str) and any(
            delta_type in event_type for delta_type in _TEXT_RESPONSE_DELTA_TYPES
        ):
            fragments.append(delta)
        elif isinstance(delta, dict):
            for key in ("text", "partial_json", "arguments", "thinking", "content"):
                value = delta.get(key)
                if isinstance(value, str):
                    fragments.append(value)

        candidates = payload.get("candidates")
        if isinstance(candidates, list):
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    continue
                content = candidate.get("content")
                if not isinstance(content, dict):
                    continue
                parts = content.get("parts")
                if not isinstance(parts, list):
                    continue
                for part in parts:
                    fragments.extend(_google_content_strings(part))
        return sum(len(fragment) for fragment in fragments)

    def _all_google_candidates_finished(self, payload: dict[str, Any]) -> bool:
        candidates = payload.get("candidates")
        if not isinstance(candidates, list):
            return False
        for position, candidate in enumerate(candidates):
            if not isinstance(candidate, dict) or not candidate.get("finishReason"):
                continue
            index = candidate.get("index", position)
            if isinstance(index, int) and not isinstance(index, bool):
                self._finished_candidates.add(index)
        return len(self._finished_candidates) >= self.expected_candidates

    def _estimated_completion_tokens(self) -> int:
        if self.emitted_output_characters <= 0:
            return 0
        return max(1, math.ceil(self.emitted_output_characters / 4))

    def _set_terminal_hint(self, hint: StreamTerminalHint) -> None:
        priority = {
            "completed": 0,
            "cancelled": 1,
            "provider_error": 2,
            "timeout": 3,
            "internal_error": 4,
        }
        if self.terminal_hint is None or priority[hint] > priority[self.terminal_hint]:
            self.terminal_hint = hint

    @classmethod
    def _first_token_count(
        cls,
        values: dict[str, Any],
        *keys: str,
    ) -> int | None:
        for key in keys:
            parsed = cls._nonnegative_int(values.get(key))
            if parsed is not None:
                return parsed
        return None

    @staticmethod
    def _nonnegative_int(value: Any) -> int | None:
        return (
            value
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            else None
        )


def _sum_optional_counts(*values: int | None) -> int | None:
    present = [value for value in values if value is not None]
    return sum(present) if present else None


def _initial_or_media_content(event_type: str, payload: Mapping[str, Any]) -> bool:
    """Recognize content readiness without treating opaque media as text tokens."""

    if event_type == "content_block_start":
        block = payload.get("content_block")
        if isinstance(block, Mapping) and any(
            isinstance(block.get(field), str) and block[field]
            for field in ("text", "thinking")
        ):
            return True
    field = {
        "response.audio.delta": "delta",
        "response.image_generation_call.partial_image": "partial_image_b64",
    }.get(event_type)
    if field is not None and isinstance(payload.get(field), str) and payload[field]:
        return True
    choices = payload.get("choices")
    if isinstance(choices, list):
        for choice in choices:
            delta = choice.get("delta") if isinstance(choice, Mapping) else None
            audio = delta.get("audio") if isinstance(delta, Mapping) else None
            if (
                isinstance(audio, Mapping)
                and isinstance(audio.get("data"), str)
                and audio["data"]
            ):
                return True
    candidates = payload.get("candidates")
    if isinstance(candidates, list):
        for candidate in candidates:
            content = (
                candidate.get("content") if isinstance(candidate, Mapping) else None
            )
            parts = content.get("parts") if isinstance(content, Mapping) else None
            if not isinstance(parts, list):
                continue
            for part in parts:
                media = part.get("inlineData") if isinstance(part, Mapping) else None
                if (
                    isinstance(media, Mapping)
                    and isinstance(media.get("data"), str)
                    and media["data"]
                ):
                    return True
    return False


# Only native enum values enter telemetry; free-form provider fields may contain PII.
_CHAT_REASONS = frozenset(
    {"stop", "length", "tool_calls", "content_filter", "function_call"}
)
_MESSAGE_REASONS = frozenset(
    {
        "end_turn",
        "max_tokens",
        "stop_sequence",
        "tool_use",
        "pause_turn",
        "refusal",
        "model_context_window_exceeded",
    }
)
_GOOGLE_REASONS = frozenset(
    {
        "STOP",
        "MAX_TOKENS",
        "SAFETY",
        "RECITATION",
        "LANGUAGE",
        "OTHER",
        "BLOCKLIST",
        "PROHIBITED_CONTENT",
        "SPII",
        "MALFORMED_FUNCTION_CALL",
        "IMAGE_SAFETY",
        "UNEXPECTED_TOOL_CALL",
        "IMAGE_PROHIBITED_CONTENT",
        "NO_IMAGE",
        "IMAGE_RECITATION",
        "IMAGE_OTHER",
    }
)
_GOOGLE_BLOCK_REASONS = frozenset(
    {
        "SAFETY",
        "OTHER",
        "BLOCKLIST",
        "PROHIBITED_CONTENT",
        "IMAGE_SAFETY",
        "MODEL_ARMOR",
        "JAILBREAK",
    }
)


def native_finish_reasons(
    payload: Mapping[str, Any], *, provider: str
) -> dict[str, str] | None:
    """Keep native, candidate-indexed completion facts separate from transport status."""

    reasons: dict[str, str] = {}
    if provider in {"openai", "google"}:
        collection, field, allowed = (
            ("candidates", "finishReason", _GOOGLE_REASONS)
            if provider == "google"
            else ("choices", "finish_reason", _CHAT_REASONS)
        )
        candidates = payload.get(collection)
        if isinstance(candidates, list):
            for position, candidate in enumerate(candidates):
                if not isinstance(candidate, Mapping):
                    continue
                index = candidate.get("index", position)
                reason = candidate.get(field)
                if (
                    isinstance(index, int)
                    and not isinstance(index, bool)
                    and 0 <= index < 10_000
                    and isinstance(reason, str)
                    and reason in allowed
                ):
                    reasons[f"{collection}.{index}.{field}"] = reason
    if provider == "openai":
        response = payload.get("response", payload)
        if isinstance(response, Mapping):
            status = response.get("status")
            if isinstance(status, str) and status in {
                "completed",
                "failed",
                "cancelled",
                "incomplete",
            }:
                reasons["status"] = status
            incomplete = response.get("incomplete_details")
            reason = (
                incomplete.get("reason") if isinstance(incomplete, Mapping) else None
            )
            if isinstance(reason, str) and reason in {
                "max_output_tokens",
                "content_filter",
            }:
                reasons["incomplete_details.reason"] = reason
    elif provider == "anthropic":
        for value in (payload, payload.get("delta"), payload.get("message")):
            reason = value.get("stop_reason") if isinstance(value, Mapping) else None
            if isinstance(reason, str) and reason in _MESSAGE_REASONS:
                reasons["stop_reason"] = reason
    elif provider == "google":
        feedback = payload.get("promptFeedback")
        reason = feedback.get("blockReason") if isinstance(feedback, Mapping) else None
        if isinstance(reason, str) and reason in _GOOGLE_BLOCK_REASONS:
            reasons["promptFeedback.blockReason"] = reason
    return reasons or None


def _google_content_strings(value: Any, *, content: bool = False) -> list[str]:
    if isinstance(value, str):
        return [value] if content else []
    if isinstance(value, list):
        return [
            text
            for item in value
            for text in _google_content_strings(item, content=content)
        ]
    if isinstance(value, dict):
        return [
            text
            for key, item in value.items()
            if key not in {"metadata", "partMetadata"}
            for text in _google_content_strings(
                item,
                content=content
                or key in {"args", "code", "output", "response", "text"},
            )
        ]
    return []
