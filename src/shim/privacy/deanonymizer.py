"""Wire-native restoration of verified provider content placeholders."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from shim.privacy.pii_scrubber import PIIScrubberService


_DEEP_CONTENT_FIELDS = frozenset({"arguments", "input"})
_DELTA_TYPES = (
    "audio.transcript",
    "code_interpreter_call_code",
    "custom_tool_call_input",
    "custom_tool_call_output",
    "function_call_arguments",
    "function_call_output",
    "mcp",
    "output_text",
    "reasoning",
    "refusal",
    "shell",
)
_SHARED_PROTOCOL_FIELDS = frozenset(
    {
        "authorization",
        "cachedContent",
        "cached_content",
        "call_id",
        "container",
        "conversation",
        "encrypted_content",
        "encrypted_stdout",
        "fingerprint",
        "headers",
        "id",
        "inference_geo",
        "language",
        "media_type",
        "metadata",
        "mime_type",
        "mimeType",
        "model",
        "name",
        "namespace",
        "previous_response_id",
        "role",
        "server_label",
        "server_name",
        "service_tier",
        "signature",
        "status",
        "thoughtSignature",
        "thought_signature",
        "tool_call_id",
        "tool_name",
        "tool_names",
        "tool_use_id",
        "type",
        "uri",
        "url",
    }
)
_ANTHROPIC_METADATA_FIELDS = _SHARED_PROTOCOL_FIELDS | frozenset(
    {
        "error_code",
        "file_type",
        "stop_reason",
    }
)
_ANTHROPIC_OPAQUE_FIELDS_BY_TYPE = {
    "fallback": frozenset({"from", "to", "trigger"}),
    "redacted_thinking": frozenset({"data"}),
}
_OPENAI_PROTOCOL_FIELDS = _SHARED_PROTOCOL_FIELDS | frozenset(
    {
        "caller",
    }
)


def _is_protocol_field(key: object, fields: frozenset[str]) -> bool:
    return isinstance(key, str) and (key in fields or key.endswith(("_id", "_ids")))


def restore_openai_payload(
    payload: dict[str, Any],
    verification_map: Mapping[str, str],
    scrubber: PIIScrubberService,
) -> dict[str, Any]:
    """Restore provider content without changing protocol metadata."""

    if not verification_map:
        return payload

    def visit(
        value: Any,
        *,
        content: bool = False,
        deep_content: bool = False,
    ) -> Any:
        if isinstance(value, str) and (content or deep_content):
            return scrubber.deanonymize(value, verification_map)
        if isinstance(value, list):
            return [
                visit(item, content=content, deep_content=deep_content)
                for item in value
            ]
        if isinstance(value, dict):
            value_type = value.get("type")
            restored: dict[str, Any] = {}
            for key, item in value.items():
                if deep_content:
                    restored[key] = visit(item, deep_content=True)
                elif (
                    _is_protocol_field(key, _OPENAI_PROTOCOL_FIELDS)
                    or (value_type == "image_generation_call" and key == "result")
                    or (value_type == "response.audio.delta" and key == "delta")
                ):
                    restored[key] = item
                elif (
                    key in _DEEP_CONTENT_FIELDS
                    or (
                        key == "output"
                        and isinstance(value_type, str)
                        and (value_type.endswith("_output") or value_type == "mcp_call")
                    )
                    or (key == "result" and value_type == "program_output")
                ):
                    restored[key] = visit(item, deep_content=True)
                else:
                    restored[key] = visit(
                        item,
                        content=True,
                    )
            return restored
        return value

    return visit(payload)


def restore_anthropic_payload(
    payload: dict[str, Any],
    verification_map: Mapping[str, str],
    scrubber: PIIScrubberService,
) -> dict[str, Any]:
    """Restore native Anthropic content without changing protocol metadata."""

    if not verification_map:
        return payload

    def visit(
        value: Any,
        *,
        content: bool = False,
        deep_content: bool = False,
    ) -> Any:
        if isinstance(value, str) and (content or deep_content):
            return scrubber.deanonymize(value, verification_map)
        if isinstance(value, list):
            return [
                visit(item, content=content, deep_content=deep_content)
                for item in value
            ]
        if isinstance(value, dict):
            value_type = value.get("type")
            restored: dict[str, Any] = {}
            for key, item in value.items():
                if deep_content:
                    restored[key] = visit(item, deep_content=True)
                elif _is_protocol_field(key, _ANTHROPIC_METADATA_FIELDS) or key in (
                    _ANTHROPIC_OPAQUE_FIELDS_BY_TYPE.get(value_type, ())
                ):
                    restored[key] = item
                elif key == "input":
                    restored[key] = visit(item, deep_content=True)
                else:
                    restored[key] = visit(
                        item,
                        content=True,
                    )
            return restored
        return value

    return visit(payload)


class AnthropicStreamRestorer:
    """Restore placeholders split across interleaved Anthropic content blocks."""

    def __init__(
        self,
        verification_map: Mapping[str, str],
        scrubber: PIIScrubberService,
    ) -> None:
        self._verification_map = verification_map
        self._scrubber = scrubber
        self._buffers: dict[tuple[object, ...], str] = {}

    def restore_events(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        if not self._verification_map:
            return [payload]
        event_type = payload.get("type")
        delta = payload.get("delta")
        if event_type == "content_block_delta" and isinstance(delta, dict):
            for field in ("text", "partial_json", "thinking", "content"):
                fragment = delta.get(field)
                if isinstance(fragment, str):
                    delta[field] = self._restore_fragment(
                        (payload.get("index"), field),
                        fragment,
                    )
        flushed: list[dict[str, Any]] = []
        if event_type == "content_block_stop":
            flushed = self._flush_events(payload.get("index"))
        elif event_type == "message_stop":
            flushed = self._flush_events()
        return [
            *flushed,
            restore_anthropic_payload(
                payload,
                self._verification_map,
                self._scrubber,
            ),
        ]

    def _restore_fragment(self, key: tuple[object, ...], fragment: str) -> str:
        text = self._buffers.pop(key, "") + fragment
        ready, carry = _split_placeholder_prefix(text, self._verification_map)
        if carry:
            self._buffers[key] = carry
        return self._scrubber.deanonymize(ready, self._verification_map)

    def _flush_events(self, index: object | None = None) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for key in tuple(self._buffers):
            if index is not None and key[0] != index:
                continue
            field = str(key[1])
            events.append(
                {
                    "type": "content_block_delta",
                    "index": key[0],
                    "delta": {
                        "type": {
                            "content": "compaction_delta",
                            "partial_json": "input_json_delta",
                            "text": "text_delta",
                            "thinking": "thinking_delta",
                        }[field],
                        field: self._scrubber.deanonymize(
                            self._buffers.pop(key),
                            self._verification_map,
                        ),
                    },
                }
            )
        return events


class OpenAIStreamRestorer:
    """Restore placeholders across independently interleaved OpenAI deltas."""

    def __init__(
        self,
        verification_map: Mapping[str, str],
        scrubber: PIIScrubberService,
    ) -> None:
        self._verification_map = verification_map
        self._scrubber = scrubber
        self._buffers: dict[tuple[object, ...], str] = {}

    def restore_response_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self._verification_map:
            return payload
        event_type = str(payload.get("type", ""))
        delta = payload.get("delta")
        if isinstance(delta, str) and any(
            token in event_type for token in _DELTA_TYPES
        ):
            key = (
                event_type.removesuffix(".delta"),
                payload.get("item_id"),
                payload.get("output_index"),
                payload.get("content_index"),
            )
            payload["delta"] = self._restore_fragment(key, delta)
        payload = restore_openai_payload(
            payload,
            self._verification_map,
            self._scrubber,
        )
        if event_type.endswith(".done"):
            prefix = event_type.removesuffix(".done")
            self._drop_buffers(prefix, payload.get("item_id"))
        elif event_type in {
            "response.completed",
            "response.failed",
            "response.incomplete",
            "response.cancelled",
        }:
            self._buffers.clear()
        return payload

    def restore_chat_chunk(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self._verification_map:
            return payload
        for choice in payload.get("choices", ()):
            if not isinstance(choice, dict):
                continue
            choice_index = choice.get("index", 0)
            delta = choice.get("delta")
            if not isinstance(delta, dict):
                continue
            for field in ("content", "refusal"):
                value = delta.get(field)
                if isinstance(value, str):
                    delta[field] = self._restore_fragment(
                        ("chat", choice_index, field), value
                    )
            function_call = delta.get("function_call")
            if isinstance(function_call, dict) and isinstance(
                function_call.get("arguments"), str
            ):
                function_call["arguments"] = self._restore_fragment(
                    ("chat", choice_index, "function_call"),
                    function_call["arguments"],
                )
            for tool_call in delta.get("tool_calls") or ():
                if not isinstance(tool_call, dict):
                    continue
                function = tool_call.get("function")
                if isinstance(function, dict) and isinstance(
                    function.get("arguments"), str
                ):
                    function["arguments"] = self._restore_fragment(
                        ("chat", choice_index, "tool", tool_call.get("index", 0)),
                        function["arguments"],
                    )
            if choice.get("finish_reason") is not None:
                self._flush_chat_choice(choice_index, delta)
        return restore_openai_payload(
            payload,
            self._verification_map,
            self._scrubber,
        )

    def _restore_fragment(self, key: tuple[object, ...], fragment: str) -> str:
        text = self._buffers.pop(key, "") + fragment
        ready, carry = _split_placeholder_prefix(text, self._verification_map)
        if carry:
            self._buffers[key] = carry
        return self._scrubber.deanonymize(ready, self._verification_map)

    def _drop_buffers(self, event_prefix: str, item_id: object) -> None:
        for key in tuple(self._buffers):
            if key[0] == event_prefix and (item_id is None or key[1] == item_id):
                self._buffers.pop(key, None)

    def _flush_chat_choice(self, choice_index: object, delta: dict[str, Any]) -> None:
        for key in tuple(self._buffers):
            if key[:2] != ("chat", choice_index):
                continue
            carry = self._buffers.pop(key)
            restored = self._scrubber.deanonymize(carry, self._verification_map)
            if key[2] in {"content", "refusal"}:
                delta[str(key[2])] = str(delta.get(str(key[2])) or "") + restored
            elif key[2] == "function_call":
                call = delta.setdefault("function_call", {})
                call["arguments"] = str(call.get("arguments") or "") + restored
            elif key[2] == "tool":
                calls = delta.setdefault("tool_calls", [])
                call = next(
                    (item for item in calls if item.get("index") == key[3]),
                    None,
                )
                if call is None:
                    call = {"index": key[3], "function": {}}
                    calls.append(call)
                function = cast(dict[str, Any], call.setdefault("function", {}))
                function["arguments"] = str(function.get("arguments") or "") + restored


def _split_placeholder_prefix(
    text: str,
    placeholders: Mapping[str, str],
) -> tuple[str, str]:
    last_open = text.rfind("<")
    if last_open < 0:
        return text, ""
    tail = text[last_open:]
    compact_tail = "<" + "".join(tail[1:].split())
    if any(
        len(compact_tail) < len(placeholder) and placeholder.startswith(compact_tail)
        for placeholder in placeholders
    ):
        return text[:last_open], tail
    return text, ""
