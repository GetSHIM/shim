"""The transform band: content changes a tenant turns on, lossless and version-pinned."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
import json
import re
from typing import Any

from shim.gateway.kernel.result import PreparedInference
from shim.gateway.kernel.stage import TraceValue
from shim.gateway.pipeline.settings_band import thinking_bound
from shim.observability.metrics import TRANSFORMS_TOTAL

JSON_COMPACTION_VERSION = 1
# shim-cli's MIN_CANDIDATE_CHARS, and the privacy scan's text bound.
JSON_COMPACTION_MIN_CHARS = 64
JSON_COMPACTION_MAX_CHARS = 1_000_000
# Above this many candidate characters the band runs off the event loop.
THREAD_CHARS = 65_536
_GEMINI_DEPTH = 32
_TOKENS = re.compile(r'("(?:[^"\\]|\\.)*")|[ \t\r\n]+')


def compact_json(text: str) -> str:
    """`text` without whitespace between JSON tokens, or `text` itself.

    A lexer, not a parse and re-serialise: string literals, number literals and
    duplicate keys survive byte for byte. The result depends only on `text`.
    """

    if (
        not JSON_COMPACTION_MIN_CHARS <= len(text) <= JSON_COMPACTION_MAX_CHARS
        or text[0] not in "{["
        # Already compact: nothing to remove, so no parse.
        or not any(space in text for space in " \t\r\n")
    ):
        return text
    try:
        # Parsed first, so the lexer only ever reads well-formed strings.
        value = json.loads(text)
        result = _TOKENS.sub(lambda match: match.group(1) or "", text)
        if len(result) >= len(text) or json.loads(result) != value:
            return text
    except (ValueError, RecursionError):
        return text
    return result


@dataclass(frozen=True)
class TransformResult:
    payload: dict[str, Any]
    before_chars: int
    after_chars: int
    items: int


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _rebuilt(items: list[Any], change: Callable[[Any], Any]) -> list[Any]:
    changed = [change(item) for item in items]
    return changed if any(a is not b for a, b in zip(changed, items)) else items


def _texts(items: list[Any], kind: str, fn: Callable[[str], str]) -> list[Any]:
    return _rebuilt(
        items,
        lambda item: (
            {**item, "text": text}
            if isinstance(item, Mapping)
            and item.get("type") == kind
            and isinstance(item.get("text"), str)
            and (text := fn(item["text"])) is not item["text"]
            else item
        ),
    )


def _field(container: Any, key: str, kind: str, fn: Callable[[str], str]) -> Any:
    value = container.get(key)
    if isinstance(value, str):
        new: Any = fn(value)
    elif isinstance(value, list):
        new = _texts(value, kind, fn)
    else:
        return container
    return container if new is value else {**container, key: new}


def _strings(value: Any, fn: Callable[[str], str], depth: int) -> Any:
    if isinstance(value, str):
        return fn(value)
    if depth == 0:
        return value
    if isinstance(value, Mapping):
        changed = {key: _strings(item, fn, depth - 1) for key, item in value.items()}
        return (
            changed
            if any(changed[key] is not item for key, item in value.items())
            else value
        )
    if isinstance(value, list):
        return _rebuilt(value, lambda item: _strings(item, fn, depth - 1))
    return value


# `payload` with `fn` applied to each tool result string, copying only what changed.
def _tool_results(
    protocol: str, payload: dict[str, Any], fn: Callable[[str], str]
) -> dict[str, Any]:
    def chat(message: Any) -> Any:
        if isinstance(message, Mapping) and message.get("role") == "tool":
            return _field(message, "content", "text", fn)
        return message

    def responses(item: Any) -> Any:
        if isinstance(item, Mapping) and item.get("type") == "function_call_output":
            return _field(item, "output", "input_text", fn)
        return item

    def block(item: Any) -> Any:
        if isinstance(item, Mapping) and item.get("type") == "tool_result":
            return _field(item, "content", "text", fn)
        return item

    def messages(message: Any) -> Any:
        content = message.get("content") if isinstance(message, Mapping) else None
        if not isinstance(content, list):
            return message
        changed = _rebuilt(content, block)
        return message if changed is content else {**message, "content": changed}

    def part(item: Any) -> Any:
        call = item.get("functionResponse") if isinstance(item, Mapping) else None
        if not isinstance(call, Mapping) or "response" not in call:
            return item
        response = _strings(call["response"], fn, _GEMINI_DEPTH)
        if response is call["response"]:
            return item
        return {**item, "functionResponse": {**call, "response": response}}

    def content(item: Any) -> Any:
        parts = item.get("parts") if isinstance(item, Mapping) else None
        if not isinstance(parts, list):
            return item
        changed = _rebuilt(parts, part)
        return item if changed is parts else {**item, "parts": changed}

    key, change = {
        "chat": ("messages", chat),
        "responses": ("input", responses),
        "messages": ("messages", messages),
        "generate_content": ("contents", content),
    }[protocol]
    items = payload.get(key)
    if not isinstance(items, list):
        return payload
    changed = _rebuilt(items, change)
    return payload if changed is items else {**payload, key: changed}


def _json_compaction(
    prepared: PreparedInference, payload: dict[str, Any]
) -> TransformResult | None:
    sizes = [0, 0, 0]

    def compact(text: str) -> str:
        result = compact_json(text)
        if result is not text:
            sizes[0] += len(text)
            sizes[1] += len(result)
            sizes[2] += 1
        return result

    changed = _tool_results(prepared.protocol, payload, compact)
    if changed is payload:
        return None
    return TransformResult(changed, *sizes)


def _candidate_chars(prepared: PreparedInference) -> int:
    total = 0

    def measure(text: str) -> str:
        nonlocal total
        total += len(text)
        return text

    _tool_results(prepared.protocol, prepared.payload, measure)
    return total


# (id, version, protocols, apply). A step copies on write along the path of each
# string it changes and returns None when it changed nothing.
STEPS: tuple[
    tuple[
        str,
        int,
        frozenset[str],
        Callable[[PreparedInference, dict[str, Any]], TransformResult | None],
    ],
    ...,
] = (
    (
        "json_compaction",
        JSON_COMPACTION_VERSION,
        frozenset({"chat", "responses", "messages", "generate_content"}),
        _json_compaction,
    ),
)


def _apply(prepared: PreparedInference) -> PreparedInference:
    # Documents the privacy stage turned into text come first.
    payload = prepared.payload
    applied = list(prepared.privacy.conversions if prepared.privacy else ())
    for step_id, version, protocols, apply in STEPS:
        if prepared.protocol not in protocols:
            continue
        # A changed earlier turn invalidates every later Anthropic thinking block.
        # OpenAI's encrypted reasoning items were not checked live: skipped alike.
        if (prepared.protocol == "messages" and thinking_bound(payload)) or (
            prepared.protocol == "responses"
            and any(
                isinstance(item, Mapping) and item.get("type") == "reasoning"
                for item in _list(payload.get("input"))
            )
        ):
            prepared.record_verdict(
                f"transforms.{step_id}",
                stage="transforms",
                outcome="skip",
                reason_code="TRANSFORM_THINKING_BOUND",
                policy={"id": step_id, "version": version},
            )
            TRANSFORMS_TOTAL.labels(transform=step_id, result="skipped").inc()
            continue
        result = apply(prepared, payload)
        TRANSFORMS_TOTAL.labels(
            transform=step_id, result="unchanged" if result is None else "applied"
        ).inc()
        if result is None:
            continue
        payload = result.payload
        applied.append(
            {
                "id": step_id,
                "version": version,
                "before_chars": result.before_chars,
                "after_chars": result.after_chars,
                "items": result.items,
            }
        )
    return replace(prepared, payload=payload, transforms_applied=tuple(applied))


class TransformBandStage:
    name = "transform_band"

    async def run(self, value: PreparedInference) -> PreparedInference:
        if _candidate_chars(value) >= THREAD_CHARS:
            return await asyncio.to_thread(_apply, value)
        return _apply(value)

    def trace_metadata(self, output: PreparedInference) -> Mapping[str, TraceValue]:
        applied = output.transforms_applied or ()
        return {
            "items": sum(entry["items"] for entry in applied),
            "chars_saved": sum(
                entry["before_chars"] - entry["after_chars"] for entry in applied
            ),
        }
