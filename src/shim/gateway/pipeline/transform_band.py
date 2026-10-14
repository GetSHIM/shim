"""The transform band: content changes a tenant turns on, lossless and version-pinned."""

from __future__ import annotations

import asyncio
import base64
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
import io
import json
import logging
import re
from typing import Any

from shim.gateway.image_rules import IMAGE_RULES_VERSION, target_size
from shim.gateway.kernel.result import PreparedInference
from shim.gateway.kernel.stage import TraceValue
from shim.gateway.media import MediaPart, classify_media, split_data_url, value_at
from shim.gateway.pipeline.settings_band import (
    provider_target,
    write_at,
    thinking_bound,
)
from shim.observability.metrics import IMAGE_DOWNSCALE_TOTAL, TRANSFORMS_TOTAL

logger = logging.getLogger(__name__)

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
    # A step's own record fields, merged into its transforms_applied entry.
    extra: Mapping[str, Any] = field(default_factory=dict)


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
    return TransformResult(changed, sizes[0], sizes[1], sizes[2])


IMAGE_DOWNSCALE_VERSION = 1
_MAX_IMAGE_BYTES = 32 * 1024 * 1024
_MAX_IMAGE_PIXELS = 64_000_000
_RECORDED_IMAGES = 64
_FORMATS = {"PNG": "png", "JPEG": "jpeg", "WEBP": "webp"}
# Same format out as in; JPEG and WEBP lossy at quality 90, PNG lossless.
_ENCODE: Mapping[str, Mapping[str, Any]] = {
    "PNG": {"compress_level": 6, "optimize": False},
    "JPEG": {"quality": 90, "subsampling": 2, "optimize": False, "progressive": False},
    "WEBP": {"quality": 90, "method": 4, "lossless": False},
}
# Images whose coordinates or size the client relies on.
_OPT_OUT_TYPES = frozenset(
    {"tool_result", "computer_call_output", "computer_screenshot"}
)


class _Untouched(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason


def _inline_images(prepared: PreparedInference) -> bool:
    return any(
        part.kind == "image" and part.source == "inline"
        for part in prepared.media or ()
    )


def _opted_out(payload: Mapping[str, Any], part: MediaPart) -> bool:
    nodes = [value_at(payload, part.path[:end]) for end in range(1, len(part.path) + 1)]
    image = nodes[-1]
    transformations = (
        image.get("transformations") if isinstance(image, Mapping) else None
    )
    return any(
        isinstance(node, Mapping) and node.get("type") in _OPT_OUT_TYPES
        for node in nodes
    ) or (
        isinstance(transformations, Mapping)
        and transformations.get("oversized_image") == "error"
    )


def _detail(protocol: str, image: Mapping[str, Any]) -> object:
    if protocol == "chat":
        url = image.get("image_url")
        return url.get("detail") if isinstance(url, Mapping) else None
    return image.get("detail") if protocol == "responses" else None


def _resize(raw: bytes, target: tuple[int, int]) -> tuple[bytes, str]:
    """The image re-encoded at `target` in its own format, and that format."""
    from PIL import Image

    with Image.open(io.BytesIO(raw)) as image:
        if image.format not in _FORMATS or getattr(image, "is_animated", False):
            raise _Untouched("unsupported")
        # Rotating it would change what the model sees.
        if image.getexif().get(0x0112, 1) != 1:
            raise _Untouched("unsupported")
        source_format, icc = image.format, image.info.get("icc_profile")
        if image.mode == "P":
            image = image.convert("RGBA" if "transparency" in image.info else "RGB")
        elif image.mode not in {"L", "LA", "RGB", "RGBA"}:
            raise _Untouched("unsupported")
        if source_format == "JPEG":
            image.draft(image.mode, target)
        resized = image.resize(target, Image.Resampling.LANCZOS, reducing_gap=None)
    output = io.BytesIO()
    resized.save(
        output,
        format=source_format,
        **_ENCODE[source_format],
        **({"icc_profile": icc} if icc else {}),
    )
    return output.getvalue(), _FORMATS[source_format]


def _image_downscale(
    prepared: PreparedInference, payload: dict[str, Any]
) -> TransformResult | None:
    if not _inline_images(prepared) or not provider_target(prepared):
        return None
    skipped: Counter[str] = Counter()
    images: list[dict[str, Any]] = []
    sizes = [0, 0, 0, 0]
    for part in classify_media(payload):
        if part.kind != "image" or part.source != "inline" or part.data_path is None:
            continue
        data = value_at(payload, part.data_path)
        try:
            if _opted_out(payload, part):
                raise _Untouched("client_opt_out")
            if part.dimensions is None:
                raise _Untouched("unsupported")
            width, height = part.dimensions
            detail = _detail(prepared.protocol, value_at(payload, part.path))
            target = target_size(
                str(prepared.provider),
                prepared.pricing_model,
                detail if isinstance(detail, str) else None,
                width,
                height,
            )
            if target is None:
                raise _Untouched("unknown_model")
            if target[0] >= width and target[1] >= height:
                raise _Untouched("below_threshold")
            if (part.decoded_bytes or 0) > _MAX_IMAGE_BYTES or (
                width * height > _MAX_IMAGE_PIXELS
            ):
                raise _Untouched("too_large")
            try:
                raw = base64.b64decode(split_data_url(data)[1])
                smaller, image_format = _resize(raw, target)
            except _Untouched:
                raise
            except Exception as error:
                # A decoder error leaves the image alone; a transform never fails a request.
                logger.info("Image left unchanged error_type=%s", type(error).__name__)
                raise _Untouched("corrupt") from None
            if len(smaller) >= len(raw):
                raise _Untouched("not_smaller")
        except _Untouched as untouched:
            skipped[untouched.reason] += 1
            IMAGE_DOWNSCALE_TOTAL.labels(outcome=untouched.reason).inc()
            continue
        # A data URL keeps its `data:<mime>;base64,` prefix.
        head = data[: data.index(",") + 1] if data.startswith("data:") else ""
        replacement = head + base64.b64encode(smaller).decode()
        payload = write_at(payload, part.data_path, replacement)
        IMAGE_DOWNSCALE_TOTAL.labels(outcome="downscaled").inc()
        sizes = [
            sizes[0] + len(data),
            sizes[1] + len(replacement),
            sizes[2] + len(raw),
            sizes[3] + len(smaller),
        ]
        images.append(
            {
                "format": image_format,
                "before": [width, height],
                "after": list(target),
                "before_bytes": len(raw),
                "after_bytes": len(smaller),
            }
        )
    if not images:
        return None
    from PIL import __version__ as pillow_version

    return TransformResult(
        payload,
        before_chars=sizes[0],
        after_chars=sizes[1],
        items=len(images),
        extra={
            "rules": IMAGE_RULES_VERSION,
            "library": f"pillow-{pillow_version}",
            "before_bytes": sizes[2],
            "after_bytes": sizes[3],
            "images": images[:_RECORDED_IMAGES],
            "skipped": dict(skipped),
        },
    )


def _candidate_chars(prepared: PreparedInference) -> int:
    total = 0

    def measure(text: str) -> str:
        nonlocal total
        total += len(text)
        return text

    _tool_results(prepared.protocol, prepared.payload, measure)
    return total


# (id, version, protocols, on, apply). A step copies on write along the path of each
# string it changes and returns None when it changed nothing.
STEPS: tuple[
    tuple[
        str,
        int,
        frozenset[str],
        Callable[[PreparedInference], bool],
        Callable[[PreparedInference, dict[str, Any]], TransformResult | None],
    ],
    ...,
] = (
    (
        "json_compaction",
        JSON_COMPACTION_VERSION,
        frozenset({"chat", "responses", "messages", "generate_content"}),
        lambda prepared: prepared.band.json_compaction,
        _json_compaction,
    ),
    (
        "image_downscale",
        IMAGE_DOWNSCALE_VERSION,
        frozenset({"chat", "responses", "messages"}),
        lambda prepared: prepared.band.image_downscale,
        _image_downscale,
    ),
)


def _apply(prepared: PreparedInference) -> PreparedInference:
    # Documents the privacy stage turned into text come first.
    payload = prepared.payload
    applied = list(prepared.privacy.conversions if prepared.privacy else ())
    for step_id, version, protocols, on, apply in STEPS:
        if prepared.protocol not in protocols or not on(prepared):
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
            if step_id == "image_downscale":
                IMAGE_DOWNSCALE_TOTAL.labels(outcome="thinking_bound").inc()
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
                **result.extra,
            }
        )
    return replace(prepared, payload=payload, transforms_applied=tuple(applied))


class TransformBandStage:
    name = "transform_band"

    async def run(self, value: PreparedInference) -> PreparedInference:
        # Image work always runs off the event loop.
        if _candidate_chars(value) >= THREAD_CHARS or (
            value.band.image_downscale and _inline_images(value)
        ):
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
