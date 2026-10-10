"""The `shape` analyzer: what a request is made of, counted on the masked payload."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from hashlib import sha256
from itertools import takewhile
import json
import struct
from typing import Any

from shim.gateway.pipeline.analysis import TOOL_NAME, AnalysisContext

MAX_PARTS = 20_000
MAX_DEPTH = 64
MAX_TOOLS = 128
# Base64 read for an image's dimensions: 64 KiB, a whole number of quanta.
_HEADER_BASE64 = 65_536
_STANDARD_BASE64 = str.maketrans("-_", "+/")
_SYSTEM_ROLES = frozenset({"system", "developer"})
_TEXT_KINDS = frozenset({"text", "input_text", "output_text"})


def _image_size(data: bytes) -> tuple[int | None, int | None]:
    if data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) >= 24:
        return struct.unpack(">II", data[16:24])
    if data[:6] in (b"GIF87a", b"GIF89a") and len(data) >= 10:
        return struct.unpack("<HH", data[6:10])
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        chunk = data[12:16]
        if chunk == b"VP8X" and len(data) >= 30:
            return (
                int.from_bytes(data[24:27], "little") + 1,
                int.from_bytes(data[27:30], "little") + 1,
            )
        if chunk == b"VP8L" and len(data) >= 25 and data[20] == 0x2F:
            bits = int.from_bytes(data[21:25], "little")
            return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
        if chunk == b"VP8 " and len(data) >= 30 and data[23:26] == b"\x9d\x01\x2a":
            width, height = struct.unpack("<HH", data[26:30])
            return width & 0x3FFF, height & 0x3FFF
        return None, None
    if data[:2] == b"\xff\xd8":
        index = 2
        while index + 9 <= len(data):
            if data[index] != 0xFF:
                return None, None
            marker = data[index + 1]
            if marker == 0xFF:
                index += 1
                continue
            length = struct.unpack(">H", data[index + 2 : index + 4])[0]
            # SOF0 to SOF15, without DHT (C4), JPG (C8) and DAC (CC).
            if 0xC0 <= marker <= 0xCF and marker not in {0xC4, 0xC8, 0xCC}:
                height, width = struct.unpack(">HH", data[index + 5 : index + 9])
                return width, height
            index += 2 + length
    return None, None


@dataclass
class _Walk:
    parts: int = 0
    truncated: bool = False
    largest_part: int = 0
    tool_results: list[int] = field(default_factory=list)
    called: set[str] = field(default_factory=set)
    dropped: int = 0
    images: int = 0
    documents: int = 0
    largest_image: dict[str, Any] | None = None

    def part(self, _item: Any) -> bool:
        self.parts += 1
        if self.parts > MAX_PARTS:
            self.truncated = True
        return not self.truncated

    def items(self, values: Any) -> Any:
        """The values of a list the part budget still allows; the walk stops at the first refused."""

        return takewhile(self.part, values if isinstance(values, list) else [])

    def chars(self, value: Any, depth: int = 0) -> int:
        """Text characters in a value, nested lists and objects included, within the bounds."""

        if depth > MAX_DEPTH:
            self.truncated = True
            return 0
        if isinstance(value, str):
            return len(value)
        if isinstance(value, dict):
            value = list(value.values())
        return sum(self.chars(item, depth + 1) for item in self.items(value))

    def text(self, value: str) -> int:
        self.largest_part = max(self.largest_part, len(value))
        return len(value)

    def tool_result(self, size: int) -> int:
        self.tool_results.append(size)
        self.largest_part = max(self.largest_part, size)
        return size

    def name(self, value: Any) -> str | None:
        """A tool name as providers allow it; anything else is dropped and counted."""

        if isinstance(value, str) and TOOL_NAME.fullmatch(value):
            return value
        self.dropped += 1
        return None

    def call(self, value: Any) -> None:
        if (name := self.name(value)) is not None:
            self.called.add(name)

    def image(self, data: Any = None, encoded: bool = True) -> None:
        """An image part: its inline data, base64 unless a data URL says otherwise."""

        self.images += 1
        if not isinstance(data, str):
            return
        size = (
            len(data) * 3 // 4 - (2 if data.endswith("==") else data.endswith("="))
            if encoded
            else len(data)
        )
        if self.largest_image is not None and size <= self.largest_image["bytes"]:
            return
        width = height = None
        if encoded:
            # A model dump re-encodes inline bytes as URL-safe base64.
            head = data[:_HEADER_BASE64].translate(_STANDARD_BASE64)
            try:
                width, height = _image_size(
                    base64.b64decode(head[: len(head) - len(head) % 4])
                )
            except (binascii.Error, ValueError, struct.error):
                pass
        self.largest_image = {"bytes": size, "width": width, "height": height}


def _data_url(value: Any) -> tuple[str | None, bool]:
    """The data of a data: URL and whether it is base64; None for a reference."""

    if not (isinstance(value, str) and value.startswith("data:")):
        return None, True
    header, _, data = value.partition(",")
    return data, header.endswith(";base64")


def _content(walk: _Walk, content: Any, part) -> int:
    if isinstance(content, str):
        return walk.text(content)
    return sum(part(walk, item) for item in walk.items(content))


def _openai_part(walk: _Walk, part: Any) -> int:
    if isinstance(part, str):
        return walk.text(part)
    if not isinstance(part, dict):
        return 0
    kind = part.get("type")
    if kind in _TEXT_KINDS and isinstance(part.get("text"), str):
        return walk.text(part["text"])
    if kind == "image_url":
        image = part.get("image_url")
        walk.image(*_data_url(image.get("url") if isinstance(image, dict) else image))
    elif kind == "input_image":
        walk.image(*_data_url(part.get("image_url")))
    elif kind in {"file", "input_file"}:
        walk.documents += 1
    return 0


def _chat(walk: _Walk, payload: dict[str, Any]) -> tuple[list[tuple[str, int]], int]:
    turns = []
    for message in walk.items(payload.get("messages")):
        if not isinstance(message, dict):
            continue
        role = str(message.get("role"))
        size = _content(walk, message.get("content"), _openai_part)
        if role == "tool":
            walk.tool_result(size)
        for call in walk.items(message.get("tool_calls")):
            if isinstance(call, dict):
                named = call.get("function") or call.get("custom")
                walk.call(named.get("name") if isinstance(named, dict) else None)
        if isinstance(message.get("function_call"), dict):
            walk.call(message["function_call"].get("name"))
        turns.append((role, size))
    return turns, 0


def _responses(
    walk: _Walk, payload: dict[str, Any]
) -> tuple[list[tuple[str, int]], int]:
    instructions = payload.get("instructions")
    system = walk.text(instructions) if isinstance(instructions, str) else 0
    items = payload.get("input")
    if isinstance(items, str):
        return [("user", walk.text(items))], system
    turns = []
    for item in walk.items(items):
        if not isinstance(item, dict):
            continue
        kind = item.get("type", "message")
        if kind in {"function_call_output", "custom_tool_call_output"}:
            size = _content(walk, item.get("output"), _openai_part)
            turns.append(("tool", walk.tool_result(size)))
        elif kind == "message":
            role = str(item.get("role"))
            turns.append((role, _content(walk, item.get("content"), _openai_part)))
        else:
            if kind in {"function_call", "custom_tool_call"}:
                walk.call(item.get("name"))
            turns.append(("assistant", 0))
    return turns, system


def _anthropic_block(walk: _Walk, block: Any) -> int:
    if not isinstance(block, dict):
        return 0
    kind = block.get("type")
    if kind == "text" and isinstance(block.get("text"), str):
        return walk.text(block["text"])
    if kind == "tool_result":
        return walk.tool_result(_content(walk, block.get("content"), _anthropic_block))
    if kind in {"tool_use", "server_tool_use"}:
        walk.call(block.get("name"))
        return 0
    source = block.get("source")
    source = source if isinstance(source, dict) else {}
    if kind == "image":
        walk.image(source.get("data") if source.get("type") == "base64" else None)
    elif kind == "document":
        walk.documents += 1
        if source.get("type") == "text" and isinstance(source.get("data"), str):
            return walk.text(source["data"])
    return 0


def _messages(
    walk: _Walk, payload: dict[str, Any]
) -> tuple[list[tuple[str, int]], int]:
    system = _content(walk, payload.get("system"), _anthropic_block)
    turns = [
        (
            str(message.get("role")),
            _content(walk, message.get("content"), _anthropic_block),
        )
        for message in walk.items(payload.get("messages"))
        if isinstance(message, dict)
    ]
    return turns, system


def _gemini_part(walk: _Walk, part: Any) -> int:
    if not isinstance(part, dict):
        return 0
    if isinstance(part.get("text"), str):
        return walk.text(part["text"])
    response = part.get("functionResponse")
    if isinstance(response, dict):
        return walk.tool_result(
            walk.chars(response.get("response"))
            + _content(walk, response.get("parts"), _gemini_part)
        )
    if isinstance(part.get("functionCall"), dict):
        walk.call(part["functionCall"].get("name"))
    for key in ("inlineData", "fileData"):
        media = part.get(key)
        if isinstance(media, dict):
            if str(media.get("mimeType", "")).startswith("image/"):
                walk.image(media.get("data") if key == "inlineData" else None)
            else:
                walk.documents += 1
    return 0


def _generate_content(
    walk: _Walk, payload: dict[str, Any]
) -> tuple[list[tuple[str, int]], int]:
    instruction = payload.get("systemInstruction")
    system = (
        _content(walk, instruction.get("parts"), _gemini_part)
        if isinstance(instruction, dict)
        else 0
    )
    turns = [
        (
            str(content.get("role", "user")),
            _content(walk, content.get("parts"), _gemini_part),
        )
        for content in walk.items(payload.get("contents"))
        if isinstance(content, dict)
    ]
    return turns, system


def _offered(walk: _Walk, protocol: str, tools: list[Any]) -> list[str | None]:
    """Each offered tool's name, None where it was dropped; a built-in as builtin:<type>."""

    names: list[str | None] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        if protocol == "generate_content":
            for key, value in tool.items():
                if key == "functionDeclarations" and isinstance(value, list):
                    names.extend(
                        walk.name(item.get("name"))
                        for item in value
                        if isinstance(item, dict)
                    )
                else:
                    names.append(_builtin(walk, key))
            continue
        named = (
            tool.get("function", tool.get("custom"))
            if protocol == "chat"
            else tool
            if "name" in tool
            else None
        )
        names.append(
            walk.name(named.get("name"))
            if isinstance(named, dict)
            else _builtin(walk, tool.get("type"))
        )
    return names


def _builtin(walk: _Walk, kind: Any) -> str | None:
    return None if (name := walk.name(kind)) is None else f"builtin:{name}"


_WALKS = {
    "chat": _chat,
    "responses": _responses,
    "messages": _messages,
    "generate_content": _generate_content,
}


def _digest(names: list[str]) -> str | None:
    return sha256("\x1f".join(names).encode()).hexdigest()[:16] if names else None


def shape(payload: dict[str, Any], protocol: str) -> dict[str, Any] | None:
    walk_turns = _WALKS.get(protocol)
    if walk_turns is None:
        return None
    walk = _Walk()
    turns, system = walk_turns(walk, payload)
    system += sum(size for role, size in turns if role in _SYSTEM_ROLES)
    users = [index for index, (role, _) in enumerate(turns) if role == "user"]
    tools = payload.get("tools")
    tools = tools if isinstance(tools, list) else []
    offered = _offered(walk, protocol, tools)
    named = [name for name in offered if name is not None]
    called = sorted(walk.called)
    if len(named) > MAX_TOOLS or len(called) > MAX_TOOLS:
        walk.truncated = True
    recorded = named[:MAX_TOOLS]
    return {
        "message_count": len(turns),
        "system_chars": system,
        # Everything before the final turn, so an agent loop ending in tool results
        # measures the same in every protocol.
        "history_chars": sum(
            size for role, size in turns[:-1] if role not in _SYSTEM_ROLES
        ),
        "last_user_chars": turns[users[-1]][1] if users else 0,
        "largest_part_chars": walk.largest_part,
        "tool_result_count": len(walk.tool_results),
        "tool_result_chars": sum(walk.tool_results),
        "largest_tool_result_chars": max(walk.tool_results, default=0),
        "tool_count": len(offered),
        "tool_definition_chars": len(
            json.dumps(tools, ensure_ascii=False, separators=(",", ":"))
        )
        if tools
        else 0,
        "tools_offered": recorded,
        "tools_called_in_history": called[:MAX_TOOLS],
        "tools_order_digest": _digest(recorded),
        "tools_set_digest": _digest(sorted(recorded)),
        "tool_names_dropped": walk.dropped,
        "image_count": walk.images,
        "document_count": walk.documents,
        "largest_image": walk.largest_image,
        "truncated": walk.truncated,
    }


class ShapeAnalyzer:
    """Counts and names only, from the masked request; it never reads the answer."""

    name = "shape"
    version = "1"
    reads_answer = False

    def analyze(self, ctx: AnalysisContext) -> dict[str, Any] | None:
        return shape(ctx.payload, ctx.protocol)
