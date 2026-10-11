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

from shim.gateway.pipeline.analysis import AnalysisContext

MAX_PARTS = 20_000
MAX_DEPTH = 64
MAX_TOOLS = 128
MAX_NAME = 64
# Base64 read for an image's dimensions: 64 KiB, a whole number of quanta.
_HEADER_BASE64 = 65_536
_SYSTEM_ROLES = frozenset({"system", "developer"})


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
    images: int = 0
    documents: int = 0
    largest_image: dict[str, Any] | None = None

    def part(self, _item: Any = None) -> bool:
        self.parts += 1
        if self.parts > MAX_PARTS:
            self.truncated = True
        return not self.truncated

    def items(self, values: Any) -> Any:
        """The values the part budget still allows; the walk stops at the first refused."""

        return takewhile(self.part, values)

    def chars(self, value: Any, depth: int = 0) -> int:
        """Text characters in a value, nested lists and objects included, within the bounds."""

        if depth > MAX_DEPTH:
            self.truncated = True
            return 0
        if isinstance(value, str):
            return len(value)
        if isinstance(value, dict):
            value = list(value.values())
        if isinstance(value, list):
            return sum(self.chars(item, depth + 1) for item in self.items(value))
        return 0

    def text(self, value: str) -> int:
        self.largest_part = max(self.largest_part, len(value))
        return len(value)

    def tool_result(self, size: int) -> int:
        self.tool_results.append(size)
        self.largest_part = max(self.largest_part, size)
        return size

    def call(self, name: Any) -> None:
        if isinstance(name, str):
            self.called.add(name[:MAX_NAME])

    def image(self, encoded: Any = None) -> None:
        """An image part; `encoded` is its inline base64, None for a reference."""

        self.images += 1
        if not isinstance(encoded, str):
            return
        padding = len(encoded) - len(encoded.rstrip("="))
        size = len(encoded) * 3 // 4 - padding
        if self.largest_image is not None and size <= self.largest_image["bytes"]:
            return
        head = encoded[: _HEADER_BASE64 - _HEADER_BASE64 % 4]
        try:
            width, height = _image_size(
                base64.b64decode(head[: len(head) - len(head) % 4])
            )
        except (binascii.Error, ValueError, struct.error):
            width = height = None
        self.largest_image = {"bytes": size, "width": width, "height": height}


def _data_url(value: Any) -> str | None:
    if isinstance(value, str) and value.startswith("data:"):
        return value.partition("base64,")[2]
    return None


def _content(walk: _Walk, content: Any, part) -> int:
    if isinstance(content, str):
        return walk.text(content)
    if isinstance(content, list):
        return sum(part(walk, item) for item in walk.items(content))
    return 0


def _blocks_text(walk: _Walk, content: Any) -> int:
    """A tool result: a string, or the text of its text blocks."""

    if isinstance(content, str):
        return walk.text(content)
    if isinstance(content, list):
        return sum(
            walk.text(item["text"])
            for item in walk.items(content)
            if isinstance(item, dict)
            and item.get("type") in {"text", "input_text", "output_text"}
            and isinstance(item.get("text"), str)
        )
    return 0


def _openai_part(walk: _Walk, part: Any) -> int:
    if isinstance(part, str):
        return walk.text(part)
    if not isinstance(part, dict):
        return 0
    kind = part.get("type")
    if kind in {"text", "input_text", "output_text"} and isinstance(
        part.get("text"), str
    ):
        return walk.text(part["text"])
    if kind == "image_url":
        image = part.get("image_url")
        walk.image(_data_url(image.get("url") if isinstance(image, dict) else image))
    elif kind == "input_image":
        walk.image(_data_url(part.get("image_url")))
    elif kind in {"file", "input_file"}:
        walk.documents += 1
    return 0


def _chat(walk: _Walk, payload: dict[str, Any]) -> tuple[list[tuple[str, int]], int]:
    turns = []
    for message in walk.items(payload.get("messages") or []):
        if not isinstance(message, dict):
            continue
        role = str(message.get("role"))
        size = _content(walk, message.get("content"), _openai_part)
        if role == "tool":
            walk.tool_result(size)
        for call in message.get("tool_calls") or []:
            if isinstance(call, dict):
                named = call.get("function") or call.get("custom") or {}
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
    for item in walk.items(items if isinstance(items, list) else []):
        if not isinstance(item, dict):
            continue
        kind = item.get("type", "message")
        if kind in {"function_call_output", "custom_tool_call_output"}:
            output = item.get("output")
            turns.append(("tool", walk.tool_result(_blocks_text(walk, output))))
        elif kind in {"function_call", "custom_tool_call"}:
            walk.call(item.get("name"))
            turns.append(("assistant", 0))
        elif kind == "message":
            role = str(item.get("role"))
            turns.append((role, _content(walk, item.get("content"), _openai_part)))
        else:
            turns.append(("assistant", 0))
    return turns, system


def _anthropic_block(walk: _Walk, block: Any) -> int:
    if not isinstance(block, dict):
        return 0
    kind = block.get("type")
    if kind == "text" and isinstance(block.get("text"), str):
        return walk.text(block["text"])
    if kind == "tool_result":
        return walk.tool_result(_blocks_text(walk, block.get("content")))
    if kind in {"tool_use", "server_tool_use"}:
        walk.call(block.get("name"))
    elif kind in {"image", "document"}:
        source = block.get("source")
        inline = (
            source.get("data")
            if isinstance(source, dict) and source.get("type") == "base64"
            else None
        )
        if kind == "image":
            walk.image(inline)
        else:
            walk.documents += 1
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
        for message in walk.items(payload.get("messages") or [])
        if isinstance(message, dict)
    ]
    return turns, system


def _gemini_part(walk: _Walk, part: Any) -> int:
    if not isinstance(part, dict):
        return 0
    if isinstance(part.get("text"), str):
        return walk.text(part["text"])
    if "functionResponse" in part:
        response = part["functionResponse"]
        return walk.tool_result(
            walk.chars(response.get("response")) if isinstance(response, dict) else 0
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
        for content in walk.items(payload.get("contents") or [])
        if isinstance(content, dict)
    ]
    return turns, system


def _offered(protocol: str, tools: list[Any]) -> list[str]:
    names = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        if protocol == "generate_content":
            for key, value in tool.items():
                if key == "functionDeclarations" and isinstance(value, list):
                    names.extend(
                        str(item.get("name"))
                        for item in value
                        if isinstance(item, dict)
                    )
                else:
                    names.append(f"builtin:{key}")
            continue
        named = (
            tool.get("function") or tool.get("custom") if protocol == "chat" else tool
        )
        if isinstance(named, dict) and isinstance(named.get("name"), str):
            names.append(named["name"])
        else:
            names.append(f"builtin:{tool.get('type')}")
    return names


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
    last_user = users[-1] if users else len(turns)
    tools = payload.get("tools")
    tools = tools if isinstance(tools, list) else []
    offered = _offered(protocol, tools)
    if len(offered) > MAX_TOOLS:
        walk.truncated = True
    recorded = [name[:MAX_NAME] for name in offered[:MAX_TOOLS]]
    called = sorted(walk.called)
    if len(called) > MAX_TOOLS:
        walk.truncated = True
    return {
        "message_count": len(turns),
        "system_chars": system,
        "history_chars": sum(
            size for role, size in turns[:last_user] if role not in _SYSTEM_ROLES
        ),
        "last_user_chars": turns[last_user][1] if users else 0,
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
        "image_count": walk.images,
        "document_count": walk.documents,
        "largest_image": walk.largest_image,
        "truncated": walk.truncated,
    }


class ShapeAnalyzer:
    """Counts and names only, from the masked request; it never reads the answer."""

    name = "shape"
    version = "1"

    def analyze(self, ctx: AnalysisContext) -> dict[str, Any] | None:
        return shape(ctx.payload, ctx.protocol)
