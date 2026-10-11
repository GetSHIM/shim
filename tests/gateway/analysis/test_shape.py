from __future__ import annotations

import base64
from hashlib import sha256
import struct

import pytest

from shim.gateway.analyzers import ANALYZER_NAMES, ANALYZERS
from shim.gateway.analyzers.shape import MAX_TOOLS, ShapeAnalyzer, shape
from shim.gateway.pipeline.analysis import AnalysisContext


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _png(width: int, height: int, padding: int = 0) -> bytes:
    return (
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\x0dIHDR"
        + struct.pack(">II", width, height)
        + b"\x00" * padding
    )


def _gif(width: int, height: int) -> bytes:
    return b"GIF89a" + struct.pack("<HH", width, height) + b"\x00" * 8


def _webp_vp8x(width: int, height: int) -> bytes:
    return (
        b"RIFF\x00\x00\x00\x00WEBPVP8X"
        + b"\x0a\x00\x00\x00\x00\x00\x00\x00"
        + (width - 1).to_bytes(3, "little")
        + (height - 1).to_bytes(3, "little")
    )


def _webp_vp8l(width: int, height: int) -> bytes:
    bits = (width - 1) | ((height - 1) << 14)
    return b"RIFF\x00\x00\x00\x00WEBPVP8L\x00\x00\x00\x00\x2f" + bits.to_bytes(
        4, "little"
    )


def _webp_vp8(width: int, height: int) -> bytes:
    return (
        b"RIFF\x00\x00\x00\x00WEBPVP8 \x00\x00\x00\x00"
        + b"\x00\x00\x00\x9d\x01\x2a"
        + struct.pack("<HH", width, height)
    )


def _jpeg(width: int, height: int) -> bytes:
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00" + b"\x00" * 9
    sof2 = b"\xff\xc2" + struct.pack(">HBHH", 11, 8, height, width) + b"\x00" * 4
    return b"\xff\xd8" + app0 + sof2


_TOOLS_CHAT = [
    {"type": "function", "function": {"name": "lookup", "parameters": {}}},
    {"type": "function", "function": {"name": "search", "parameters": {}}},
]


def test_chat_counts_every_key() -> None:
    payload = {
        "model": "gpt-5-nano",
        "messages": [
            {"role": "system", "content": "You are terse."},
            {"role": "user", "content": "first question"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "type": "function",
                        "function": {"name": "lookup", "arguments": "{}"},
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "c1", "content": "tool says hi"},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "and now"},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": "data:image/png;base64," + _b64(_png(3, 2))
                        },
                    },
                    {
                        "type": "image_url",
                        "image_url": {"url": "https://example.com/a.png"},
                    },
                    {"type": "file", "file": {"file_id": "f1"}},
                ],
            },
        ],
        "tools": _TOOLS_CHAT,
    }

    result = shape(payload, "chat")

    names = ["lookup", "search"]
    assert result == {
        "message_count": 5,
        "system_chars": len("You are terse."),
        "history_chars": len("first question") + len("tool says hi"),
        "last_user_chars": len("and now"),
        "largest_part_chars": len("first question"),
        "tool_result_count": 1,
        "tool_result_chars": len("tool says hi"),
        "largest_tool_result_chars": len("tool says hi"),
        "tool_count": 2,
        "tool_definition_chars": len(
            '[{"type":"function","function":{"name":"lookup","parameters":{}}},'
            '{"type":"function","function":{"name":"search","parameters":{}}}]'
        ),
        "tools_offered": names,
        "tools_called_in_history": ["lookup"],
        "tools_order_digest": sha256("\x1f".join(names).encode()).hexdigest()[:16],
        "tools_set_digest": sha256("\x1f".join(names).encode()).hexdigest()[:16],
        "image_count": 2,
        "document_count": 1,
        "largest_image": {"bytes": len(_png(3, 2)), "width": 3, "height": 2},
        "truncated": False,
    }


def test_responses_string_input_instructions_and_builtins() -> None:
    result = shape(
        {
            "input": "hello there",
            "instructions": "be brief",
            "tools": [{"type": "function", "name": "lookup"}, {"type": "web_search"}],
        },
        "responses",
    )

    assert (
        result["message_count"],
        result["last_user_chars"],
        result["system_chars"],
    ) == (1, 11, 8)
    assert result["tools_offered"] == ["lookup", "builtin:web_search"]
    assert result["tool_count"] == 2


def test_responses_items_replay_calls_and_outputs() -> None:
    result = shape(
        {
            "input": [
                {"role": "developer", "content": "rules"},
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": "find it"}],
                },
                {
                    "type": "function_call",
                    "name": "lookup",
                    "arguments": "{}",
                    "call_id": "c",
                },
                {"type": "function_call_output", "call_id": "c", "output": "found"},
                {
                    "type": "custom_tool_call",
                    "name": "grep",
                    "input": "x",
                    "call_id": "d",
                },
                {
                    "type": "custom_tool_call_output",
                    "call_id": "d",
                    "output": [{"type": "input_text", "text": "lines"}],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_image",
                            "image_url": "https://example.com/i.png",
                        },
                        {"type": "input_file", "file_id": "f"},
                    ],
                },
            ]
        },
        "responses",
    )

    assert result["tools_called_in_history"] == ["grep", "lookup"]
    assert (result["tool_result_count"], result["tool_result_chars"]) == (
        2,
        len("found") + len("lines"),
    )
    assert (
        result["system_chars"],
        result["image_count"],
        result["document_count"],
    ) == (5, 1, 1)
    assert result["history_chars"] == len("find it") + len("found") + len("lines")


def test_anthropic_system_blocks_tool_results_and_media() -> None:
    result = shape(
        {
            "system": [
                {"type": "text", "text": "sys one"},
                {"type": "text", "text": "two"},
            ],
            "messages": [
                {"role": "user", "content": "start"},
                {
                    "role": "assistant",
                    "content": [
                        {"type": "tool_use", "id": "t", "name": "lookup", "input": {}},
                        {
                            "type": "server_tool_use",
                            "id": "s",
                            "name": "web_search",
                            "input": {},
                        },
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "t",
                            "content": [
                                {"type": "text", "text": "abc"},
                                {
                                    "type": "image",
                                    "source": {"type": "url", "url": "u"},
                                },
                            ],
                        },
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/gif",
                                "data": _b64(_gif(5, 7)),
                            },
                        },
                        {
                            "type": "document",
                            "source": {
                                "type": "base64",
                                "media_type": "application/pdf",
                                "data": "JVBERi0=",
                            },
                        },
                    ],
                },
            ],
            "tools": [{"name": "lookup", "input_schema": {}}],
        },
        "messages",
    )

    assert result["system_chars"] == len("sys one") + len("two")
    assert result["tools_called_in_history"] == ["lookup", "web_search"]
    assert (result["tool_result_count"], result["tool_result_chars"]) == (1, 3)
    assert result["last_user_chars"] == 3 and result["history_chars"] == len("start")
    assert result["largest_image"] == {
        "bytes": len(_gif(5, 7)),
        "width": 5,
        "height": 7,
    }
    assert (result["image_count"], result["document_count"]) == (1, 1)


def test_gemini_parts_and_builtin_tools() -> None:
    result = shape(
        {
            "systemInstruction": {"parts": [{"text": "sys"}]},
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {"text": "hi"},
                        {
                            "fileData": {
                                "mimeType": "image/png",
                                "fileUri": "gs://b/i.png",
                            }
                        },
                        {
                            "fileData": {
                                "mimeType": "application/pdf",
                                "fileUri": "gs://b/d.pdf",
                            }
                        },
                    ],
                },
                {
                    "role": "model",
                    "parts": [{"functionCall": {"name": "lookup", "args": {}}}],
                },
                {
                    "role": "user",
                    "parts": [
                        {
                            "functionResponse": {
                                "name": "lookup",
                                "response": {"result": "found it"},
                            }
                        }
                    ],
                },
            ],
            "tools": [
                {"functionDeclarations": [{"name": "lookup"}]},
                {"googleSearch": {}},
            ],
        },
        "generate_content",
    )

    assert result["tools_offered"] == ["lookup", "builtin:googleSearch"]
    assert result["tools_called_in_history"] == ["lookup"]
    assert (result["image_count"], result["document_count"]) == (1, 1)
    assert (result["tool_result_count"], result["tool_result_chars"]) == (
        1,
        len("found it"),
    )
    assert (result["system_chars"], result["message_count"]) == (3, 3)


def test_without_tools_the_digests_are_null() -> None:
    result = shape({"messages": [{"role": "user", "content": "x"}]}, "chat")

    assert (
        result["tool_count"],
        result["tools_offered"],
        result["tool_definition_chars"],
    ) == (0, [], 0)
    assert result["tools_order_digest"] is result["tools_set_digest"] is None


def test_the_order_digest_follows_order_and_the_set_digest_does_not() -> None:
    forward = shape({"messages": [], "tools": _TOOLS_CHAT}, "chat")
    backward = shape({"messages": [], "tools": _TOOLS_CHAT[::-1]}, "chat")
    again = shape({"messages": [], "tools": _TOOLS_CHAT}, "chat")

    assert forward["tools_set_digest"] == backward["tools_set_digest"]
    assert forward["tools_order_digest"] != backward["tools_order_digest"]
    assert forward["tools_order_digest"] == again["tools_order_digest"]


def test_tools_and_names_are_bounded() -> None:
    tools = [
        {"type": "function", "function": {"name": f"t{index}"}}
        for index in range(MAX_TOOLS + 1)
    ]
    tools[0]["function"]["name"] = "n" * 65

    result = shape({"messages": [], "tools": tools}, "chat")

    assert result["tool_count"] == 129 and len(result["tools_offered"]) == 128
    assert result["tools_offered"][0] == "n" * 64 and result["truncated"] is True


def test_nesting_and_part_counts_are_bounded() -> None:
    nested: object = "deep"
    for _ in range(65):
        nested = {"x": nested}
    deep = shape(
        {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"functionResponse": {"name": "f", "response": nested}}],
                }
            ]
        },
        "generate_content",
    )
    many = shape({"messages": [{"role": "user", "content": "x"}] * 20_001}, "chat")

    assert deep["truncated"] is True and deep["tool_result_chars"] == 0
    assert many["truncated"] is True and many["message_count"] < 20_001


@pytest.mark.parametrize(
    ("data", "size"),
    [
        (_png(640, 480, 100), (640, 480)),
        (_gif(32, 16), (32, 16)),
        (_webp_vp8x(1024, 768), (1024, 768)),
        (_webp_vp8l(300, 200), (300, 200)),
        (_webp_vp8(50, 40), (50, 40)),
        (_jpeg(800, 600), (800, 600)),
        (b"plain text, not an image", (None, None)),
        (_png(640, 480)[:12], (None, None)),
    ],
)
def test_image_headers_give_their_size(data: bytes, size) -> None:
    result = shape(
        {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image_url",
                            "image_url": {"url": "data:image/png;base64," + _b64(data)},
                        }
                    ],
                }
            ]
        },
        "chat",
    )

    assert result["largest_image"] == {
        "bytes": len(data),
        "width": size[0],
        "height": size[1],
    }


def test_malformed_base64_and_the_largest_image() -> None:
    parts = [
        {
            "type": "image_url",
            "image_url": {"url": "data:image/png;base64," + _b64(_png(2, 2))},
        },
        {
            "type": "image_url",
            "image_url": {"url": "data:image/png;base64,@@@notbase64@@@"},
        },
        {
            "type": "image_url",
            "image_url": {
                "url": "data:image/gif;base64," + _b64(_gif(9, 9) + b"\x00" * 500)
            },
        },
    ]

    result = shape({"messages": [{"role": "user", "content": parts}]}, "chat")

    assert result["image_count"] == 3
    assert result["largest_image"] == {
        "bytes": len(_gif(9, 9)) + 500,
        "width": 9,
        "height": 9,
    }


def test_a_placeholder_is_counted_as_written() -> None:
    placeholder = "<EMAIL_ADDRESS_0123abcd>"

    result = shape(
        {"messages": [{"role": "system", "content": f"Mail {placeholder}"}]}, "chat"
    )

    assert result["system_chars"] == len(f"Mail {placeholder}")


def test_the_analyzer_is_registered_and_never_reads_the_answer() -> None:
    class _NoAnswer(AnalysisContext):
        def __getattribute__(self, name: str):
            if name in {"answer_text", "tool_calls"}:
                raise AssertionError(f"read {name}")
            return super().__getattribute__(name)

    context = _NoAnswer(
        request_id="req",
        protocol="chat",
        model="gpt-5-nano",
        payload={"messages": [{"role": "user", "content": "hi"}]},
        answer_text="secret answer",
        answer_truncated=False,
        tool_calls=(),
        completion_outcome="complete",
        restore=lambda text: text,
    )

    assert "shape" in ANALYZER_NAMES
    assert any(isinstance(analyzer, ShapeAnalyzer) for analyzer in ANALYZERS)
    assert ShapeAnalyzer().analyze(context)["last_user_chars"] == 2
