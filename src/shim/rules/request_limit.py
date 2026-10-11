"""Request-limit rules: caps on tools, documents, history, size and the price tier."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

_NOT_DOCUMENTS = ("image/", "audio/", "video/")


class RequestLimitMatch(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    max_tools: int | None = Field(default=None, ge=0, le=10_000)
    max_documents: int | None = Field(default=None, ge=0, le=1_000)
    max_history: int | None = Field(default=None, ge=1, le=100_000)
    max_input_bytes: int | None = Field(default=None, ge=1_024, le=32_000_000)
    below_price_tier: Literal[True] | None = None

    @model_validator(mode="after")
    def at_least_one(self) -> RequestLimitMatch:
        if all(value is None for value in self.model_dump().values()):
            raise ValueError("set at least one limit")
        return self


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _parts(items: object) -> Iterator[Mapping[str, Any]]:
    """The content parts of each item in a list of turns."""
    for item in _list(items):
        if isinstance(item, Mapping):
            yield from (
                part for part in _list(item.get("content")) if isinstance(part, Mapping)
            )


def _anthropic_documents(blocks: object) -> int:
    count = 0
    for block in _list(blocks):
        if isinstance(block, Mapping):
            if block.get("type") == "document":
                count += 1
            elif block.get("type") == "tool_result":
                count += _anthropic_documents(block.get("content"))
    return count


def request_measures(payload: Mapping[str, Any], protocol: str) -> tuple[int, int, int]:
    """Tool definitions, document parts and history items, as the request sends them."""
    if protocol == "generate_content":
        tools = sum(
            len(_list(tool.get("functionDeclarations")))
            if "functionDeclarations" in tool
            else 1
            for tool in _list(payload.get("tools"))
            if isinstance(tool, Mapping)
        )
        documents = 0
        for content in _list(payload.get("contents")):
            for part in _list(
                content.get("parts") if isinstance(content, Mapping) else None
            ):
                media = (
                    (part.get("inlineData") or part.get("fileData"))
                    if isinstance(part, Mapping)
                    else None
                )
                if isinstance(media, Mapping) and not str(
                    media.get("mimeType", "")
                ).startswith(_NOT_DOCUMENTS):
                    documents += 1
        return tools, documents, len(_list(payload.get("contents")))
    tools = len(_list(payload.get("tools")))
    if protocol == "chat":
        documents = sum(
            part.get("type") == "file" for part in _parts(payload.get("messages"))
        )
        return tools, documents, len(_list(payload.get("messages")))
    if protocol == "responses":
        items = payload.get("input")
        documents = sum(
            part.get("type") == "input_file" for part in _parts(items)
        ) + sum(
            isinstance(item, Mapping) and item.get("type") == "input_file"
            for item in _list(items)
        )
        return tools, documents, 1 if isinstance(items, str) else len(_list(items))
    messages = payload.get("messages")
    documents = sum(
        _anthropic_documents(message.get("content"))
        for message in _list(messages)
        if isinstance(message, Mapping)
    )
    return tools, documents, len(_list(messages))
