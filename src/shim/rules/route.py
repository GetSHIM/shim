"""Route rules: a conversation's first turn decides which model serves all of it."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import hmac
import re
import unicodedata
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from shim.rules.content import turkish_fold
from shim.privacy.policies import (
    OPAQUE_MEDIA_FIELDS,
    OPAQUE_MEDIA_TYPE_FIELDS,
)

_Model = Annotated[str, StringConstraints(min_length=1, max_length=200)]
_Keyword = Annotated[str, StringConstraints(min_length=1, max_length=64)]
_Chars = Annotated[int, Field(ge=1, le=10_000_000)]
# Characters of the start view the keywords are looked for in.
KEYWORD_WINDOW = 20_000
_CONVERSATION_HEADER = re.compile(r"[A-Za-z0-9._:-]{1,128}")
# The `on` values other features own: E63 unavailable, E64 capacity, E65
# format_invalid, E66 split, E67 degrade, E68 size, E70 shadow.
ROUTE_TRIGGERS = frozenset(
    {"unavailable", "capacity", "format_invalid", "split", "degrade", "size", "shadow"}
)


class RouteWhen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    max_start_chars: _Chars | None = None
    min_start_chars: _Chars | None = None
    tools: bool | None = None
    media: bool | None = None
    structured_output: bool | None = None
    keywords_any: tuple[_Keyword, ...] | None = Field(default=None, max_length=50)
    keywords_none: tuple[_Keyword, ...] | None = Field(default=None, max_length=50)

    @model_validator(mode="after")
    def at_least_one(self) -> RouteWhen:
        if all(value is None for value in self.model_dump().values()):
            raise ValueError("when names at least one condition")
        return self


class RequestRoute(BaseModel):
    """The request-start route rule: `from` models go to `to` when `when` holds."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    from_: tuple[_Model, ...] = Field(alias="from", min_length=1, max_length=20)
    to: _Model
    when: RouteWhen | None = None

    @model_validator(mode="after")
    def to_is_not_from(self) -> RequestRoute:
        if self.to in self.from_:
            raise ValueError("to is one of the from models")
        return self


class RouteMatch(BaseModel):
    """A `route` rule's match. Without `on` it is this module's request-start rule;
    an `on` value another feature owns is kept as sent, for that feature to read."""

    model_config = ConfigDict(frozen=True, extra="allow")

    @model_validator(mode="before")
    @classmethod
    def by_owner(cls, data: Any) -> Any:
        if not isinstance(data, Mapping):
            raise ValueError("match is an object")
        if "on" not in data:
            return RequestRoute.model_validate(data).model_dump(
                mode="json", by_alias=True, exclude_none=True
            )
        on = data["on"]
        if not isinstance(on, str) or on not in ROUTE_TRIGGERS:
            raise ValueError(f"on is one of {', '.join(sorted(ROUTE_TRIGGERS))}")
        return data


def owned(match: Mapping[str, Any]) -> bool:
    """A match the request-start router evaluates; every `on` value is another's."""
    return "on" not in match


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(content: object) -> str:
    if isinstance(content, str):
        return content
    return "\n".join(
        part["text"]
        for part in _list(content)
        if isinstance(part, Mapping) and isinstance(part.get("text"), str)
    )


def _parts(content: object) -> list[Mapping[str, Any]]:
    return [part for part in _list(content) if isinstance(part, Mapping)]


def start_view(
    payload: Mapping[str, Any], protocol: str
) -> tuple[str, list[Mapping[str, Any]]] | None:
    """The first turn's text and parts; None for a conversation the provider keeps
    and for endpoints that are not conversations (token counts, embeddings)."""

    if protocol == "responses":
        # The provider holds that conversation's state where it started.
        if (
            payload.get("previous_response_id")
            or payload.get("conversation")
            or payload.get("store") is not False
        ):
            return None
        items = payload.get("input")
        first = (
            items
            if isinstance(items, str)
            else next(
                (
                    item.get("content")
                    for item in _list(items)
                    if isinstance(item, Mapping) and item.get("role") == "user"
                ),
                None,
            )
        )
        return "\n".join(
            filter(None, [_text(payload.get("instructions")), _text(first)])
        ), _parts(first)
    if protocol == "generate_content":
        system = payload.get("systemInstruction")
        first = next(
            (
                content.get("parts")
                for content in _list(payload.get("contents"))
                if isinstance(content, Mapping)
                and content.get("role", "user") == "user"
            ),
            None,
        )
        return "\n".join(
            filter(
                None,
                [
                    _text(system.get("parts") if isinstance(system, Mapping) else None),
                    _text(first),
                ],
            )
        ), _parts(first)
    if protocol not in {"chat", "messages"}:
        return None
    texts = [_text(payload.get("system"))] if protocol == "messages" else []
    first: object = None
    for message in _list(payload.get("messages")):
        if not isinstance(message, Mapping):
            continue
        if message.get("role") == "user":
            first = message.get("content")
            break
        if message.get("role") in {"system", "developer"}:
            texts.append(_text(message.get("content")))
    return "\n".join(filter(None, [*texts, _text(first)])), _parts(first)


def _folded(text: str) -> str:
    # The fold term rules use: Turkish I letters as one, whitespace runs as one space.
    return turkish_fold(unicodedata.normalize("NFKC", text[:KEYWORD_WINDOW]))


def _has_keyword(folded: str, keyword: str) -> bool:
    # At a word start, so "fatura" finds "faturalar" and not "afatura".
    return re.search(rf"(?<!\w){re.escape(_folded(keyword))}", folded) is not None


def _media(parts: list[Mapping[str, Any]]) -> bool:
    return any(
        part.get("type") in OPAQUE_MEDIA_TYPE_FIELDS
        or part.get("type") == "document"
        or any(part.get(field) is not None for field in OPAQUE_MEDIA_FIELDS)
        for part in parts
    )


def _structured(payload: Mapping[str, Any]) -> bool:
    response_format = payload.get("response_format")
    text = payload.get("text")
    output = payload.get("output_config")
    config = payload.get("generationConfig")
    return bool(
        (
            isinstance(response_format, Mapping)
            and response_format.get("type") in {"json_schema", "json_object"}
        )
        or (
            isinstance(text, Mapping)
            and isinstance(text.get("format"), Mapping)
            and text["format"].get("type") in {"json_schema", "json_object"}
        )
        or (isinstance(output, Mapping) and output.get("format") is not None)
        or (
            isinstance(config, Mapping)
            and (
                config.get("responseSchema") is not None
                or config.get("responseJsonSchema") is not None
            )
        )
    )


def route_reason(
    when: Mapping[str, Any] | None,
    payload: Mapping[str, Any],
    view: tuple[str, list[Mapping[str, Any]]],
) -> str | None:
    """The first condition's name, `always` without conditions, None when one fails."""

    if not when:
        return "always"
    text, parts = view
    folded = (
        _folded(text) if when.get("keywords_any") or when.get("keywords_none") else ""
    )
    checks = {
        "max_start_chars": lambda bound: len(text) <= bound,
        "min_start_chars": lambda bound: len(text) >= bound,
        "tools": lambda wanted: bool(_list(payload.get("tools"))) is wanted,
        "media": lambda wanted: _media(parts) is wanted,
        "structured_output": lambda wanted: _structured(payload) is wanted,
        "keywords_any": lambda words: any(_has_keyword(folded, word) for word in words),
        "keywords_none": lambda words: (
            not any(_has_keyword(folded, word) for word in words)
        ),
    }
    named = [name for name in checks if when.get(name) is not None]
    if all(checks[name](when[name]) for name in named):
        return named[0]
    return None


def conversation_id(sent: str | None, key: bytes, start_text: str) -> str:
    """A keyed digest of the client's `X-Shim-Conversation-Id`, else of the first turn.

    Never the header itself: a client may put a name or an identifier in it.
    """

    if sent is not None and _CONVERSATION_HEADER.fullmatch(sent):
        material = b"header\0" + sent.encode("ascii")
    else:
        # The resolver runs before admission refuses a lone surrogate with a 400.
        material = b"start\0" + start_text.encode("utf-8", "surrogatepass")
    return hmac.new(key, material, hashlib.sha256).hexdigest()[:16]
