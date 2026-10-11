"""Instructions hidden in tool results and documents, counted and never acted on.

The patterns are shim-cli's (`src/shim_cli/events/injection.py`), so both products
flag the same text; a change to them goes to both.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
import re
from typing import Any
import unicodedata

INSTRUCTION_OVERRIDE = "INSTRUCTION_OVERRIDE"
ROLE_REASSIGNMENT = "ROLE_REASSIGNMENT"
SYSTEM_IMPERSONATION = "SYSTEM_IMPERSONATION"
SECRECY_REQUEST = "SECRECY_REQUEST"
HIDDEN_TEXT = "HIDDEN_TEXT"

MARKERS = (
    INSTRUCTION_OVERRIDE,
    ROLE_REASSIGNMENT,
    SYSTEM_IMPERSONATION,
    SECRECY_REQUEST,
    HIDDEN_TEXT,
)

_INVISIBLE = re.compile("[\u200b\u2060-\u2064\u202a-\u202e\U000e0000-\U000e007f]")

# Text and patterns are folded alike (see `fold`), so Turkish typed without its
# letters, in capitals or with the accents apart is the same sentence, and every
# pattern below is written in folded form. A gap between the words of a phrase
# may be a few spaces or a line break.
_S = r"\s{1,4}"
_TR_QUALIFIER = r"\b(?:onceki|yukaridaki|tum|butun|eski|mevcut)\b"
_TR_RULE = r"\b(?:talimat|komut|kural|yonerge|direktif|yonlendirme)\w*"
# Only imperatives end at a word boundary, so "kurallari yok saydik" (a report
# of the past) is not an order.
_TR_IGNORE = (
    rf"\b(?:yok{_S}say(?:in|iniz)?|gormezden{_S}gel(?:in|iniz)?|unut(?:un|unuz)?"
    rf"|dikkate{_S}alma(?:yin|yiniz)?|uyma(?:yin|yiniz)?"
    rf"|gecersiz{_S}say(?:in|iniz)?|iptal{_S}et(?:in|iniz)?)\b"
)
# The nearest rule noun decides; letting the gap swallow one only makes the scan
# retry every later noun, which is what made "eski kural " repeated slow.
_TR_BEFORE_RULE = rf"(?:(?!{_TR_RULE})[^.\n]){{0,40}}?"
# "fix: eski komutlari unut bayragi" is a commit subject, not an order.
_COMMIT = (
    r"(?:fix|feat|chore|docs|refactor|test|perf|build|ci|style|revert)"
    r"(?:\([^)\n]*\))?!?:"
)
# A role is assigned by a predicate ("yoneticisin", "botsun"), not by "sen
# artik" alone; a verb in the aorist ("yapabilirsin", ending "rsin") is not one.
_TR_ROLE = (
    rf"\b(?:sen{_S}artik|artik{_S}sen|bundan{_S}(?:sonra|boyle){_S}sen)\b"
    r"[^.\n]{0,30}[^\Wr]s[iu]n\b"
    rf"|\b(?:gibi{_S}davran(?:in|iniz)?|rolune{_S}gir(?:in|iniz)?"
    rf"|rolunu{_S}ustlen(?:in|iniz)?)\b"
)
# "gosterme mantigi" names a thing; "soyleme," or "gizle ve" gives an order.
_TR_SECRECY = (
    r"\bkullanici(?:ya|dan)\b[^.\n]{0,30}?"
    r"\b(?:soyleme|bildirme|gosterme|aciklama|belirtme|bahsetme|gizle)(?:yin|yiniz)?"
    r"(?=[^\S\n]*(?:[.,;:!?)\]\"']|$|\n)"
    r"|[^\S\n]{1,4}(?:ve|veya|ama|fakat|yoksa|cunku|sakin|asla|lutfen)\b)"
)


def fold(text: str) -> str:
    """Lower case with the Turkish letters as plain ones. Chained `replace`
    because `str.translate` takes ten times as long on text that is not ASCII."""
    folded = unicodedata.normalize("NFC", text).replace("İ", "i").casefold()
    for letter, plain in ("çc", "ğg", "ıi", "öo", "şs", "üu"):
        folded = folded.replace(letter, plain)
    return folded


_PATTERNS = (
    (
        INSTRUCTION_OVERRIDE,
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}?"
            r"\b(?:previous|prior|above|earlier|all)\b[^.\n]{0,20}?"
            r"\b(?:instruction|prompt|rule|direction|command)s?\b"
        ),
    ),
    (
        INSTRUCTION_OVERRIDE,
        re.compile(
            rf"(?m)^(?![^\S\n]*{_COMMIT})[^\n]*?(?:"
            rf"{_TR_QUALIFIER}{_TR_BEFORE_RULE}{_TR_RULE}[^.\n]{{0,30}}?{_TR_IGNORE}"
            rf"|{_TR_IGNORE}[^.\n]{{0,30}}?{_TR_QUALIFIER}[^.\n]{{0,40}}?{_TR_RULE})"
        ),
    ),
    (
        ROLE_REASSIGNMENT,
        re.compile(
            r"\b(?:you\s{1,4}are\s{1,4}now|from\s{1,4}now\s{1,4}on\s{1,4}you"
            r"|act\s{1,4}as\s{1,4}(?:a|an|the)\b"
            r"|pretend\s{1,4}(?:to\s{1,4}be|you\s{1,4}are))"
        ),
    ),
    (ROLE_REASSIGNMENT, re.compile(_TR_ROLE)),
    (
        # The Turkish label is data ("Sistem: Linux 6.1", YAML "sistem:
        # production") unless it is bracketed or followed by a sentence.
        SYSTEM_IMPERSONATION,
        re.compile(
            r"(?:^|\n)[^\S\n]{0,8}(?:"
            r"(?:\[|<|\#{1,3}[^\S\n]{0,4})?(?:system|assistant)[^\S\n]{0,4}(?:\]|>|:)"
            r"|[\[<][^\S\n]{0,4}(?:sistem|asistan)[^\S\n]{0,4}[\]>:]"
            r"|(?:\#{1,3}[^\S\n]{0,4})?(?:sistem|asistan)[^\S\n]{0,4}:"
            r"[^\S\n]{0,4}[^\W\d_]+[^\S\n]{1,4}[^\W\d_]+)"
            r"|<[^\S\n]{0,4}/?[^\S\n]{0,4}"
            r"(?:system|important_instructions)[^\S\n]{0,4}>"
        ),
    ),
    (
        SECRECY_REQUEST,
        re.compile(
            r"\b(?:do\s{0,4}not|don'?t|never)\b[^.\n]{0,30}?"
            r"\b(?:tell|inform|mention|reveal|show|disclose)\b[^.\n]{0,20}?"
            r"\b(?:the\s{1,4})?(?:user|human|operator)\b"
        ),
    ),
    (SECRECY_REQUEST, re.compile(_TR_SECRECY)),
)

MIN_TEXT_CHARACTERS = 24


def scan(text: str) -> tuple[str, ...]:
    if len(text) < MIN_TEXT_CHARACTERS:
        return ()
    found = []
    if _INVISIBLE.search(text):
        found.append(HIDDEN_TEXT)
    folded = fold(text)
    for name, pattern in _PATTERNS:
        if pattern.search(folded):
            found.append(name)
    return tuple(name for name in MARKERS if name in found)


# Per tool result or document, longer text is cut before scanning.
MAX_SCANNED_CHARACTERS = 1_000_000


def _texts(value: Any) -> Iterator[str]:
    """Every string inside a JSON value, without recursion."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, Mapping):
            stack.extend(reversed(list(item.values())))
        elif isinstance(item, list):
            stack.extend(reversed(item))


def _parts(content: Any, kinds: frozenset[str]) -> Iterator[str]:
    """A string, or the `text` of each part of the given types in a list."""
    if isinstance(content, str):
        yield content
    elif isinstance(content, list):
        for part in content:
            if isinstance(part, Mapping) and part.get("type") in kinds:
                text = part.get("text")
                if isinstance(text, str):
                    yield text


_TEXT = frozenset({"text"})
_INPUT_TEXT = frozenset({"input_text", "output_text", "text"})


def _blocks(payload: Mapping[str, Any], protocol: str) -> Iterator[Iterator[str]]:
    """The text of each tool result and document block the request carries."""
    if protocol == "chat":
        for message in payload.get("messages") or ():
            if isinstance(message, Mapping) and message.get("role") in {
                "tool",
                "function",
            }:
                yield _parts(message.get("content"), _TEXT)
    elif protocol == "responses":
        items = payload.get("input")
        for item in items if isinstance(items, list) else ():
            if not isinstance(item, Mapping):
                continue
            if item.get("type") in {
                "function_call_output",
                "custom_tool_call_output",
                "mcp_call",
            }:
                yield _parts(item.get("output"), _INPUT_TEXT)
    elif protocol in {"messages", "count_tokens"}:
        for message in payload.get("messages") or ():
            content = message.get("content") if isinstance(message, Mapping) else None
            for block in content if isinstance(content, list) else ():
                if not isinstance(block, Mapping):
                    continue
                kind = block.get("type")
                if kind in {"tool_result", "search_result"}:
                    yield _parts(block.get("content"), _TEXT)
                elif kind == "document" and isinstance(
                    source := block.get("source"), Mapping
                ):
                    if source.get("type") == "text":
                        yield _parts(source.get("data"), _TEXT)
                    elif source.get("type") == "content":
                        yield _parts(source.get("content"), _TEXT)
    elif protocol == "generate_content":
        for content in payload.get("contents") or ():
            parts = content.get("parts") if isinstance(content, Mapping) else None
            for part in parts if isinstance(parts, list) else ():
                response = (
                    part.get("functionResponse") if isinstance(part, Mapping) else None
                )
                if isinstance(response, Mapping):
                    yield _texts(response.get("response"))


def scan_payload(payload: Mapping[str, Any], protocol: str) -> dict[str, int]:
    """Per marker, how many tool results or documents carry it; user and system text is not read."""
    counts: dict[str, int] = {}
    for texts in _blocks(payload, protocol):
        for marker in scan("\n".join(texts)[:MAX_SCANNED_CHARACTERS]):
            counts[marker] = counts.get(marker, 0) + 1
    return counts
