"""The `language` analyzer: Turkish or English, in the question and the answer, without a model."""

from __future__ import annotations

from importlib.resources import files
import json
import re
from typing import Any, Literal
import unicodedata

from shim.gateway.analyzers.schema import requested_output
from shim.gateway.pipeline.analysis import AnalysisContext

Label = Literal["tr", "en", "other", "unknown"]

# A change to the word lists after release is a new file and a new version.
VERSION = "1"
_DATA = json.loads(
    files("shim.gateway.analyzers")
    .joinpath(f"language-v{VERSION}.json")
    .read_text("utf-8")
)
_ASCII_FOLD = str.maketrans(
    {
        "ç": "c",
        "ğ": "g",
        "ı": "i",
        "ö": "o",
        "ş": "s",
        "ü": "u",
        "â": "a",
        "î": "i",
        "û": "u",
    }
)
_STRONG = frozenset("ğĞıİşŞ")
_WEAK = frozenset("çÇöÖüÜ")
_CLEAN = re.compile(
    r"```.*?(?:```|\Z)"  # fenced code, closed or running to the end
    r"|`[^`\n]*`"  # inline code
    r"|\b(?:https?://|www\.)\S+"  # URLs
    r"|(?<!\S)[^\s@]{1,64}@[^\s@]{1,64}"  # e-mail-like tokens; bounded, from a token's start
    r"|<\s*[A-Z][A-Z0-9_]*_[0-9a-f]{8,32}(?:~[0-9A-Z]{4})?\s*>",  # placeholders
    re.DOTALL,
)
_WORD = re.compile(r"[^\W\d_]+")


def _turkish_lower(word: str) -> str:
    return word.replace("İ", "i").replace("I", "ı").lower()


def _fold(word: str) -> str:
    return _turkish_lower(word).translate(_ASCII_FOLD)


_TR_WORDS = frozenset(_fold(word) for word in _DATA["tr_function_words"])
_EN_WORDS = frozenset(_DATA["en_function_words"])
_TR_SUFFIXES = tuple(_fold(suffix) for suffix in _DATA["tr_suffixes"])


def _latin(character: str) -> bool:
    return unicodedata.name(character, "").startswith("LATIN")


def label(text: str) -> tuple[Label, bool, int]:
    """The label, whether the text is mixed, and its word count."""

    # Cut first: the cleaning pattern then reads a bounded window, whatever the text.
    words = _WORD.findall(_CLEAN.sub(" ", text[: _DATA["max_characters"]]))
    letters = sum(len(word) for word in words)
    if len(words) < _DATA["min_words"] or letters < _DATA["min_letters"]:
        return "unknown", False, len(words)
    if sum(_latin(c) for word in words for c in word) * 2 < letters:
        return "other", False, len(words)
    turkish = english = 0.0
    strong = turkish_hits = 0
    for word in words:
        folded = _fold(word)
        if _STRONG.intersection(word):
            turkish += _DATA["strong_letter_score"]
            strong += 1
        elif _WEAK.intersection(word):
            turkish += _DATA["weak_letter_score"]
        if folded in _TR_WORDS:
            turkish += 1
            turkish_hits += 1
        if len(word) >= _DATA["suffix_min_letters"] and folded.endswith(_TR_SUFFIXES):
            turkish += _DATA["suffix_score"]
        # The pronoun I counts only as written, so a Turkish "ı" or "i" never does.
        if word == "I" or (word.lower() in _EN_WORDS):
            english += 1
    qualify = _DATA["qualify_score"]
    tr_ok = turkish >= qualify and (strong > 0 or turkish_hits >= 2)
    # A share, not only a count: a long Dutch or Italian text has a few English words too.
    en_ok = english >= max(qualify, _DATA["en_min_share"] * len(words))
    if tr_ok and en_ok:
        small, large = sorted((turkish, english))
        larger: Label = "tr" if turkish > english else "en"
        return larger, small >= _DATA["mixed_ratio"] * large, len(words)
    if tr_ok or en_ok:
        return "tr" if tr_ok else "en", False, len(words)
    return "other", False, len(words)


def _text(content: Any, kinds: frozenset[str]) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    return "\n".join(
        part["text"]
        for part in content
        if isinstance(part, dict)
        and part.get("type", "text") in kinds
        and isinstance(part.get("text"), str)
    )


def request_text(payload: dict[str, Any], protocol: str) -> str:
    """The text of the most recent user turn that has any; tool results are not text."""

    kinds = frozenset({"text"})
    if protocol == "responses":
        items = payload.get("input")
        if isinstance(items, str):
            return items
        kinds = frozenset({"input_text"})
        turns = [
            (item.get("role"), item.get("content"))
            for item in (items if isinstance(items, list) else [])
            if isinstance(item, dict) and item.get("type", "message") == "message"
        ]
    elif protocol == "generate_content":
        turns = [
            (content.get("role", "user"), content.get("parts"))
            for content in payload.get("contents") or []
            if isinstance(content, dict)
        ]
    else:
        turns = [
            (message.get("role"), message.get("content"))
            for message in payload.get("messages") or []
            if isinstance(message, dict)
        ]
    for role, content in reversed(turns):
        text = _text(content, kinds) if role == "user" else ""
        if text.strip():
            return text
    return ""


class LanguageAnalyzer:
    """Labels the last user question and the answer: tr, en, other or unknown."""

    name = "language"
    version = VERSION
    reads_answer = True

    def analyze(self, ctx: AnalysisContext) -> dict[str, Any]:
        request, _, request_words = label(request_text(ctx.payload, ctx.protocol))
        if not ctx.answer_text or requested_output(ctx.payload, ctx.protocol):
            answer, mixed, answer_words = "unknown", False, 0
        else:
            answer, mixed, answer_words = label(ctx.answer_text)
        return {
            "request": request,
            "answer": answer,
            "answer_mixed": mixed,
            "request_words": request_words,
            "answer_words": answer_words,
        }
