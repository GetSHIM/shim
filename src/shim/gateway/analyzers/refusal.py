"""The `refusal` analyzer: a complete answer that refuses in words ("yardımcı olamam")."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
import json
import re
from typing import Any

from shim.gateway.pipeline.analysis import AnalysisContext

_DATA = json.loads(
    files("shim.gateway.analyzers").joinpath("refusal-v1.json").read_text("utf-8")
)
_QUOTES = str.maketrans(
    {
        "’": "'",
        "‘": "'",
        "ʼ": "'",
        "‛": "'",
        "“": '"',
        "”": '"',
        "„": '"',
        "«": '"',
        "»": '"',
    }
)
_ASCII_FOLD = str.maketrans(
    {"ç": "c", "ğ": "g", "ı": "i", "ö": "o", "ş": "s", "ü": "u"}
)
# Emphasis anywhere, then leading whitespace, heading and quote markers.
_LEADING = re.compile(r"""^[\s#>"'`]+""")
_EMPHASIS = re.compile(r"[*_]+")
_QUOTE_CHARACTERS = frozenset("\"'`")


def normalise(text: str) -> str:
    start = _EMPHASIS.sub("", text.translate(_QUOTES))
    start = _LEADING.sub("", start)[: _DATA["normalised_characters"]]
    start = start.replace("İ", "i").replace("I", "ı").lower().translate(_ASCII_FOLD)
    return " ".join(start.split())


@dataclass(frozen=True, slots=True)
class _Marker:
    id: str
    phrases: tuple[str, ...]
    unless: tuple[str, ...]


_MARKERS = tuple(
    _Marker(
        marker["id"],
        tuple(normalise(phrase) for phrase in marker["phrases"]),
        tuple(normalise(phrase) for phrase in marker["unless_followed_by"]),
    )
    for marker in _DATA["markers"]
)


def _refuses(start: str, marker: _Marker) -> bool:
    for phrase in marker.phrases:
        index = start.find(phrase)
        while 0 <= index < _DATA["start_window"]:
            end = index + len(phrase)
            quoted = index > 0 and start[index - 1] in _QUOTE_CHARACTERS
            # An exception phrase starting within the window after the match.
            partial = any(
                start.find(unless, end, end + _DATA["unless_window"] + len(unless)) >= 0
                for unless in marker.unless
            )
            if not quoted and not partial:
                return True
            index = start.find(phrase, index + 1)
    return False


def soft_refusal(text: str) -> str | None:
    """The id of the first marker the answer's start matches, or None."""

    if len(text) > _DATA["max_answer_characters"]:
        return None
    start = normalise(text)
    return next((marker.id for marker in _MARKERS if _refuses(start, marker)), None)


class RefusalAnalyzer:
    """Marks a complete answer that refuses in words; native refusals stay in completion_outcome."""

    name = "refusal"
    version = "1"

    def analyze(self, ctx: AnalysisContext) -> dict[str, Any] | None:
        if ctx.completion_outcome != "complete" or not ctx.answer_text.strip():
            return None
        marker = soft_refusal(ctx.answer_text)
        return {"soft_refusal": marker is not None, "marker": marker}
