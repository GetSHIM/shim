"""The `refusal` analyzer: a complete answer that refuses in words ("yardımcı olamam")."""

from __future__ import annotations

from importlib.resources import files
import json
import re
from typing import Any
import unicodedata

from shim.gateway.analyzers.language import fold
from shim.gateway.pipeline.analysis import AnalysisContext

# A change to the markers after release is a new file and a new version.
VERSION = "1"
_DATA = json.loads(
    files("shim.gateway.analyzers")
    .joinpath(f"refusal-v{VERSION}.json")
    .read_text("utf-8")
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
# Emphasis anywhere, then leading whitespace, heading, quote-block and code markers.
_LEADING = re.compile(r"^[\s#>`]+")
_EMPHASIS = re.compile(r"[*_]+")
_LETTER = r"[^\W\d_]"
# A double quote, or a single one that is not an apostrophe between two letters.
_QUOTE = re.compile(rf"\"|(?<!{_LETTER})'|'(?!{_LETTER})")


def normalise(text: str) -> str:
    start = _EMPHASIS.sub("", unicodedata.normalize("NFKC", text).translate(_QUOTES))
    start = _LEADING.sub("", start).rstrip()
    # An answer wrapped in one pair of quotes is the answer, not a quotation.
    if len(start) > 1 and start[0] in "\"'" and start[-1] == start[0]:
        start = start[1:-1]
    start = fold(start[: _DATA["normalised_characters"]])
    return "\n".join(" ".join(line.split()) for line in start.splitlines())


def _words(phrase: str) -> re.Pattern[str]:
    """The phrase with no letter directly before or after it."""

    return re.compile(rf"(?<!{_LETTER}){re.escape(normalise(phrase))}(?!{_LETTER})")


_MARKERS = tuple(
    (marker["id"], tuple(_words(phrase) for phrase in marker["phrases"]))
    for marker in _DATA["markers"]
)
_UNLESS = tuple(_words(phrase) for phrase in _DATA["unless_followed_by"])
# Reported speech ("yardımcı olamam dedi") only right after the phrase.
_REPORTED = tuple(_words(phrase) for phrase in _DATA["unless_directly_followed_by"])


def _quoted(start: str, index: int) -> bool:
    line = start[start.rfind("\n", 0, index) + 1 : index]
    return len(_QUOTE.findall(line)) % 2 == 1


def _partial(start: str, end: int) -> bool:
    """An exception phrase starting within the window after the match, or reported speech."""

    if any(reported.match(start, end + 1) for reported in _REPORTED):
        return True
    for unless in _UNLESS:
        found = unless.search(start, end)
        if found and found.start() - end <= _DATA["unless_window"]:
            return True
    return False


def _refuses(start: str, phrases: tuple[re.Pattern[str], ...]) -> bool:
    for phrase in phrases:
        for found in phrase.finditer(start):
            if found.start() >= _DATA["start_window"]:
                break
            if not _quoted(start, found.start()) and not _partial(start, found.end()):
                return True
    return False


def soft_refusal(text: str) -> str | None:
    """The id of the first marker the answer's start matches, or None."""

    if len(text) > _DATA["max_answer_characters"]:
        return None
    start = normalise(text)
    return next(
        (marker for marker, phrases in _MARKERS if _refuses(start, phrases)), None
    )


class RefusalAnalyzer:
    """Marks a complete answer that refuses in words; native refusals stay in completion_outcome."""

    name = "refusal"
    version = VERSION
    reads_answer = True

    def analyze(self, ctx: AnalysisContext) -> dict[str, Any] | None:
        if ctx.completion_outcome != "complete" or not ctx.answer_text.strip():
            return None
        marker = soft_refusal(ctx.answer_text)
        return {"soft_refusal": marker is not None, "marker": marker}
