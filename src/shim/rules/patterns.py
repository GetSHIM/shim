"""Tenant regular expressions: refused when they can backtrack, bounded when they run."""

from __future__ import annotations

import re
import re._constants as sre  # ty: ignore[unresolved-import]
import re._parser as sre_parse  # ty: ignore[unresolved-import]
from time import perf_counter
from typing import Any

import regex

PROBE_SECONDS = 0.05
PROBE_LENGTH = 10_000
SEARCH_SECONDS = 0.25
REQUEST_BUDGET_SECONDS = 1.0
_REPEATS = {sre.MAX_REPEAT, sre.MIN_REPEAT, sre.POSSESSIVE_REPEAT}
_BACKREFERENCES = {sre.GROUPREF, sre.GROUPREF_EXISTS}


class PatternTimeout(Exception):
    """A tenant pattern ran out of its time, or of the request's budget."""


def _backtracks(pattern: sre_parse.SubPattern, repeated: bool = False) -> bool:
    """A backreference, or a repeat with a choice of length inside another repeat."""

    for op, av in pattern:
        if op in _BACKREFERENCES:
            return True
        repeat = op in _REPEATS
        if repeat and repeated and av[0] != av[1]:
            return True
        for part in av if isinstance(av, tuple | list) else (av,):
            for sub in part if isinstance(part, list) else (part,):
                if isinstance(sub, sre_parse.SubPattern) and _backtracks(
                    sub, repeated or repeat
                ):
                    return True
    return False


# regex ships no type information, so its pattern and match objects are Any here.
def compile_safe(source: str, flags: int, *, probe: bool = True) -> Any | None:
    """The pattern compiled with the flags it runs with, or None when it must not run.

    The structure is checked on Python's own parser, so syntax only the regex module
    knows (\\p{..}, fuzzy matching, recursion) is refused too. The timed probes are a
    long run of each letter of the pattern, in sorted order, then of newlines.
    """

    try:
        if _backtracks(sre_parse.parse(source, flags)):
            return None
        compiled = regex.compile(source, flags)
        if probe:
            trailing = next(
                (character for character in "!#~" if character not in source), "\x00"
            )
            letters = sorted({c for c in source if c.isalnum()}) or ["a"]
            for text in (
                *(c * PROBE_LENGTH + trailing for c in letters),
                "\n" * PROBE_LENGTH,
            ):
                compiled.search(text, timeout=PROBE_SECONDS)
    except (re.error, regex.error, TimeoutError, OverflowError, RecursionError):
        return None
    return compiled


class SearchBudget:
    """The time one request's pattern searches share."""

    def __init__(self, seconds: float = REQUEST_BUDGET_SECONDS) -> None:
        self.remaining = seconds

    def finditer(self, pattern: Any, text: str) -> list[Any]:
        if self.remaining <= 0:
            raise PatternTimeout
        started = perf_counter()
        try:
            return list(
                pattern.finditer(text, timeout=min(SEARCH_SECONDS, self.remaining))
            )
        except TimeoutError:
            raise PatternTimeout from None
        finally:
            self.remaining -= perf_counter() - started
