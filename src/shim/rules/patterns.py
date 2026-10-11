"""Tenant regular expressions: refused when they can backtrack, bounded when they run."""

from __future__ import annotations

from time import perf_counter
from typing import Any

import regex

# A quantified group that already contains a quantifier, and backreferences:
# the two checks shim-cli applies to custom patterns.
_BACKREFERENCE = regex.compile(r"\\[1-9]")
_NESTED_QUANTIFIER = regex.compile(r"\([^()]*[*+{][^()]*\)\s*[*+{]")
PROBE_SECONDS = 0.05
PROBE_LENGTH = 10_000
SEARCH_SECONDS = 0.25
REQUEST_BUDGET_SECONDS = 1.0


class PatternTimeout(Exception):
    """A tenant pattern ran out of its time, or of the request's budget."""


def _probes(source: str) -> tuple[str, ...]:
    letters = [character for character in source if character.isalnum()]
    common = max(set(letters), key=letters.count) if letters else "a"
    trailing = next(
        (character for character in "!#~" if character not in source), "\x00"
    )
    return (common * PROBE_LENGTH + trailing, "\n" * PROBE_LENGTH)


# regex ships no type information, so its pattern and match objects are Any here.
def compile_safe(source: str) -> Any | None:
    """The compiled pattern, or None when it must not run on a request path."""

    if _BACKREFERENCE.search(source) or _NESTED_QUANTIFIER.search(source):
        return None
    try:
        compiled = regex.compile(source)
        for probe in _probes(source):
            compiled.search(probe, timeout=PROBE_SECONDS)
    except (regex.error, TimeoutError):
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
