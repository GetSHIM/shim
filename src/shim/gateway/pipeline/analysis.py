"""One pass over a delivered answer: named analyzers that record counts, never text."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
import json
import logging
import re
from time import monotonic
from typing import Any, Protocol

logger = logging.getLogger(__name__)

MAX_RESULT_CHARACTERS = 4_096
# Checked between analyzers: a running one cannot be interrupted, so the after-answer
# lane's bounded backlog is what keeps a stuck analyzer from holding memory.
MAX_RUN_SECONDS = 1.0
# Tool names come from the app and the model; only what providers allow is recorded.
TOOL_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,64}")


@dataclass(frozen=True, slots=True)
class AnalysisToolCall:
    name: str
    arguments: str


@dataclass(frozen=True, slots=True)
class AnalysisContext:
    request_id: str
    protocol: str
    model: str
    # Masked, as the provider saw it; analyzers must not mutate it.
    payload: dict[str, Any]
    answer_text: str
    answer_truncated: bool
    tool_calls: tuple[AnalysisToolCall, ...]
    completion_outcome: str | None
    restore: Callable[[str], str]


class ResponseAnalyzer(Protocol):
    name: str
    version: str

    def analyze(self, ctx: AnalysisContext) -> dict | None: ...


def run_analyzers(
    analyzers: Iterable[ResponseAnalyzer], ctx: AnalysisContext
) -> dict | None:
    """Each analyzer's result by name, plus their versions; never raises."""

    results: dict[str, Any] = {}
    versions: dict[str, str] = {}
    deadline = monotonic() + MAX_RUN_SECONDS
    for analyzer in analyzers:
        result = (
            _result(analyzer, ctx)
            if monotonic() < deadline
            else {"error": True, "reason": "timeout"}
        )
        if result is not None:
            results[analyzer.name] = result
            versions[analyzer.name] = analyzer.version
    return {**results, "versions": versions} if results else None


def _result(analyzer: ResponseAnalyzer, ctx: AnalysisContext) -> dict | None:
    try:
        result = analyzer.analyze(ctx)
        if result is None:
            return None
        if not isinstance(result, dict):
            raise TypeError("an analyzer result is a JSON object")
        if _size(result) > MAX_RESULT_CHARACTERS:
            # Detail lists go first; counts and digests stay.
            result = {
                key: None if isinstance(value, list) else value
                for key, value in result.items()
            }
            if _size(result) > MAX_RESULT_CHARACTERS:
                return {"error": True, "reason": "too_large"}
        return result
    except Exception as exc:
        logger.warning(
            "Response analyzer failed analyzer=%s type=%s",
            analyzer.name,
            type(exc).__name__,
        )
        return {"error": True}


def _size(result: dict) -> int:
    return len(json.dumps(result, separators=(",", ":"), allow_nan=False))
