"""One pass over a delivered answer: named analyzers that record counts, never text."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
import json
import logging
from typing import Any, Protocol

from shim.observability.metrics import RESPONSE_ANALYSIS_TOTAL

logger = logging.getLogger(__name__)

MAX_RESULT_CHARACTERS = 4_096


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
    # The registry imports this module, so its names are read at call time.
    from shim.gateway.analyzers import ANALYZER_NAMES

    results: dict[str, Any] = {}
    versions: dict[str, str] = {}
    for analyzer in analyzers:
        try:
            result = analyzer.analyze(ctx)
        except Exception as exc:
            logger.warning(
                "Response analyzer failed analyzer=%s type=%s",
                analyzer.name,
                type(exc).__name__,
            )
            result = {"error": True}
        if (
            result is not None
            and len(json.dumps(result, separators=(",", ":"), default=str))
            > MAX_RESULT_CHARACTERS
        ):
            result = {"error": True, "reason": "too_large"}
        RESPONSE_ANALYSIS_TOTAL.labels(
            analyzer=analyzer.name if analyzer.name in ANALYZER_NAMES else "other",
            result="none"
            if result is None
            else "error"
            if result.get("error")
            else "ok",
        ).inc()
        if result is not None:
            results[analyzer.name] = result
            versions[analyzer.name] = analyzer.version
    return {**results, "versions": versions} if results else None
