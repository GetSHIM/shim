"""Response analyzers in the order they run; a PRD that adds one appends it here."""

from __future__ import annotations

from shim.gateway.pipeline.analysis import ResponseAnalyzer

ANALYZERS: tuple[ResponseAnalyzer, ...] = ()
ANALYZER_NAMES: frozenset[str] = frozenset(analyzer.name for analyzer in ANALYZERS)
