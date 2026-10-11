"""Response analyzers in the order they run; a PRD that adds one appends it here."""

from __future__ import annotations

from shim.gateway.analyzers.language import LanguageAnalyzer
from shim.gateway.analyzers.refusal import RefusalAnalyzer
from shim.gateway.analyzers.schema import SchemaAnalyzer
from shim.gateway.analyzers.shape import ShapeAnalyzer
from shim.gateway.pipeline.analysis import ResponseAnalyzer

ANALYZERS: tuple[ResponseAnalyzer, ...] = (
    ShapeAnalyzer(),
    LanguageAnalyzer(),
    SchemaAnalyzer(),
    RefusalAnalyzer(),
)
ANALYZER_NAMES: frozenset[str] = frozenset(analyzer.name for analyzer in ANALYZERS)
