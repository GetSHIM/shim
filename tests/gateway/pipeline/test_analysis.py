from __future__ import annotations

from dataclasses import dataclass
import logging
import re

from prometheus_client import REGISTRY

from shim.gateway.analyzers import ANALYZER_NAMES, ANALYZERS
from shim.gateway.pipeline.analysis import AnalysisContext, run_analyzers


@dataclass
class _Analyzer:
    name: str
    result: object
    version: str = "1"

    def analyze(self, ctx: AnalysisContext) -> dict | None:
        if isinstance(self.result, Exception):
            raise self.result
        return self.result  # type: ignore[return-value]


def _context() -> AnalysisContext:
    return AnalysisContext(
        request_id="req_analysis",
        protocol="chat",
        model="gpt-5.6-luna",
        payload={"messages": [{"role": "user", "content": "<EMAIL_ADDRESS_a1>"}]},
        answer_text="private answer text",
        answer_truncated=False,
        tool_calls=(),
        completion_outcome="complete",
        restore=lambda text: text,
    )


def _runs(analyzer: str, result: str) -> float:
    return (
        REGISTRY.get_sample_value(
            "shim_response_analysis_total", {"analyzer": analyzer, "result": result}
        )
        or 0.0
    )


def test_results_keep_analyzer_order_leave_out_none_and_carry_versions() -> None:
    results = run_analyzers(
        [
            _Analyzer("first", {"count": 1}, "2"),
            _Analyzer("quiet", None),
            _Analyzer("second", {"label": "x"}),
        ],
        _context(),
    )

    assert results == {
        "first": {"count": 1},
        "second": {"label": "x"},
        "versions": {"first": "2", "second": "1"},
    }
    assert list(results) == ["first", "second", "versions"]


def test_no_result_at_all_is_none() -> None:
    assert run_analyzers([_Analyzer("quiet", None)], _context()) is None
    assert run_analyzers([], _context()) is None


def test_a_failing_analyzer_is_an_error_and_the_next_still_runs(caplog) -> None:
    caplog.set_level(logging.WARNING)

    results = run_analyzers(
        [
            _Analyzer("broken", ValueError("private answer text")),
            _Analyzer("after", {"ok": True}),
        ],
        _context(),
    )

    assert results == {
        "broken": {"error": True},
        "after": {"ok": True},
        "versions": {"broken": "1", "after": "1"},
    }
    [record] = [
        record for record in caplog.records if "analyzer" in record.getMessage()
    ]
    assert (
        record.getMessage()
        == "Response analyzer failed analyzer=broken type=ValueError"
    )
    assert "private" not in caplog.text


def test_a_result_over_the_bound_is_replaced() -> None:
    results = run_analyzers(
        [_Analyzer("big", {"ids": ["x" * 100] * 50}), _Analyzer("small", {"n": 1})],
        _context(),
    )

    assert results is not None
    assert results["big"] == {"error": True, "reason": "too_large"}
    assert results["small"] == {"n": 1}


def test_runs_are_counted_with_names_bounded_by_the_registry() -> None:
    before = {key: _runs("other", key) for key in ("ok", "none", "error")}

    run_analyzers(
        [
            _Analyzer("unregistered_ok", {"n": 1}),
            _Analyzer("unregistered_none", None),
            _Analyzer("unregistered_error", RuntimeError()),
        ],
        _context(),
    )

    assert {key: _runs("other", key) - before[key] for key in before} == {
        "ok": 1,
        "none": 1,
        "error": 1,
    }


def test_registered_names_are_valid_unique_and_match_the_name_set() -> None:
    assert all(
        re.fullmatch(r"[a-z][a-z0-9_]{0,31}", analyzer.name) for analyzer in ANALYZERS
    )
    assert ANALYZER_NAMES == {analyzer.name for analyzer in ANALYZERS}
    assert len(ANALYZER_NAMES) == len(ANALYZERS)
