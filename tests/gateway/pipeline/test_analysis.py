from __future__ import annotations

from dataclasses import dataclass
import logging
import re

import pytest

from shim.gateway.analyzers import ANALYZER_NAMES, ANALYZERS
from shim.gateway.pipeline import analysis
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


def _cyclic() -> dict:
    value: dict = {}
    value["self"] = value
    return value


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


def test_a_result_still_over_the_bound_without_its_lists_is_replaced() -> None:
    results = run_analyzers(
        [
            _Analyzer("big", {"ids": ["x" * 100] * 50, "label": "x" * 5_000}),
            _Analyzer("small", {"n": 1}),
        ],
        _context(),
    )

    assert results is not None
    assert results["big"] == {"error": True, "reason": "too_large"}
    assert results["small"] == {"n": 1}


@pytest.mark.parametrize(
    "bad",
    [["a"], "text", 7, {"values": {1, 2}}, {"ratio": float("nan")}, _cyclic()],
    ids=["list", "str", "int", "set", "nan", "cycle"],
)
def test_a_result_that_is_not_a_json_object_is_an_error_and_keeps_the_others(
    bad,
) -> None:
    results = run_analyzers(
        [
            _Analyzer("before", {"n": 1}),
            _Analyzer("bad", bad),
            _Analyzer("after", {"n": 2}),
        ],
        _context(),
    )

    assert results == {
        "before": {"n": 1},
        "bad": {"error": True},
        "after": {"n": 2},
        "versions": {"before": "1", "bad": "1", "after": "1"},
    }


def test_a_result_over_the_bound_keeps_its_counts_and_digests() -> None:
    results = run_analyzers(
        [_Analyzer("big", {"count": 50, "digest": "ab12", "names": ["x" * 100] * 50})],
        _context(),
    )

    assert results is not None
    assert results["big"] == {"count": 50, "digest": "ab12", "names": None}


def test_a_run_past_its_time_records_the_remaining_analyzers_as_timed_out(
    monkeypatch,
) -> None:
    clock = iter([0.0, 0.5, analysis.MAX_RUN_SECONDS + 0.1])
    monkeypatch.setattr(analysis, "monotonic", lambda: next(clock))

    results = run_analyzers(
        [_Analyzer("first", {"n": 1}), _Analyzer("late", {"n": 2})], _context()
    )

    assert results == {
        "first": {"n": 1},
        "late": {"error": True, "reason": "timeout"},
        "versions": {"first": "1", "late": "1"},
    }


def test_registered_names_are_valid_unique_and_never_the_reserved_key() -> None:
    assert all(
        re.fullmatch(r"[a-z][a-z0-9_]{0,31}", analyzer.name) for analyzer in ANALYZERS
    )
    assert len(ANALYZER_NAMES) == len(ANALYZERS)
    assert "versions" not in ANALYZER_NAMES
