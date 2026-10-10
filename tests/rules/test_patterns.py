from __future__ import annotations

import pytest
import regex

from shim.rules.patterns import PatternTimeout, SearchBudget, compile_safe


@pytest.mark.parametrize(
    "source",
    [r"(\w+)\1", r"(a+)+$", r"(\d{2,})*x", r"(unclosed", r"(a|aa)+b"],
)
def test_backtracking_and_broken_patterns_are_refused(source) -> None:
    assert compile_safe(source) is None


@pytest.mark.parametrize("source", [r"PRJ-\d{4}", r"\bAURORA\b", r"[A-Z]{2}\d{6}"])
def test_simple_patterns_compile(source) -> None:
    assert isinstance(compile_safe(source), regex.Pattern)


def test_a_search_past_its_time_is_a_timeout() -> None:
    slow = regex.compile(r"(a|aa)+$")

    with pytest.raises(PatternTimeout):
        SearchBudget().finditer(slow, "a" * 60 + "!")


def test_a_spent_budget_refuses_the_next_search() -> None:
    budget = SearchBudget(seconds=0.0)

    with pytest.raises(PatternTimeout):
        budget.finditer(regex.compile("x"), "x")


def test_searches_share_the_request_budget() -> None:
    budget = SearchBudget(seconds=1.0)
    found = budget.finditer(regex.compile(r"PRJ-\d{4}"), "PRJ-1234 and PRJ-5678")

    assert [match.group() for match in found] == ["PRJ-1234", "PRJ-5678"]
    assert 0 < budget.remaining < 1.0
