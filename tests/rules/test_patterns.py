from __future__ import annotations

import os
import subprocess
import sys

import pytest
import regex

from shim.rules.patterns import PatternTimeout, SearchBudget, compile_safe


_REFUSED = [
    (r"(\w+)\1", 0),
    (r"(a+)+$", 0),
    (r"(\d{2,})*x", 0),
    (r"(unclosed", 0),
    (r"(a|aa)+b", 0),
    (r"((a+)b)+c", 0),
    (r"(([a-z0-9]+)-)+key", 0),
    (r"(?:x+y?){3}z", 0),
    (r"K+k+K+k+z", regex.IGNORECASE),
    (r"K\w*k\w*K\w*z", 0),
    (r"K[a-z]*K[a-z]*K[a-z]*K[a-z]*Z", regex.IGNORECASE),
    (r"(?P<a>x)(?P=a)", 0),
    (r"(?P<a>x)\g<a>", 0),
    (r"(x)(?(1)y|z)", 0),
]


@pytest.mark.parametrize(("source", "flags"), _REFUSED)
def test_backtracking_and_broken_patterns_are_refused(source, flags) -> None:
    assert compile_safe(source, flags) is None


def test_the_check_does_not_depend_on_the_hash_seed() -> None:
    script = (
        "import regex; from shim.rules.patterns import compile_safe; "
        f"print([compile_safe(s, f) is None for s, f in {_REFUSED!r}])"
    )
    runs = {
        subprocess.run(
            [sys.executable, "-c", script],
            env={**os.environ, "PYTHONHASHSEED": seed},
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        for seed in ("0", "1", "4242")
    }

    assert runs == {f"{[True] * len(_REFUSED)}\n"}


@pytest.mark.parametrize(
    "source",
    [
        r"PRJ-\d{4}",
        r"\bAURORA\b",
        r"[A-Z]{2}\d{6}",
        r"(?:\d{3}-){2}\d{4}",
        r"INV(?:-\d{2})+",
        r"(?i:müşteri)\s+no",
    ],
)
def test_simple_patterns_compile_with_the_flags_they_run_with(source) -> None:
    compiled = compile_safe(source, regex.IGNORECASE)

    assert isinstance(compiled, regex.Pattern)
    assert compiled.flags & regex.IGNORECASE


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
