import pytest

from shim.gateway.image_rules import (
    DETAIL_LOWERS_V1,
    IMAGE_RULES_VERSION,
    gemini3,
    openai_family,
)


@pytest.mark.parametrize("family", sorted(DETAIL_LOWERS_V1))
def test_every_family_matches_itself_and_its_dated_snapshots(family) -> None:
    assert openai_family(family) == family
    assert openai_family(f"{family}-2026-03-05") == family


@pytest.mark.parametrize(
    "model",
    [
        "gpt-4.1-nano",
        "gpt-5.4-pro",
        "gpt-5.6",
        "gpt-6-sol",
        "gpt-4o-mini-tts",
        "gpt-4o-2024-08",
        "gpt-4o-latest",
        "",
    ],
)
def test_near_misses_are_no_family(model) -> None:
    assert openai_family(model) is None


def test_a_dated_mini_is_the_mini_family() -> None:
    assert openai_family("gpt-4o-mini-2024-07-18") == "gpt-4o-mini"
    assert openai_family("gpt-4o-2024-08-06") == "gpt-4o"


def test_the_table_is_version_one() -> None:
    low, both, none = frozenset({"low"}), frozenset({"low", "high"}), frozenset()
    assert IMAGE_RULES_VERSION == 1
    assert DETAIL_LOWERS_V1 == {
        "gpt-4o": low,
        "gpt-4o-mini": low,
        "gpt-4.1": low,
        "gpt-5.1": low,
        "gpt-4.1-mini": none,
        "gpt-5.2": none,
        "gpt-5.4": none,
        "gpt-5.4-mini": none,
        "gpt-5.4-nano": none,
        "gpt-5.5": both,
        "gpt-5.6-sol": both,
        "gpt-5.6-terra": both,
        "gpt-5.6-luna": both,
        "gpt-6-astra": both,
    }


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("gemini-3.5-flash", True),
        ("gemini-3.1-pro-preview", True),
        ("gemini-3-flash", True),
        ("gemini-2.5-flash", False),
        ("gemini-30x", False),
        ("gemini-3", False),
    ],
)
def test_gemini_3_is_the_only_gemini_family(model, expected) -> None:
    assert gemini3(model) is expected
