import pytest

from shim.gateway.image_rules import (
    DETAIL_LOWERS_V1,
    IMAGE_RULES_VERSION,
    SIZE_RULES_V1,
    anthropic_size,
    anthropic_tier,
    fit,
    gemini3,
    image_tokens,
    openai_family,
    patch,
    target_size,
    tile,
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
    assert IMAGE_RULES_VERSION == 3
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


@pytest.mark.parametrize(
    ("tier", "size", "expected"),
    [
        ("standard", (1920, 1080), (1456, 819)),
        ("standard", (3840, 2160), (1456, 819)),
        ("standard", (1075, 1520), (924, 1307)),
        # The reference implementation's answer; the docs' table says 1269x952.
        ("standard", (2000, 1500), (1270, 952)),
        ("standard", (1500, 2000), (952, 1270)),
        ("standard", (8000, 100), (1568, 20)),
        ("standard", (1000, 800), (1000, 800)),
        ("high", (3840, 2160), (2576, 1449)),
        ("high", (1920, 1080), (1920, 1080)),
        ("high", (1075, 1520), (1075, 1520)),
        ("high", (4000, 3000), (2212, 1659)),
    ],
)
def test_anthropic_sizes_follow_the_reference(tier, size, expected) -> None:
    edge, tokens = {"standard": (1568, 1568), "high": (2576, 4784)}[tier]
    width, height = anthropic_size(*size, tier)

    assert (width, height) == expected
    assert max(width, height) <= edge
    assert -(-width // 28) * -(-height // 28) <= tokens


@pytest.mark.parametrize(
    ("model", "tier"),
    [
        ("claude-haiku-4-5", "standard"),
        ("claude-opus-4-6", "standard"),
        ("claude-opus-4-7", "high"),
        ("claude-opus-5", "high"),
        ("claude-opus-5-5", "high"),
        ("claude-haiku-4-5-20251001", "standard"),
        ("us.anthropic.claude-opus-4-7-v1:0", "high"),
        ("claude-3-5-sonnet-20241022", "standard"),
        ("claude-instant", None),
        ("gpt-4o", None),
    ],
)
def test_the_anthropic_tier_follows_the_model_version(model, tier) -> None:
    assert anthropic_tier(model) == tier


@pytest.mark.parametrize(
    ("rule", "size", "expected"),
    [
        (lambda w, h: patch(w, h, 65535, 2500), (2048, 2048), (1600, 1600)),
        (lambda w, h: patch(w, h, 2048, 2500), (4000, 3000), (1824, 1368)),
        (lambda w, h: patch(w, h, 6000, 10000), (4000, 3000), (3669, 2752)),
        (tile, (4000, 3000), (1024, 768)),
        (tile, (1024, 1024), (768, 768)),
        (tile, (3000, 4000), (768, 1024)),
        (lambda w, h: fit(w, h, 512), (4000, 3000), (512, 384)),
        (lambda w, h: fit(w, h, 512), (300, 200), (300, 200)),
    ],
)
def test_openai_rules_give_the_documented_sizes(rule, size, expected) -> None:
    assert rule(*size) == expected


@pytest.mark.parametrize(
    "size", [(4000, 3000), (3000, 4000), (5000, 37), (2049, 2049), (640, 480)]
)
@pytest.mark.parametrize("family", sorted(SIZE_RULES_V1))
def test_every_openai_cell_keeps_its_bounds(family, size) -> None:
    for level, rule in SIZE_RULES_V1[family].items():
        width, height = rule(*size)
        assert width <= size[0] and height <= size[1], (family, level)
        assert target_size("openai", family, level, *size) == (width, height)


def test_the_openai_table_has_each_cell_of_version_one() -> None:
    levels = {family: set(rules) for family, rules in SIZE_RULES_V1.items()}
    tiles = {"high", "auto"}
    every = {"low", "high", "original", "auto"}
    assert levels == {
        "gpt-4o": tiles,
        "gpt-4o-mini": tiles,
        "gpt-4.1": tiles,
        "gpt-5.1": tiles,
        "gpt-4.1-mini": {"low", "high", "auto"},
        "gpt-5.2": {"low", "high", "auto"},
        "gpt-5.4": every,
        "gpt-5.4-mini": every,
        "gpt-5.4-nano": every,
        "gpt-5.5": every,
        "gpt-5.6-sol": every,
        "gpt-5.6-terra": every,
        "gpt-5.6-luna": every,
        "gpt-6-astra": every,
    }
    sample = (4000, 3000)
    assert target_size("openai", "gpt-5.4", None, *sample) == (1824, 1368)
    assert target_size("openai", "gpt-5.4", "original", *sample) == (3669, 2752)
    assert target_size("openai", "gpt-5.5", "low", *sample) == (512, 384)
    assert target_size("openai", "gpt-5.5", None, *sample) == (3669, 2752)
    assert target_size("openai", "gpt-6-astra", "high", 2048, 2048) == (1600, 1600)
    assert target_size("openai", "gpt-4o", "low", *sample) is None
    assert target_size("openai", "gpt-4o-2024-08-06", None, *sample) == (1024, 768)


def test_unknown_models_and_gemini_have_no_size() -> None:
    assert target_size("openai", "gpt-4.1-nano", None, 4000, 3000) is None
    assert target_size("openai", "o3", None, 4000, 3000) is None
    assert target_size("google", "gemini-3.5-flash", None, 4000, 3000) is None
    assert target_size("anthropic", "claude-instant", None, 4000, 3000) is None
    assert target_size("anthropic", "claude-haiku-4-5", None, 4000, 3000) == (1270, 952)


@pytest.mark.parametrize(
    ("size", "tier", "expected"),
    [
        # Where a reconstruction rounding the short side differently was off by one.
        ((1961, 2458), "standard", (980, 1228)),
        ((1651, 2158), "standard", (952, 1244)),
        ((2016, 2004), "high", (1932, 1921)),
        # The published examples.
        ((1075, 1520), "standard", (924, 1307)),
        ((1920, 1080), "standard", (1456, 819)),
        ((3840, 2160), "high", (2576, 1449)),
    ],
)
def test_anthropic_resizes_as_its_published_reference(size, tier, expected) -> None:
    assert anthropic_size(*size, tier) == expected


@pytest.mark.parametrize(
    ("provider", "model", "detail", "size", "tokens"),
    [
        # The live run billed 25,514 for one 1024-pixel square image, text included.
        ("openai", "gpt-4o-mini", None, (1024, 1024), 2833 + 5667 * 4),
        ("openai", "gpt-4o-mini", "low", (1024, 1024), 2833),
        ("openai", "gpt-4o", "high", (100, 100), 85 + 170),
        ("openai", "gpt-5.1-2025-11-13", None, (2048, 768), 70 + 140 * 8),
        ("openai", "gpt-4.1-mini", None, (1024, 1024), 1659),
        ("openai", "gpt-5.4", "original", (6000, 6000), 12_000),
        ("anthropic", "claude-haiku-4-5", None, (3840, 2160), 52 * 30),
        ("anthropic", "claude-opus-5-5", None, (3840, 2160), 4784),
        ("anthropic", "claude-instant", None, (100, 100), None),
        ("openai", "gpt-5-nano", None, (100, 100), None),
        ("google", "gemini-3.5-flash", None, (100, 100), None),
    ],
)
def test_image_tokens_are_what_the_provider_bills(
    provider, model, detail, size, tokens
) -> None:
    assert image_tokens(provider, model, detail, *size) == tokens
