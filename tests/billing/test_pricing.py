from decimal import Decimal

import pytest

import shim.billing.pricing as pricing_module
from shim.billing.pricing import (
    DEFAULT_PRICE_BOOK,
    ModelPrice,
    PriceBook,
    UNSPECIFIED_PROVIDER_MODEL,
    compute_cost_usd,
    model_display_name,
)


def test_cost_uses_decimal_prices_per_million_tokens() -> None:
    assert compute_cost_usd("gpt-5-nano", 1_000_000, 500_000) == Decimal("0.25")


@pytest.mark.parametrize(
    ("model", "input_price", "output_price"),
    [
        ("gpt-4.1", "2.00", "8.00"),
        ("gpt-4.1-mini", "0.40", "1.60"),
        ("gpt-5.4", "2.50", "15.00"),
        ("gpt-5.4-mini", "0.75", "4.50"),
        ("gpt-5.4-nano", "0.20", "1.25"),
    ],
)
def test_reviewed_openai_model_prices(
    model: str,
    input_price: str,
    output_price: str,
) -> None:
    price = DEFAULT_PRICE_BOOK.resolve(model)

    assert price.input_per_million == Decimal(input_price)
    assert price.output_per_million == Decimal(output_price)


@pytest.mark.parametrize(
    ("provider", "model", "cost"),
    [
        # Unknown cache split: input at Anthropic's one-hour write price, 2x base.
        ("anthropic", "claude-opus-5", Decimal("35")),
        ("google", "gemini-2.5-pro", Decimal("17.5")),
        ("google", "gemini-3.5-flash", Decimal("10.5")),
    ],
)
def test_provider_models_use_their_own_price_catalog(
    provider: str,
    model: str,
    cost: Decimal,
) -> None:
    assert compute_cost_usd(model, 1_000_000, 1_000_000, provider) == cost


def test_gemini_pro_large_context_uses_the_documented_tier() -> None:
    assert compute_cost_usd(
        "gemini-3.1-pro-preview", 200_001, 100_000, "google"
    ) == Decimal("2.600004")


def test_price_resolution_uses_the_longest_model_prefix() -> None:
    price_book = PriceBook(
        version="test",
        prices={
            "model": ModelPrice(Decimal("10"), Decimal("20")),
            "model-small": ModelPrice(Decimal("1"), Decimal("2")),
        },
        fallback=ModelPrice(Decimal("100"), Decimal("200")),
    )

    resolved = price_book.resolve("MODEL-SMALL-2026-07-12")

    assert resolved.input_per_million == Decimal("1")


def test_price_book_exposes_model_output_ceiling() -> None:
    price_book = PriceBook(
        version="test",
        prices={
            "model": ModelPrice(
                Decimal("1"),
                Decimal("2"),
                max_output_tokens=64_000,
            )
        },
        fallback=ModelPrice(Decimal("10"), Decimal("20")),
    )

    assert price_book.maximum_output_tokens("model") == 64_000
    assert price_book.maximum_output_tokens("unknown") == 200_000


def test_unknown_model_uses_the_explicit_fallback_price() -> None:
    assert compute_cost_usd("unknown-model", 1_000_000, 1_000_000) == Decimal("3")


def test_unspecified_openai_model_uses_the_most_expensive_configured_price() -> None:
    expected = max(
        price.cost(1_000_000, 1_000_000) for price in DEFAULT_PRICE_BOOK.prices.values()
    )

    assert (
        compute_cost_usd(UNSPECIFIED_PROVIDER_MODEL, 1_000_000, 1_000_000) == expected
    )


@pytest.mark.parametrize(
    ("model", "base_cost", "large_cost"),
    [
        ("gpt-5.6", Decimal("21.36"), Decimal("32.72001")),
        ("gpt-5.6-sol", Decimal("21.36"), Decimal("32.72001")),
        ("gpt-5.6-terra", Decimal("12.68"), Decimal("19.360005")),
        ("gpt-5.6-luna", Decimal("1.268"), Decimal("1.9360005")),
    ],
)
def test_gpt_5_6_large_context_tier(
    model: str,
    base_cost: Decimal,
    large_cost: Decimal,
) -> None:
    assert compute_cost_usd(model, 272_000, 1_000_000) == base_cost
    assert compute_cost_usd(model, 272_001, 1_000_000) == large_cost


def test_claude_opus_4_5_versioned_alias_is_priced() -> None:
    assert compute_cost_usd(
        "claude-opus-4-5-20251101", 1_000_000, 1_000_000, "anthropic"
    ) == Decimal("35")


def test_negative_usage_is_rejected() -> None:
    with pytest.raises(ValueError, match="cannot be negative"):
        compute_cost_usd("gpt-5.6-luna", -1, 0)


def test_catalog_exposes_source_name_and_pricing_version() -> None:
    metadata = DEFAULT_PRICE_BOOK.resolved_price_metadata(
        "gpt-5-nano",
        input_tokens=1,
        output_tokens=1,
    )

    assert model_display_name("gpt-5-nano") == "GPT-5 Nano"
    assert metadata["catalog_version"] == DEFAULT_PRICE_BOOK.version
    assert metadata["input_per_million"] == "0.05"


def _priced(provider: str, **raw: object) -> ModelPrice:
    return pricing_module._catalog_price(
        {"input_per_million": "4", "output_per_million": "20", **raw}, provider
    )


@pytest.mark.parametrize(
    ("provider", "raw", "cache", "expected"),
    [
        # 1,000 uncached at 4, 6,000 read at 0.4, 4,000 written at 5, 20 out at 20.
        (
            "anthropic",
            {"cache_read_per_million": "0.4", "cache_write_per_million": "5"},
            (6_000, 4_000, 0),
            Decimal("0.0268"),
        ),
        # The same 4,000 written for one hour cost 2x input, 8.
        (
            "anthropic",
            {"cache_read_per_million": "0.4", "cache_write_per_million": "5"},
            (6_000, 0, 4_000),
            Decimal("0.0388"),
        ),
        # No source cache prices: read at input, Anthropic write at 1.25x input.
        ("anthropic", {}, (6_000, 4_000, 0), Decimal("0.0484")),
        # OpenAI and Gemini report reads only; a missing read price is the input price.
        ("openai", {"cache_read_per_million": "0.4"}, (6_000, 0, 0), Decimal("0.0228")),
        ("google", {}, (6_000, 0, 0), Decimal("0.0444")),
    ],
)
def test_a_reported_cache_split_prices_each_part(provider, raw, cache, expected):
    assert _priced(provider, **raw).cost(11_000, 20, cache) == expected


@pytest.mark.parametrize(
    ("provider", "raw", "expected"),
    [
        # Anthropic's bound is the one-hour write price, 2x input.
        ("anthropic", {"cache_write_per_million": "5"}, Decimal("0.0884")),
        ("openai", {"cache_write_per_million": "5"}, Decimal("0.0554")),
        ("openai", {"cache_read_per_million": "0.4"}, Decimal("0.0444")),
    ],
)
def test_an_unknown_split_is_priced_at_the_highest_input_rate(provider, raw, expected):
    price = _priced(provider, **raw)

    assert price.cost(11_000, 20) == expected
    assert price.cost(11_000, 20) >= price.cost(11_000, 20, (0, 11_000, 0))
    assert price.cost(11_000, 20) >= price.cost(11_000, 20, (0, 0, 0))


@pytest.mark.parametrize(
    ("tier_cache", "expected"),
    [
        # Tier input 8: read 0.8 and write 10 from the tier; one token written for an hour at 8.
        (
            {
                "large_context_cache_read_per_million": "0.8",
                "large_context_cache_write_per_million": "10",
            },
            Decimal("0.54"),
        ),
        # No tier cache prices: the base entry's 0.4 and 5.
        ({}, Decimal("0.27")),
    ],
)
def test_the_large_context_tier_keys_on_total_input(tier_cache, expected):
    price = _priced(
        "google",
        cache_read_per_million="0.4",
        cache_write_per_million="5",
        large_context_threshold=100_000,
        large_context_input_per_million="8",
        large_context_output_per_million="30",
        **tier_cache,
    )

    assert price.cost(100_000, 0, (50_000, 50_000, 0)) == Decimal("0.27")
    assert price.cost(100_001, 0, (50_000, 50_000, 1)) == expected + Decimal("0.000008")


def test_openai_writes_are_billed_as_uncached_input_at_the_write_price():
    # OpenAI reports no cache-write count, so a written token arrives as uncached input.
    price = _priced(
        "openai",
        cache_read_per_million="0.4",
        cache_write_per_million="5",
        large_context_threshold=100_000,
        large_context_input_per_million="8",
        large_context_output_per_million="30",
        large_context_cache_write_per_million="10",
    )

    assert price.cache_write_per_million is None
    # 5,000 uncached at 5 (not the base 4), 6,000 read at 0.4, 20 out at 20.
    assert price.cost(11_000, 20, (6_000, 0, 0)) == Decimal("0.0278")
    assert price.cost(100_001, 0, (0, 0, 0)) == Decimal("1.00001")
    assert price.cost(11_000, 20) == price.cost(11_000, 20, (0, 0, 0))


def test_the_charged_model_is_named_in_unspecified_model_metadata():
    # Uncached, "cached-cheap" costs more; read from the cache, "uncached-only" does.
    book = PriceBook(
        version="test",
        prices={
            "cached-cheap": ModelPrice(
                Decimal("10"), Decimal("1"), cache_read_per_million=Decimal("0.1")
            ),
            "uncached-only": ModelPrice(Decimal("5"), Decimal("1")),
        },
        fallback=ModelPrice(Decimal("1"), Decimal("1")),
    )
    cache = (1_000_000, 0, 0)

    metadata = book.resolved_price_metadata(
        UNSPECIFIED_PROVIDER_MODEL, input_tokens=1_000_000, output_tokens=0, cache=cache
    )

    assert metadata["provider_model"] == "uncached-only"
    assert book.compute(UNSPECIFIED_PROVIDER_MODEL, 1_000_000, 0, cache=cache) == 5


def test_a_free_tier_cache_price_is_not_mistaken_for_a_missing_one():
    price = _priced(
        "openai",
        cache_read_per_million="0.4",
        large_context_threshold=10,
        large_context_input_per_million="8",
        large_context_output_per_million="30",
        large_context_cache_read_per_million="0",
    )

    assert price.cost(1_000_000, 0, (1_000_000, 0, 0)) == Decimal("0")


def test_catalog_entries_carry_limits_capabilities_and_status():
    entry = pricing_module._catalog_price(
        {
            "input_per_million": "1",
            "output_per_million": "2",
            "context_window": 200_000,
            "tools": True,
            "input_modalities": ["image", "text"],
            "status": "deprecated",
        }
    )

    assert (entry.context_window, entry.input_limit) == (200_000, None)
    assert (entry.tools, entry.structured_output) == (True, None)
    assert entry.input_modalities == ("image", "text")
    assert entry.status == "deprecated"
    haiku = DEFAULT_PRICE_BOOK.resolve("claude-haiku-4-5-20251001", "anthropic")
    assert haiku.context_window and haiku.tools is True


@pytest.mark.parametrize(
    "raw",
    [
        {"context_window": 0},
        {"input_limit": True},
        {"tools": "yes"},
        {"input_modalities": ["text", "smell"]},
        {"status": "retired"},
        {"cache_read_per_million": 0.1},
        {"cache_write_per_million": "-1"},
    ],
)
def test_catalog_refuses_malformed_entries(raw):
    with pytest.raises(ValueError):
        pricing_module._catalog_price(
            {"input_per_million": "1", "output_per_million": "2", **raw}
        )


def test_price_metadata_carries_cache_prices_and_the_reported_split():
    metadata = DEFAULT_PRICE_BOOK.resolved_price_metadata(
        "claude-haiku-4-5",
        "anthropic",
        input_tokens=10,
        output_tokens=1,
        cache=(3, 2, 1),
    )

    assert metadata["cache_read_per_million"] == "0.1"
    assert metadata["cache_write_per_million"] == "1.25"
    assert metadata["cache_write_1h_per_million"] == "2"
    assert (
        metadata["cache_read_tokens"],
        metadata["cache_write_tokens"],
        metadata["cache_write_1h_tokens"],
    ) == (3, 2, 1)
