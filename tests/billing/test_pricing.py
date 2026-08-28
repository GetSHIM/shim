from decimal import Decimal

import pytest

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
        ("anthropic", "claude-opus-5", Decimal("31.25")),
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
    ) == Decimal("31.25")


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
