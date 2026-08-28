"""Deterministic provider pricing used by reservations and settlement."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any


TOKENS_PER_MILLION = Decimal("1000000")
DEFAULT_MAX_OUTPUT_TOKENS = 200_000
UNSPECIFIED_PROVIDER_MODEL = "__unspecified_provider_model__"
_CATALOG_PATH = Path(__file__).with_name("model_catalog.json")


@dataclass(frozen=True, slots=True)
class ModelPrice:
    """USD prices per million provider tokens."""

    input_per_million: Decimal
    output_per_million: Decimal
    large_context_threshold: int | None = None
    large_context_input_per_million: Decimal | None = None
    large_context_output_per_million: Decimal | None = None
    max_output_tokens: int | None = None

    def __post_init__(self) -> None:
        if (
            not self.input_per_million.is_finite()
            or not self.output_per_million.is_finite()
        ):
            raise ValueError("model prices must be finite")
        if self.input_per_million < 0 or self.output_per_million < 0:
            raise ValueError("model prices cannot be negative")
        large_context = (
            self.large_context_threshold,
            self.large_context_input_per_million,
            self.large_context_output_per_million,
        )
        if any(value is not None for value in large_context) and not all(
            value is not None for value in large_context
        ):
            raise ValueError("large-context pricing requires a complete tier")
        if (
            self.large_context_threshold is not None
            and self.large_context_threshold < 1
        ):
            raise ValueError("large-context threshold must be positive")
        large_prices = (
            self.large_context_input_per_million,
            self.large_context_output_per_million,
        )
        if any(value is not None and not value.is_finite() for value in large_prices):
            raise ValueError("large-context prices must be finite")
        if any(value is not None and value < 0 for value in large_prices):
            raise ValueError("large-context prices cannot be negative")
        if self.max_output_tokens is not None and (
            isinstance(self.max_output_tokens, bool)
            or not isinstance(self.max_output_tokens, int)
            or self.max_output_tokens < 1
        ):
            raise ValueError("maximum output tokens must be positive")

    def cost(self, input_tokens: int, output_tokens: int) -> Decimal:
        if input_tokens < 0 or output_tokens < 0:
            raise ValueError("token counts cannot be negative")
        input_price = self.input_per_million
        output_price = self.output_per_million
        if (
            self.large_context_threshold is not None
            and input_tokens > self.large_context_threshold
        ):
            assert self.large_context_input_per_million is not None
            assert self.large_context_output_per_million is not None
            input_price = self.large_context_input_per_million
            output_price = self.large_context_output_per_million
        return (
            Decimal(input_tokens) * input_price + Decimal(output_tokens) * output_price
        ) / TOKENS_PER_MILLION


@dataclass(frozen=True, slots=True)
class PriceBook:
    """Immutable model price registry with deterministic longest-prefix lookup."""

    version: str
    prices: Mapping[str, ModelPrice]
    fallback: ModelPrice
    provider_prices: Mapping[str, Mapping[str, ModelPrice]] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if not self.version.strip():
            raise ValueError("price-book version cannot be empty")
        normalized: dict[str, ModelPrice] = {}
        for model, price in self.prices.items():
            key = _normalize_model(model)
            if key in normalized:
                raise ValueError(f"duplicate model price: {key}")
            normalized[key] = price
        object.__setattr__(self, "prices", MappingProxyType(normalized))
        catalogs: dict[str, Mapping[str, ModelPrice]] = {"openai": self.prices}
        for provider, prices in self.provider_prices.items():
            normalized_prices = {
                _normalize_model(model): price for model, price in prices.items()
            }
            if provider == "openai" or not provider.strip():
                raise ValueError("provider price-book key is invalid")
            if len(normalized_prices) != len(prices):
                raise ValueError(f"duplicate model price for provider: {provider}")
            catalogs[provider] = MappingProxyType(normalized_prices)
        object.__setattr__(self, "provider_prices", MappingProxyType(catalogs))

    def resolve(self, model: str | None, provider: str = "openai") -> ModelPrice:
        if model is None or not model.strip():
            return self.fallback
        normalized = _normalize_model(model)
        prices = self.provider_prices.get(provider, {})
        exact = prices.get(normalized)
        if exact is not None:
            return exact
        candidates = (
            (prefix, price)
            for prefix, price in prices.items()
            if normalized.startswith(f"{prefix}-")
        )
        return max(
            candidates, key=lambda item: len(item[0]), default=("", self.fallback)
        )[1]

    def supports(self, model: str | None, provider: str = "openai") -> bool:
        if model is None or not model.strip():
            return False
        normalized = _normalize_model(model)
        prices = self.provider_prices.get(provider, {})
        return any(
            normalized == prefix or normalized.startswith(f"{prefix}-")
            for prefix in prices
        )

    def compute(
        self,
        model: str | None,
        input_tokens: int,
        output_tokens: int,
        provider: str = "openai",
    ) -> Decimal:
        if model == UNSPECIFIED_PROVIDER_MODEL and provider == "openai":
            return max(
                (
                    price.cost(input_tokens, output_tokens)
                    for price in self.provider_prices[provider].values()
                ),
                default=self.fallback.cost(input_tokens, output_tokens),
            )
        return self.resolve(model, provider).cost(input_tokens, output_tokens)

    def models(self, provider: str) -> tuple[str, ...]:
        return tuple(self.provider_prices.get(provider, ()))

    def maximum_output_tokens(
        self,
        model: str | None,
        provider: str = "openai",
    ) -> int:
        if model == UNSPECIFIED_PROVIDER_MODEL and provider == "openai":
            return max(
                (
                    price.max_output_tokens or DEFAULT_MAX_OUTPUT_TOKENS
                    for price in self.provider_prices[provider].values()
                ),
                default=DEFAULT_MAX_OUTPUT_TOKENS,
            )
        return (
            self.resolve(model, provider).max_output_tokens or DEFAULT_MAX_OUTPUT_TOKENS
        )

    def resolved_price_metadata(
        self,
        model: str | None,
        provider: str = "openai",
        *,
        input_tokens: int,
        output_tokens: int,
    ) -> dict[str, str | int]:
        metadata: dict[str, str | int] = {
            "catalog_version": self.version,
            "provider": provider,
        }
        if model == UNSPECIFIED_PROVIDER_MODEL and provider == "openai":
            metadata["pricing_resolution"] = "conservative_max"
            resolved_model, price = max(
                self.provider_prices[provider].items(),
                key=lambda item: item[1].cost(input_tokens, output_tokens),
                default=("", self.fallback),
            )
        else:
            resolved_model = model or ""
            price = self.resolve(model, provider)
            metadata["pricing_resolution"] = (
                "catalog" if self.supports(model, provider) else "fallback"
            )
        metadata.update(
            {
                "provider_model": resolved_model,
                "input_per_million": str(price.input_per_million),
                "output_per_million": str(price.output_per_million),
            }
        )
        if price.large_context_threshold is not None:
            assert price.large_context_input_per_million is not None
            assert price.large_context_output_per_million is not None
            metadata.update(
                {
                    "large_context_threshold": price.large_context_threshold,
                    "large_context_input_per_million": str(
                        price.large_context_input_per_million
                    ),
                    "large_context_output_per_million": str(
                        price.large_context_output_per_million
                    ),
                }
            )
        return metadata


def _normalize_model(model: str) -> str:
    normalized = model.strip().casefold()
    if not normalized:
        raise ValueError("model name cannot be empty")
    return normalized


def _price(input_usd: str, output_usd: str) -> ModelPrice:
    return ModelPrice(Decimal(input_usd), Decimal(output_usd))


def _catalog_price(raw: object) -> ModelPrice:
    if not isinstance(raw, Mapping):
        raise ValueError("catalog model must be an object")
    input_price = raw.get("input_per_million")
    output_price = raw.get("output_per_million")
    if not isinstance(input_price, str) or not isinstance(output_price, str):
        raise ValueError("catalog model prices must be decimal strings")
    max_output_tokens = raw.get("max_output_tokens")
    if max_output_tokens is not None and (
        isinstance(max_output_tokens, bool)
        or not isinstance(max_output_tokens, int)
        or max_output_tokens < 1
    ):
        raise ValueError("catalog maximum output tokens must be positive")
    tier_values = (
        raw.get("large_context_threshold"),
        raw.get("large_context_input_per_million"),
        raw.get("large_context_output_per_million"),
    )
    if any(value is not None for value in tier_values):
        threshold, large_input, large_output = tier_values
        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, int)
            or not isinstance(large_input, str)
            or not isinstance(large_output, str)
        ):
            raise ValueError("catalog large-context pricing is incomplete")
        return ModelPrice(
            Decimal(input_price),
            Decimal(output_price),
            threshold,
            Decimal(large_input),
            Decimal(large_output),
            max_output_tokens,
        )
    return ModelPrice(
        Decimal(input_price),
        Decimal(output_price),
        max_output_tokens=max_output_tokens,
    )


def _load_catalog() -> tuple[
    str,
    dict[str, dict[str, ModelPrice]],
    dict[str, dict[str, dict[str, str]]],
]:
    raw: Any = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("version"), str):
        raise ValueError("model catalog version is missing")
    providers = raw.get("providers")
    if not isinstance(providers, dict):
        raise ValueError("model catalog providers are missing")
    prices: dict[str, dict[str, ModelPrice]] = {}
    details: dict[str, dict[str, dict[str, str]]] = {}
    for provider in ("openai", "anthropic", "google"):
        models = providers.get(provider)
        if not isinstance(models, dict) or not models:
            raise ValueError(f"model catalog provider is missing: {provider}")
        prices[provider] = {}
        details[provider] = {}
        for model_id, model in models.items():
            if (
                not isinstance(model_id, str)
                or not model_id.strip()
                or len(model_id) > 200
                or not model_id.isprintable()
                or any(character.isspace() for character in model_id)
            ):
                raise ValueError("catalog model ID is invalid")
            if not isinstance(model, dict) or not isinstance(model.get("name"), str):
                raise ValueError(f"catalog model name is missing: {model_id}")
            release_date = model.get("release_date")
            if release_date is not None:
                if not isinstance(release_date, str):
                    raise ValueError(f"catalog release date is invalid: {model_id}")
                date.fromisoformat(release_date)
            prices[provider][model_id] = _catalog_price(model)
            details[provider][_normalize_model(model_id)] = {
                key: value
                for key, value in {
                    "name": model["name"],
                    "release_date": release_date,
                }.items()
                if isinstance(value, str)
            }
    return raw["version"], prices, details


PRICE_BOOK_VERSION, _CATALOG_PRICES, _MODEL_DETAILS = _load_catalog()
DEFAULT_PRICE_BOOK = PriceBook(
    version=PRICE_BOOK_VERSION,
    prices=_CATALOG_PRICES["openai"],
    fallback=_price("1.00", "2.00"),
    provider_prices={
        provider: prices
        for provider, prices in _CATALOG_PRICES.items()
        if provider != "openai"
    },
)


def model_display_name(model: str, provider: str = "openai") -> str:
    detail = _MODEL_DETAILS.get(provider, {}).get(_normalize_model(model), {})
    return detail.get("name", model)


def model_release_date(model: str, provider: str = "openai") -> date | None:
    value = (
        _MODEL_DETAILS.get(provider, {})
        .get(_normalize_model(model), {})
        .get("release_date")
    )
    return date.fromisoformat(value) if value is not None else None


def compute_cost_usd(
    model: str | None,
    prompt_tokens: int,
    completion_tokens: int,
    provider: str = "openai",
) -> Decimal:
    """Return the deterministic provider cost for a token pair."""

    return DEFAULT_PRICE_BOOK.compute(model, prompt_tokens, completion_tokens, provider)
