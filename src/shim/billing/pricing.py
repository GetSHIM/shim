"""Deterministic provider pricing used by reservations and settlement."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
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
_MODALITIES = frozenset({"text", "image", "pdf", "audio", "video"})
_STATUSES = frozenset({"alpha", "beta", "deprecated"})
# Anthropic documents 1.25x base input for 5-minute cache writes and 2x for 1-hour ones.
_ANTHROPIC_CACHE_WRITE = Decimal("1.25")
_ANTHROPIC_ONE_HOUR_WRITE = Decimal("2")
# Cache-read, cache-write and one-hour cache-write input tokens.
CacheSplit = tuple[int, int, int]


@dataclass(frozen=True, slots=True)
class ModelPrice:
    """USD prices per million provider tokens, and the catalog's limits for the model."""

    input_per_million: Decimal
    output_per_million: Decimal
    large_context_threshold: int | None = None
    large_context_input_per_million: Decimal | None = None
    large_context_output_per_million: Decimal | None = None
    max_output_tokens: int | None = None
    cache_read_per_million: Decimal | None = None
    cache_write_per_million: Decimal | None = None
    large_context_cache_read_per_million: Decimal | None = None
    large_context_cache_write_per_million: Decimal | None = None
    one_hour_write_multiplier: Decimal = Decimal("1")
    context_window: int | None = None
    input_limit: int | None = None
    tools: bool | None = None
    structured_output: bool | None = None
    input_modalities: tuple[str, ...] | None = None
    status: str | None = None

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
        if self.large_context_threshold is not None and not _positive_int(
            self.large_context_threshold
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
        cache_prices = (
            self.cache_read_per_million,
            self.cache_write_per_million,
            self.large_context_cache_read_per_million,
            self.large_context_cache_write_per_million,
        )
        if any(
            value is not None and (not value.is_finite() or value < 0)
            for value in cache_prices
        ):
            raise ValueError("cache prices must be finite and nonnegative")
        if self.max_output_tokens is not None and not _positive_int(
            self.max_output_tokens
        ):
            raise ValueError("maximum output tokens must be positive")

    def rates(
        self, input_tokens: int
    ) -> tuple[Decimal, Decimal, Decimal, Decimal, Decimal]:
        """Input, output, cache-read, cache-write and one-hour-write prices per million."""

        tier = (
            self.large_context_threshold is not None
            and input_tokens > self.large_context_threshold
        )
        input_price = self.input_per_million
        output_price = self.output_per_million
        read = self.cache_read_per_million
        write = self.cache_write_per_million
        if tier:
            assert self.large_context_input_per_million is not None
            assert self.large_context_output_per_million is not None
            input_price = self.large_context_input_per_million
            output_price = self.large_context_output_per_million
            if self.large_context_cache_read_per_million is not None:
                read = self.large_context_cache_read_per_million
            if self.large_context_cache_write_per_million is not None:
                write = self.large_context_cache_write_per_million
        return (
            input_price,
            output_price,
            input_price if read is None else read,
            input_price if write is None else write,
            input_price * self.one_hour_write_multiplier,
        )

    def cost(
        self,
        input_tokens: int,
        output_tokens: int,
        cache: CacheSplit | None = None,
    ) -> Decimal:
        """Price input exactly when the cache split is known, else at its highest rate."""

        if input_tokens < 0 or output_tokens < 0:
            raise ValueError("token counts cannot be negative")
        input_price, output_price, read, write, one_hour = self.rates(input_tokens)
        if cache is None:
            input_cost = Decimal(input_tokens) * max(input_price, write, one_hour)
        else:
            read_tokens, write_tokens, one_hour_tokens = cache
            input_cost = (
                Decimal(max(0, input_tokens - sum(cache))) * input_price
                + Decimal(read_tokens) * read
                + Decimal(write_tokens) * write
                + Decimal(one_hour_tokens) * one_hour
            )
        return (input_cost + Decimal(output_tokens) * output_price) / TOKENS_PER_MILLION


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

    def exact(self, model: str, provider: str = "openai") -> ModelPrice | None:
        """The model's own entry, never a prefix match that describes another model."""

        return self.provider_prices.get(provider, {}).get(model.strip().casefold())

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
        cache: CacheSplit | None = None,
    ) -> Decimal:
        if model == UNSPECIFIED_PROVIDER_MODEL and provider == "openai":
            return max(
                (
                    price.cost(input_tokens, output_tokens, cache)
                    for price in self.provider_prices[provider].values()
                ),
                default=self.fallback.cost(input_tokens, output_tokens, cache),
            )
        return self.resolve(model, provider).cost(input_tokens, output_tokens, cache)

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
        unpriced: bool = False,
        cache: CacheSplit | None = None,
        price: ModelPrice | None = None,
    ) -> dict[str, str | int]:
        metadata: dict[str, str | int] = {
            "catalog_version": self.version,
            "provider": provider,
        }
        if unpriced:
            return {
                **metadata,
                "provider_model": model or "",
                "pricing_resolution": "unknown",
            }
        if price is not None:
            metadata["pricing_resolution"] = "deployment"
            resolved_model = model or ""
        elif model == UNSPECIFIED_PROVIDER_MODEL and provider == "openai":
            metadata["pricing_resolution"] = "conservative_max"
            resolved_model, price = max(
                self.provider_prices[provider].items(),
                key=lambda item: item[1].cost(input_tokens, output_tokens, cache),
                default=("", self.fallback),
            )
        else:
            resolved_model = model or ""
            price = self.resolve(model, provider)
            metadata["pricing_resolution"] = (
                "catalog" if self.supports(model, provider) else "fallback"
            )
        _, _, read, write, one_hour = price.rates(input_tokens)
        metadata.update(
            {
                "provider_model": resolved_model,
                "input_per_million": str(price.input_per_million),
                "output_per_million": str(price.output_per_million),
                "cache_read_per_million": str(read),
                "cache_write_per_million": str(write),
                "cache_write_1h_per_million": str(one_hour),
            }
        )
        if cache is not None:
            metadata.update(
                zip(
                    (
                        "cache_read_tokens",
                        "cache_write_tokens",
                        "cache_write_1h_tokens",
                    ),
                    cache,
                )
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


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _normalize_model(model: str) -> str:
    normalized = model.strip().casefold()
    if not normalized:
        raise ValueError("model name cannot be empty")
    return normalized


def _price(input_usd: str, output_usd: str) -> ModelPrice:
    return ModelPrice(Decimal(input_usd), Decimal(output_usd))


def _catalog_decimal(raw: Mapping[str, object], key: str) -> Decimal | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"catalog {key} must be a decimal string")
    return Decimal(value)


def _catalog_facts(raw: Mapping[str, object]) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    for key in ("context_window", "input_limit"):
        value = raw.get(key)
        if value is not None:
            if not _positive_int(value):
                raise ValueError(f"catalog {key} must be a positive integer")
            facts[key] = value
    for key in ("tools", "structured_output"):
        value = raw.get(key)
        if value is not None:
            if not isinstance(value, bool):
                raise ValueError(f"catalog {key} must be a boolean")
            facts[key] = value
    modalities = raw.get("input_modalities")
    if modalities is not None:
        if not isinstance(modalities, list) or not set(modalities) <= _MODALITIES:
            raise ValueError("catalog input modalities are invalid")
        facts["input_modalities"] = tuple(modalities)
    status = raw.get("status")
    if status is not None:
        if status not in _STATUSES:
            raise ValueError("catalog status is invalid")
        facts["status"] = status
    return facts


def _catalog_price(raw: object, provider: str = "openai") -> ModelPrice:
    if not isinstance(raw, Mapping):
        raise ValueError("catalog model must be an object")
    input_price = raw.get("input_per_million")
    output_price = raw.get("output_per_million")
    if not isinstance(input_price, str) or not isinstance(output_price, str):
        raise ValueError("catalog model prices must be decimal strings")
    anthropic = provider == "anthropic"
    cache_write = _catalog_decimal(raw, "cache_write_per_million")
    if cache_write is None and anthropic:
        cache_write = Decimal(input_price) * _ANTHROPIC_CACHE_WRITE
    extras: dict[str, Any] = {
        "max_output_tokens": raw.get("max_output_tokens"),
        "cache_read_per_million": _catalog_decimal(raw, "cache_read_per_million"),
        "cache_write_per_million": cache_write,
        "large_context_cache_read_per_million": _catalog_decimal(
            raw, "large_context_cache_read_per_million"
        ),
        "large_context_cache_write_per_million": _catalog_decimal(
            raw, "large_context_cache_write_per_million"
        ),
        "one_hour_write_multiplier": _ANTHROPIC_ONE_HOUR_WRITE
        if anthropic
        else Decimal("1"),
        **_catalog_facts(raw),
    }
    tier_values = (
        raw.get("large_context_threshold"),
        raw.get("large_context_input_per_million"),
        raw.get("large_context_output_per_million"),
    )
    tier: tuple[Any, ...] = ()
    if any(value is not None for value in tier_values):
        threshold, large_input, large_output = tier_values
        if not isinstance(large_input, str) or not isinstance(large_output, str):
            raise ValueError("catalog large-context pricing is incomplete")
        tier = (threshold, Decimal(large_input), Decimal(large_output))
    price = ModelPrice(Decimal(input_price), Decimal(output_price), *tier, **extras)
    if provider != "openai":
        return price
    # OpenAI reports no cache-write count, so a written token arrives as uncached
    # input: bill uncached input at the higher of the input and write prices.
    return replace(
        price,
        input_per_million=max(
            price.input_per_million,
            price.cache_write_per_million or price.input_per_million,
        ),
        cache_write_per_million=None,
        large_context_input_per_million=None
        if price.large_context_input_per_million is None
        else max(
            price.large_context_input_per_million,
            price.large_context_cache_write_per_million
            or price.large_context_input_per_million,
        ),
        large_context_cache_write_per_million=None,
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
            prices[provider][model_id] = _catalog_price(model, provider)
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
    *,
    unpriced: bool = False,
    cache: CacheSplit | None = None,
    price: ModelPrice | None = None,
) -> Decimal:
    """Return the deterministic provider cost for a token pair."""

    if unpriced:
        # Ledger arithmetic needs a numeric placeholder; metadata must mark it unknown.
        return Decimal("0")
    if price is not None:
        return price.cost(prompt_tokens, completion_tokens, cache)
    return DEFAULT_PRICE_BOOK.compute(
        model, prompt_tokens, completion_tokens, provider, cache
    )
