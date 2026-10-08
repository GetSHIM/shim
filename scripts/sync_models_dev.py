"""Refresh the checked-in billing catalog from Models.dev."""

from __future__ import annotations

import argparse
from datetime import date
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from shim.billing.pricing import _MODALITIES, _STATUSES, _positive_int


SOURCE_URL = "https://models.dev/api.json"
TARGET = Path(__file__).parents[1] / "src" / "shim" / "billing" / "model_catalog.json"
PROVIDERS = ("openai", "anthropic", "google")
MAX_RESPONSE_BYTES = 10_000_000
UNSUPPORTED_MARKERS = (
    "embedding",
    "moderation",
    "safety",
    "rerank",
    "computer-use",
    "computer_use",
    "robotics",
    "deep-research",
    "deep_research",
    "customtools",
)
_CACHE_COST_KEYS = frozenset({"cache_read", "cache_write"})


def _decimal(value: object) -> Decimal | None:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        return None
    try:
        result = Decimal(value)
    except (InvalidOperation, ValueError):
        return None
    return result if result.is_finite() and result >= 0 else None


def _decimal_text(value: Decimal) -> str:
    return format(value, "f")


def _invalid_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON number: {value}")


def fetch_catalog() -> dict[str, Any]:
    request = Request(SOURCE_URL, headers={"User-Agent": "shim model catalog sync"})
    with urlopen(request, timeout=30) as response:  # noqa: S310 - fixed HTTPS URL
        payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ValueError("Models.dev response exceeds the 10 MB safety limit")
    parsed = json.loads(
        payload,
        parse_float=Decimal,
        parse_constant=_invalid_json_constant,
    )
    if not isinstance(parsed, dict):
        raise ValueError("Models.dev catalog must be an object")
    return parsed


def _eligible(model_id: str, model: object) -> bool:
    if not isinstance(model, dict):
        return False
    modalities = model.get("modalities")
    cost = model.get("cost")
    if not isinstance(modalities, dict) or not isinstance(cost, dict):
        return False
    searchable = f"{model_id} {model.get('family', '')}".casefold()
    return (
        isinstance(modalities.get("input"), list)
        and "text" in modalities["input"]
        and modalities.get("output") == ["text"]
        and _decimal(cost.get("input")) is not None
        and (_decimal(cost.get("output")) or Decimal("0")) > 0
        and _cost_dimensions_are_safe(cost)
        and not any(marker in searchable for marker in UNSUPPORTED_MARKERS)
    )


def _cost_dimensions_are_safe(cost: dict[str, object]) -> bool:
    """Accept aggregate billing only when modality rates cannot exceed it."""

    input_price = _decimal(cost.get("input"))
    output_price = _decimal(cost.get("output"))
    if input_price is None or output_price is None:
        return False
    for key, value in cost.items():
        if key.startswith("input_"):
            rate = _decimal(value)
            if rate is None or rate > input_price:
                return False
        elif key.startswith("output_"):
            rate = _decimal(value)
            if rate is None or rate > output_price:
                return False
        elif key.startswith("cache_") and (
            key not in _CACHE_COST_KEYS or _decimal(value) is None
        ):
            return False
    tiers = cost.get("tiers")
    if isinstance(tiers, list) and any(
        isinstance(tier, dict) and not _cost_dimensions_are_safe(tier) for tier in tiers
    ):
        return False
    legacy_tier = cost.get("context_over_200k")
    return not isinstance(legacy_tier, dict) or _cost_dimensions_are_safe(legacy_tier)


def _cache_prices(cost: dict[str, object], prefix: str = "") -> dict[str, str]:
    prices = {}
    for key in sorted(_CACHE_COST_KEYS & cost.keys()):
        price = _decimal(cost[key])
        if price is None:
            raise ValueError("cache prices must be nonnegative numbers")
        prices[f"{prefix}{key}_per_million"] = _decimal_text(price)
    return prices


def _tier(cost: dict[str, object]) -> dict[str, str | int]:
    tiers = cost.get("tiers")
    if tiers is None:
        tiers = []
    if not isinstance(tiers, list) or len(tiers) > 1:
        raise ValueError("only one context-pricing tier is supported")
    if tiers:
        candidate = tiers[0]
        if not isinstance(candidate, dict) or not isinstance(
            candidate.get("tier"), dict
        ):
            raise ValueError("context-pricing tier is malformed")
        condition = candidate["tier"]
        if condition.get("type") != "context":
            raise ValueError("only context-pricing tiers are supported")
        threshold = condition.get("size")
    else:
        candidate = cost.get("context_over_200k")
        threshold = 200_000
        if candidate is None:
            return {}
        if not isinstance(candidate, dict):
            raise ValueError("large-context pricing is malformed")
    input_price = _decimal(candidate.get("input"))
    output_price = _decimal(candidate.get("output"))
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, int)
        or threshold < 1
        or input_price is None
        or output_price is None
    ):
        raise ValueError("large-context pricing is incomplete")
    return {
        "large_context_threshold": threshold,
        "large_context_input_per_million": _decimal_text(input_price),
        "large_context_output_per_million": _decimal_text(output_price),
        **_cache_prices(candidate, "large_context_"),
    }


def _entry(model_id: str, model: dict[str, object]) -> dict[str, Any]:
    if (
        not model_id.strip()
        or len(model_id) > 200
        or not model_id.isprintable()
        or any(character.isspace() for character in model_id)
    ):
        raise ValueError("model ID is invalid")
    if model.get("id") not in {None, model_id}:
        raise ValueError(f"model ID does not match its catalog key: {model_id}")
    name = model.get("name")
    if (
        not isinstance(name, str)
        or not name.strip()
        or len(name) > 200
        or not name.isprintable()
    ):
        raise ValueError(f"model name is invalid: {model_id}")
    release_date = model.get("release_date")
    if release_date is not None:
        if not isinstance(release_date, str):
            raise ValueError(f"model release date is invalid: {model_id}")
        date.fromisoformat(release_date)
    cost = model.get("cost")
    if not isinstance(cost, dict):
        raise ValueError(f"model cost is invalid: {model_id}")
    input_price = _decimal(cost.get("input"))
    output_price = _decimal(cost.get("output"))
    if input_price is None or output_price is None:
        raise ValueError(f"model prices are invalid: {model_id}")
    entry: dict[str, Any] = {
        "name": name.strip(),
        "input_per_million": _decimal_text(input_price),
        "output_per_million": _decimal_text(output_price),
        **_cache_prices(cost),
    }
    limits = model.get("limit")
    if limits is not None:
        if not isinstance(limits, dict):
            raise ValueError(f"model limits are invalid: {model_id}")
        if not _positive_int(limits.get("output")):
            raise ValueError(f"model output limit is invalid: {model_id}")
        entry["max_output_tokens"] = limits["output"]
        for source_key, key in (
            ("context", "context_window"),
            ("input", "input_limit"),
        ):
            if source_key in limits:
                if not _positive_int(limits[source_key]):
                    raise ValueError(f"model {source_key} limit is invalid: {model_id}")
                entry[key] = limits[source_key]
    for source_key, key in (
        ("tool_call", "tools"),
        ("structured_output", "structured_output"),
    ):
        if source_key in model:
            if not isinstance(model[source_key], bool):
                raise ValueError(f"model {source_key} flag is invalid: {model_id}")
            entry[key] = model[source_key]
    modalities = model.get("modalities")
    input_modalities = modalities.get("input") if isinstance(modalities, dict) else None
    if (
        not isinstance(input_modalities, list)
        or not set(input_modalities) <= _MODALITIES
    ):
        raise ValueError(f"model input modalities are invalid: {model_id}")
    entry["input_modalities"] = sorted(set(input_modalities))
    status = model.get("status")
    if status is not None:
        if status not in _STATUSES:
            raise ValueError(f"model status is invalid: {model_id}")
        entry["status"] = status
    if release_date is not None:
        entry["release_date"] = release_date
    entry.update(_tier(cost))
    return entry


def build_catalog(source: dict[str, Any]) -> dict[str, object]:
    providers: dict[str, dict[str, dict[str, Any]]] = {}
    for provider in PROVIDERS:
        provider_catalog = source.get(provider)
        models = (
            provider_catalog.get("models")
            if isinstance(provider_catalog, dict)
            else None
        )
        if not isinstance(models, dict):
            raise ValueError(f"Models.dev provider is missing: {provider}")
        selected = {
            model_id: _entry(model_id, model)
            for model_id, model in sorted(models.items())
            if isinstance(model_id, str) and _eligible(model_id, model)
        }
        if len({model_id.casefold() for model_id in selected}) != len(selected):
            raise ValueError(f"Models.dev provider has duplicate model IDs: {provider}")
        if not selected:
            raise ValueError(f"Models.dev provider has no supported models: {provider}")
        providers[provider] = selected
    canonical = json.dumps(providers, sort_keys=True, separators=(",", ":"))
    version = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
    return {
        "source": SOURCE_URL,
        "version": f"models.dev:{version}",
        "providers": providers,
    }


def render_catalog(catalog: dict[str, object]) -> str:
    return json.dumps(catalog, indent=2, sort_keys=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when the checked-in catalog differs from Models.dev",
    )
    args = parser.parse_args()
    rendered = render_catalog(build_catalog(fetch_catalog()))
    current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
    if args.check:
        if current != rendered:
            raise SystemExit("model catalog is stale; run scripts/sync_models_dev.py")
        return
    if current == rendered:
        return
    temporary = TARGET.with_suffix(".json.tmp")
    temporary.write_text(rendered, encoding="utf-8")
    temporary.replace(TARGET)


if __name__ == "__main__":
    main()
