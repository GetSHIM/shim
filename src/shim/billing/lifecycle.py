"""Model retirement dates: a reviewed overlay beside the price catalog, plus an operator file.

OpenAI, Anthropic and Google publish retirement dates on web pages only, so the dates
live in a file reviewed like the catalog. The gateway warns before a date and never
refuses a model because of one: the provider's own error stays the truth.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import date
from functools import cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from shim.billing.pricing import DATE_SUFFIX, DEFAULT_PRICE_BOOK, MODEL_ID

# Between Anthropic's 60-day and OpenAI's six-month minimum notice.
RETIREMENT_WARNING_DAYS = 90
_SHIPPED = Path(__file__).with_name("model_lifecycle.json")


class Retirement(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    retires_on: date
    deprecated_on: date | None = None
    replacement: str | None = None
    source: str = Field(pattern=r"^https://\S+$")
    checked_on: date

    @model_validator(mode="after")
    def deprecated_before_retired(self) -> Retirement:
        if self.deprecated_on is not None and self.deprecated_on > self.retires_on:
            raise ValueError("deprecated_on is after retires_on")
        return self

    def warning(self, today: date) -> Literal["MODEL_RETIRING", "MODEL_RETIRED"] | None:
        days = (self.retires_on - today).days
        if days < 0:
            return "MODEL_RETIRED"
        return "MODEL_RETIRING" if days <= RETIREMENT_WARNING_DAYS else None


class _LifecycleFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: Literal["shim.model.lifecycle"]
    version: Literal[1]
    models: dict[
        Literal["openai", "anthropic", "google", "registry"], dict[str, Retirement]
    ]


def _parse(text: str, *, operator: bool) -> dict[str, dict[str, Retirement]]:
    models = _LifecycleFile.model_validate_json(text, strict=True).models
    if "registry" in models and not operator:
        raise ValueError("only an operator file may list registry aliases")
    unknown = sorted(
        f"{provider}/{model}"
        for provider, entries in models.items()
        if provider != "registry"
        for model in entries
        # Any model of a catalog family: a deployment may serve one the catalog
        # does not price, such as gpt-4o-realtime-preview.
        if not MODEL_ID.fullmatch(model)
        or _longest_prefix(
            model.casefold(), DEFAULT_PRICE_BOOK.provider_prices.get(provider, {})
        )
        is None
    )
    if unknown:
        raise ValueError(f"models not in the catalog: {', '.join(unknown)}")
    return {
        provider: {model.strip().casefold(): entry for model, entry in entries.items()}
        for provider, entries in models.items()
    }


class ModelLifecycle:
    """Retirement dates by provider and model, for catalog models and their family."""

    def __init__(self, models: Mapping[str, Mapping[str, Retirement]]) -> None:
        self.models = models

    def retirement(
        self, model: str, provider: str, alias: str | None = None
    ) -> Retirement | None:
        found = self.match(model, provider, alias)
        return None if found is None else found[2]

    def match(
        self, model: str, provider: str, alias: str | None = None
    ) -> tuple[str, str, Retirement] | None:
        """The provider and entry name that matched, and the date: a registry alias
        first, then the model under its provider.

        An entry matches its own name or a dashed suffix of it, unless the catalog
        prices that longer name as a model of its own (``gpt-5`` never covers
        ``gpt-5-mini``). An undated alias retires with its dated snapshots when
        every one the catalog lists retires, on the last of their dates.
        """
        if alias is not None:
            name = alias.strip().casefold()
            if name in (registry := self.models.get("registry", {})):
                return "registry", name, registry[name]
        entries = self.models.get(provider, {})
        name = model.strip().casefold()
        key = name if name in entries else _longest_prefix(name, entries)
        if key is None:
            snapshots = [
                snapshot
                for snapshot in DEFAULT_PRICE_BOOK.models(provider)
                if DATE_SUFFIX.sub("", snapshot) == name and snapshot != name
            ]
            if not snapshots or any(item not in entries for item in snapshots):
                return None
            key = max(snapshots, key=lambda item: entries[item].retires_on)
            return provider, key, entries[key]
        catalog = _longest_prefix(name, DEFAULT_PRICE_BOOK.models(provider))
        if key != name and catalog is not None and len(key) < len(catalog):
            return None
        return provider, key, entries[key]


def _longest_prefix(name: str, keys: Iterable[str]) -> str | None:
    return max(
        (key for key in keys if name == key or name.startswith(f"{key}-")),
        key=len,
        default=None,
    )


@cache
def load_lifecycle(operator_file: Path | None = None) -> ModelLifecycle:
    """The shipped dates, with ``SHIM_MODEL_LIFECYCLE_FILE`` merged over them; read once."""
    models = _parse(_SHIPPED.read_text(encoding="utf-8"), operator=False)
    if operator_file is not None:
        try:
            extra = _parse(operator_file.read_text(encoding="utf-8"), operator=True)
        except (OSError, ValueError) as error:
            raise ValueError(
                f"SHIM_MODEL_LIFECYCLE_FILE {operator_file}: {error}"
            ) from None
        models = {
            provider: {**models.get(provider, {}), **extra.get(provider, {})}
            for provider in {*models, *extra}
        }
    return ModelLifecycle(models)
