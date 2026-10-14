"""What each provider's image parameters cost, per model family, version-pinned."""

from __future__ import annotations

from collections.abc import Mapping
import re

# Read on 2026-10-08 from platform.openai.com/docs/guides/images-vision ("Choose an
# image detail level", "Model sizing behavior", "Calculating costs") and
# ai.google.dev/gemini-api/docs/media-resolution. A new family is a new version.
IMAGE_RULES_VERSION = 1

# OpenAI: the detail levels that lower a family's image budget below its default
# (`auto`). gpt-5.4's `low` can cost more than its `high`, so it lists none.
DETAIL_LOWERS_V1: Mapping[str, frozenset[str]] = {
    "gpt-4o": frozenset({"low"}),
    "gpt-4o-mini": frozenset({"low"}),
    "gpt-4.1": frozenset({"low"}),
    "gpt-5.1": frozenset({"low"}),
    "gpt-4.1-mini": frozenset(),
    "gpt-5.2": frozenset(),
    "gpt-5.4": frozenset(),
    "gpt-5.4-mini": frozenset(),
    "gpt-5.4-nano": frozenset(),
    "gpt-5.5": frozenset({"low", "high"}),
    "gpt-5.6-sol": frozenset({"low", "high"}),
    "gpt-5.6-terra": frozenset({"low", "high"}),
    "gpt-5.6-luna": frozenset({"low", "high"}),
    "gpt-6-astra": frozenset({"low", "high"}),
}
_FAMILIES = sorted(DETAIL_LOWERS_V1, key=len, reverse=True)
_DATED = re.compile(r"-\d{4}-\d{2}-\d{2}")
# Gemini 3 is the only family with per-part levels; low (280) and medium (560) both
# lower its default of 1,120 tokens an image.
_GEMINI_3 = re.compile(r"^gemini-3(\.\d+)?-")


def openai_family(model: str) -> str | None:
    """The listed family `model` names, alone or with a dated snapshot suffix."""
    return next(
        (
            family
            for family in _FAMILIES
            if model == family
            or (model.startswith(family) and _DATED.fullmatch(model[len(family) :]))
        ),
        None,
    )


def gemini3(model: str) -> bool:
    return _GEMINI_3.match(model) is not None
