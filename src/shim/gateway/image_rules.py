"""What each provider's image parameters cost, per model family, version-pinned."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from fractions import Fraction
from functools import partial
import math
import re

# Read on 2026-10-08 from platform.openai.com/docs/guides/images-vision ("Choose an
# image detail level", "Model sizing behavior", "Patch-based image tokenization",
# "Tile-based image tokenization", "Calculating costs"),
# ai.google.dev/gemini-api/docs/media-resolution and
# platform.claude.com/docs/en/build-with-claude/vision ("Resolution and token cost",
# and vision-coordinates "How Claude resizes and pads images"). A new family or size
# rule is a new version.
IMAGE_RULES_VERSION = 2

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


Size = tuple[int, int]

# Anthropic: (longest edge, visual tokens of 28-pixel tiles) per tier.
_ANTHROPIC_TIERS = {"standard": (1568, 1568), "high": (2576, 4784)}
_CLAUDE = re.compile(
    r"(?:^|[./])claude-(opus|sonnet|haiku)-(\d+)(?:-(\d{1,2}))?(?:-\d{8})?(?:-v\d+(?::\d+)?)?$"
)
_CLAUDE_OLD = re.compile(r"(?:^|[./])claude-\d+(?:-\d)?-(opus|sonnet|haiku)")


def anthropic_tier(model: str) -> str | None:
    """`high` for Claude 4.7 and later, `standard` before; None for an unknown name."""
    if match := _CLAUDE.search(model):
        version = (int(match.group(2)), int(match.group(3) or 0))
        return "high" if version >= (4, 7) else "standard"
    return "standard" if _CLAUDE_OLD.search(model) else None


def anthropic_size(width: int, height: int, tier: str) -> Size:
    """Anthropic's reference resize: the largest aspect-preserving size within both limits."""
    edge, tokens = _ANTHROPIC_TIERS[tier]

    def fits(w: int, h: int) -> bool:
        return max(w, h) <= edge and math.ceil(w / 28) * math.ceil(h / 28) <= tokens

    if fits(width, height):
        return width, height
    portrait = height > width
    long, short = (height, width) if portrait else (width, height)
    low, high = 1, long
    while low < high:
        middle = (low + high + 1) // 2
        if fits(middle, max(1, round(short * middle / long))):
            low = middle
        else:
            high = middle - 1
    resized = (low, max(1, round(short * low / long)))
    return (resized[1], resized[0]) if portrait else resized


def fit(width: int, height: int, edge: int) -> Size:
    """The long side down to `edge`, the short side rounded down."""
    long, short = max(width, height), min(width, height)
    if long <= edge:
        return width, height
    short = max(1, short * edge // long)
    return (edge, short) if width >= height else (short, edge)


def patch(width: int, height: int, edge: int, budget: int) -> Size:
    """OpenAI's patch rule: fit `edge`, then shrink to at most `budget` 32-pixel patches."""
    width, height = fit(width, height, edge)
    if math.ceil(width / 32) * math.ceil(height / 32) <= budget:
        return width, height
    shrink = math.sqrt(32 * 32 * budget / (width * height))
    # The adjusted factor makes one side a whole number of patches; exact from here on.
    factor = min(
        Fraction(math.floor(width * shrink / 32) * 32, width),
        Fraction(math.floor(height * shrink / 32) * 32, height),
    )
    return max(1, math.floor(width * factor)), max(1, math.floor(height * factor))


def tile(width: int, height: int) -> Size:
    """OpenAI's tile rule: fit 2048, then the short side down to 768."""
    width, height = fit(width, height, 2048)
    short = min(width, height)
    if short <= 768:
        return width, height
    long = max(width, height) * 768 // short
    return (long, 768) if width >= height else (768, long)


_FIT_512 = partial(fit, edge=512)
_FIT_MAX = partial(fit, edge=65535)


def _patch(edge: int, budget: int) -> Callable[[int, int], Size]:
    return partial(patch, edge=edge, budget=budget)


# OpenAI: per family, the size each detail level (absent is `auto`) is read at; a
# level without a published size is left out and never touched.
SIZE_RULES_V1: Mapping[str, Mapping[str, Callable[[int, int], Size]]] = {
    **dict.fromkeys(
        ("gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-5.1"), {"high": tile, "auto": tile}
    ),
    **dict.fromkeys(
        ("gpt-4.1-mini", "gpt-5.2"),
        {level: _patch(2048, 6144) for level in ("low", "high", "auto")},
    ),
    **dict.fromkeys(
        ("gpt-5.4", "gpt-5.4-mini", "gpt-5.4-nano"),
        {
            "low": _patch(2048, 6144),
            "high": _patch(2048, 2500),
            "original": _patch(6000, 10000),
            "auto": _patch(2048, 2500),
        },
    ),
    "gpt-5.5": {
        "low": _FIT_512,
        "high": _patch(2048, 2500),
        "original": _patch(6000, 10000),
        "auto": _patch(6000, 10000),
    },
    **dict.fromkeys(
        ("gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"),
        {
            "low": _FIT_512,
            "high": _patch(2048, 2500),
            "original": _FIT_MAX,
            "auto": _FIT_MAX,
        },
    ),
    "gpt-6-astra": {
        "low": _FIT_512,
        "high": _patch(65535, 2500),
        "original": _FIT_MAX,
        "auto": _FIT_MAX,
    },
}


def target_size(
    provider: str, model: str, detail: str | None, width: int, height: int
) -> Size | None:
    """The size the provider reads an image at; None where none is published."""
    if provider == "anthropic":
        tier = anthropic_tier(model)
        return None if tier is None else anthropic_size(width, height, tier)
    if provider == "openai":
        rule = SIZE_RULES_V1.get(openai_family(model) or "", {}).get(detail or "auto")
        return None if rule is None else rule(width, height)
    return None
