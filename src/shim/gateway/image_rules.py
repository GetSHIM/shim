"""What each provider's image parameters cost, per model family, version-pinned."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from fractions import Fraction
from functools import partial
import io
import math
import re
from typing import Any
import warnings

# Read on 2026-10-08 from platform.openai.com/docs/guides/images-vision ("Choose an
# image detail level", "Model sizing behavior", "Patch-based image tokenization",
# "Tile-based image tokenization", "Calculating costs"),
# ai.google.dev/gemini-api/docs/media-resolution and
# platform.claude.com/docs/en/build-with-claude/vision ("Resolution and token cost",
# and vision-coordinates "How Claude resizes and pads images"). A new family or size
# rule is a new version. 3: Anthropic's published reference resize (2026-10-14).
IMAGE_RULES_VERSION = 3

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
    """Anthropic's published `resized_size` (vision-coordinates, read 2026-10-14)."""
    max_edge, max_tokens = _ANTHROPIC_TIERS[tier]

    def fits(w: int, h: int) -> bool:
        return (
            math.ceil(w / 28) * 28 <= max_edge
            and math.ceil(h / 28) * 28 <= max_edge
            and math.ceil(w / 28) * math.ceil(h / 28) <= max_tokens
        )

    if fits(width, height):
        return (width, height)
    if height > width:
        resized_h, resized_w = anthropic_size(height, width, tier)
        return (resized_w, resized_h)
    aspect_ratio = width / height
    lo, hi = 1, width  # lo always fits; hi never fits
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if fits(mid, max(round(mid / aspect_ratio), 1)):
            lo = mid
        else:
            hi = mid
    return (lo, max(round(lo / aspect_ratio), 1))


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


# Image tokens as billed, read 2026-10-14 from the OpenAI page above ("Calculating
# costs"): tile families cost a base plus a price per 512-pixel tile of the size they
# read at; patch families cost their 32-pixel patches times a multiplier.
IMAGE_TOKENS_V1: Mapping[str, tuple[int, int] | float] = {
    "gpt-5.1": (70, 140),
    "gpt-4o": (85, 170),
    "gpt-4.1": (85, 170),
    "gpt-4o-mini": (2833, 5667),
    **dict.fromkeys(
        (
            "gpt-6-astra",
            "gpt-5.6-sol",
            "gpt-5.6-terra",
            "gpt-5.6-luna",
            "gpt-5.5",
            "gpt-5.4",
            "gpt-5.4-mini",
            "gpt-5.4-nano",
            "gpt-5.2",
        ),
        1.2,
    ),
    "gpt-4.1-mini": 1.62,
}
# OpenAI refuses an image over this many patches after its resize.
_OPENAI_MAX_PATCHES = 30_000


def image_tokens(
    provider: str, model: str, detail: str | None, width: int, height: int
) -> int | None:
    """The input tokens a provider bills for an image; None where none is published."""
    if provider == "anthropic":
        tier = anthropic_tier(model)
        if tier is None:
            return None
        resized = anthropic_size(width, height, tier)
        return math.ceil(resized[0] / 28) * math.ceil(resized[1] / 28)
    family = openai_family(model) if provider == "openai" else None
    cost = IMAGE_TOKENS_V1.get(family or "")
    if family is None or cost is None:
        return None
    rules = SIZE_RULES_V1[family]
    if isinstance(cost, tuple):
        base, per_tile = cost
        if detail == "low":
            return base
        tiled = tile(width, height)
        return base + per_tile * math.ceil(tiled[0] / 512) * math.ceil(tiled[1] / 512)
    # A level with no published size is read at the largest one the family lists.
    sizes = (
        [rules[detail or "auto"](width, height)]
        if (detail or "auto") in rules
        else [rule(width, height) for rule in rules.values()]
    )
    patches = max(math.ceil(w / 32) * math.ceil(h / 32) for w, h in sizes)
    return math.ceil(min(patches, _OPENAI_MAX_PATCHES) * cost)


def image_detail(protocol: str, image: Mapping[str, Any]) -> object:
    """The `detail` an OpenAI image part asks for, as sent."""
    if protocol == "chat":
        url = image.get("image_url")
        return url.get("detail") if isinstance(url, Mapping) else None
    return image.get("detail") if protocol == "responses" else None


# Header pixels an image may declare before it is decoded, here and in Pillow.
MAX_IMAGE_PIXELS = 64_000_000
_FORMATS = {"PNG": "png", "JPEG": "jpeg", "WEBP": "webp"}
# Same format out as in; JPEG and WEBP lossy at quality 90, PNG lossless. A JPEG
# comment is not carried over: like EXIF and XMP, it is metadata.
_ENCODE: Mapping[str, Mapping[str, Any]] = {
    "PNG": {"compress_level": 6, "optimize": False},
    "JPEG": {
        "quality": 90,
        "subsampling": 2,
        "optimize": False,
        "progressive": False,
        "comment": b"",
    },
    "WEBP": {"quality": 90, "method": 4, "lossless": False},
}


class Unsupported(Exception):
    """An image this resize leaves alone: its format, animation, rotation or mode."""


def resize(raw: bytes, target: Size) -> tuple[bytes, str]:
    """The image re-encoded at `target` in its own format, and that format.

    Runs in an isolated worker (`shim.core.isolation`): decoding is the costly part.
    """
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
    with warnings.catch_warnings():
        # Pillow only warns between its limit and twice it.
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        resized, source_format, icc = _decoded(Image.open(io.BytesIO(raw)), target)
    output = io.BytesIO()
    resized.save(
        output,
        format=source_format,
        **_ENCODE[source_format],
        **({"icc_profile": icc} if icc else {}),
    )
    return output.getvalue(), _FORMATS[source_format]


def _decoded(image: Any, target: Size) -> tuple[Any, str, bytes | None]:
    from PIL import Image

    with image:
        if image.format not in _FORMATS or getattr(image, "is_animated", False):
            raise Unsupported
        # Rotating it would change what the model sees.
        if image.getexif().get(0x0112, 1) != 1:
            raise Unsupported
        source_format, icc = image.format, image.info.get("icc_profile")
        if image.mode == "P":
            image = image.convert("RGBA" if "transparency" in image.info else "RGB")
        elif image.mode not in {"L", "LA", "RGB", "RGBA"}:
            raise Unsupported
        if source_format == "JPEG":
            image.draft(image.mode, target)
        resized = image.resize(target, Image.Resampling.LANCZOS, reducing_gap=None)
    return resized, source_format, icc


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
