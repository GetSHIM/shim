"""What each lever saved on a request: measured apart from estimated, never content."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal
import math
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from shim.gateway.kernel.result import PreparedInference
    from shim.gateway.streaming.meter import StreamUsageSnapshot

SAVINGS_VERSION = 1
Method = Literal["measured", "estimated", "not_attributed", "counted"]
_PLACES = Decimal("0.0000000001")
_MILLION = Decimal(1_000_000)


@dataclass(frozen=True, slots=True)
class Lever:
    name: str
    methods: tuple[Method, ...]
    note: str


# One row per lever, in the order the read route lists them.
LEVERS: tuple[Lever, ...] = (
    Lever(
        "inflight_share",
        ("measured",),
        "A provider call that did not happen; its usage is the one the provider reported for the first request.",
    ),
    Lever(
        "provider_cache",
        ("measured",),
        "Cache reads at the input rate minus the read rate, less cache writes above the input rate, at this request's settled rates; can be negative.",
    ),
    Lever(
        "provider_cache_key",
        ("not_attributed",),
        "OpenAI caches without the key too, so its discount is shown but not attributed to shim.",
    ),
    Lever(
        "json_compaction",
        ("measured", "estimated"),
        "Characters removed are measured; tokens are estimated at four characters a token.",
    ),
    Lever(
        "image_downscale",
        ("measured",),
        "Bytes not sent; tokens are unchanged because the provider resizes to the same size.",
    ),
    Lever(
        "context_clearing",
        ("measured", "estimated"),
        "Tokens the provider reported clearing; money is gross, before the cache rewrite clearing causes.",
    ),
    Lever(
        "routing",
        ("estimated",),
        "Same tokens priced at both models; the other model would have written a different answer.",
    ),
    Lever(
        "routing_monitor",
        ("estimated",),
        "Same tokens priced at both models; the other model would have written a different answer.",
    ),
    *(
        Lever(
            name,
            ("counted",),
            "Requests counted only: the provider reports no tokens for this lever.",
        )
        for name in (
            "image_detail",
            "tool_search",
            "openai_reasoning_context",
            "parameter_pin",
            "document_text",
        )
    ),
)


_PRICED_SETTINGS = frozenset(
    {"anthropic_auto_cache", "openai_prompt_cache_key", "anthropic_clear_thinking"}
)
_MEASURED_TRANSFORMS = frozenset({"json_compaction", "image_downscale"})


def usd(amount: Decimal) -> str:
    return f"{amount.quantize(_PLACES, rounding=ROUND_HALF_EVEN):f}"


def cleared_tokens(context_management: object) -> int | None:
    """The input tokens an Anthropic answer's applied edits cleared, or None."""
    edits = (
        context_management.get("applied_edits")
        if isinstance(context_management, Mapping)
        else None
    )
    if not isinstance(edits, list):
        return None
    counts = [
        count
        for edit in edits
        if isinstance(edit, Mapping)
        and type(count := edit.get("cleared_input_tokens")) is int
        and count >= 0
    ]
    return sum(counts) if counts else None


def _rates(usage: StreamUsageSnapshot) -> tuple[Decimal, ...] | None:
    """Input, cache-read, cache-write and one-hour-write rates the request settled at."""
    metadata = usage.pricing_metadata
    if (
        metadata.get("pricing_resolution") == "unknown"
        or "input_per_million" not in metadata
    ):
        return None
    threshold = metadata.get("large_context_threshold")
    tier = isinstance(threshold, int) and usage.prompt_tokens > threshold
    return tuple(
        Decimal(str(metadata[key]))
        for key in (
            "large_context_input_per_million" if tier else "input_per_million",
            "cache_read_per_million",
            "cache_write_per_million",
            "cache_write_1h_per_million",
        )
    )


def _money(amount: Decimal | None) -> dict[str, Any]:
    return {"usd": None, "unpriced": True} if amount is None else {"usd": usd(amount)}


def request_savings(
    prepared: PreparedInference,
    usage: StreamUsageSnapshot,
    cleared_input_tokens: int | None = None,
) -> dict[str, Any] | None:
    """The `savings` record of a completed request; None when no lever has a figure."""
    applied = {entry["id"] for entry in prepared.settings_applied or ()}
    transforms = {entry["id"]: entry for entry in prepared.transforms_applied or ()}
    # Default traffic has no lever on and costs nothing here.
    if not (applied & _PRICED_SETTINGS or transforms.keys() & _MEASURED_TRANSFORMS):
        return None
    rates = _rates(usage)
    measured: dict[str, dict[str, Any]] = {}
    estimated: dict[str, dict[str, Any]] = {}
    not_attributed: dict[str, dict[str, Any]] = {}
    split = usage.cache_split
    if "anthropic_auto_cache" in applied:
        if split is None:
            measured["provider_cache"] = {
                "read_tokens": None,
                "write_tokens": None,
                **_money(None),
            }
        else:
            read, write, write_1h = split
            measured["provider_cache"] = {
                "read_tokens": read,
                "write_tokens": write + write_1h,
                **_money(
                    None
                    if rates is None
                    else (
                        read * (rates[0] - rates[1])
                        - write * (rates[2] - rates[0])
                        - write_1h * (rates[3] - rates[0])
                    )
                    / _MILLION
                ),
            }
    if "openai_prompt_cache_key" in applied:
        read = None if split is None else split[0]
        not_attributed["provider_cache_key"] = {
            "read_tokens": read,
            **_money(
                None
                if rates is None or read is None
                else read * (rates[0] - rates[1]) / _MILLION
            ),
        }
    if compaction := transforms.get("json_compaction"):
        chars = compaction["before_chars"] - compaction["after_chars"]
        tokens = math.ceil(chars / 4)
        measured["json_compaction"] = {"chars": chars}
        estimated["json_compaction"] = {
            "tokens": tokens,
            **_money(None if rates is None else tokens * rates[0] / _MILLION),
        }
    if downscale := transforms.get("image_downscale"):
        measured["image_downscale"] = {
            "bytes": downscale["before_bytes"] - downscale["after_bytes"]
        }
    if "anthropic_clear_thinking" in applied and cleared_input_tokens is not None:
        measured["context_clearing"] = {"tokens": cleared_input_tokens}
        estimated["context_clearing"] = _money(
            None if rates is None else cleared_input_tokens * rates[0] / _MILLION
        )
    return _record(measured, estimated, not_attributed)


def shared_savings(inflight_share: Mapping[str, Any]) -> dict[str, Any] | None:
    """A follower's record: the provider call its shared answer avoided."""
    return _record(
        {
            "inflight_share": {
                "usd": usd(Decimal(str(inflight_share["avoided_cost_usd"]))),
                "tokens": inflight_share["prompt_tokens"]
                + inflight_share["completion_tokens"],
            }
        },
        {},
        {},
    )


def _record(*sections: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    named = dict(zip(("measured", "estimated", "not_attributed"), sections))
    present = {name: section for name, section in named.items() if section}
    return {"version": SAVINGS_VERSION, **present} if present else None
