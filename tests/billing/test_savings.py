from decimal import Decimal
from types import SimpleNamespace
from typing import Any

import pytest

from shim.billing.pricing import DEFAULT_PRICE_BOOK
from shim.billing.savings import (
    LEVERS,
    SAVINGS_VERSION,
    cleared_tokens,
    request_savings,
    shared_savings,
)
from shim.gateway.streaming.meter import StreamUsageSnapshot

# claude-haiku-4-5's catalog rates: 1.00 input, 0.10 cache read, 1.25 write, 2.00 one-hour write.
_HAIKU = DEFAULT_PRICE_BOOK.resolved_price_metadata(
    "claude-haiku-4-5", "anthropic", input_tokens=5000, output_tokens=10
)


def _usage(
    split=None, metadata=None, prompt=5000, estimated=False
) -> StreamUsageSnapshot:
    return StreamUsageSnapshot(
        prompt_tokens=prompt,
        completion_tokens=10,
        settlement_cost_usd=Decimal("0.001"),
        provider_model="claude-haiku-4-5",
        pricing_metadata=dict(_HAIKU if metadata is None else metadata),
        estimated=estimated,
        output_hash=None,
        cache_split=split,
    )


def _prepared(settings=(), transforms=None) -> Any:
    return SimpleNamespace(
        settings_applied=tuple({"id": name, "version": 1} for name in settings),
        transforms_applied=transforms,
    )


def _rates() -> tuple[Decimal, Decimal, Decimal, Decimal]:
    return tuple(
        Decimal(str(_HAIKU[key]))
        for key in (
            "input_per_million",
            "cache_read_per_million",
            "cache_write_per_million",
            "cache_write_1h_per_million",
        )
    )  # type: ignore[return-value]


@pytest.mark.parametrize(
    ("split", "expected"),
    [
        ((0, 4000, 0), lambda i, r, w, h: -4000 * (w - i)),
        ((4000, 0, 0), lambda i, r, w, h: 4000 * (i - r)),
        ((1000, 0, 2000), lambda i, r, w, h: 1000 * (i - r) - 2000 * (h - i)),
    ],
)
def test_the_breakpoint_shim_added_is_priced_at_the_settled_rates(
    split, expected
) -> None:
    saved = request_savings(_prepared(["anthropic_auto_cache"]), _usage(split))

    amount = expected(*_rates()) / Decimal(1_000_000)
    assert saved == {
        "version": SAVINGS_VERSION,
        "measured": {
            "provider_cache": {
                "read_tokens": split[0],
                "write_tokens": split[1] + split[2],
                "usd": str(amount.quantize(Decimal("0.0000000001"))),
            }
        },
    }


def test_a_write_only_request_saves_a_negative_amount() -> None:
    saved = request_savings(_prepared(["anthropic_auto_cache"]), _usage((0, 4000, 0)))

    assert saved is not None
    assert Decimal(saved["measured"]["provider_cache"]["usd"]) == Decimal("-0.001")


def test_the_large_context_input_rate_is_used_above_its_threshold() -> None:
    metadata = {
        **_HAIKU,
        "large_context_threshold": 1000,
        "large_context_input_per_million": "2",
    }

    saved = request_savings(
        _prepared(["anthropic_auto_cache"]), _usage((1000, 0, 0), metadata)
    )

    read = Decimal(str(_HAIKU["cache_read_per_million"]))
    assert saved is not None
    assert (
        Decimal(saved["measured"]["provider_cache"]["usd"])
        == 1000 * (2 - read) / 1_000_000
    )


@pytest.mark.parametrize(
    ("split", "metadata"),
    [
        ((4000, 0, 0), {"pricing_resolution": "unknown", "provider_model": "x"}),
        (None, None),
    ],
)
def test_without_rates_or_a_split_money_is_null_and_marked(split, metadata) -> None:
    saved = request_savings(
        _prepared(["anthropic_auto_cache"]), _usage(split, metadata)
    )

    assert saved is not None
    row = saved["measured"]["provider_cache"]
    assert row["usd"] is None and row["unpriced"] is True


def test_the_openai_key_is_never_counted_as_saved() -> None:
    saved = request_savings(
        _prepared(["openai_prompt_cache_key"]), _usage((4096, 0, 0))
    )

    assert saved is not None and set(saved) == {"version", "not_attributed"}
    row = saved["not_attributed"]["provider_cache_key"]
    input_rate, read, _, _ = _rates()
    assert row["read_tokens"] == 4096
    assert Decimal(row["usd"]) == 4096 * (input_rate - read) / 1_000_000


def test_a_clients_own_breakpoint_is_not_a_saving() -> None:
    assert request_savings(_prepared(), _usage((4000, 0, 0))) is None


def test_json_compaction_measures_characters_and_estimates_tokens() -> None:
    entry = {
        "id": "json_compaction",
        "version": 1,
        "before_chars": 2000,
        "after_chars": 1001,
        "items": 1,
    }

    saved = request_savings(_prepared(transforms=(entry,)), _usage())

    assert saved is not None
    assert saved["measured"] == {"json_compaction": {"chars": 999}}
    assert saved["estimated"]["json_compaction"]["tokens"] == 250
    assert (
        Decimal(saved["estimated"]["json_compaction"]["usd"])
        == 250 * _rates()[0] / 1_000_000
    )


def test_image_downscale_measures_bytes_only() -> None:
    entry = {
        "id": "image_downscale",
        "version": 1,
        "before_chars": 10,
        "after_chars": 5,
        "items": 1,
        "before_bytes": 6_000_000,
        "after_bytes": 250_000,
    }

    saved = request_savings(_prepared(transforms=(entry,)), _usage())

    assert saved == {
        "version": 1,
        "measured": {"image_downscale": {"bytes": 5_750_000}},
    }


def test_cleared_thinking_is_measured_with_a_gross_estimate() -> None:
    saved = request_savings(_prepared(["anthropic_clear_thinking"]), _usage(), 15_000)

    assert saved is not None
    assert saved["measured"] == {"context_clearing": {"tokens": 15_000}}
    assert (
        Decimal(saved["estimated"]["context_clearing"]["usd"])
        == 15_000 * _rates()[0] / 1_000_000
    )
    assert request_savings(_prepared(), _usage(), 15_000) is None
    assert (
        request_savings(_prepared(["anthropic_clear_thinking"]), _usage(), None) is None
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            {
                "applied_edits": [
                    {"cleared_input_tokens": 100},
                    {"cleared_input_tokens": 50},
                ]
            },
            150,
        ),
        (
            {
                "applied_edits": [
                    {"cleared_input_tokens": -1},
                    {"cleared_input_tokens": 1.5},
                ]
            },
            None,
        ),
        ({"applied_edits": [{"cleared_input_tokens": True}]}, None),
        ({"applied_edits": "x"}, None),
        (None, None),
        ({"applied_edits": [{"cleared_input_tokens": 0}]}, 0),
        # A provider's figure past any request's size is dropped (L11).
        ({"applied_edits": [{"cleared_input_tokens": 10**25}]}, None),
        ({"applied_edits": [{"cleared_input_tokens": 10**9}]}, 10**9),
    ],
)
def test_cleared_tokens_take_non_negative_integers_only(value, expected) -> None:
    assert cleared_tokens(value) == expected


def test_counted_levers_alone_record_nothing() -> None:
    prepared = _prepared(
        [
            "parameter_pin.temp",
            "image_detail",
            "tool_search",
            "openai_reasoning_context",
        ],
        transforms=(
            {
                "id": "document_text",
                "version": 1,
                "before_chars": 9,
                "after_chars": 3,
                "items": 1,
            },
        ),
    )

    assert request_savings(prepared, _usage((4000, 0, 0))) is None


def test_a_follower_records_the_call_it_avoided() -> None:
    saved = shared_savings(
        {
            "leader_request_id": "req_a",
            "prompt_tokens": 1200,
            "completion_tokens": 200,
            "avoided_cost_usd": "0.0012",
        },
        _usage(),
    )

    assert saved == {
        "version": 1,
        "measured": {"inflight_share": {"usd": "0.0012000000", "tokens": 1400}},
    }


def test_amounts_round_half_even_to_ten_places() -> None:
    saved = shared_savings(
        {
            "prompt_tokens": 1,
            "completion_tokens": 0,
            "avoided_cost_usd": "0.00000000005",
        },
        _usage(),
    )

    assert (
        saved is not None
        and saved["measured"]["inflight_share"]["usd"] == "0.0000000000"
    )


def test_the_record_holds_only_counts_ids_and_decimal_strings() -> None:
    entry = {
        "id": "json_compaction",
        "version": 1,
        "before_chars": 2000,
        "after_chars": 1000,
        "items": 1,
    }
    saved = request_savings(
        _prepared(
            ["anthropic_auto_cache", "anthropic_clear_thinking"], transforms=(entry,)
        ),
        _usage((10, 20, 30)),
        5,
    )

    def leaves(value: object):
        if isinstance(value, dict):
            for item in value.values():
                yield from leaves(item)
        else:
            yield value

    assert saved is not None
    assert all(
        isinstance(leaf, int | str | bool) or leaf is None for leaf in leaves(saved)
    )
    assert {lever.name for lever in LEVERS} >= {
        name for section in ("measured", "estimated") for name in saved[section]
    }


def test_a_follower_of_an_estimated_or_unpriced_answer_saves_no_measured_money() -> (
    None
):
    share = {"prompt_tokens": 1200, "completion_tokens": 200, "avoided_cost_usd": "0"}

    estimated = shared_savings(
        {**share, "avoided_cost_usd": "0.0012"}, _usage(estimated=True)
    )
    unpriced = shared_savings(share, _usage(metadata={"pricing_resolution": "unknown"}))

    assert estimated == {
        "version": 1,
        "estimated": {"inflight_share": {"usd": "0.0012000000", "tokens": 1400}},
    }
    assert unpriced == {
        "version": 1,
        "measured": {"inflight_share": {"usd": None, "unpriced": True, "tokens": 1400}},
    }


def test_a_huge_cleared_count_from_upstream_never_fails_settlement() -> None:
    edits = {"applied_edits": [{"cleared_input_tokens": 10**25}]}

    saved = request_savings(
        _prepared(["anthropic_clear_thinking"]), _usage(), cleared_tokens(edits)
    )

    assert saved is None


def test_document_conversion_is_protection_not_a_lever() -> None:
    assert "document_text" not in {lever.name for lever in LEVERS}
