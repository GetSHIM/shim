from decimal import Decimal

import pytest

from scripts.sync_models_dev import build_catalog


def _model(
    model_id: str,
    *,
    output: list[str] | None = None,
    status: str | None = None,
    tiered: bool = False,
    cost_overrides: dict[str, Decimal] | None = None,
) -> dict[str, object]:
    cost: dict[str, object] = {"input": Decimal("1.25"), "output": Decimal("5")}
    cost.update(cost_overrides or {})
    if tiered:
        cost["tiers"] = [
            {
                "input": Decimal("2.5"),
                "output": Decimal("7.5"),
                "tier": {"type": "context", "size": 200_000},
            }
        ]
    return {
        "id": model_id,
        "name": model_id.replace("-", " ").title(),
        "release_date": "2026-01-02",
        "status": status,
        "family": model_id,
        "modalities": {"input": ["text"], "output": output or ["text"]},
        "limit": {"context": 1_000_000, "output": 64_000},
        "cost": cost,
    }


def test_catalog_keeps_only_billable_text_generation_models() -> None:
    source = {
        "openai": {
            "models": {
                "gpt-valid": _model("gpt-valid", tiered=True),
                "gpt-old": _model("gpt-old", status="deprecated"),
                "text-embedding": _model("text-embedding"),
            }
        },
        "anthropic": {"models": {"claude-valid": _model("claude-valid")}},
        "google": {
            "models": {
                "gemini-valid": _model("gemini-valid"),
                "gemini-audio": _model(
                    "gemini-audio",
                    cost_overrides={"input_audio": Decimal("1.25")},
                ),
                "gemini-expensive-audio": _model(
                    "gemini-expensive-audio",
                    cost_overrides={"input_audio": Decimal("2")},
                ),
                "gemini-robotics": _model("gemini-robotics"),
            }
        },
    }

    catalog = build_catalog(source)

    providers = catalog["providers"]
    assert isinstance(providers, dict)
    assert set(providers["openai"]) == {"gpt-old", "gpt-valid"}
    assert providers["openai"]["gpt-old"]["status"] == "deprecated"
    assert "status" not in providers["openai"]["gpt-valid"]
    assert set(providers["anthropic"]) == {"claude-valid"}
    assert set(providers["google"]) == {"gemini-audio", "gemini-valid"}
    assert providers["openai"]["gpt-valid"]["large_context_threshold"] == 200_000
    assert providers["openai"]["gpt-valid"]["max_output_tokens"] == 64_000


def test_catalog_keeps_base_input_and_cache_prices_apart() -> None:
    source = {
        "openai": {
            "models": {
                "gpt-cache": _model(
                    "gpt-cache",
                    cost_overrides={
                        "cache_read": Decimal("0.125"),
                        "cache_write": Decimal("1.5"),
                    },
                )
            }
        },
        "anthropic": {"models": {"claude-valid": _model("claude-valid")}},
        "google": {"models": {"gemini-valid": _model("gemini-valid")}},
    }

    catalog = build_catalog(source)
    providers = catalog["providers"]

    assert isinstance(providers, dict)
    entry = providers["openai"]["gpt-cache"]
    assert entry["input_per_million"] == "1.25"
    assert entry["cache_read_per_million"] == "0.125"
    assert entry["cache_write_per_million"] == "1.5"
    assert "cache_read_per_million" not in providers["google"]["gemini-valid"]


def test_catalog_keeps_limits_capabilities_and_modalities() -> None:
    flagged = _model("gpt-flags", tiered=True)
    flagged.update(tool_call=True, structured_output=False)
    flagged["modalities"] = {"input": ["text", "image", "pdf"], "output": ["text"]}
    flagged["limit"] = {"context": 400_000, "input": 272_000, "output": 128_000}
    flagged["cost"]["tiers"][0].update(cache_read=Decimal("0.25"))  # type: ignore[index]
    plain = _model("gpt-plain")
    plain["tool_call"] = False
    source = {
        "openai": {"models": {"gpt-flags": flagged, "gpt-plain": plain}},
        "anthropic": {"models": {"claude-valid": _model("claude-valid")}},
        "google": {"models": {"gemini-valid": _model("gemini-valid")}},
    }

    providers = build_catalog(source)["providers"]

    assert isinstance(providers, dict)
    entry = providers["openai"]["gpt-flags"]
    assert (entry["context_window"], entry["input_limit"]) == (400_000, 272_000)
    assert (entry["tools"], entry["structured_output"]) == (True, False)
    assert entry["input_modalities"] == ["image", "pdf", "text"]
    assert entry["large_context_input_per_million"] == "2.5"
    assert entry["large_context_cache_read_per_million"] == "0.25"
    assert "large_context_cache_write_per_million" not in entry
    assert "structured_output" not in providers["openai"]["gpt-plain"]
    assert "input_limit" not in providers["openai"]["gpt-plain"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("limit", {"context": 0, "output": 10}),
        ("tool_call", "yes"),
        ("status", "retired"),
        ("modalities", {"input": ["text", "smell"], "output": ["text"]}),
    ],
)
def test_catalog_refuses_malformed_source_facts(field, value) -> None:
    model = _model("gpt-bad")
    model[field] = value
    source = {
        "openai": {"models": {"gpt-bad": model}},
        "anthropic": {"models": {"claude-valid": _model("claude-valid")}},
        "google": {"models": {"gemini-valid": _model("gemini-valid")}},
    }

    with pytest.raises(ValueError):
        build_catalog(source)
