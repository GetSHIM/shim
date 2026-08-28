from decimal import Decimal

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
    assert set(providers["openai"]) == {"gpt-valid"}
    assert set(providers["anthropic"]) == {"claude-valid"}
    assert set(providers["google"]) == {"gemini-audio", "gemini-valid"}
    assert providers["openai"]["gpt-valid"]["large_context_threshold"] == 200_000
    assert providers["openai"]["gpt-valid"]["max_output_tokens"] == 64_000


def test_catalog_uses_the_highest_cache_rate_for_gross_input_tokens() -> None:
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
    assert providers["openai"]["gpt-cache"]["input_per_million"] == "1.5"
