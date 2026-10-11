from datetime import date
import json

import pytest

from shim.billing.lifecycle import (
    RETIREMENT_WARNING_DAYS,
    Retirement,
    _parse,
    load_lifecycle,
)

_ENTRY = {
    "retires_on": "2027-01-05",
    "deprecated_on": "2026-10-01",
    "replacement": "gpt-5.6-sol",
    "source": "https://developers.openai.com/api/docs/deprecations",
    "checked_on": "2026-10-11",
}


def _file(models: dict) -> str:
    return json.dumps(
        {"format": "shim.model.lifecycle", "version": 1, "models": models}
    )


def test_the_shipped_file_loads_and_every_entry_names_its_source() -> None:
    lifecycle = load_lifecycle()

    assert lifecycle.models["openai"]
    assert "registry" not in lifecycle.models
    assert all(
        entry.source.startswith("https://") and entry.checked_on <= date.today()
        for entries in lifecycle.models.values()
        for entry in entries.values()
    )


@pytest.mark.parametrize(
    ("change", "error"),
    [
        ({"retires_on": None}, "retires_on"),
        ({"source": None}, "source"),
        ({"checked_on": None}, "checked_on"),
        ({"retires_on": "05/01/2027"}, "retires_on"),
        ({"retires_on": 1798934400}, "retires_on"),
        ({"deprecated_on": "2027-02-01"}, "deprecated_on is after retires_on"),
        ({"source": "http://example.com/deprecations"}, "source"),
        ({"note": "extra"}, "note"),
    ],
)
def test_an_entry_needs_its_dates_in_order_and_an_https_source(change, error) -> None:
    entry = {
        key: value
        for key, value in {**_ENTRY, **change}.items()
        if value is not None or key not in change
    }

    with pytest.raises(ValueError, match=error):
        _parse(_file({"openai": {"gpt-4": entry}}), operator=False)


@pytest.mark.parametrize(
    ("models", "operator", "error"),
    [
        ({"openai": {"gpt-typo": _ENTRY}}, False, "openai/gpt-typo"),
        ({"anthropic": {"gpt-4": _ENTRY}}, False, "anthropic/gpt-4"),
        ({"azure": {"gpt-4": _ENTRY}}, False, "azure"),
        ({"registry": {"internal-llm": _ENTRY}}, False, "operator file"),
    ],
)
def test_a_model_outside_the_catalog_fails_the_load(models, operator, error) -> None:
    with pytest.raises(ValueError, match=error):
        _parse(_file(models), operator=operator)


def test_the_format_and_version_are_checked() -> None:
    with pytest.raises(ValueError):
        _parse(
            json.dumps({"format": "other", "version": 1, "models": {}}), operator=False
        )
    with pytest.raises(ValueError):
        _parse(
            json.dumps({"format": "shim.model.lifecycle", "version": 2, "models": {}}),
            operator=False,
        )


def test_the_lookup_follows_the_catalog_rule_without_covering_another_model(
    tmp_path,
) -> None:
    path = tmp_path / "lifecycle.json"
    path.write_text(
        _file(
            {
                "openai": {"gpt-5": _ENTRY, "gpt-4.1-nano": _ENTRY},
                "registry": {"internal-llm": {**_ENTRY, "retires_on": "2026-12-01"}},
            }
        )
    )
    lifecycle = load_lifecycle(path)

    assert lifecycle.retirement("gpt-5", "openai") is not None
    assert lifecycle.retirement("GPT-5-2025-08-07", "openai") is not None, "dated"
    assert lifecycle.retirement("gpt-4.1-nano-2025-04-14", "openai") is not None
    assert lifecycle.retirement("gpt-5-mini", "openai") is None, "a model of its own"
    assert lifecycle.retirement("gpt-4.1", "openai") is None
    assert lifecycle.retirement("gpt-5", "anthropic") is None
    registry = lifecycle.retirement("llama-70b", "openai", "internal-llm")
    assert registry is not None and registry.retires_on == date(2026, 12, 1)
    upstream = lifecycle.retirement("gpt-5", "openai", "other-alias")
    assert upstream is not None and upstream.retires_on == date(2027, 1, 5)


def test_an_operator_file_merges_over_the_shipped_dates(tmp_path) -> None:
    shipped = load_lifecycle()
    model, entry = next(iter(shipped.models["openai"].items()))
    path = tmp_path / "lifecycle.json"
    path.write_text(_file({"openai": {model: {**_ENTRY, "retires_on": "2030-01-01"}}}))

    merged = load_lifecycle(path)

    assert merged.models["openai"][model].retires_on == date(2030, 1, 1)
    assert entry.retires_on != date(2030, 1, 1)
    assert len(merged.models["openai"]) == len(shipped.models["openai"])


@pytest.mark.parametrize(
    "content", ["{not json", _file({"openai": {"gpt-typo": _ENTRY}})]
)
def test_a_malformed_operator_file_names_the_setting(tmp_path, content) -> None:
    path = tmp_path / "lifecycle.json"
    path.write_text(content)

    with pytest.raises(ValueError, match="SHIM_MODEL_LIFECYCLE_FILE"):
        load_lifecycle(path)
    with pytest.raises(ValueError, match="SHIM_MODEL_LIFECYCLE_FILE"):
        load_lifecycle(tmp_path / "missing.json")


@pytest.mark.parametrize(
    ("days_left", "warning"),
    [
        (RETIREMENT_WARNING_DAYS + 1, None),
        (RETIREMENT_WARNING_DAYS, "MODEL_RETIRING"),
        (0, "MODEL_RETIRING"),
        (-1, "MODEL_RETIRED"),
    ],
)
def test_the_warning_starts_ninety_days_ahead_and_turns_retired(
    days_left, warning
) -> None:
    retirement = Retirement.model_validate({**_ENTRY, "retires_on": "2027-01-05"})
    today = date.fromordinal(date(2027, 1, 5).toordinal() - days_left)

    assert retirement.warning(today) == warning
