from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import shim.cli as cli
from shim.core.community_config import CommunitySettings


ENTERPRISE_REQUIRED_FIELDS = {
    "DATABASE_URL",
    "REDIS_URL",
    "SECRET_KEY",
    "SUPABASE_URL",
}


def test_community_settings_require_no_enterprise_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for field in ENTERPRISE_REQUIRED_FIELDS:
        monkeypatch.delenv(field, raising=False)

    configured = CommunitySettings(_env_file=None)

    assert ENTERPRISE_REQUIRED_FIELDS.isdisjoint(CommunitySettings.model_fields)
    assert all(not hasattr(configured, field) for field in ENTERPRISE_REQUIRED_FIELDS)


def test_community_settings_support_production_without_enterprise_fields() -> None:
    configured = CommunitySettings(ENVIRONMENT="production", _env_file=None)

    assert configured.ENVIRONMENT == "production"


@pytest.mark.parametrize(
    "api_key",
    ["too-short", "valid-key-with-space ", "valid-key-with\nnewline"],
)
def test_community_api_key_rejects_short_or_whitespace_values(api_key: str) -> None:
    with pytest.raises(ValidationError) as error:
        CommunitySettings(SHIM_API_KEY=api_key, _env_file=None)

    assert api_key not in str(error.value)


def test_community_api_key_is_optional_and_redacted() -> None:
    secret = "valid-local-shim-key"
    configured = CommunitySettings(SHIM_API_KEY=secret, _env_file=None)

    assert configured.SHIM_API_KEY is not None
    assert configured.SHIM_API_KEY.get_secret_value() == secret
    assert secret not in repr(configured)


def test_global_rate_limit_defaults_to_one_thousand_and_must_be_positive() -> None:
    assert CommunitySettings(_env_file=None).GLOBAL_RATE_LIMIT_PER_MINUTE == 1000
    with pytest.raises(ValidationError):
        CommunitySettings(GLOBAL_RATE_LIMIT_PER_MINUTE=0, _env_file=None)


def test_cli_names_the_bad_setting_without_its_value(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("SHIM_API_KEY", "twelve-chars")

    with pytest.raises(SystemExit) as exit_info:
        cli.main(["serve"])

    error = capsys.readouterr().err
    assert exit_info.value.code == 2
    assert "shim: error: SHIM_API_KEY: Value should have at least 16 items" in error
    assert "twelve-chars" not in error


def test_pii_entity_actions_are_parsed_from_json_and_default_to_none() -> None:
    assert CommunitySettings(_env_file=None).PII_ENTITY_ACTIONS == {}
    settings = CommunitySettings(
        _env_file=None,
        PII_ENTITY_ACTIONS='{"SECRET": "block", "EMAIL_ADDRESS": "monitor", "PERSON_NAME_TR": "mask"}',
    )
    assert settings.PII_ENTITY_ACTIONS == {
        "SECRET": "block",
        "EMAIL_ADDRESS": "monitor",
        "PERSON_NAME_TR": "mask",
    }


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("{not json", "Expecting property name"),
        ('{"PERSON": "mask"}', "unknown entity type: PERSON"),
        (
            '{"SECRET": "warn"}',
            "Input should be 'off', 'monitor', 'mask_last4', 'mask' or 'block'",
        ),
        (
            '{"EMAIL_ADDRESS": "mask_last4"}',
            "mask_last4 is only for CREDIT_CARD and IBAN_CODE: EMAIL_ADDRESS",
        ),
        ('["SECRET"]', "Input should be a valid dictionary"),
    ],
)
def test_cli_names_an_invalid_pii_entity_actions_setting(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    value: str,
    message: str,
) -> None:
    monkeypatch.setenv("PII_ENTITY_ACTIONS", value)

    with pytest.raises(SystemExit):
        cli.main(["serve"])

    error = capsys.readouterr().err
    assert "shim: error: PII_ENTITY_ACTIONS" in error
    assert message in error


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        (
            {"PII_PLACEHOLDER_MODE": "stable"},
            "PII_PLACEHOLDER_KEY: Value error, required when PII_PLACEHOLDER_MODE is stable",
        ),
        (
            {"PII_PLACEHOLDER_MODE": "stable", "PII_PLACEHOLDER_KEY": "k" * 31},
            "PII_PLACEHOLDER_KEY: Value should have at least 32 items",
        ),
        (
            {"PII_PLACEHOLDER_MODE": "fixed"},
            "PII_PLACEHOLDER_MODE: Input should be 'random' or 'stable'",
        ),
    ],
)
def test_cli_names_an_invalid_placeholder_setting(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    environment: dict[str, str],
    message: str,
) -> None:
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    with pytest.raises(SystemExit):
        cli.main(["serve"])

    error = capsys.readouterr().err
    assert f"shim: error: {message}" in error
    assert "k" * 31 not in error


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("1", "PII_BULK_THRESHOLD: Value error, must be 0 (off) or at least 2"),
        ("-1", "PII_BULK_THRESHOLD: Input should be greater than or equal to 0"),
        ("many", "PII_BULK_THRESHOLD: Input should be a valid integer"),
    ],
)
def test_cli_names_an_invalid_bulk_threshold(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    value: str,
    message: str,
) -> None:
    monkeypatch.setenv("PII_BULK_THRESHOLD", value)

    with pytest.raises(SystemExit):
        cli.main(["serve"])

    assert f"shim: error: {message}" in capsys.readouterr().err


def test_the_bulk_threshold_defaults_to_50_and_0_is_accepted() -> None:
    assert CommunitySettings(_env_file=None).PII_BULK_THRESHOLD == 50
    assert (
        CommunitySettings(_env_file=None, PII_BULK_THRESHOLD=0).PII_BULK_THRESHOLD == 0
    )


def test_the_response_scan_is_off_unless_count_is_chosen() -> None:
    assert CommunitySettings(_env_file=None).PII_RESPONSE_SCAN == "off"
    assert CommunitySettings(
        _env_file=None, PII_RESPONSE_SCAN="count"
    ).PII_RESPONSE_SCAN == ("count")
    with pytest.raises(ValueError, match="'off' or 'count'"):
        CommunitySettings(_env_file=None, PII_RESPONSE_SCAN="mask")


def test_cli_names_a_short_system_prompt_hash_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SYSTEM_PROMPT_HASH_KEY", "k" * 31)

    with pytest.raises(SystemExit):
        cli.main(["serve"])

    error = capsys.readouterr().err
    assert "shim: error: SYSTEM_PROMPT_HASH_KEY: Value should have at least 32" in error
    assert "k" * 31 not in error


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", []),
        ("language,shape", ["shape", "language"]),
        (' ["shape", "language", "shape"] ', ["shape", "language"]),
        ("shape, shape", ["shape"]),
    ],
)
def test_response_analysis_names_follow_the_registry(
    monkeypatch, value, expected
) -> None:
    import shim.core.community_config as community_config

    analyzers = (SimpleNamespace(name="shape"), SimpleNamespace(name="language"))
    monkeypatch.setattr(community_config, "ANALYZERS", analyzers)
    monkeypatch.setattr(
        community_config, "ANALYZER_NAMES", frozenset({"shape", "language"})
    )

    settings = CommunitySettings(_env_file=None, SHIM_RESPONSE_ANALYSIS=value)

    assert settings.SHIM_RESPONSE_ANALYSIS == expected


def test_an_unknown_analyzer_names_the_setting_and_the_name() -> None:
    with pytest.raises(ValidationError) as error:
        CommunitySettings(_env_file=None, SHIM_RESPONSE_ANALYSIS="nope")

    assert "SHIM_RESPONSE_ANALYSIS" in str(error.value)
    assert "unknown analyzer: nope" in str(error.value)
    assert CommunitySettings(_env_file=None).SHIM_RESPONSE_ANALYSIS == []


@pytest.mark.parametrize(("value", "on"), [("on", True), ("off", False)])
def test_the_price_tier_warning_setting_is_on_or_off(value, on) -> None:
    settings = CommunitySettings(_env_file=None, SHIM_PRICE_TIER_WARNING=value)

    assert (settings.SHIM_PRICE_TIER_WARNING == "on") is on
    assert CommunitySettings(_env_file=None).SHIM_PRICE_TIER_WARNING == "off"


def test_an_unknown_price_tier_warning_value_stops_the_gateway() -> None:
    with pytest.raises(ValidationError):
        CommunitySettings(_env_file=None, SHIM_PRICE_TIER_WARNING="yes")


@pytest.mark.parametrize("value", ["ignore", "honor"])
def test_the_trace_parent_setting_is_ignore_or_honor(value) -> None:
    assert CommunitySettings(_env_file=None).SHIM_TRACE_PARENT == "ignore"
    assert (
        CommunitySettings(_env_file=None, SHIM_TRACE_PARENT=value).SHIM_TRACE_PARENT
        == value
    )
    with pytest.raises(ValidationError):
        CommunitySettings(_env_file=None, SHIM_TRACE_PARENT="follow")


@pytest.mark.parametrize(
    "values",
    [
        {"SHIM_TASK_MAX_CALLS": 0},
        {"SHIM_TASK_MAX_CALLS": 100_001},
        {"SHIM_TASK_MAX_COST_USD": "0"},
        {"SHIM_TASK_MAX_COST_USD": "100000.01"},
        {"SHIM_TASK_WINDOW_SECONDS": 59},
        {"SHIM_TASK_WINDOW_SECONDS": 86_401},
        {"SHIM_AGENT_LOOP": "warn"},
        {"SHIM_AGENT_LOOP_REPEATS": 2},
        {"SHIM_AGENT_LOOP_REPEATS": 101},
    ],
)
def test_task_cap_and_loop_settings_refuse_values_out_of_bounds(values) -> None:
    with pytest.raises(ValidationError):
        CommunitySettings(_env_file=None, **values)


def test_task_caps_are_off_and_the_loop_signal_counts_by_default() -> None:
    settings = CommunitySettings(_env_file=None)

    assert (settings.SHIM_TASK_MAX_CALLS, settings.SHIM_TASK_MAX_COST_USD) == (
        None,
        None,
    )
    assert (settings.SHIM_TASK_WINDOW_SECONDS, settings.SHIM_AGENT_LOOP) == (
        3600,
        "count",
    )
    assert settings.SHIM_AGENT_LOOP_REPEATS == 5


@pytest.mark.parametrize(
    ("value", "valid"), [("off", True), ("on", True), ("yes", False)]
)
def test_inflight_sharing_is_off_unless_turned_on(value, valid) -> None:
    assert CommunitySettings(_env_file=None).SHIM_INFLIGHT_SHARING == "off"
    if valid:
        assert (
            CommunitySettings(
                _env_file=None, SHIM_INFLIGHT_SHARING=value
            ).SHIM_INFLIGHT_SHARING
            == value
        )
    else:
        with pytest.raises(ValidationError):
            CommunitySettings(_env_file=None, SHIM_INFLIGHT_SHARING=value)


@pytest.mark.parametrize(
    ("value", "valid"), [("block", True), ("allow", True), ("scan", False)]
)
def test_media_inputs_are_blocked_unless_allowed(value, valid) -> None:
    assert CommunitySettings(_env_file=None).SHIM_MEDIA_INPUTS == "block"
    if valid:
        assert (
            CommunitySettings(_env_file=None, SHIM_MEDIA_INPUTS=value).SHIM_MEDIA_INPUTS
            == value
        )
    else:
        with pytest.raises(ValidationError):
            CommunitySettings(_env_file=None, SHIM_MEDIA_INPUTS=value)


@pytest.mark.parametrize(
    ("name", "values"),
    [
        ("SHIM_ANTHROPIC_AUTO_CACHE", ("off", "5m", "1h")),
        ("SHIM_OPENAI_PROMPT_CACHE_KEY", ("off", "key", "tenant")),
    ],
)
def test_provider_cache_settings_are_off_unless_set(name, values) -> None:
    assert getattr(CommunitySettings(_env_file=None), name) == "off"
    for value in values:
        assert (
            getattr(CommunitySettings(_env_file=None, **{name: value}), name) == value
        )
    for value in ("on", "1d", ""):
        with pytest.raises(ValidationError):
            CommunitySettings(_env_file=None, **{name: value})


def test_tool_search_and_thinking_settings_are_off_and_bounded() -> None:
    settings = CommunitySettings(_env_file=None)
    assert (
        settings.SHIM_TOOL_SEARCH,
        settings.SHIM_TOOL_SEARCH_MIN_TOOLS,
        settings.SHIM_TOOL_SEARCH_KEEP_LOADED,
        settings.SHIM_ANTHROPIC_KEEP_THINKING_TURNS,
        settings.SHIM_OPENAI_REASONING_CONTEXT,
    ) == ("off", 10, [], 0, "off")
    for raw in ("lookup, create", '["lookup", "create"]'):
        assert CommunitySettings(
            _env_file=None, SHIM_TOOL_SEARCH_KEEP_LOADED=raw
        ).SHIM_TOOL_SEARCH_KEEP_LOADED == ["lookup", "create"]
    for name, value in (
        ("SHIM_TOOL_SEARCH", "on"),
        ("SHIM_TOOL_SEARCH_MIN_TOOLS", 1),
        ("SHIM_TOOL_SEARCH_MIN_TOOLS", 10_001),
        ("SHIM_TOOL_SEARCH_KEEP_LOADED", ",".join(f"t{n}" for n in range(65))),
        ("SHIM_TOOL_SEARCH_KEEP_LOADED", "x" * 129),
        ("SHIM_ANTHROPIC_KEEP_THINKING_TURNS", 9),
        ("SHIM_ANTHROPIC_KEEP_THINKING_TURNS", -1),
        ("SHIM_OPENAI_REASONING_CONTEXT", "all_turns"),
    ):
        with pytest.raises(ValidationError):
            CommunitySettings(_env_file=None, **{name: value})


@pytest.mark.parametrize(
    ("value", "valid"), [("off", True), ("on", True), ("yes", False)]
)
def test_json_compaction_is_off_unless_turned_on(value, valid) -> None:
    assert CommunitySettings(_env_file=None).SHIM_JSON_COMPACTION == "off"
    if not valid:
        with pytest.raises(ValidationError):
            CommunitySettings(_env_file=None, SHIM_JSON_COMPACTION=value)
        return
    assert (
        CommunitySettings(
            _env_file=None, SHIM_JSON_COMPACTION=value
        ).SHIM_JSON_COMPACTION
        == value
    )


def test_the_concurrency_limit_is_off_unless_set() -> None:
    settings = CommunitySettings(_env_file=None)
    assert (
        settings.SHIM_CONCURRENCY_TOKEN_LIMIT,
        settings.SHIM_CONCURRENCY_MAX_WAIT_MS,
    ) == (
        None,
        0,
    )
    configured = CommunitySettings(
        _env_file=None,
        SHIM_CONCURRENCY_TOKEN_LIMIT=2_000,
        SHIM_CONCURRENCY_MAX_WAIT_MS=60_000,
    )
    assert configured.SHIM_CONCURRENCY_TOKEN_LIMIT == 2_000
    for name, value in (
        ("SHIM_CONCURRENCY_TOKEN_LIMIT", 0),
        ("SHIM_CONCURRENCY_TOKEN_LIMIT", 100_000_001),
        ("SHIM_CONCURRENCY_MAX_WAIT_MS", -1),
        ("SHIM_CONCURRENCY_MAX_WAIT_MS", 60_001),
    ):
        with pytest.raises(ValidationError):
            CommunitySettings(_env_file=None, **{name: value})


def test_retirement_dates_are_recorded_and_the_header_is_opt_in(tmp_path) -> None:
    settings = CommunitySettings(_env_file=None)

    assert settings.SHIM_MODEL_RETIRING_WARNING == "record"
    assert settings.SHIM_MODEL_LIFECYCLE_FILE is None
    assert (
        CommunitySettings(
            _env_file=None,
            SHIM_MODEL_RETIRING_WARNING="header",
            SHIM_MODEL_LIFECYCLE_FILE=str(tmp_path / "dates.json"),
        ).SHIM_MODEL_LIFECYCLE_FILE
        == tmp_path / "dates.json"
    )
    with pytest.raises(ValidationError):
        CommunitySettings(_env_file=None, SHIM_MODEL_RETIRING_WARNING="refuse")


def test_embeddings_monitor_types_are_known_entity_types() -> None:
    assert CommunitySettings(_env_file=None).PII_EMBEDDINGS_MONITOR == []
    assert CommunitySettings(
        _env_file=None, PII_EMBEDDINGS_MONITOR="TR_NATIONAL_ID, IBAN_CODE"
    ).PII_EMBEDDINGS_MONITOR == ["IBAN_CODE", "TR_NATIONAL_ID"]
    with pytest.raises(ValidationError, match="unknown entity type"):
        CommunitySettings(_env_file=None, PII_EMBEDDINGS_MONITOR="NOT_A_TYPE")


_KEY = {"SHIM_AZURE_OPENAI_API_KEY": "azure-key"}
_ENTRA = {
    "SHIM_AZURE_TENANT_ID": "contoso.onmicrosoft.com",
    "SHIM_AZURE_CLIENT_ID": "00000000-0000-0000-0000-0000000000a1",
    "SHIM_AZURE_CLIENT_SECRET": "entra-secret",
}


@pytest.mark.parametrize(
    ("endpoint", "normalised"),
    [
        ("https://bank.openai.azure.com", "https://bank.openai.azure.com"),
        ("https://bank.openai.azure.com/openai/v1/", "https://bank.openai.azure.com"),
        ("http://127.0.0.1:9101", "http://127.0.0.1:9101"),
        ("http://localhost/openai/v1", "http://localhost"),
        ("http://[::1]:9101", "http://[::1]:9101"),
    ],
)
def test_an_azure_endpoint_is_normalised_and_http_only_on_loopback(
    endpoint, normalised
) -> None:
    configured = CommunitySettings(
        _env_file=None, SHIM_AZURE_OPENAI_ENDPOINT=endpoint, **_KEY
    )

    assert configured.SHIM_AZURE_OPENAI_ENDPOINT == normalised


def test_azure_is_off_by_default_and_an_empty_value_is_unset(monkeypatch) -> None:
    for name in (
        "SHIM_AZURE_OPENAI_ENDPOINT",
        "SHIM_AZURE_TENANT_ID",
        "OPENAI_BASE_URL",
    ):
        monkeypatch.setenv(name, "")
    monkeypatch.setenv("SHIM_AZURE_OPENAI_DEPLOYMENTS", "")
    assert CommunitySettings(_env_file=None).SHIM_AZURE_OPENAI_ENDPOINT is None

    monkeypatch.setenv("SHIM_AZURE_OPENAI_ENDPOINT", "https://bank.openai.azure.com")
    monkeypatch.setenv("SHIM_AZURE_OPENAI_API_KEY", "azure-key")
    monkeypatch.setenv(
        "SHIM_AZURE_OPENAI_DEPLOYMENTS", '{"gpt-5.6-luna": "kurum-mini"}'
    )
    configured = CommunitySettings(_env_file=None)

    assert configured.SHIM_AZURE_OPENAI_DEPLOYMENTS == {"gpt-5.6-luna": "kurum-mini"}
    assert configured.SHIM_AZURE_TOKEN_SCOPE == (
        "https://cognitiveservices.azure.com/.default"
    )
    assert configured.SHIM_AZURE_AUTHORITY_HOST == "https://login.microsoftonline.com"


@pytest.mark.parametrize(
    ("values", "named"),
    [
        ({"SHIM_AZURE_OPENAI_ENDPOINT": "http://bank.openai.azure.com", **_KEY}, "SHIM_AZURE_OPENAI_ENDPOINT"),
        ({"SHIM_AZURE_OPENAI_ENDPOINT": "http://127.0.0.2", **_KEY}, "SHIM_AZURE_OPENAI_ENDPOINT"),
        ({"SHIM_AZURE_OPENAI_ENDPOINT": "http://127.0.0.1@bank.example", **_KEY}, "SHIM_AZURE_OPENAI_ENDPOINT"),
        ({"SHIM_AZURE_OPENAI_ENDPOINT": "https://bank.openai.azure.com"}, "SHIM_AZURE_OPENAI_API_KEY"),
        ({"SHIM_AZURE_OPENAI_ENDPOINT": "https://bank.openai.azure.com", **_KEY, **_ENTRA}, "SHIM_AZURE_OPENAI_API_KEY"),
        ({"SHIM_AZURE_OPENAI_ENDPOINT": "https://bank.openai.azure.com", "SHIM_AZURE_TENANT_ID": "contoso.com"}, "SHIM_AZURE_CLIENT_ID"),
        (_ENTRA, "SHIM_AZURE_TENANT_ID"),
        ({"SHIM_AZURE_CLIENT_SECRET": "s"}, "SHIM_AZURE_CLIENT_SECRET needs"),
        ({"SHIM_AZURE_OPENAI_DEPLOYMENTS": '{"gpt-5.6-luna": "kurum-mini"}'}, "SHIM_AZURE_OPENAI_DEPLOYMENTS"),
        ({"SHIM_AZURE_OPENAI_ENDPOINT": "https://bank.openai.azure.com", "OPENAI_BASE_URL": "https://x.test/v1", **_KEY}, "OPENAI_BASE_URL"),
        ({"SHIM_AZURE_OPENAI_ENDPOINT": "https://bank.openai.azure.com", **_ENTRA, "SHIM_AZURE_CLIENT_ID": "app"}, "SHIM_AZURE_CLIENT_ID"),
        ({"SHIM_AZURE_OPENAI_ENDPOINT": "https://bank.openai.azure.com", **_ENTRA, "SHIM_AZURE_TENANT_ID": "a b"}, "SHIM_AZURE_TENANT_ID"),
        ({"SHIM_AZURE_OPENAI_ENDPOINT": "https://bank.openai.azure.com", **_ENTRA, "SHIM_AZURE_TOKEN_SCOPE": "https://ai.azure.com/"}, "SHIM_AZURE_TOKEN_SCOPE"),
        ({"SHIM_AZURE_OPENAI_ENDPOINT": "https://bank.openai.azure.com", **_KEY, "SHIM_AZURE_OPENAI_DEPLOYMENTS": '{"kurum-mini": "kurum-mini"}'}, "SHIM_AZURE_OPENAI_DEPLOYMENTS"),
        ({"SHIM_AZURE_OPENAI_ENDPOINT": "https://bank.openai.azure.com", **_KEY, "SHIM_AZURE_OPENAI_DEPLOYMENTS": '{"gpt-5.6-luna": "-kurum"}'}, "SHIM_AZURE_OPENAI_DEPLOYMENTS"),
        ({"SHIM_AZURE_OPENAI_ENDPOINT": "https://bank.openai.azure.com", **_KEY, "SHIM_AZURE_OPENAI_DEPLOYMENTS": "not json"}, "SHIM_AZURE_OPENAI_DEPLOYMENTS"),
    ],
)  # fmt: skip
def test_an_incoherent_azure_setting_stops_the_gateway_by_name(values, named) -> None:
    with pytest.raises(ValidationError, match=named):
        CommunitySettings(_env_file=None, **values)
