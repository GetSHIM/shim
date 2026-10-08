from __future__ import annotations

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
        PII_ENTITY_ACTIONS='{"SECRET": "block", "EMAIL_ADDRESS": "monitor"}',
    )
    assert settings.PII_ENTITY_ACTIONS == {
        "SECRET": "block",
        "EMAIL_ADDRESS": "monitor",
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
