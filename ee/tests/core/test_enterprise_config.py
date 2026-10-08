from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from shim_enterprise.core.config import Settings


ENTERPRISE_REQUIRED_FIELDS = {
    "DATABASE_URL",
    "REDIS_URL",
    "SECRET_KEY",
}
ENTERPRISE_REQUIRED_VALUES = {
    "DATABASE_URL": "postgresql+asyncpg://test:test@localhost/test",
    "REDIS_URL": "redis://localhost:6379/0",
    "SECRET_KEY": "test-secret-key-value",
    "SUPABASE_URL": "https://example.supabase.co",
}


def test_enterprise_settings_still_require_enterprise_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for field in ENTERPRISE_REQUIRED_FIELDS:
        monkeypatch.delenv(field, raising=False)

    with pytest.raises(ValidationError) as error:
        Settings(_env_file=None)

    missing = {
        item["loc"][0] for item in error.value.errors() if item["type"] == "missing"
    }
    assert ENTERPRISE_REQUIRED_FIELDS <= missing


def test_enterprise_settings_load_canonical_environment_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    for field in ENTERPRISE_REQUIRED_FIELDS:
        monkeypatch.delenv(field, raising=False)
    environment_directory = tmp_path / "ee"
    environment_directory.mkdir()
    (environment_directory / ".env").write_text(
        "DATABASE_URL=postgresql+asyncpg://test:test@localhost/test\n"
        "REDIS_URL=redis://localhost:6379/0\n"
        "SECRET_KEY=test-secret-key-value\n"
        "SUPABASE_URL=https://example.supabase.co\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    configured = Settings()

    assert configured.DATABASE_URL == ENTERPRISE_REQUIRED_VALUES["DATABASE_URL"]


def test_enterprise_api_prefix_is_immutable() -> None:
    with pytest.raises(ValidationError) as error:
        Settings(
            **ENTERPRISE_REQUIRED_VALUES,
            API_PREFIX="/other",
            _env_file=None,
        )

    assert any(
        item["loc"] == ("API_PREFIX",) and item["type"] == "literal_error"
        for item in error.value.errors()
    )


def test_enterprise_settings_inherit_csv_list_parsing() -> None:
    configured = Settings(
        **ENTERPRISE_REQUIRED_VALUES,
        TRUSTED_PROXIES="10.0.0.1, 10.0.0.2",
        _env_file=None,
    )

    assert configured.TRUSTED_PROXIES == ["10.0.0.1", "10.0.0.2"]


@pytest.mark.parametrize("seconds", [30, 300, 86_400])
def test_budget_evaluation_interval_accepts_its_bounds(seconds: int) -> None:
    configured = Settings(
        **ENTERPRISE_REQUIRED_VALUES,
        BUDGET_EVALUATION_INTERVAL_SECONDS=seconds,
        _env_file=None,
    )

    assert configured.BUDGET_EVALUATION_INTERVAL_SECONDS == seconds


@pytest.mark.parametrize("seconds", [0, 29, 86_401])
def test_budget_evaluation_interval_rejects_values_outside_its_bounds(
    seconds: int,
) -> None:
    with pytest.raises(ValidationError):
        Settings(
            **ENTERPRISE_REQUIRED_VALUES,
            BUDGET_EVALUATION_INTERVAL_SECONDS=seconds,
            _env_file=None,
        )


def test_budget_evaluation_interval_defaults_to_five_minutes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("BUDGET_EVALUATION_INTERVAL_SECONDS", raising=False)

    assert (
        Settings(
            **ENTERPRISE_REQUIRED_VALUES, _env_file=None
        ).BUDGET_EVALUATION_INTERVAL_SECONDS
        == 300
    )


@pytest.mark.parametrize(
    ("seconds", "valid"), [(59, False), (60, True), (86_400, True), (86_401, False)]
)
def test_findings_evaluation_interval_is_bounded(seconds: int, valid: bool) -> None:
    def build() -> Settings:
        return Settings(
            **ENTERPRISE_REQUIRED_VALUES,
            FINDINGS_EVALUATION_INTERVAL_SECONDS=seconds,
            _env_file=None,
        )

    if valid:
        assert build().FINDINGS_EVALUATION_INTERVAL_SECONDS == seconds
    else:
        with pytest.raises(ValidationError):
            build()


def test_findings_evaluation_interval_defaults_to_fifteen_minutes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FINDINGS_EVALUATION_INTERVAL_SECONDS", raising=False)

    assert (
        Settings(
            **ENTERPRISE_REQUIRED_VALUES, _env_file=None
        ).FINDINGS_EVALUATION_INTERVAL_SECONDS
        == 900
    )
