from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from shim_enterprise.core.config import Settings


ENTERPRISE_REQUIRED_FIELDS = {
    "DATABASE_URL",
    "REDIS_URL",
    "SECRET_KEY",
    "SUPABASE_URL",
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
