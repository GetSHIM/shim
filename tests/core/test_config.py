from __future__ import annotations

import pytest
from pydantic import ValidationError

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
