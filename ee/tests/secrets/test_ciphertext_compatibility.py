from __future__ import annotations

import uuid

import pytest

from shim.gateway.contracts.ids import SecretRef, TenantId
from shim_enterprise.secrets import fernet_store


RECORDED_KEY = "1yuHjGCrKdLoXrHt6qVL4vd6GHUZ1KVDbsXWJsbq3Kw="
RECORDED_TENANT = TenantId(uuid.UUID("6f1d5f4e-2a3b-4c5d-8e9f-0a1b2c3d4e5f"))
RECORDED_PURPOSE = "provider:openai"
RECORDED_PLAINTEXT = "sk-recorded-under-cryptography-48"
CRYPTOGRAPHY_48_SECRET_REF = SecretRef(
    "fernet:v2:gAAAAABqkvPGv30lA0Cho4Uu7dcBRb_DTs9_dXxcTH3V-5fCWQ3zZWjmPDcC1HSwj"
    "asQ4IGyeM_462RGImRO6TgYzURGgYXizgGsSo3pkRco-cgoszHWv_DllqMMovLrP7jUFkSiQXLy"
    "fFErkfJb87hmL7Zw77AZhbsjuYszX4-UJs6IjYYSPf-guw75gxNZb9YMtIzX037bfhxdV3r_YGJ"
    "WSaNurha-7a-0XJ0ayzhAkfzQmVGPIq-JaQF7-U7GUkrXSvYL5p38QkZYBhNBA-BEHiOb-uuClg"
    "wnxNWyU0BhWG-CZfMN_h4="
)


@pytest.mark.asyncio
async def test_cryptography_48_ciphertext_still_decrypts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fernet_store.settings, "ENCRYPTION_KEY", RECORDED_KEY)
    assert (
        await fernet_store.FernetSecretStore().get_secret(
            RECORDED_TENANT,
            CRYPTOGRAPHY_48_SECRET_REF,
            expected_purpose=RECORDED_PURPOSE,
        )
        == RECORDED_PLAINTEXT
    )
