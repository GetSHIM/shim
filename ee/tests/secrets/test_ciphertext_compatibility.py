"""Secrets written by an older cryptography release must still decrypt.

The round-trip tests prove the library can read what it just wrote, which stays
true across a breaking change. Customer provider keys in production were written
by whichever release was pinned at the time, so the version that matters is the
one that is no longer installed. This test carries a recorded secret reference
instead, produced under cryptography 48.0.1, and fails if an upgrade ever stops
reading it.

Regenerating the constant defeats the test. If it fails, the upgrade is unsafe
for stored data and needs a migration, not a new recording.
"""

from __future__ import annotations

import uuid

import pytest

from shim.gateway.contracts.ids import SecretRef, TenantId
from shim_enterprise.secrets.fernet_store import FernetSecretStore
from shim_enterprise.secrets.store import parse_secret_ref


RECORDED_KEY = "1yuHjGCrKdLoXrHt6qVL4vd6GHUZ1KVDbsXWJsbq3Kw="
RECORDED_TENANT = TenantId(uuid.UUID("6f1d5f4e-2a3b-4c5d-8e9f-0a1b2c3d4e5f"))
RECORDED_PURPOSE = "provider:openai"
RECORDED_PLAINTEXT = "sk-recorded-under-cryptography-48"
RECORDED_SECRET_REF = SecretRef(
    "fernet:v2:gAAAAABqkvPGv30lA0Cho4Uu7dcBRb_DTs9_dXxcTH3V-5fCWQ3zZWjmPDcC1HSwj"
    "asQ4IGyeM_462RGImRO6TgYzURGgYXizgGsSo3pkRco-cgoszHWv_DllqMMovLrP7jUFkSiQXLy"
    "fFErkfJb87hmL7Zw77AZhbsjuYszX4-UJs6IjYYSPf-guw75gxNZb9YMtIzX037bfhxdV3r_YGJ"
    "WSaNurha-7a-0XJ0ayzhAkfzQmVGPIq-JaQF7-U7GUkrXSvYL5p38QkZYBhNBA-BEHiOb-uuClg"
    "wnxNWyU0BhWG-CZfMN_h4="
)


@pytest.fixture
def recorded_store(monkeypatch: pytest.MonkeyPatch) -> FernetSecretStore:
    # The recording is bound to its key, so the test must not depend on whatever
    # ENCRYPTION_KEY the surrounding environment happens to carry.
    from shim_enterprise.secrets import fernet_store

    monkeypatch.setattr(fernet_store.settings, "ENCRYPTION_KEY", RECORDED_KEY)
    return FernetSecretStore()


@pytest.mark.asyncio
async def test_a_secret_written_by_cryptography_48_still_decrypts(
    recorded_store: FernetSecretStore,
) -> None:
    plaintext = await recorded_store.get_secret(
        RECORDED_TENANT,
        RECORDED_SECRET_REF,
        expected_purpose=RECORDED_PURPOSE,
    )

    assert plaintext == RECORDED_PLAINTEXT


@pytest.mark.asyncio
async def test_the_recorded_reference_keeps_its_envelope_shape(
    recorded_store: FernetSecretStore,
) -> None:
    parsed = parse_secret_ref(RECORDED_SECRET_REF)

    assert parsed.backend == "fernet"
    assert parsed.version == "v2"
    assert RECORDED_PLAINTEXT not in str(RECORDED_SECRET_REF)


@pytest.mark.asyncio
async def test_the_recorded_reference_stays_bound_to_its_tenant(
    recorded_store: FernetSecretStore,
) -> None:
    # Tenant binding lives inside the encrypted envelope, so a decryption change
    # that quietly loosened it would show up here rather than in production.
    # The message is asserted because a broken decryption also raises, and this
    # test must not pass by catching that instead.
    with pytest.raises(ValueError, match="does not belong to this tenant"):
        await recorded_store.get_secret(
            TenantId(uuid.uuid4()),
            RECORDED_SECRET_REF,
            expected_purpose=RECORDED_PURPOSE,
        )
