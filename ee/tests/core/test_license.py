from __future__ import annotations

import base64
from datetime import date, timedelta
import json
import logging

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
import pytest

from shim_enterprise.core.errors import ConfigurationError
from shim_enterprise.core.license import GRACE_PERIOD_DAYS, verify_license


TODAY = date(2026, 9, 3)


@pytest.fixture
def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _issue(
    signing_key: Ed25519PrivateKey,
    customer: str = "Regulated Bank A.S.",
    expires: date = date(2027, 9, 3),
) -> str:
    payload = _encode(
        json.dumps({"customer": customer, "expires": expires.isoformat()}).encode()
    )
    return f"{payload}.{_encode(signing_key.sign(payload.encode('ascii')))}"


def _public_key(signing_key: Ed25519PrivateKey) -> Ed25519PublicKey:
    return signing_key.public_key()


def test_valid_license_is_accepted(signing_key: Ed25519PrivateKey) -> None:
    license = verify_license(
        _issue(signing_key),
        today=TODAY,
        public_key=_public_key(signing_key),
    )

    assert license.customer == "Regulated Bank A.S."
    assert license.expires == date(2027, 9, 3)


def test_missing_license_is_rejected(signing_key: Ed25519PrivateKey) -> None:
    for token in (None, "", "   "):
        with pytest.raises(ConfigurationError, match="SHIM_LICENSE_KEY is required"):
            verify_license(token, today=TODAY, public_key=_public_key(signing_key))


def test_license_signed_by_another_key_is_rejected(
    signing_key: Ed25519PrivateKey,
) -> None:
    with pytest.raises(ConfigurationError, match="not issued for this installation"):
        verify_license(
            _issue(Ed25519PrivateKey.generate()),
            today=TODAY,
            public_key=_public_key(signing_key),
        )


def test_tampered_expiry_is_rejected(signing_key: Ed25519PrivateKey) -> None:
    payload, _, signature = _issue(signing_key).partition(".")
    forged = _encode(
        json.dumps(
            {"customer": "Regulated Bank A.S.", "expires": "2099-01-01"}
        ).encode()
    )

    with pytest.raises(ConfigurationError, match="not issued for this installation"):
        verify_license(
            f"{forged}.{signature}",
            today=TODAY,
            public_key=_public_key(signing_key),
        )
    assert payload != forged


@pytest.mark.parametrize(
    "token",
    ["not-a-license", "onlypayload.", ".onlysignature", "a.b"],
)
def test_malformed_license_is_rejected(
    signing_key: Ed25519PrivateKey, token: str
) -> None:
    with pytest.raises(ConfigurationError):
        verify_license(token, today=TODAY, public_key=_public_key(signing_key))


def test_license_without_customer_is_rejected(signing_key: Ed25519PrivateKey) -> None:
    payload = _encode(json.dumps({"expires": "2027-09-03"}).encode())
    token = f"{payload}.{_encode(signing_key.sign(payload.encode('ascii')))}"

    with pytest.raises(ConfigurationError, match="not a valid shim licence"):
        verify_license(token, today=TODAY, public_key=_public_key(signing_key))


def test_expired_license_boots_inside_the_grace_period(
    signing_key: Ed25519PrivateKey, caplog: pytest.LogCaptureFixture
) -> None:
    expires = TODAY - timedelta(days=GRACE_PERIOD_DAYS)

    with caplog.at_level(logging.WARNING):
        license = verify_license(
            _issue(signing_key, expires=expires),
            today=TODAY,
            public_key=_public_key(signing_key),
        )

    assert license.expires == expires
    assert "grace_days_remaining=0" in caplog.text


def test_expired_license_is_rejected_after_the_grace_period(
    signing_key: Ed25519PrivateKey,
) -> None:
    expires = TODAY - timedelta(days=GRACE_PERIOD_DAYS + 1)

    with pytest.raises(ConfigurationError, match="grace period has ended"):
        verify_license(
            _issue(signing_key, expires=expires),
            today=TODAY,
            public_key=_public_key(signing_key),
        )
