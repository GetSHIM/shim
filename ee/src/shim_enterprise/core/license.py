"""Offline licence verification for production enterprise deployments."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import UTC, date, datetime
from importlib.resources import files
import json
import logging

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from shim_enterprise.core.errors import ConfigurationError
from shim_enterprise.observability.enterprise_metrics import LICENSE_DAYS_REMAINING


logger = logging.getLogger(__name__)

GRACE_PERIOD_DAYS = 30
PUBLIC_KEY_RESOURCE = "license_public_key.pem"
MALFORMED = "SHIM_LICENSE_KEY is not a valid shim licence."


@dataclass(frozen=True, slots=True)
class License:
    customer: str
    expires: date


def verify_license(
    token: str | None,
    *,
    today: date | None = None,
    public_key: Ed25519PublicKey | None = None,
) -> License:
    if token is None or not token.strip():
        raise ConfigurationError(
            "SHIM_LICENSE_KEY is required to run shim enterprise in production."
        )
    license = _decode(token.strip(), public_key or _packaged_public_key())
    remaining = (license.expires - (today or datetime.now(UTC).date())).days
    LICENSE_DAYS_REMAINING.set(remaining)
    if remaining < -GRACE_PERIOD_DAYS:
        raise ConfigurationError(
            f"The shim licence for {license.customer} expired on {license.expires} "
            f"and its {GRACE_PERIOD_DAYS}-day grace period has ended."
        )
    if remaining < 0:
        logger.warning(
            "shim licence expired customer=%s expires=%s grace_days_remaining=%d",
            license.customer,
            license.expires,
            GRACE_PERIOD_DAYS + remaining,
        )
    return license


def _decode(token: str, public_key: Ed25519PublicKey) -> License:
    payload_segment, separator, signature_segment = token.partition(".")
    if not separator or not payload_segment or not signature_segment:
        raise ConfigurationError(MALFORMED)
    try:
        public_key.verify(
            _decode_segment(signature_segment), payload_segment.encode("ascii")
        )
    except InvalidSignature as exc:
        raise ConfigurationError(
            "SHIM_LICENSE_KEY was not issued for this installation."
        ) from exc
    except (binascii.Error, ValueError) as exc:
        raise ConfigurationError(MALFORMED) from exc
    try:
        payload = json.loads(_decode_segment(payload_segment))
        customer = payload["customer"]
        expires = date.fromisoformat(payload["expires"])
    except (binascii.Error, KeyError, TypeError, ValueError) as exc:
        raise ConfigurationError(MALFORMED) from exc
    if not isinstance(customer, str) or not customer.strip():
        raise ConfigurationError(MALFORMED)
    return License(customer=customer, expires=expires)


def _decode_segment(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _packaged_public_key() -> Ed25519PublicKey:
    resource = files("shim_enterprise.core").joinpath(PUBLIC_KEY_RESOURCE)
    if not resource.is_file():
        raise ConfigurationError(
            f"{PUBLIC_KEY_RESOURCE} is missing from this installation; "
            "issue it with ee/scripts/sign_license.py keygen."
        )
    public_key = load_pem_public_key(resource.read_bytes())
    if not isinstance(public_key, Ed25519PublicKey):
        raise ConfigurationError(f"{PUBLIC_KEY_RESOURCE} is not an Ed25519 public key.")
    return public_key
