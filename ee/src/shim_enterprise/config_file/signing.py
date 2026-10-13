"""What a configuration signature covers, and the one check that accepts it."""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import TYPE_CHECKING
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

if TYPE_CHECKING:
    from shim_enterprise.config_file.models import ConfigSigningKey

# The prefix keeps a config signature from verifying as anything else; the tenant id
# keeps a file signed for one tenant from applying to another.
_DOMAIN = b"shim-config-v1\n"


def signed_message(organization_id: UUID, file_bytes: bytes) -> bytes:
    return _DOMAIN + str(organization_id).encode("ascii") + b"\n" + file_bytes


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:32]


def sign(
    private_key: Ed25519PrivateKey, organization_id: UUID, file_bytes: bytes
) -> str:
    """`<key_id>.<signature>`, base64url without padding as licence keys are."""
    signature = private_key.sign(signed_message(organization_id, file_bytes))
    encoded = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{key_id(private_key.public_key())}.{encoded}"


async def verify_config_signature(
    session: AsyncSession, organization_id: UUID, file_bytes: bytes, signature: str
) -> ConfigSigningKey:
    """The tenant's unrevoked key, held by an active user, that signed exactly this file."""
    # Here, not at the top: the operator script signs files without a database.
    from shim_enterprise.config_file.models import ConfigSigningKey
    from shim_enterprise.tenants.models import User

    refused = HTTPException(
        status_code=403,
        detail={
            "code": "CONFIG_SIGNATURE_INVALID",
            "message": "The signature does not verify.",
            "hint": "Sign the exact file with a registered key of this tenant.",
        },
    )
    signer, _, encoded = signature.partition(".")
    key = await session.scalar(
        select(ConfigSigningKey)
        .join(
            User,
            (User.organization_id == ConfigSigningKey.organization_id)
            & (User.id == ConfigSigningKey.user_id),
        )
        .where(
            ConfigSigningKey.organization_id == organization_id,
            ConfigSigningKey.key_id == signer,
            ConfigSigningKey.revoked_at.is_(None),
            User.is_active.is_(True),
        )
    )
    if key is None:
        raise refused
    public_key = load_pem_public_key(key.public_key.encode("ascii"))
    assert isinstance(public_key, Ed25519PublicKey)
    try:
        public_key.verify(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)),
            signed_message(organization_id, file_bytes),
        )
    except (InvalidSignature, binascii.Error, ValueError):
        raise refused from None
    return key
