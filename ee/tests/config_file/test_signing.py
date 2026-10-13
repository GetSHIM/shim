from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import HTTPException

from shim_enterprise.config_file.models import ConfigSigningKey
from shim_enterprise.config_file.signing import (
    key_id,
    sign,
    verify_config_signature,
)
from shim_enterprise.tenants.models import Organization, User

# A fixed key, tenant and file: the signature below pins the signed message format.
SEED = bytes(range(32))
TENANT = UUID("00000000-0000-4000-8000-000000000001")
FILE = b"format: shim.config\nversion: 1\n"
KEY_ID = "56475aa75463474c0285df5dbf2bcab7"
SIGNATURE = (
    "56475aa75463474c0285df5dbf2bcab7."
    "xd8uYlRYZ2XxO9CX1l2cJVyrSZuHCzg1ZHwlc_0VmZQNAhTX6uGfPWntU_FfywEYAOOgB8dgxsDDOENraYdzBg"
)


def test_the_signature_covers_the_prefix_the_tenant_and_the_exact_bytes() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(SEED)
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    assert sign(private_key, TENANT, FILE) == SIGNATURE
    assert (
        key_id(private_key.public_key())
        == KEY_ID
        == hashlib.sha256(raw).hexdigest()[:32]
    )
    # Verifiable from the documented message alone.
    private_key.public_key().verify(
        base64.urlsafe_b64decode(SIGNATURE.split(".")[1] + "=="),
        b"shim-config-v1\n00000000-0000-4000-8000-000000000001\n" + FILE,
    )


async def _registered(db, *, active: bool = True, revoked: bool = False):
    organization = Organization(
        id=uuid4(), name="Signing", slug=f"signing-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    holder = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"signing-{uuid4().hex}@example.com",
        role="owner",
        is_active=active,
        is_verified=True,
    )
    db.add(holder)
    await db.flush()
    private_key = Ed25519PrivateKey.generate()
    db.add(
        ConfigSigningKey(
            organization_id=organization.id,
            key_id=key_id(private_key.public_key()),
            public_key=private_key.public_key()
            .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            .decode(),
            user_id=holder.id,
            name="ci",
            revoked_at=datetime.now(timezone.utc) if revoked else None,
        )
    )
    await db.flush()
    return organization.id, private_key


@pytest.mark.asyncio
async def test_a_registered_key_of_the_tenant_verifies(db) -> None:
    tenant, private_key = await _registered(db)

    key = await verify_config_signature(
        db, tenant, FILE, sign(private_key, tenant, FILE)
    )

    assert key.key_id == key_id(private_key.public_key())


@pytest.mark.asyncio
async def test_every_failed_check_answers_the_same_403(db) -> None:
    tenant, private_key = await _registered(db)
    other_tenant, _ = await _registered(db)
    revoked_tenant, revoked_key = await _registered(db, revoked=True)
    inactive_tenant, inactive_key = await _registered(db, active=False)
    good = sign(private_key, tenant, FILE)
    prefix, encoded = good.split(".")
    flipped = ("A" if encoded[0] != "A" else "B") + encoded[1:]
    cases = [
        (tenant, FILE + b" ", good),
        (tenant, FILE, sign(private_key, other_tenant, FILE)),
        (other_tenant, FILE, sign(private_key, other_tenant, FILE)),
        (revoked_tenant, FILE, sign(revoked_key, revoked_tenant, FILE)),
        (inactive_tenant, FILE, sign(inactive_key, inactive_tenant, FILE)),
        (tenant, FILE, f"{'0' * 32}.{encoded}"),
        (tenant, FILE, f"{prefix}.{flipped}"),
        (tenant, FILE, f"{prefix}.not*base64!"),
        (tenant, FILE, f"{prefix}.é"),
        (tenant, FILE, prefix),
        (tenant, FILE, ""),
    ]
    details = []
    for organization_id, data, signature in cases:
        with pytest.raises(HTTPException) as refused:
            await verify_config_signature(db, organization_id, data, signature)
        details.append((refused.value.status_code, refused.value.detail))

    assert details == [
        (
            403,
            {
                "code": "CONFIG_SIGNATURE_INVALID",
                "message": "The signature does not verify.",
                "hint": "Sign the exact file with a registered key of this tenant.",
            },
        )
    ] * len(cases)
