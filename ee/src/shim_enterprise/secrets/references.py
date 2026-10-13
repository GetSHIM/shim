"""The credential reference a deployment target carries to the credential resolver.

A bare secret id for every deployment, or `<id>|<region>|<session tag>` for an AWS
one, so the region a Bedrock key is minted for travels without a core change. It
names a secret and is never logged or recorded.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from uuid import UUID

AWS_REGION = re.compile(r"^[a-z]{2}(-[a-z]+)+-[0-9]$")
_TAG = re.compile(r"^[A-Za-z0-9_.:/=+@ -]{0,256}$")


@dataclass(frozen=True)
class CredentialReference:
    secret_id: UUID
    aws_region: str | None = None
    session_tag: str | None = None


def format_reference(
    secret_id: UUID, aws_region: str | None = None, session_tag: str | None = None
) -> str:
    if aws_region is None:
        return str(secret_id)
    return f"{secret_id}|{aws_region}|{session_tag or ''}"


def parse_reference(value: str) -> CredentialReference:
    parts = value.split("|")
    if len(parts) == 1:
        return CredentialReference(UUID(value))
    if len(parts) != 3:
        raise ValueError("malformed credential reference")
    secret_id, region, tag = parts
    if not AWS_REGION.fullmatch(region) or not _TAG.fullmatch(tag):
        raise ValueError("malformed credential reference")
    return CredentialReference(UUID(secret_id), region, tag or None)
