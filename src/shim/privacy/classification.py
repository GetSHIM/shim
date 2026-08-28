"""Explicit classifications for metadata crossing persistence boundaries."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
import hashlib
from types import MappingProxyType


class MetadataClassification(str, Enum):
    """Retention and disclosure class for gateway metadata."""

    PUBLIC = "public"
    TENANT_CONFIDENTIAL = "tenant_confidential"
    SECRET = "secret"
    CONTENT_DERIVED = "content_derived"
    REGULATED = "regulated"


@dataclass(frozen=True)
class MetadataDescriptor:
    """A named metadata field with an explicit disclosure classification."""

    name: str
    classification: MetadataClassification
    allowed_destinations: frozenset[str]

    def permits(self, destination: str) -> bool:
        return destination in self.allowed_destinations


PUBLIC_METADATA_DESTINATIONS = frozenset(
    {"audit", "analytics", "logs", "outbox", "traces"}
)
TENANT_METADATA_DESTINATIONS = frozenset({"audit", "analytics", "outbox"})
CONTENT_DERIVED_DESTINATIONS = frozenset({"analytics", "audit", "lifecycle", "outbox"})
REGULATED_METADATA_DESTINATIONS = frozenset(
    {"analytics", "audit", "lifecycle", "outbox", "traces"}
)
SECRET_METADATA_DESTINATIONS = frozenset({"secret_store"})


GATEWAY_METADATA: Mapping[str, MetadataDescriptor] = MappingProxyType(
    {
        "input_hash": MetadataDescriptor(
            name="input_hash",
            classification=MetadataClassification.CONTENT_DERIVED,
            allowed_destinations=CONTENT_DERIVED_DESTINATIONS,
        ),
        "output_hash": MetadataDescriptor(
            name="output_hash",
            classification=MetadataClassification.CONTENT_DERIVED,
            allowed_destinations=CONTENT_DERIVED_DESTINATIONS,
        ),
        "pii_detected": MetadataDescriptor(
            name="pii_detected",
            classification=MetadataClassification.REGULATED,
            allowed_destinations=REGULATED_METADATA_DESTINATIONS,
        ),
        "provider_credential": MetadataDescriptor(
            name="provider_credential",
            classification=MetadataClassification.SECRET,
            allowed_destinations=SECRET_METADATA_DESTINATIONS,
        ),
        "pii_entities": MetadataDescriptor(
            name="pii_entities",
            classification=MetadataClassification.REGULATED,
            allowed_destinations=REGULATED_METADATA_DESTINATIONS,
        ),
        "raw_prompt": MetadataDescriptor(
            name="raw_prompt",
            classification=MetadataClassification.TENANT_CONFIDENTIAL,
            allowed_destinations=frozenset(),
        ),
        "request_id": MetadataDescriptor(
            name="request_id",
            classification=MetadataClassification.PUBLIC,
            allowed_destinations=PUBLIC_METADATA_DESTINATIONS,
        ),
        "redacted_fields": MetadataDescriptor(
            name="redacted_fields",
            classification=MetadataClassification.REGULATED,
            allowed_destinations=REGULATED_METADATA_DESTINATIONS,
        ),
        "tenant_id": MetadataDescriptor(
            name="tenant_id",
            classification=MetadataClassification.TENANT_CONFIDENTIAL,
            allowed_destinations=TENANT_METADATA_DESTINATIONS,
        ),
        "verification_map": MetadataDescriptor(
            name="verification_map",
            classification=MetadataClassification.REGULATED,
            allowed_destinations=frozenset({"encrypted_privacy_store"}),
        ),
    }
)


def metadata_descriptor(name: str) -> MetadataDescriptor:
    """Return the reviewed descriptor, rejecting unclassified metadata."""

    try:
        return GATEWAY_METADATA[name]
    except KeyError as exc:
        raise ValueError(f"unclassified gateway metadata: {name!r}") from exc


def content_ref(salt: str, text: str) -> str:
    """Create a salted irreversible reference for content-derived metadata."""

    digest = hashlib.sha256()
    digest.update(salt.encode())
    digest.update(b"\x1f")
    digest.update(text.encode())
    return digest.hexdigest()
