from __future__ import annotations

import pytest

from shim.privacy.classification import (
    GATEWAY_METADATA,
    MetadataClassification,
    metadata_descriptor,
)
from shim.privacy.policies import PrivacyAction, PrivacyOutcome
from shim.privacy.retention import REQUEST_PRIVACY_RETENTION


def test_every_gateway_metadata_field_has_a_supported_classification() -> None:
    assert GATEWAY_METADATA
    assert {
        descriptor.classification for descriptor in GATEWAY_METADATA.values()
    } == set(MetadataClassification)


@pytest.mark.parametrize(
    ("name", "forbidden_destination"),
    [
        ("raw_prompt", "traces"),
        ("provider_credential", "logs"),
        ("verification_map", "analytics"),
        ("verification_map", "outbox"),
        ("verification_map", "logs"),
    ],
)
def test_sensitive_metadata_is_not_permitted_at_unsafe_destinations(
    name: str,
    forbidden_destination: str,
) -> None:
    assert not metadata_descriptor(name).permits(forbidden_destination)


def test_unclassified_metadata_is_rejected() -> None:
    with pytest.raises(ValueError, match="unclassified gateway metadata"):
        metadata_descriptor("new_unreviewed_field")


def test_privacy_outcome_keeps_verification_map_out_of_repr_and_trace() -> None:
    outcome = PrivacyOutcome(
        action=PrivacyAction.SCRUBBED,
        pii_detected=True,
        verification_map={"<PERSON_aaaa1111>": "Ada"},
    )

    assert "Ada" not in repr(outcome)
    assert "<PERSON_aaaa1111>" not in repr(outcome)
    assert "verification_map" not in outcome.trace_metadata()
    assert outcome.redacted_fields == ("<PERSON_aaaa1111>",)
    assert outcome.pii_entities == {"PERSON": 1}
    assert REQUEST_PRIVACY_RETENTION.durable_facts(outcome) == {
        "privacy_status": "scrubbed",
        "pii_detected": True,
        "pii_entities": {"PERSON": 1},
    }
