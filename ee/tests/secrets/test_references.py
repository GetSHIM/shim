from __future__ import annotations

from uuid import uuid4

import pytest

from shim_enterprise.secrets.references import (
    CredentialReference,
    format_reference,
    parse_reference,
)


def test_a_reference_round_trips_and_a_bare_id_stays_bare() -> None:
    secret = uuid4()

    assert format_reference(secret) == str(secret)
    assert parse_reference(str(secret)) == CredentialReference(secret)
    assert parse_reference(format_reference(secret, "eu-central-1")) == (
        CredentialReference(secret, "eu-central-1")
    )
    assert parse_reference(format_reference(secret, "us-east-1", "team-a")) == (
        CredentialReference(secret, "us-east-1", "team-a")
    )


@pytest.mark.parametrize(
    "value",
    [
        "not-a-uuid",
        "{secret}|eu-central-1",
        "{secret}|eu-central-1|a|b",
        "{secret}|Europe|",
        "{secret}|eu-central-1|a|",
        "nope|eu-central-1|",
    ],
)
def test_malformed_references_are_refused(value) -> None:
    with pytest.raises(ValueError):
        parse_reference(value.format(secret=uuid4()))
