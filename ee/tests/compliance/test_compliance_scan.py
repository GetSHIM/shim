from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from shim_enterprise.compliance.classification import classify
from shim_enterprise.compliance.normalized import ContentUnit, NormalizedContent
from shim_enterprise.compliance.services.scan import ComplianceScanService, value_hash
from shim.privacy.pii_scrubber import PIIScrubberService


def test_presidio_entities_receive_the_intended_classification() -> None:
    assert classify("TR_NATIONAL_ID").severity == "critical"
    assert classify("IBAN_CODE").severity == "high"


@pytest.mark.asyncio
async def test_findings_in_distinct_units_have_distinct_offsets() -> None:
    text = "alice@example.com"
    scrubber = SimpleNamespace(
        analyze=Mock(
            return_value=[
                {
                    "type": "EMAIL_ADDRESS",
                    "start": 0,
                    "end": len(text),
                }
            ]
        )
    )
    content = NormalizedContent(
        provider="openai",
        content_type="conversation",
        content_id="conversation-1",
        units=[
            ContentUnit(unit_id="one", text=text),
            ContentUnit(unit_id="two", text=text),
        ],
    )

    findings = await ComplianceScanService(
        pii_scrubber=scrubber,
        salt="test-salt",
    ).scan_content(content)

    assert [finding["match_offset"] for finding in findings] == [0, len(text)]


@pytest.mark.asyncio
async def test_transformed_findings_hash_the_reported_source_span() -> None:
    source_value = "alice%40example.com"
    text = f"Contact: {source_value}"
    content = NormalizedContent(
        provider="openai",
        content_type="conversation",
        content_id="conversation-1",
        units=[ContentUnit(unit_id="one", text=text)],
    )

    findings = await ComplianceScanService(
        pii_scrubber=PIIScrubberService(),
        salt="test-salt",
    ).scan_content(content)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["match_offset"] == text.index(source_value)
    assert finding["match_length"] == len(source_value)
    assert finding["value_hash"] == value_hash(
        "test-salt",
        "EMAIL_ADDRESS",
        source_value,
    )
