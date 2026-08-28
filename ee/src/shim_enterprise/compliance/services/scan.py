"""Ephemeral compliance-content scanning with metadata-only findings."""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any

from shim_enterprise.compliance.classification import classify
from shim_enterprise.compliance.normalized import NormalizedContent
from shim_enterprise.core.config import settings
from shim.privacy.pii_scrubber import PIIScrubberService


def value_hash(salt: str, entity_type: str, value: str) -> str:
    return hashlib.sha256(f"{salt}:{entity_type}:{value}".encode()).hexdigest()


class ComplianceScanService:
    """Bound CPU scanning while keeping raw content request-local."""

    def __init__(
        self,
        pii_scrubber: PIIScrubberService | None = None,
        *,
        salt: str | None = None,
        concurrency: int | None = None,
    ) -> None:
        self.pii_scrubber = pii_scrubber or PIIScrubberService()
        self.salt = salt or settings.COMPLIANCE_HASH_SALT or settings.SECRET_KEY
        self.semaphore = asyncio.Semaphore(
            concurrency or settings.COMPLIANCE_SCAN_CONCURRENCY
        )

    async def scan_content(
        self,
        content: NormalizedContent,
        pii_config: dict[str, bool] | None = None,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        unit_offset = 0
        for unit in content.units:
            current_offset = unit_offset
            unit_offset += len(unit.text)
            if not unit.text:
                continue
            async with self.semaphore:
                detections = await asyncio.to_thread(
                    self.pii_scrubber.analyze,
                    unit.text,
                    pii_config,
                )
            for detection in detections:
                start = int(detection["start"])
                end = int(detection["end"])
                if start < 0 or end <= start or end > len(unit.text):
                    continue
                entity_type = str(detection["type"])
                classification = classify(entity_type)
                findings.append(
                    {
                        "content_id": content.content_id,
                        "entity_type": entity_type,
                        "severity": classification.severity,
                        "kvkk_category": classification.kvkk_category,
                        "gdpr_category": classification.gdpr_category,
                        "match_offset": current_offset + start,
                        "match_length": end - start,
                        "value_hash": value_hash(
                            self.salt,
                            entity_type,
                            unit.text[start:end],
                        ),
                        "actor_email": content.actor_email,
                        "model": content.model,
                        "occurred_at": unit.occurred_at or content.occurred_at,
                    }
                )
        return findings
