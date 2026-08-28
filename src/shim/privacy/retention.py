"""Explicit retention policy for request-local privacy material."""

from __future__ import annotations

from dataclasses import dataclass

from shim.privacy.policies import PrivacyOutcome


@dataclass(frozen=True, slots=True)
class PrivacyRetentionPolicy:
    verification_map_persisted: bool = True
    raw_prompt_persisted: bool = False
    entity_counts_persisted: bool = True

    def durable_facts(self, outcome: PrivacyOutcome) -> dict[str, object]:
        """Project request-local privacy state into approved durable facts."""

        action = getattr(outcome.action, "value", outcome.action)
        return {
            "privacy_status": str(action),
            "pii_detected": outcome.pii_detected,
            "pii_entities": (
                dict(outcome.pii_entities) if self.entity_counts_persisted else {}
            ),
        }


REQUEST_PRIVACY_RETENTION = PrivacyRetentionPolicy()
