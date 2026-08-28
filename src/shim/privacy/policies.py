"""Typed outcome of the gateway privacy stage."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType


class PrivacyAction(str, Enum):
    DISABLED = "disabled"
    DETECTED = "detected"
    SCRUBBED = "scrubbed"


@dataclass(frozen=True)
class PrivacyOutcome:
    """Privacy decision plus request-local data needed for deanonymization.

    The verification map is deliberately excluded from repr and safe metadata.
    Continuation mappings may be encrypted in the tenant-bound Responses chain
    store.
    """

    action: PrivacyAction
    pii_detected: bool
    verification_map: Mapping[str, str] = field(
        default_factory=dict,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "verification_map",
            MappingProxyType(dict(self.verification_map)),
        )

    def trace_metadata(self) -> dict[str, str | bool]:
        """Return only metadata safe for a sanitized pipeline trace."""

        return {
            "action": self.action.value,
            "pii_detected": self.pii_detected,
        }

    @property
    def redacted_fields(self) -> tuple[str, ...]:
        """Return placeholder identifiers without their reversible values."""

        return tuple(self.verification_map)

    @property
    def pii_entities(self) -> Mapping[str, int]:
        """Return irreversible entity counts for audit/analytics metadata."""

        counts: Counter[str] = Counter()
        for placeholder in self.verification_map:
            name = str(placeholder).strip("<>")
            entity_type, _, _suffix = name.rpartition("_")
            counts[entity_type or name] += 1
        return MappingProxyType(dict(counts))
