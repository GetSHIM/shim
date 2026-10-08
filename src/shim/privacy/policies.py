"""Privacy policy tables and the typed outcome of the gateway privacy stage."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Literal, cast, get_args


PII_CONFIG_DEFAULTS: Mapping[str, bool] = MappingProxyType(
    {
        "block_email": True,
        "block_phone": True,
        "block_credit_card": True,
        "block_secrets": True,
        "block_pii_tr": True,
    }
)

_PII_CONFIG_ENTITIES: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "block_email": frozenset({"EMAIL_ADDRESS"}),
        "block_phone": frozenset({"PHONE_NUMBER"}),
        "block_credit_card": frozenset({"CREDIT_CARD"}),
        "block_secrets": frozenset(
            {
                "SECRET",
                "US_SSN",
                "IP_ADDRESS",
                "MAC_ADDRESS",
                "DB_URI",
                "FILE_PATH",
            }
        ),
        "block_pii_tr": frozenset(
            {"TR_NATIONAL_ID", "TR_VKN", "IBAN_CODE", "TR_LICENSE_PLATE"}
        ),
    }
)


def effective_pii_config(config: Mapping[str, Any] | None = None) -> dict[str, bool]:
    overrides = config or {}
    return {
        name: bool(overrides.get(name, default))
        for name, default in PII_CONFIG_DEFAULTS.items()
    }


# Weakest to strongest: an overlap goes to the stronger action, and a move down
# this order is a relaxation.
EntityAction = Literal["off", "monitor", "mask_last4", "mask", "block"]


def effective_entity_actions(
    pii_config: Mapping[str, Any] | None = None,
    overrides: Mapping[str, str] | None = None,
) -> dict[str, EntityAction]:
    switches = effective_pii_config(pii_config)
    actions: dict[str, EntityAction] = {
        entity_type: "mask" if switches[setting] else "off"
        for setting, entity_types in _PII_CONFIG_ENTITIES.items()
        for entity_type in entity_types
    }
    for entity_type, action in (overrides or {}).items():
        if entity_type not in actions:
            raise ValueError(f"unknown entity type: {entity_type}")
        if action not in get_args(EntityAction):
            raise ValueError(f"unknown entity action: {action}")
        if action == "mask_last4" and entity_type not in {
            "CREDIT_CARD",
            "IBAN_CODE",
        }:
            raise ValueError(
                f"mask_last4 is only for CREDIT_CARD and IBAN_CODE: {entity_type}"
            )
        actions[entity_type] = cast(EntityAction, action)
    return dict(sorted(actions.items()))


def block_code(blocked_types: Iterable[str]) -> str | None:
    blocked = set(blocked_types)
    if not blocked:
        return None
    return "SECRET_BLOCKED" if blocked & {"SECRET", "DB_URI"} else "PII_BLOCKED"


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
    # Values first detected in this request, by type; inherited placeholders
    # of a Responses continuation are not counted again.
    pii_entities: Mapping[str, int] = field(default_factory=dict)
    monitored_entities: Mapping[str, int] = field(default_factory=dict)
    blocked_entities: Mapping[str, int] = field(default_factory=dict)
    bulk_disclosure: Mapping[str, int] | None = None
    # Held for the response-side scan only; never persisted or logged.
    monitored_values: frozenset[str] = field(
        default=frozenset(), repr=False, compare=False
    )

    def __post_init__(self) -> None:
        for name in (
            "verification_map",
            "pii_entities",
            "monitored_entities",
            "blocked_entities",
        ):
            object.__setattr__(self, name, MappingProxyType(dict(getattr(self, name))))

    @property
    def block_code(self) -> str | None:
        return block_code(self.blocked_entities)

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
