"""Privacy policy tables and the typed outcome of the gateway privacy stage."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Literal, cast, get_args

# Parts the privacy stage treats as opaque media: by type, with the fields that
# hold the media, and fields that hold media whatever the type.
OPAQUE_MEDIA_TYPE_FIELDS = {
    "computer_screenshot": ("file_id", "image_url"),
    "container_upload": ("file_id",),
    "file": ("file",),
    "image": (),
    "image_generation_call": ("result",),
    "image_url": ("image_url",),
    "input_audio": ("input_audio",),
    "input_file": ("file_data", "file_id", "file_url"),
    "input_image": ("file_id", "image_url"),
}
OPAQUE_MEDIA_FIELDS = frozenset(
    {"fileData", "file_data", "inlineData", "inline_data", "input_image_mask"}
)


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

# Types no switch covers: off until an override turns them on.
OPT_IN_ENTITY_TYPES: Mapping[str, EntityAction] = MappingProxyType(
    {"PERSON_NAME_TR": "off"}
)


def effective_entity_actions(
    pii_config: Mapping[str, Any] | None = None,
    overrides: Mapping[str, str] | None = None,
) -> dict[str, EntityAction]:
    switches = effective_pii_config(pii_config)
    actions: dict[str, EntityAction] = {
        entity_type: "mask" if switches[setting] else "off"
        for setting, entity_types in _PII_CONFIG_ENTITIES.items()
        for entity_type in entity_types
    } | dict(OPT_IN_ENTITY_TYPES)
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


def placeholder_type(placeholder: str) -> str:
    """The entity type or rule label of `<TYPE_hex>` or `<TYPE_hex~tail>`."""
    return placeholder.strip("<>").partition("~")[0].rpartition("_")[0]


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
    # Tool results and documents carrying each marker; None when the scan is off,
    # {"error": True} when it failed.
    injection_markers: Mapping[str, int] | None = None
    # Held for the response-side scan only; never persisted or logged.
    monitored_values: frozenset[str] = field(
        default=frozenset(), repr=False, compare=False
    )
    # Types this caller gets back as placeholders (enterprise restore permission).
    restore_withheld: frozenset[str] = frozenset()

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

    @property
    def restore_map(self) -> Mapping[str, str]:
        """The placeholders this caller gets back as values; the rest stay placeholders."""
        if not self.restore_withheld:
            return self.verification_map
        return {
            placeholder: value
            for placeholder, value in self.verification_map.items()
            if placeholder_type(placeholder) not in self.restore_withheld
        }

    @property
    def withheld_counts(self) -> dict[str, int]:
        return dict(
            Counter(
                kind
                for placeholder in self.verification_map
                if (kind := placeholder_type(placeholder)) in self.restore_withheld
            )
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
