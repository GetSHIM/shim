"""Privacy policy tables and the typed outcome of the gateway privacy stage."""

from __future__ import annotations

from bisect import bisect_right
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import Enum
from functools import cached_property
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

# How the privacy stage walks a payload: fields read whole as tool data, fields
# that carry content, and protocol fields inspected only as identifiers.
DEEP_PRIVACY_FIELDS = frozenset(
    {
        "arguments",
        "args",
        "action",
        "client_metadata",
        "custom",
        "environment",
        "input_examples",
        "input_schema",
        "metadata",
        "operation",
        "output",
        "parameters",
        "parametersJsonSchema",
        "parameters_json_schema",
        "response",
        "result",
        "responseJsonSchema",
        "responseSchema",
        "response_json_schema",
        "response_schema",
        "schema",
        "userLocation",
        "user_location",
    }
)
PRIVACY_BEARING_FIELDS = frozenset(
    {
        "content",
        "contents",
        "description",
        "instructions",
        "prompt",
        "prompt_cache_key",
        "parts",
        "safety_identifier",
        "stop",
        "stopSequences",
        "stop_sequences",
        "system",
        "text",
        "user",
        "user_profile_id",
    }
)
_PROTOCOL_FIELDS = frozenset(
    {
        "authorization",
        "cachedContent",
        "cached_content",
        "call_id",
        "container",
        "conversation",
        "encrypted_content",
        "encrypted_stdout",
        "fingerprint",
        "headers",
        "id",
        "inference_geo",
        "language",
        "media_type",
        "mimeType",
        "mime_type",
        "model",
        "name",
        "namespace",
        "previous_response_id",
        "role",
        "service_tier",
        "server_label",
        "server_name",
        "signature",
        "status",
        "thoughtSignature",
        "thought_signature",
        "tool_call_id",
        "tool_name",
        "tool_names",
        "tool_use_id",
        "type",
        "url",
        "uri",
    }
)
OPAQUE_PROTOCOL_FIELDS_BY_TYPE = {
    "encrypted_code_execution_result": frozenset({"encrypted_stdout"}),
    "fallback": frozenset({"from", "to", "trigger"}),
    "redacted_thinking": frozenset({"data"}),
}


def is_protocol_field(key: object) -> bool:
    return isinstance(key, str) and (
        key in _PROTOCOL_FIELDS or key.endswith(("_id", "_ids"))
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

# Types no pii_config switch covers, with their default action.
UNSWITCHED_ENTITY_ACTIONS: Mapping[str, EntityAction] = MappingProxyType(
    {"PERSON_NAME_TR": "mask"}
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
    } | dict(UNSWITCHED_ENTITY_ACTIONS)
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


class PlaceholderMap(Mapping[str, str]):
    """Placeholder to value, indexed so restoring an answer is linear in its length.

    The indexes are built on first use; the wrapped mapping must not change after.
    """

    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = values

    def __getitem__(self, placeholder: str) -> str:
        return self._values[placeholder]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    @cached_property
    def untailed(self) -> dict[str, str]:
        """`<TYPE_hex>` to the value of the first `<TYPE_hex~tail>`."""
        index: dict[str, str] = {}
        for placeholder, value in self._values.items():
            head, tilde, _ = placeholder.partition("~")
            if tilde:
                index.setdefault(f"{head}>", value)
        return index

    @cached_property
    def _ordered(self) -> list[str]:
        return sorted(self._values)

    def continues(self, prefix: str) -> bool:
        """Whether a placeholder is longer than `prefix` and starts with it."""
        index = bisect_right(self._ordered, prefix)
        return index < len(self._ordered) and self._ordered[index].startswith(prefix)


def placeholder_map(values: Mapping[str, str]) -> PlaceholderMap:
    return values if isinstance(values, PlaceholderMap) else PlaceholderMap(values)


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
    # media_parts, media_unscanned, media_images and the document records when the
    # request carried media.
    media: Mapping[str, Any] | None = None
    # The document_text transforms the privacy stage applied, for every attempt's record.
    conversions: tuple[Mapping[str, Any], ...] = ()

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
