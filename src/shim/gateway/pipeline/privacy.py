"""Request-local privacy transformation before provider access."""

from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any, NoReturn

from fastapi import HTTPException, status

from shim.gateway.kernel.result import PreparedInference
from shim.gateway.contracts.errors import ScanAnalysisError
from shim.gateway.contracts.inference import ScanEntity, ScanPolicy, ScanVerdict
from shim.gateway.kernel.stage import TraceValue
from shim.observability.metrics import PRIVACY_DETECTION_TOTAL, bounded_label
from shim.privacy.pii_scrubber import (
    PIIInputTooLarge,
    PIIScrubberService,
    pii_scrubbing_enabled,
)
from shim.privacy.policies import PrivacyAction, PrivacyOutcome
from shim.privacy.continuation import PrivacyContinuationStore

_DEEP_PRIVACY_FIELDS = frozenset(
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
_PRIVACY_BEARING_FIELDS = frozenset(
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
_OPAQUE_MEDIA_TYPE_FIELDS = {
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
_OPAQUE_MEDIA_FIELDS = frozenset(
    {"fileData", "file_data", "inlineData", "inline_data", "input_image_mask"}
)
_OPAQUE_PROTOCOL_FIELDS_BY_TYPE = {
    "encrypted_code_execution_result": frozenset({"encrypted_stdout"}),
    "fallback": frozenset({"from", "to", "trigger"}),
    "redacted_thinking": frozenset({"data"}),
}


def _is_protocol_field(key: object) -> bool:
    return isinstance(key, str) and (
        key in _PROTOCOL_FIELDS or key.endswith(("_id", "_ids"))
    )


class PrivacyStage:
    """Scrub content and carry reversible maps across Responses continuations."""

    name = "privacy"

    def __init__(
        self,
        scrubber: PIIScrubberService,
        chain_store: PrivacyContinuationStore,
    ) -> None:
        self.scrubber = scrubber
        self.chain_store = chain_store

    async def run(self, value: PreparedInference) -> PreparedInference:
        parent_map: dict[str, str] = {}
        previous_response_id = (
            value.payload.get("previous_response_id")
            if value.provider == "openai" and value.protocol == "responses"
            else None
        )
        if previous_response_id is not None:
            parent_map = (
                await self.chain_store.load(value.tenant_id, str(previous_response_id))
                or {}
            )
        safe_payload, verification_map = await asyncio.to_thread(
            scrub_payload,
            value.payload,
            value.pii_config,
            self.scrubber,
            known_placeholders=parent_map,
            request_model=value.model,
        )
        pii_detected = bool(verification_map)
        if (
            pii_detected
            and value.provider == "openai"
            and value.protocol == "responses"
        ):
            await self.chain_store.ensure_available()
        privacy = PrivacyOutcome(
            action=(
                PrivacyAction.SCRUBBED
                if pii_detected
                else PrivacyAction.DETECTED
                if value.context.privacy_policy.pii_mode != "disabled"
                else PrivacyAction.DISABLED
            ),
            pii_detected=pii_detected,
            verification_map=verification_map,
        )
        for entity_type, count in privacy.pii_entities.items():
            PRIVACY_DETECTION_TOTAL.labels(
                entity_type=bounded_label("entity_type", entity_type)
            ).inc(count)
        return replace(value, payload=safe_payload, privacy=privacy)

    def trace_metadata(
        self,
        output: PreparedInference,
    ) -> Mapping[str, TraceValue]:
        assert output.privacy is not None
        return output.privacy.trace_metadata()


def scrub_payload(
    payload: Mapping[str, Any],
    config: Mapping[str, Any] | None,
    scrubber: PIIScrubberService,
    *,
    known_placeholders: Mapping[str, str] | None = None,
    request_model: str | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    verification_map = dict(known_placeholders or {})
    if not pii_scrubbing_enabled(config):
        return dict(payload), verification_map

    placeholders_by_value = {
        value: placeholder for placeholder, value in verification_map.items()
    }
    pii_cache: dict[str, bool] = {}
    text_cache: dict[str, str] = {}

    def reject(
        message: str,
        *,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        code: str = "PRIVACY_POLICY_BLOCKED",
    ) -> NoReturn:
        raise HTTPException(
            status_code=status_code,
            detail={
                "code": code,
                "message": message,
            },
        )

    def inspect_identifier(value: Any) -> Any:
        if isinstance(value, str):
            detected = pii_cache.get(value)
            if detected is None:
                _, found = scrubber.scrub(value, config)
                detected = bool(found)
                pii_cache[value] = detected
                if not detected:
                    text_cache[value] = value
            if detected:
                reject("PII is not allowed in provider protocol identifiers.")
        elif isinstance(value, list):
            for item in value:
                inspect_identifier(item)
        elif isinstance(value, dict):
            for key, item in value.items():
                inspect_identifier(key)
                inspect_identifier(item)
        return value

    def contains_opaque_media(value: Mapping[str, Any], *, deep: bool) -> bool:
        media_type = value.get("type")
        media_fields = (
            _OPAQUE_MEDIA_TYPE_FIELDS.get(media_type)
            if isinstance(media_type, str)
            else None
        )
        requires_field = deep or media_type == "image_generation_call"
        if media_fields is not None and (
            not requires_field
            or any(value.get(field) is not None for field in media_fields)
        ):
            return True
        if isinstance(media_type, str) and media_type in {"document", "image"}:
            source = value.get("source")
            source_type = source.get("type") if isinstance(source, Mapping) else None
            if isinstance(source_type, str) and source_type in {"base64", "url"}:
                return True
        return any(value.get(field) is not None for field in _OPAQUE_MEDIA_FIELDS)

    def scrub_text(value: str) -> str:
        if value in text_cache:
            return text_cache[value]
        scrubbed, found = scrubber.scrub(
            value,
            config,
            known_placeholders=verification_map,
            placeholders_by_value=placeholders_by_value,
        )
        verification_map.update(found)
        pii_cache[value] = bool(found)
        text_cache[value] = scrubbed
        return scrubbed

    def visit(value: Any, *, content: bool = False, deep: bool = False) -> Any:
        if isinstance(value, str):
            return scrub_text(value)
        if isinstance(value, list):
            return [visit(item, content=content, deep=deep) for item in value]
        if isinstance(value, dict):
            value_type = value.get("type")
            if (content or value_type == "image_generation") and contains_opaque_media(
                value, deep=deep
            ):
                reject("PII scrubbing does not support opaque media inputs.")
            scrubbed: dict[str, Any] = {}
            for key, item in value.items():
                inspect_identifier(key)
                if deep:
                    scrubbed[key] = visit(item, content=content, deep=True)
                elif (
                    key == "model"
                    and request_model is not None
                    and item == request_model
                ):
                    # Admission validates the request model against the catalog
                    # before privacy runs, so it is a known-safe identifier that
                    # must reach the provider verbatim. Running PII detection on it
                    # only yields false positives — a dated Anthropic snapshot such
                    # as claude-sonnet-4-5-20250929 trips the phone-number
                    # recognizer on its "4-5-20250929" suffix. Only the validated
                    # request model is exempt; any other "model" value (e.g. inside
                    # metadata) still passes through identifier inspection.
                    scrubbed[key] = item
                elif _is_protocol_field(key) or (
                    isinstance(value_type, str)
                    and key in _OPAQUE_PROTOCOL_FIELDS_BY_TYPE.get(value_type, ())
                ):
                    scrubbed[key] = inspect_identifier(item)
                elif key == "input":
                    scrubbed[key] = visit(item, content=True, deep=content)
                elif key in _DEEP_PRIVACY_FIELDS:
                    scrubbed[key] = visit(item, content=content, deep=True)
                else:
                    scrubbed[key] = visit(
                        item,
                        content=content or key in _PRIVACY_BEARING_FIELDS,
                    )
            return scrubbed
        return value

    try:
        return visit(dict(payload)), verification_map
    except PIIInputTooLarge as exc:
        reject(
            str(exc),
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            code="REQUEST_TOO_LARGE",
        )


@dataclass(frozen=True, slots=True)
class ScanPrivacyOutcome:
    entities: tuple[ScanEntity, ...]
    entity_counts: dict[str, int]
    verdict: ScanVerdict

    @property
    def entity_types(self) -> tuple[str, ...]:
        return tuple(sorted(self.entity_counts))


class ScanPrivacyStage:
    """Perform provider-free PII classification under resolved tenant policy."""

    def __init__(self, scrubber: PIIScrubberService) -> None:
        self.scrubber = scrubber

    def analyze(
        self,
        text: str,
        *,
        config: Mapping[str, Any],
        policy: ScanPolicy,
    ) -> ScanPrivacyOutcome:
        try:
            entities = tuple(
                ScanEntity.model_validate(entity)
                for entity in (
                    self.scrubber.analyze(text, config=config) if text.strip() else ()
                )
            )
        except Exception:
            raise ScanAnalysisError() from None
        counts = dict(Counter(entity.type for entity in entities))
        for entity_type, count in counts.items():
            PRIVACY_DETECTION_TOTAL.labels(
                entity_type=bounded_label("entity_type", entity_type)
            ).inc(count)
        return ScanPrivacyOutcome(
            entities=entities,
            entity_counts=counts,
            verdict=policy if counts else "clean",
        )
