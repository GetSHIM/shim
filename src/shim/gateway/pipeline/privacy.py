"""Request-local privacy transformation before provider access."""

from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from functools import partial
import logging
from typing import Any, Literal, NoReturn

from fastapi import HTTPException, status

from shim.gateway.kernel.result import EMBEDDINGS_PROTOCOLS, PreparedInference
from shim.gateway.media import MediaPart, classify_media, value_at
from shim.gateway.contracts.errors import ScanAnalysisError
from shim.gateway.contracts.inference import ScanEntity, ScanPolicy, ScanVerdict
from shim.gateway.kernel.stage import TraceValue
from shim.observability.metrics import (
    INJECTION_MARKERS_TOTAL,
    DOCUMENTS_TOTAL,
    MEDIA_PARTS_TOTAL,
    PRIVACY_BULK_DISCLOSURES_TOTAL,
    PRIVACY_DETECTION_TOTAL,
    PRIVACY_RESPONSE_DETECTION_TOTAL,
    bounded_label,
)
from shim.privacy.pii_scrubber import (
    MAX_ANALYZABLE_TEXT_LENGTH,
    PLACEHOLDER,
    PIIInputTooLarge,
    PIIScrubberService,
    placeholder_period_key,
)
from shim.privacy.policies import (
    DEEP_PRIVACY_FIELDS,
    OPAQUE_PROTOCOL_FIELDS_BY_TYPE,
    PRIVACY_BEARING_FIELDS,
    EntityAction,
    PrivacyAction,
    PrivacyOutcome,
    UNSWITCHED_ENTITY_ACTIONS,
    block_code,
    effective_entity_actions,
    is_protocol_field,
    placeholder_type,
)
from shim.core.isolation import request_deadline
from shim.privacy.continuation import PrivacyContinuationStore
from shim.privacy.documents import (
    DOCUMENT_FORMAT_V1,
    DOCUMENT_TEXT_VERSION,
    MAX_REQUEST_CHARS,
    Unscannable,
    is_document,
    pdf_reader_version,
    read_document,
)
from shim.privacy.injection import scan_payload
from shim.rules.content import CONTENT_KINDS, ContentRules, content_rules
from shim.rules.destination import destination_actions
from shim.rules.evaluate import in_scope
from shim.rules.model import Rule

logger = logging.getLogger(__name__)

# Actions that keep a value from the provider.
_HIDING = frozenset({"mask", "mask_last4", "block"})


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
        actions = _base_actions(value)
        policy = {
            "pii_config": value.pii_config,
            "entity_actions": actions,
            "media_inputs": value.media_inputs,
            "documents": value.documents,
            "document_format": value.document_format,
        }
        try:
            prepared = await self._run(value, actions)
        except BaseException as error:
            refused = isinstance(error, HTTPException) and error.status_code < 500
            detail = getattr(error, "detail", None)
            detail = detail if refused and isinstance(detail, dict) else {}
            code = detail.get("code")
            value.record_verdict(
                "privacy.input",
                stage="privacy",
                outcome="deny" if refused else "error",
                reason_code=detail.get("reason_code", code)
                if code in {"SECRET_BLOCKED", "PII_BLOCKED", "DOCUMENT_UNSCANNABLE"}
                else "PRIVACY_POLICY_BLOCKED"
                if refused
                else "PRIVACY_UNAVAILABLE",
                policy=policy,
            )
            raise
        privacy = prepared.privacy
        assert privacy is not None
        if privacy.bulk_disclosure is not None:
            prepared.record_verdict(
                "privacy.bulk",
                stage="privacy",
                outcome="allow",
                reason_code="BULK_DISCLOSURE",
                policy={"bulk_threshold": value.bulk_threshold},
            )
            PRIVACY_BULK_DISCLOSURES_TOTAL.labels(
                provider=bounded_label("provider", str(value.provider))
            ).inc()
        disabled = value.context.privacy_policy.pii_mode == "disabled"
        outcome, reason_code = (
            ("deny", privacy.block_code)
            if privacy.block_code
            else ("mask", "PII_MASKED")
            if privacy.verification_map
            else ("allow", "PII_MONITORED")
            if privacy.monitored_entities
            else ("skip", "PII_DISABLED")
            if disabled
            else ("allow", "PII_NOT_DETECTED")
        )
        prepared.record_verdict(
            "privacy.input",
            stage="privacy",
            outcome=outcome,
            reason_code=reason_code,
            policy=policy,
        )
        if value.restore_withheld:
            withheld = privacy.withheld_counts
            prepared.record_verdict(
                "privacy.restore",
                stage="privacy",
                outcome="mask" if withheld else "allow",
                reason_code="RESTORE_WITHHELD" if withheld else "RESTORE_NOT_NEEDED",
                policy=sorted(value.restore_withheld),
            )
        return prepared

    async def _run(
        self, value: PreparedInference, actions: Mapping[str, EntityAction]
    ) -> PreparedInference:
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
        unmasked: dict[str, str] = {}
        tags = value.admission.tags if value.admission is not None else ()
        media = classify_media(value.payload) if value.media is None else value.media
        report = DocumentReport()
        content = content_rules(
            value.rules, lambda rule: in_scope(rule, value, tags), value.record_sets
        )
        unloadable = [
            rule
            for rule in (content.rules if content is not None else ())
            if rule.kind == "record_set"
            and str(rule.match["set_id"]) not in (value.record_sets or {})
        ]
        # The set could not be loaded; an enforced rule would not see the text.
        if any(
            rule.state == "enforced" and rule.action in {"mask", "block"}
            for rule in unloadable
        ):
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "PRIVACY_STATE_UNAVAILABLE",
                    "message": "A record set this request is checked against could "
                    "not be loaded; retry shortly.",
                },
                headers={"Retry-After": "5"},
            )
        destinations = [
            rule
            for rule in (value.rules.rules if value.rules is not None else ())
            if rule.kind == "destination" and in_scope(rule, value, tags)
        ]
        actions = destination_actions(actions, destinations)
        token_ids = (
            value.protocol == "embeddings"
            and not isinstance(value.payload["input"], str)
            and not isinstance(value.payload["input"][0], str)
        )
        refusing = _unreadable_actions(value, destinations)
        # Token ids cannot be read, so whatever would hide or refuse text refuses them.
        if token_ids and (
            any(action in _HIDING for action in refusing.values())
            or any(
                rule.state == "enforced"
                and rule.action in {"mask", "block", "require_approval"}
                for rule in [
                    *(content.rules if content is not None else ()),
                    *destinations,
                ]
            )
        ):
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "PRIVACY_POLICY_BLOCKED",
                    "message": "Token-id embeddings input cannot be scanned.",
                },
            )
        scrub = partial(
            scrub_payload,
            value.payload,
            actions,
            self.scrubber,
            known_placeholders=parent_map,
            request_model=value.model,
            unmasked=unmasked,
            content=content,
            batch=embedded_texts(value.payload, value.protocol)
            if value.protocol in EMBEDDINGS_PROTOCOLS
            else (),
            media=media,
            refusing=refusing,
            media_inputs=value.media_inputs,
            documents=value.documents,
            convert_clean=frozenset(
                {"docx"}
                | (
                    {"pdf"}
                    if DOCUMENT_FORMAT_V1.get(str(value.provider)) == "text"
                    else set()
                )
            )
            if value.document_format == "by_provider"
            else frozenset(),
            native_pdf=value.document_format == "by_provider"
            and DOCUMENT_FORMAT_V1.get(str(value.provider)) == "native",
            report=report,
            # An enforced block cannot see inside media either.
            protects=any(
                (rule.state, rule.action) == ("enforced", "block")
                for rule in destinations
            ),
            placeholder_key=None
            if value.placeholder_key is None
            else placeholder_period_key(
                value.placeholder_key.get_secret_value(),
                value.tenant_id,
                value.context.started_at,
            ),
        )

        def scrub_and_scan() -> tuple[
            dict[str, Any], dict[str, str], Mapping[str, int] | None
        ]:
            scrubbed = scrub()
            if value.injection_markers == "off":
                return *scrubbed, None
            try:
                # The raw request: invisible characters are gone after scrubbing.
                return *scrubbed, scan_payload(value.payload, value.protocol)
            except Exception as error:
                logger.warning(
                    "Injection marker scan failed error_type=%s", type(error).__name__
                )
                return *scrubbed, {"error": True}

        safe_payload, verification_map, injection_markers = await asyncio.to_thread(
            scrub_and_scan
        )
        if (
            verification_map
            and value.provider == "openai"
            and value.protocol == "responses"
        ):
            await self.chain_store.ensure_available()
        monitored = {
            item: entity_type
            for item, entity_type in unmasked.items()
            if actions[entity_type] == "monitor"
        }
        blocked = Counter(
            entity_type
            for entity_type in unmasked.values()
            if actions[entity_type] == "block"
        )
        pii_detected = bool(verification_map or unmasked)
        new_placeholders = verification_map.keys() - parent_map.keys()
        distinct_values = len(new_placeholders) + len(unmasked)
        threshold = value.bulk_threshold
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
            # <TYPE_hex> or <TYPE_hex~tail>
            pii_entities=Counter(map(placeholder_type, new_placeholders)),
            monitored_entities=Counter(monitored.values()),
            blocked_entities=blocked,
            bulk_disclosure={"distinct_values": distinct_values, "threshold": threshold}
            if threshold is not None and distinct_values >= threshold
            else None,
            monitored_values=frozenset(monitored),
            injection_markers=injection_markers,
            restore_withheld=value.restore_withheld,
            media=_media_record(media, report.scanned)
            | (
                report.record()
                if value.documents != "as_media" and any(map(is_document, media))
                else {}
            )
            if media
            else None,
            conversions=tuple(report.transforms),
        )
        for part in media:
            MEDIA_PARTS_TOTAL.labels(kind=part.kind, outcome="forwarded").inc()
        if injection_markers and "error" not in injection_markers:
            for marker, count in injection_markers.items():
                INJECTION_MARKERS_TOTAL.labels(
                    marker=bounded_label("marker", marker)
                ).inc(count)
            if value.injection_markers == "warn":
                value.warn("INJECTION_MARKERS")
        for counts in (
            privacy.pii_entities,
            privacy.monitored_entities,
            privacy.blocked_entities,
        ):
            for entity_type, count in counts.items():
                PRIVACY_DETECTION_TOTAL.labels(
                    entity_type=bounded_label("entity_type", entity_type)
                ).inc(count)
        if content is not None:
            for rule in content.rules:
                if rule.id in (
                    content.values.keys() | content.errors | content.truncated
                ):
                    value.record_rule_match(
                        rule,
                        len(content.values.get(rule.id, ())),
                        error=rule.id in content.errors,
                        truncated=rule.id in content.truncated,
                    )
        detected = (
            Counter(privacy.pii_entities)
            + Counter(privacy.monitored_entities)
            + Counter(privacy.blocked_entities)
        )
        for rule in destinations:
            count = sum(detected[name] for name in rule.match["entity_types"])
            if count:
                value.record_rule_match(rule, count)
        return replace(
            value,
            payload=safe_payload,
            privacy=privacy,
            # A scanned document is reserved by its text too, read only now.
            admission=replace(
                value.admission,
                estimated_input_tokens=value.admission.estimated_input_tokens
                + report.text_bytes,
            )
            if value.admission is not None and report.text_bytes
            else value.admission,
            transforms_applied=privacy.conversions or value.transforms_applied,
            rules_evaluated=value.rules_evaluated
            or content is not None
            or bool(destinations),
        )

    def trace_metadata(
        self,
        output: PreparedInference,
    ) -> Mapping[str, TraceValue]:
        assert output.privacy is not None
        return output.privacy.trace_metadata()


def _base_actions(
    value: PreparedInference, *, unswitched_defaults: bool = True
) -> Mapping[str, EntityAction]:
    """Without `unswitched_defaults`, a type no switch covers is `off` unless set."""
    overrides = value.entity_actions or {}
    if not unswitched_defaults:
        overrides = dict.fromkeys(UNSWITCHED_ENTITY_ACTIONS, "off") | dict(overrides)
    actions = effective_entity_actions(value.pii_config, overrides)
    if value.protocol not in EMBEDDINGS_PROTOCOLS:
        return actions
    # The tenant's embeddings relaxation: listed types are only counted.
    return {
        kind: "monitor"
        if kind in value.embeddings_monitor_types and action in _HIDING
        else action
        for kind, action in actions.items()
    }


def _unreadable_actions(
    value: PreparedInference, destinations: Sequence[Rule]
) -> Mapping[str, EntityAction]:
    """The actions that decide whether input no scan reads is refused: media, token ids.

    The default of a type no switch covers does not count, so Turkish names masked
    by default let it through; names the settings or a destination rule turn on do.
    """
    return destination_actions(
        _base_actions(value, unswitched_defaults=False), destinations
    )


def media_refused(value: PreparedInference, tags: Sequence[str]) -> bool:
    """Whether the privacy stage will refuse the request's media parts.

    The same test as `scrub_payload`'s `refuse_media`, from the rules in scope for `tags`.
    """
    if value.media_inputs == "allow":
        return False
    rules = [
        rule
        for rule in (value.rules.rules if value.rules is not None else ())
        if rule.kind == "destination" or rule.kind in CONTENT_KINDS
        if in_scope(rule, value, tags)
    ]
    destinations = [rule for rule in rules if rule.kind == "destination"]
    actions = _unreadable_actions(value, destinations)
    return any(action in _HIDING for action in actions.values()) or any(
        rule.state == "enforced"
        and (
            rule.action == "block"
            if rule.kind == "destination"
            else rule.action in {"mask", "block", "require_approval"}
        )
        for rule in rules
    )


_MEDIA_IMAGES_LIMIT = 16


def _media_record(media: Sequence[MediaPart], scanned: int) -> dict[str, Any]:
    images = [
        [*part.dimensions, part.decoded_bytes]
        for part in media
        if part.dimensions is not None
    ]
    return {
        "media_parts": dict(Counter(part.kind for part in media)),
        "media_unscanned": len(media) - scanned,
        **({"media_images": images[:_MEDIA_IMAGES_LIMIT]} if images else {}),
        **(
            {"media_images_truncated": True}
            if len(images) > _MEDIA_IMAGES_LIMIT
            else {}
        ),
    }


def embedded_texts(payload: Mapping[str, Any], protocol: str) -> list[str]:
    """The texts an embeddings request embeds."""
    if protocol == "embeddings":
        texts = payload["input"]
        return [
            text
            for text in (texts if isinstance(texts, list) else [texts])
            if isinstance(text, str)
        ]
    requests = payload["requests"] if "requests" in payload else [payload]
    return [
        part["text"]
        for request in requests
        for part in request["content"]["parts"]
        if isinstance(part, Mapping) and isinstance(part.get("text"), str)
    ]


def scrub_payload(
    payload: Mapping[str, Any],
    actions: Mapping[str, EntityAction],
    scrubber: PIIScrubberService,
    *,
    known_placeholders: Mapping[str, str] | None = None,
    request_model: str | None = None,
    unmasked: dict[str, str] | None = None,
    placeholder_key: bytes | None = None,
    content: ContentRules | None = None,
    protects: bool = False,
    batch: Sequence[str] = (),
    media: Sequence[MediaPart] | None = None,
    refusing: Mapping[str, EntityAction] | None = None,
    media_inputs: Literal["block", "allow"] = "block",
    documents: Literal["as_media", "scan", "scan_and_convert"] = "as_media",
    convert_clean: frozenset[str] = frozenset(),
    native_pdf: bool = False,
    report: DocumentReport | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """`batch`: texts scanned together in one analyzer pass before the walk.

    `media`: the payload's media parts (`classify_media`), found here when None.
    `refusing`: the actions that decide whether media is refused, `actions` when None.
    `documents`: whether inline PDF, Word and text files are read and scanned;
    `convert_clean` names the kinds sent as text even when nothing was masked, and
    `native_pdf` keeps a clean PDF native for a tenant that hides values;
    `report` collects what happened to them.
    """
    verification_map = dict(known_placeholders or {})
    if content is None and all(action == "off" for action in actions.values()):
        return dict(payload), verification_map
    if not isinstance(payload, dict):
        payload = dict(payload)
    media = classify_media(payload) if media is None else media
    # Monitored values pass unchanged, so only masked or blocked types refuse
    # what cannot be rewritten; media cannot be searched for tenant terms either.
    rules_protect = protects or (content is not None and content.protects)
    refuse_media = media_inputs == "block" and (
        rules_protect
        or any(
            action in _HIDING
            for action in (actions if refusing is None else refusing).values()
        )
    )
    protects = rules_protect or any(action in _HIDING for action in actions.values())
    # A provider reads a PDF's pages drawn: images, glyphs without text and form
    # appearances no scan saw. A tenant that hides values sends the text that was scanned.
    if protects and not native_pdf:
        convert_clean |= {"pdf"}
    unmasked = {} if unmasked is None else unmasked
    report = DocumentReport() if report is None else report
    deadline: float | None = None
    document_parts = {
        id(value_at(payload, part.path)): part
        for part in media
        if documents != "as_media" and is_document(part)
    }
    refused_parts = (
        {id(value_at(payload, part.path)) for part in media} - document_parts.keys()
        if refuse_media
        else set()
    )
    # A part's data is never read: base64 is no text, and a false match would corrupt it.
    unread = {
        (id(value_at(payload, part.data_path[:-1])), part.data_path[-1])
        for part in media
        if part.data_path is not None
    }

    placeholders_by_value = {
        value: placeholder for placeholder, value in verification_map.items()
    }
    # A value's verdict as an identifier: PII to mask, and the types it blocks.
    pii_cache: dict[str, tuple[bool, frozenset[str]]] = {}
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
            if not protects:
                return value
            detected = pii_cache.get(value)
            if detected is None:
                kept: dict[str, str] = {}
                _, found = scrubber.scrub(value, actions, unmasked=kept)
                detected = protected(found, kept)
                pii_cache[value] = detected
                # Identifiers are not searched for tenant terms, so a clean
                # identifier says nothing about the same text as content.
                if not found and not kept and content is None:
                    text_cache[value] = value
            masked, blocked = detected
            if blocked:
                reject(
                    f"Request blocked by privacy policy: {', '.join(sorted(blocked))}.",
                    code=str(block_code(blocked)),
                )
            if masked:
                reject("PII is not allowed in provider protocol identifiers.")
        elif isinstance(value, list):
            for item in value:
                inspect_identifier(item)
        elif isinstance(value, dict):
            for key, item in value.items():
                inspect_identifier(key)
                inspect_identifier(item)
        return value

    def protected(
        found: Mapping[str, str], kept: Mapping[str, str]
    ) -> tuple[bool, frozenset[str]]:
        return bool(found), frozenset(
            kind for kind in kept.values() if actions[kind] == "block"
        )

    def scrub_text(value: str) -> str:
        if value in text_cache:
            return text_cache[value]
        kept: dict[str, str] = {}
        scrubbed, found = scrubber.scrub(
            value,
            actions,
            known_placeholders=verification_map,
            placeholders_by_value=placeholders_by_value,
            unmasked=kept,
            placeholder_key=placeholder_key,
            content=content,
        )
        verification_map.update(found)
        unmasked.update(kept)
        # An identifier's verdict is built-in types only, never tenant terms.
        if content is None:
            pii_cache[value] = protected(found, kept)
        text_cache[value] = scrubbed
        return scrubbed

    # Tenant rules read texts one by one: a record match must not join two of them.
    distinct = list(dict.fromkeys(batch))
    if len(distinct) > 1 and content is None:
        kept: dict[str, str] = {}
        try:
            done = scrubber.scrub_many(
                distinct,
                actions,
                known_placeholders=verification_map,
                placeholders_by_value=placeholders_by_value,
                unmasked=kept,
                placeholder_key=placeholder_key,
            )
        except PIIInputTooLarge:
            done = None
        if done is not None:
            scrubbed_texts, found = done
            verification_map.update(found)
            unmasked.update(kept)
            text_cache.update(zip(distinct, scrubbed_texts))

    def document(part: MediaPart, scanned: dict[str, Any]) -> dict[str, Any]:
        nonlocal deadline
        data = value_at(payload, part.data_path) if part.data_path else None
        # One deadline for all of a request's documents.
        deadline = request_deadline() if deadline is None else deadline
        try:
            text = read_document(part, data, deadline)
            if report.characters + len(text) > MAX_REQUEST_CHARS:
                raise Unscannable("too_large")
        except Unscannable as error:
            report.unscannable[error.reason] += 1
            DOCUMENTS_TOTAL.labels(kind=part.kind, outcome="unscannable").inc()
            if refuse_media:
                reject(
                    f"A document in the request cannot be scanned: {error.reason}.",
                    code="DOCUMENT_UNSCANNABLE",
                )
            return scanned
        report.characters += len(text)
        report.text_bytes += len(text.encode())
        report.scanned += 1
        DOCUMENTS_TOTAL.labels(kind=part.kind, outcome="scanned").inc()
        kept: dict[str, str] = {}
        masked, found = scrubber.scrub(
            text,
            actions,
            known_placeholders=verification_map,
            placeholders_by_value=placeholders_by_value,
            unmasked=kept,
            placeholder_key=placeholder_key,
            content=content,
        )
        verification_map.update(found)
        unmasked.update(kept)
        hidden = Counter(
            placeholder_type(placeholder)
            for placeholder in {
                match.group(0) for match in PLACEHOLDER.finditer(masked)
            }
            & verification_map.keys()
        )
        report.entities.update(hidden + Counter(kept.values()))
        # A blocked type refuses the whole request after this stage, as in message text.
        if any(actions.get(kind) == "block" for kind in kept.values()):
            return scanned
        # Gemini's function response parts hold files only; text cannot replace one.
        native_only = (
            "functionResponse" in part.path or "function_response" in part.path
        )
        if masked != text and (documents == "scan" or native_only):
            DOCUMENTS_TOTAL.labels(kind=part.kind, outcome="stopped").inc()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": block_code(hidden),
                    "message": f"Request blocked by privacy policy: {', '.join(sorted(hidden))}. "
                    + (
                        "A document in a function response carries them and cannot be sent as text."
                        if native_only
                        else "A document carries them; turn on document conversion to send it masked."
                    ),
                    "reason_code": "DOCUMENT_MASKING_REQUIRED",
                },
            )
        if masked == text and (native_only or part.kind not in convert_clean):
            report.native += 1
            return scanned
        report.converted += 1
        DOCUMENTS_TOTAL.labels(kind=part.kind, outcome="converted").inc()
        report.transforms.append(
            {
                "id": "document_text",
                "version": DOCUMENT_TEXT_VERSION,
                "before_chars": len(data or ""),
                "after_chars": len(masked),
                "items": 1,
                **(
                    {"reader": f"pypdf {pdf_reader_version()}"}
                    if part.kind == "pdf"
                    else {}
                ),
            }
        )
        return as_text(scanned, masked)

    def visit(value: Any, *, content: bool = False, deep: bool = False) -> Any:
        if isinstance(value, str):
            return scrub_text(value)
        if isinstance(value, list):
            return [visit(item, content=content, deep=deep) for item in value]
        if isinstance(value, dict):
            value_type = value.get("type")
            if refused_parts and id(value) in refused_parts:
                for part in media:
                    MEDIA_PARTS_TOTAL.labels(kind=part.kind, outcome="blocked").inc()
                reject("PII scrubbing does not support opaque media inputs.")
            scrubbed: dict[str, Any] = {}
            for key, item in value.items():
                inspect_identifier(key)
                if unread and (id(value), key) in unread:
                    scrubbed[key] = item
                elif deep:
                    scrubbed[key] = visit(item, content=content, deep=True)
                elif (
                    key == "model"
                    and request_model is not None
                    and item == request_model
                ):
                    scrubbed[key] = item
                elif is_protocol_field(key) or (
                    isinstance(value_type, str)
                    and key in OPAQUE_PROTOCOL_FIELDS_BY_TYPE.get(value_type, ())
                ):
                    scrubbed[key] = inspect_identifier(item)
                elif key == "input":
                    scrubbed[key] = visit(item, content=True, deep=content)
                elif key in DEEP_PRIVACY_FIELDS:
                    scrubbed[key] = visit(item, content=content, deep=True)
                else:
                    scrubbed[key] = visit(
                        item,
                        content=content or key in PRIVACY_BEARING_FIELDS,
                    )
            if document_parts and id(value) in document_parts:
                return document(document_parts[id(value)], scrubbed)
            return scrubbed
        return value

    try:
        return visit(payload), verification_map
    except PIIInputTooLarge as exc:
        reject(
            str(exc),
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            code="REQUEST_TOO_LARGE",
        )


@dataclass(slots=True)
class DocumentReport:
    """What the privacy stage did with a request's documents; counts, never text."""

    scanned: int = 0
    converted: int = 0
    native: int = 0
    unscannable: Counter[str] = field(default_factory=Counter)
    entities: Counter[str] = field(default_factory=Counter)
    transforms: list[dict[str, Any]] = field(default_factory=list)
    characters: int = 0
    # UTF-8 bytes of the text read, a bound on its tokens.
    text_bytes: int = 0

    def record(self) -> dict[str, Any]:
        return {
            "documents": {
                "scanned": self.scanned,
                "converted": self.converted,
                "native": self.native,
                "unscannable": dict(self.unscannable),
            },
            "document_entities": dict(self.entities),
        }


def as_text(part: Mapping[str, Any], text: str) -> dict[str, Any]:
    """A document part replaced by its text, in the protocol's own text shape."""
    part_type = part.get("type")
    if part_type == "document":
        return {
            **part,
            "source": {"type": "text", "media_type": "text/plain", "data": text},
        }
    if part_type in {"file", "input_file"}:
        file = part.get("file") if part_type == "file" else part
        name = file.get("filename") if isinstance(file, Mapping) else None
        return {
            "type": "text" if part_type == "file" else "input_text",
            "text": f"[document: {name if isinstance(name, str) else 'document'}]\n{text}",
        }
    return {"text": text}


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
        actions: Mapping[str, EntityAction],
        policy: ScanPolicy,
    ) -> ScanPrivacyOutcome:
        try:
            entities = tuple(
                ScanEntity.model_validate(entity)
                for entity in (
                    self.scrubber.analyze(text, actions) if text.strip() else ()
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


def scan_response(
    text: str, prepared: PreparedInference, scrubber: PIIScrubberService
) -> dict[str, Any]:
    """Count distinct values in a delivered answer that the request did not carry."""

    privacy = prepared.privacy
    own = (
        {
            _compact(value)
            for value in (*privacy.verification_map.values(), *privacy.monitored_values)
        }
        if privacy is not None
        else set()
    )
    scanned = text[:MAX_ANALYZABLE_TEXT_LENGTH]
    actions = effective_entity_actions(prepared.pii_config, prepared.entity_actions)
    found = {
        (item["type"], _compact(scanned[item["start"] : item["end"]]))
        for item in (scrubber.analyze(scanned, actions) if scanned.strip() else ())
    }
    counts = Counter(entity_type for entity_type, value in found if value not in own)
    for entity_type, count in counts.items():
        PRIVACY_RESPONSE_DETECTION_TOTAL.labels(
            entity_type=bounded_label("entity_type", entity_type)
        ).inc(count)
    return {
        "response_entities": dict(sorted(counts.items())),
        "truncated": len(text) > MAX_ANALYZABLE_TEXT_LENGTH,
    }


def _compact(value: str) -> str:
    return value.replace(" ", "").replace("-", "")
