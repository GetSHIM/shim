"""Request-local PII detection and reversible redaction."""

from __future__ import annotations

import codecs
import hmac
import re
import secrets
import unicodedata
from collections.abc import Iterable, Mapping
from datetime import datetime
from hashlib import sha256
from typing import Any

from presidio_analyzer import RecognizerResult

from shim.privacy.policies import EntityAction, effective_entity_actions
from shim.privacy.presidio_analyzer import PresidioAnalyzer


_INVISIBLE = re.compile(r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_PLACEHOLDER = re.compile(
    r"<\s*([A-Z][A-Z0-9_]*_(?:[0-9a-f]{8}|[0-9a-f]{32}))(~[0-9A-Z]{4})?\s*>"
)
_PERCENT_BYTE = re.compile(r"%([0-9A-Fa-f]{2})")
_SourceSpan = tuple[int, int]
MAX_ANALYZABLE_TEXT_LENGTH = 1_000_000


class PIIInputTooLarge(ValueError):
    """Raised when normalized text exceeds the analyzer's safe input limit."""

    def __init__(self) -> None:
        super().__init__(
            f"PII-analyzable text is limited to {MAX_ANALYZABLE_TEXT_LENGTH:,} "
            "characters."
        )


def _decode_with_spans(text: str) -> tuple[str, list[_SourceSpan]]:
    output: list[str] = []
    spans: list[_SourceSpan] = []
    index = 0
    while index < len(text):
        if not text[index].isascii():
            output.append(text[index])
            spans.append((index, index + 1))
            index += 1
            continue

        end = index + 1
        while end < len(text) and text[end].isascii():
            end += 1
        encoded: list[tuple[int, _SourceSpan]] = []
        while index < end:
            match = _PERCENT_BYTE.match(text, index)
            if match:
                encoded.append((int(match.group(1), 16), (index, index + 3)))
                index += 3
            else:
                encoded.append((ord(text[index]), (index, index + 1)))
                index += 1

        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        pending: list[_SourceSpan] = []
        for byte, span in encoded:
            pending.append(span)
            decoded = decoder.decode(bytes((byte,)))
            if not decoded:
                continue
            buffered = len(decoder.getstate()[0])
            consumed = pending[:-buffered] if buffered else pending
            assert consumed
            source_span = (consumed[0][0], consumed[-1][1])
            output.extend(decoded)
            spans.extend([source_span] * len(decoded))
            pending = pending[-buffered:] if buffered else []
        decoded = decoder.decode(b"", final=True)
        if decoded:
            assert pending
            source_span = (pending[0][0], pending[-1][1])
            output.extend(decoded)
            spans.extend([source_span] * len(decoded))
        else:
            assert not pending
    return "".join(output), spans


def _normalization_continues(previous: str, current: str) -> bool:
    previous_code = ord(previous)
    current_code = ord(current)
    return bool(
        unicodedata.combining(current)
        or unicodedata.normalize("NFC", previous + current)
        != unicodedata.normalize("NFC", previous)
        + unicodedata.normalize("NFC", current)
        # A trailing Jamo composes only with the preceding L+V segment.
        or (0x1161 <= previous_code <= 0x1175 and 0x11A8 <= current_code <= 0x11C2)
    )


def _normalize_with_spans(
    text: str,
    spans: list[_SourceSpan],
) -> tuple[str, list[_SourceSpan]]:
    characters: list[str] = []
    decomposed_spans: list[_SourceSpan] = []
    origins: list[int] = []
    for origin, (character, span) in enumerate(zip(text, spans)):
        decomposed = unicodedata.normalize("NFKD", character)
        characters.extend(decomposed)
        decomposed_spans.extend([span] * len(decomposed))
        origins.extend([origin] * len(decomposed))

    output: list[str] = []
    normalized_spans: list[_SourceSpan] = []
    start = 0
    for index in range(1, len(characters) + 1):
        if index < len(characters) and (
            origins[index] == origins[index - 1]
            or _normalization_continues(characters[index - 1], characters[index])
        ):
            continue
        normalized = unicodedata.normalize("NFC", "".join(characters[start:index]))
        affected = decomposed_spans[start:index]
        assert affected
        source_span = (affected[0][0], affected[-1][1])
        output.extend(normalized)
        normalized_spans.extend([source_span] * len(normalized))
        start = index
    return "".join(output), normalized_spans


def _preprocess_with_spans(text: str) -> tuple[str, list[_SourceSpan]]:
    if not isinstance(text, str):
        raise TypeError("PII input must be text")

    if text.isascii() and "%" not in text:
        return text, [(index, index + 1) for index in range(len(text))]

    decoded, spans = _decode_with_spans(text)
    visible_characters: list[str] = []
    visible_spans: list[_SourceSpan] = []
    for character, span in zip(decoded, spans):
        if not _INVISIBLE.fullmatch(character):
            visible_characters.append(character)
            visible_spans.append(span)
    visible_text = "".join(visible_characters)
    return _normalize_with_spans(visible_text, visible_spans)


class PIIScrubberService:
    """Stateless detector with request-local placeholders and no persistence."""

    _instance: PIIScrubberService | None = None
    _analyzer: PresidioAnalyzer

    def __new__(cls) -> PIIScrubberService:
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._analyzer = PresidioAnalyzer()
            cls._instance = instance
        return cls._instance

    @staticmethod
    def preprocess(text: str) -> str:
        return _preprocess_with_spans(text)[0]

    def analyze(
        self,
        text: str,
        actions: Mapping[str, EntityAction] | None = None,
    ) -> list[dict[str, Any]]:
        actions = actions or effective_entity_actions()
        detections = self._source_detections(text, actions)
        return [
            {
                "type": item.entity_type,
                "start": item.start,
                "end": item.end,
                "score": item.score,
                "action": actions[item.entity_type],
            }
            for item in detections
        ]

    def scrub(
        self,
        text: str,
        actions: Mapping[str, EntityAction] | None = None,
        *,
        known_placeholders: Mapping[str, str] | None = None,
        placeholders_by_value: dict[str, str] | None = None,
        unmasked: dict[str, str] | None = None,
        placeholder_key: bytes | None = None,
    ) -> tuple[str, dict[str, str]]:
        """Mask `mask` detections; record `monitor`/`block` ones in `unmasked` (value to type)."""
        if not isinstance(text, str):
            raise TypeError("PII input must be text")
        actions = actions or effective_entity_actions()
        if all(action == "off" for action in actions.values()):
            return text, {}
        detections = self._source_detections(text, actions)
        if not detections:
            return text, {}
        if placeholders_by_value is None:
            placeholders_by_value = {
                value: placeholder
                for placeholder, value in (known_placeholders or {}).items()
            }
        verification_map: dict[str, str] = {}
        scrubbed: list[str] = []
        cursor = 0
        for item in detections:
            value = text[item.start : item.end]
            action = actions[item.entity_type]
            if action not in {"mask", "mask_last4"}:
                if unmasked is not None:
                    unmasked[value] = item.entity_type
                continue
            placeholder = placeholders_by_value.get(value)
            if placeholder is None:
                tail = _tail(item.entity_type, value) if action == "mask_last4" else ""
                if placeholder_key:
                    digest = hmac.new(
                        placeholder_key,
                        f"{item.entity_type}\x1f{value}".encode(),
                        sha256,
                    ).hexdigest()
                    placeholder = f"<{item.entity_type}_{digest[:32]}{tail}>"
                else:
                    placeholder = self._placeholder(item.entity_type, tail)
                # A placeholder held by another value falls back to a random one.
                while (
                    placeholder in (known_placeholders or {})
                    or placeholder in verification_map
                ):
                    placeholder = self._placeholder(item.entity_type, tail)
                placeholders_by_value[value] = placeholder
            verification_map[placeholder] = value
            scrubbed.append(text[cursor : item.start])
            scrubbed.append(placeholder)
            cursor = item.end
        scrubbed.append(text[cursor:])
        return "".join(scrubbed), verification_map

    def deanonymize(self, text: str, verification_map: Mapping[str, str]) -> str:
        if not text or not verification_map:
            return text

        def restore(match: re.Match[str]) -> str:
            identifier, tail = match.groups()
            if tail:
                return verification_map.get(f"<{identifier}{tail}>", match.group())
            value = verification_map.get(f"<{identifier}>")
            if value is None:
                # A model may write a tailed placeholder back without its tail.
                prefix = f"<{identifier}~"
                value = next(
                    (
                        original
                        for placeholder, original in verification_map.items()
                        if placeholder.startswith(prefix)
                    ),
                    None,
                )
            return match.group() if value is None else value

        return _PLACEHOLDER.sub(restore, text)

    def _detections(
        self,
        text: str,
        actions: Mapping[str, EntityAction],
    ) -> list[RecognizerResult]:
        enabled_entities = {
            entity_type for entity_type, action in actions.items() if action != "off"
        }
        return self._deduplicate(self._analyzer.analyze(text, enabled_entities))

    def _source_detections(
        self,
        text: str,
        actions: Mapping[str, EntityAction],
    ) -> list[RecognizerResult]:
        if len(text) > MAX_ANALYZABLE_TEXT_LENGTH:
            raise PIIInputTooLarge
        prepared, spans = _preprocess_with_spans(text)
        if len(prepared) > MAX_ANALYZABLE_TEXT_LENGTH:
            raise PIIInputTooLarge
        detections = self._non_overlapping(self._detections(prepared, actions))
        mapped: list[RecognizerResult] = []
        for item in detections:
            matched_spans = spans[item.start : item.end]
            assert matched_spans
            mapped.append(
                RecognizerResult(
                    entity_type=item.entity_type,
                    start=matched_spans[0][0],
                    end=matched_spans[-1][1],
                    score=item.score,
                )
            )
        return self._non_overlapping(mapped)

    @staticmethod
    def _deduplicate(items: Iterable[RecognizerResult]) -> list[RecognizerResult]:
        unique = {
            (item.entity_type, item.start, item.end): item
            for item in items
            if item.start < item.end
        }
        return sorted(unique.values(), key=lambda item: (item.start, item.end))

    @staticmethod
    def _non_overlapping(
        items: Iterable[RecognizerResult],
    ) -> list[RecognizerResult]:
        priority = {
            "DB_URI": 100,
            "SECRET": 90,
            "IBAN_CODE": 85,
            "CREDIT_CARD": 80,
            "TR_NATIONAL_ID": 70,
            "TR_VKN": 70,
        }
        ordered = sorted(items, key=lambda item: (item.start, item.end))
        selected: list[RecognizerResult] = []
        component: list[RecognizerResult] = []
        component_end = -1

        def select_component() -> None:
            if len(component) == 1:
                selected.append(component[0])
                return
            ranked = sorted(
                component,
                key=lambda item: (
                    -priority.get(item.entity_type, 0),
                    -(item.end - item.start),
                    item.start,
                ),
            )
            accepted: list[RecognizerResult] = []
            # ponytail: dense components stay O(n²); add interval indexing if profiling warrants it.
            for candidate in ranked:
                if not any(
                    candidate.start < existing.end and existing.start < candidate.end
                    for existing in accepted
                ):
                    accepted.append(candidate)
            accepted.sort(key=lambda item: item.start)
            selected.extend(accepted)

        for item in ordered:
            if component and item.start >= component_end:
                select_component()
                component = []
            component_end = max(component_end, item.end) if component else item.end
            component.append(item)
        if component:
            select_component()
        return selected

    @staticmethod
    def _placeholder(entity_type: str, tail: str = "") -> str:
        return f"<{entity_type}_{secrets.token_hex(16)}{tail}>"


def placeholder_period_key(root_key: bytes, tenant_id: object, at: datetime) -> bytes:
    period = int(at.timestamp()) // 2_592_000
    label = f"shim.placeholder.v1\x1f{tenant_id}\x1f{period}"
    return hmac.new(root_key, label.encode(), sha256).digest()


def _tail(entity_type: str, value: str) -> str:
    kept = [
        character
        for character in _preprocess_with_spans(value)[0].upper()
        if character.isascii()
        and (
            character.isdigit() if entity_type == "CREDIT_CARD" else character.isalnum()
        )
    ]
    # Fewer than four usable characters keeps the whole value masked.
    return "~" + "".join(kept[-4:]) if len(kept) >= 4 else ""
