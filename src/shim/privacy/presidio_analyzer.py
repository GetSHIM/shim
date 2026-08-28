"""Curated Presidio detection for the gateway privacy boundary."""

from __future__ import annotations

import re
from collections.abc import Iterable
from functools import lru_cache

from presidio_analyzer import (
    AnalyzerEngine,
    EntityRecognizer,
    Pattern,
    PatternRecognizer,
    RecognizerResult,
    RecognizerRegistry,
)
from presidio_analyzer.nlp_engine import NlpArtifacts, SlimSpacyNlpEngine
from presidio_analyzer.predefined_recognizers import (
    CreditCardRecognizer,
    EmailRecognizer,
    IbanRecognizer,
    IpRecognizer,
    MacAddressRecognizer,
    PhoneRecognizer,
    TrNationalIdRecognizer,
    UsSsnRecognizer,
)


_LANGUAGE = "tr"
_SCORE_THRESHOLD = 0.4


class ShimEmailRecognizer(EmailRecognizer):
    @lru_cache(maxsize=4096)
    def _validate_domain(self, domain: str) -> bool:
        return bool(super().validate_result(f"shim@{domain}"))

    def validate_result(self, pattern_text: str) -> bool:
        _, separator, domain = pattern_text.rpartition("@")
        return bool(separator) and self._validate_domain(domain.casefold())


class ShimSecretRecognizer(EntityRecognizer):
    _SECRET_KEY = (
        r"password|passwd|pwd|api[_-]?key|secret|token|db[_-]?pass|"
        r"postgres_password"
    )
    _ASSIGNMENT_PREFIX = rf"[\"']?(?:{_SECRET_KEY})[\"']?\s*(?:(?:=|:)\s*|\s+)"
    _PATTERNS: tuple[tuple[re.Pattern[str], str | None, float], ...] = (
        (
            re.compile(
                r"-----BEGIN "
                r"(?P<key_type>(?:(?:RSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY)"
                r"-----[\s\S]*?(?:-----END (?P=key_type)-----|\Z)"
            ),
            None,
            0.99,
        ),
        (
            re.compile(
                r"(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|"
                r"sk_(?:live|test)_[A-Za-z0-9]{16,}|"
                r"sk-(?:proj-)?[A-Za-z0-9_-]{16,}|"
                r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|"
                r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"
            ),
            None,
            0.99,
        ),
        (
            re.compile(
                r"https://(?:hooks\.slack\.com/services|"
                r"discord(?:app)?\.com/api/webhooks)/[^\s'\"]+",
                re.IGNORECASE,
            ),
            None,
            0.99,
        ),
        (
            re.compile(
                rf"{_ASSIGNMENT_PREFIX}(?P<quote>[\"'])"
                r"(?P<value>[^\r\n]{6,}?)(?P=quote)",
                re.IGNORECASE,
            ),
            "value",
            0.97,
        ),
        (
            re.compile(
                rf"{_ASSIGNMENT_PREFIX}(?P<value>[^\s,}}\]\"']{{6,}})",
                re.IGNORECASE,
            ),
            "value",
            0.97,
        ),
        (
            re.compile(
                r"--password(?:=|\s+)(?P<quote>[\"'])"
                r"(?P<value>[^\r\n]{6,}?)(?P=quote)",
                re.IGNORECASE,
            ),
            "value",
            0.97,
        ),
        (
            re.compile(
                r"--password(?:=|\s+)(?P<value>[^\s]+)",
                re.IGNORECASE,
            ),
            "value",
            0.97,
        ),
    )

    def __init__(self) -> None:
        super().__init__(
            supported_entities=["SECRET"],
            supported_language=_LANGUAGE,
        )

    def load(self) -> None:
        pass

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None,
    ) -> list[RecognizerResult]:
        if "SECRET" not in entities:
            return []
        results: list[RecognizerResult] = []
        for pattern, value_group, score in self._PATTERNS:
            for match in pattern.finditer(text):
                start, end = match.span(value_group) if value_group else match.span()
                results.append(
                    RecognizerResult(
                        entity_type="SECRET",
                        start=start,
                        end=end,
                        score=score,
                    )
                )
        return results


class ShimTurkishTaxIdRecognizer(PatternRecognizer):
    COUNTRY_CODE = "tr"

    def __init__(self) -> None:
        super().__init__(
            name="ShimTurkishTaxIdRecognizer",
            supported_entity="TR_VKN",
            supported_language=_LANGUAGE,
            context=["vergi", "vkn", "tax", "vergi kimlik", "vergi numarası"],
            patterns=[Pattern("Turkish tax ID", r"(?<!\d)\d{10}(?!\d)", 0.4)],
        )

    def validate_result(self, pattern_text: str) -> bool:
        digits = [int(character) for character in pattern_text]
        if len(digits) != 10 or len(set(digits)) == 1:
            return False
        checksum = 0
        for index, digit in enumerate(digits[:9]):
            adjusted = (digit + 9 - index) % 10
            if adjusted:
                checksum += (adjusted * 2 ** (9 - index)) % 9
        return digits[-1] == (10 - checksum % 10) % 10


def _custom_recognizers() -> list[EntityRecognizer]:
    return [
        ShimSecretRecognizer(),
        PatternRecognizer(
            name="ShimDatabaseUriRecognizer",
            supported_entity="DB_URI",
            supported_language=_LANGUAGE,
            patterns=[
                Pattern(
                    "Database URI",
                    r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|"
                    r"mssql)://[^\s'\"]+",
                    0.99,
                )
            ],
        ),
        PatternRecognizer(
            name="ShimFilePathRecognizer",
            supported_entity="FILE_PATH",
            supported_language=_LANGUAGE,
            patterns=[
                Pattern(
                    "Private file path",
                    r"(?<![\w])(?:/(?:Users|home|var|etc|opt|srv|tmp)/[^\s,;]+|"
                    r"[A-Za-z]:\\[^\r\n]+)",
                    0.85,
                )
            ],
        ),
        ShimTurkishTaxIdRecognizer(),
    ]


def _build_registry() -> RecognizerRegistry:
    recognizers = [
        ShimEmailRecognizer(
            supported_language=_LANGUAGE,
            context=["email", "e-posta", "mail"],
        ),
        PhoneRecognizer(
            supported_language=_LANGUAGE,
            supported_regions=(*PhoneRecognizer.DEFAULT_SUPPORTED_REGIONS, "TR"),
            context=[*PhoneRecognizer.CONTEXT, "telefon", "cep", "gsm"],
        ),
        CreditCardRecognizer(supported_language=_LANGUAGE),
        IbanRecognizer(supported_language=_LANGUAGE),
        IpRecognizer(supported_language=_LANGUAGE),
        MacAddressRecognizer(supported_language=_LANGUAGE),
        UsSsnRecognizer(supported_language=_LANGUAGE),
        TrNationalIdRecognizer(supported_language=_LANGUAGE),
        *_custom_recognizers(),
    ]
    return RecognizerRegistry(
        recognizers=recognizers,
        supported_languages=[_LANGUAGE],
    )


class PresidioAnalyzer:
    def __init__(self) -> None:
        nlp_engine = SlimSpacyNlpEngine(
            supported_languages=[_LANGUAGE],
            auto_download=False,
            generic_tokenizer="blank",
        )
        self._engine = AnalyzerEngine(
            registry=_build_registry(),
            nlp_engine=nlp_engine,
            supported_languages=[_LANGUAGE],
            log_decision_process=False,
        )

    def analyze(
        self,
        text: str,
        enabled_entities: Iterable[str],
    ) -> list[RecognizerResult]:
        entities = sorted(set(enabled_entities))
        if not text or not entities:
            return []
        return self._engine.analyze(
            text=text,
            language=_LANGUAGE,
            entities=entities,
            score_threshold=_SCORE_THRESHOLD,
            return_decision_process=False,
        )
