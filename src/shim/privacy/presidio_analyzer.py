"""Curated Presidio detection for the gateway privacy boundary."""

from __future__ import annotations

import re
from collections.abc import Iterable
from functools import lru_cache
from typing import cast

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


# A local part is read once per run of local-part characters, possessively; leading
# punctuation is read but left out of the match (\K). Starting at every word boundary
# inside a long dotted run, as Presidio's pattern does, rescans the run from each start:
# quadratic in the prompt.
_LOCAL_PART = (
    r"(?<![\w.!#$%&'*+/=?^`{|}~-])[.!#$%&'*+/=?^`{|}~-]*+\K\w[\w.!#$%&'*+/=?^`{|}~-]*+"
)


class ShimEmailRecognizer(EmailRecognizer):
    PATTERNS = [
        Pattern(
            "Email (Medium)",
            _LOCAL_PART + r"@\w+(?:-+\w+)*(?:\.\w+(?:-+\w+)*)+\b",
            0.5,
        )
    ]

    @lru_cache(maxsize=4096)
    def _validate_domain(self, domain: str) -> bool:
        return bool(super().validate_result(f"shim@{domain}"))

    def validate_result(self, pattern_text: str) -> bool:
        _, separator, domain = pattern_text.rpartition("@")
        return bool(separator) and self._validate_domain(domain.casefold())


class ShimWrittenAtEmailRecognizer(ShimEmailRecognizer):
    """jane[at]example.com and jane(at)example.com, the whole written form."""

    _AT = re.compile(r"\[ *at *\]|\( *at *\)", re.IGNORECASE)
    PATTERNS = [
        Pattern(
            "Email with a written at",
            _LOCAL_PART + rf"(?:{_AT.pattern})[\w-]+(?:\.[\w-]+)+\b",
            0.5,
        )
    ]

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
        regex_flags: int | None = None,
    ) -> list[RecognizerResult]:
        # Presidio's regex engine tries the pattern at every word; this scan is ten times cheaper.
        if not self._AT.search(text):
            return []
        return super().analyze(text, entities, nlp_artifacts, regex_flags)

    def validate_result(self, pattern_text: str) -> bool:
        return super().validate_result(self._AT.sub("@", pattern_text))


class ShimIbanRecognizer(IbanRecognizer):
    """An IBAN typed in lowercase or broken over a line.

    Presidio's recognizer stays in the registry for every other IBAN: a case-insensitive,
    line-crossing pattern alone pulls a following word or line into the match, and the upstream
    fallback retries only three cut points, so a correct IBAN would be lost.
    """

    _HEAD = re.compile(r"(?<![A-Z0-9])[A-Z]{2}[0-9]{2}", re.IGNORECASE)
    _SEPARATOR = r"(?:[ -]|[ ]*\r?\n[ ]*)?"
    PATTERNS = [
        Pattern(
            "IBAN lowercase or line-broken",
            rf"(?i)(?<![A-Z0-9])([A-Z]{{2}}[0-9]{{2}}(?:{_SEPARATOR}[A-Z0-9]{{4}}){{2,6}})"
            rf"((?:{_SEPARATOR}[A-Z0-9]{{4}})?)((?:{_SEPARATOR}[A-Z0-9]{{1,3}})?)"
            r"(?![A-Z0-9])",
            0.5,
        ),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_language=_LANGUAGE,
            replacement_pairs=[("-", ""), (" ", ""), ("\r", ""), ("\n", "")],
        )

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
        regex_flags: int | None = None,
    ) -> list[RecognizerResult]:
        # As for the written-at email: a cheap scan for the IBAN head before the full pattern.
        # Presidio's IBAN analysis reads neither the NLP artifacts nor the flags.
        if not self._HEAD.search(text):
            return []
        return super().analyze(text, entities)

    def validate_result(self, pattern_text: str) -> bool | None:
        return super().validate_result(pattern_text.upper())


class ShimPhoneRecognizer(PhoneRecognizer):
    """A digit run is a phone unless something marks it as another kind of number.

    Recall first: a masked order number is restored in the answer, a missed phone
    number reaches the provider.
    """

    _BARE = re.compile(r"\d+")
    _DECIMAL = re.compile(r"\d+\.\d+")
    _TURKISH = re.compile(r"(?:90)?0?5\d{9}|0[2-4]\d{9}")
    _CUE = re.compile(
        r"\b(?:tel|telefon|phone|gsm|cep|mobile|mobil|cell|fax|whatsapp|call|contact|"
        r"numara|num|no)"
        r"(?:[ _-]?(?:number|numaras[ıi]|numaram|no|num))?\b[\"':=. ]{0,4}$",
        re.IGNORECASE,
    )
    _NOT_PHONE_CUE = re.compile(
        r"\b(?:order|sipari[şs]|fatura|invoice|ticket|ref|reference|sku|kod|code|"
        r"timestamp|epoch|ts|duration|created|updated|value|amount|total|count)"
        r"(?:[ _-]?(?:numaras[ıi]|number|no|num|id|at|ms))*[\"':=#. _-]{0,4}$",
        re.IGNORECASE,
    )
    # Anywhere in the window and inside keys (customer_phone, mobilePhone): it overrules
    # a non-phone word, so "contact code 4155552671" stays a phone.
    _PHONE_WORD = re.compile(
        r"tel|phone|mobil|gsm|cell|msisdn|fax|whatsapp|contact|cep", re.IGNORECASE
    )
    _IDENTIFIER_TAIL = re.compile(r"[A-Za-z0-9_.-]*$")
    _LETTER = re.compile(r"[A-Za-z]")

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
    ) -> list[RecognizerResult]:
        # Presidio annotates the argument as NlpArtifacts but defaults it to None.
        artifacts = cast(NlpArtifacts, nlp_artifacts)
        return [
            result
            for result in super().analyze(text, entities, artifacts)
            if self._is_phone(text, result.start, result.end)
        ]

    def _is_phone(self, text: str, start: int, end: int) -> bool:
        raw = text[start:end]
        if self._DECIMAL.fullmatch(raw) or self._in_decimal(text, start, end):
            return False
        bare = self._BARE.fullmatch(raw)
        window = max(0, start - 24)
        if (bare and self._TURKISH.fullmatch(raw)) or self._CUE.search(
            text, window, start
        ):
            return True
        if start and text[start - 1] in "-_.":
            tail = self._IDENTIFIER_TAIL.search(text, max(0, start - 65), start - 1)
            if tail is not None and self._LETTER.search(tail.group()):
                return False
        return not (
            bare
            and self._NOT_PHONE_CUE.search(text, window, start)
            and not self._PHONE_WORD.search(text, window, start)
        )

    @staticmethod
    def _in_decimal(text: str, start: int, end: int) -> bool:
        # The matcher can start after "0.", leaving the fraction of a decimal literal.
        return (
            start >= 2 and text[start - 1] == "." and text[start - 2].isdigit()
        ) or (text[end : end + 1] == "." and text[end + 1 : end + 2].isdigit())


class ShimIpRecognizer(IpRecognizer):
    """A version string is not an IP address."""

    _VERSION_CUE = re.compile(r"\b(?:v|version|sürüm)\W{0,2}$", re.IGNORECASE)

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
        regex_flags: int | None = None,
    ) -> list[RecognizerResult]:
        return [
            result
            for result in super().analyze(text, entities, nlp_artifacts, regex_flags)
            if self._is_address(text, result.start, result.end)
        ]

    def _is_address(self, text: str, start: int, end: int) -> bool:
        return not self._VERSION_CUE.search(text, max(0, start - 16), start)


class ShimSecretRecognizer(EntityRecognizer):
    _SECRET_KEY = (
        r"password|passwd|pwd|api[_-]?key|secret|token|db[_-]?pass|"
        r"postgres_password"
    )
    _ASSIGNMENT_PREFIX = rf"[\"']?(?:{_SECRET_KEY})[\"']?\s*(?:(?:=|:)\s*|\s+)"
    # An explicit separator, unlike the English keys, so "şifre unuttum" is not a finding.
    _TURKISH_ASSIGNMENT_PREFIX = r"[\"']?(?:[şs]ifre(?:si|m|n|niz)?|parola(?:s[ıi]|m|n|n[ıi]z)?)[\"']?\s*(?:=|:)\s*"
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
                r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|"
                r"(?<![A-Za-z0-9])(?:AIza[0-9A-Za-z_-]{35}|"
                r"xox[abposr]-[0-9A-Za-z-]{10,}|"
                r"hf_[A-Za-z0-9]{30,}|"
                r"glpat-[0-9A-Za-z_-]{20,}))"
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
                rf"{_TURKISH_ASSIGNMENT_PREFIX}(?P<quote>[\"'])"
                r"(?P<value>[^\r\n]{6,}?)(?P=quote)",
                re.IGNORECASE,
            ),
            "value",
            0.97,
        ),
        (
            re.compile(
                rf"{_TURKISH_ASSIGNMENT_PREFIX}(?P<value>[^\s,}}\]\"']{{6,}})",
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


class ShimTurkishPlateRecognizer(PatternRecognizer):
    """A Turkish plate with the letter and digit counts plates use, not a unit or a currency.

    Presidio's recognizer accepts any province-coded shape, and its context words cannot help
    because the blank tokenizer gives them nothing to match.
    """

    _NOT_PLATE_LETTERS = frozenset(
        "GB MB KB TB GHZ MHZ USD EUR TRY TL KM KG CM MM ML LT".split()
    )

    def __init__(self) -> None:
        letter = "[A-PR-VYZ]"
        super().__init__(
            supported_entity="TR_LICENSE_PLATE",
            supported_language=_LANGUAGE,
            patterns=[
                Pattern(
                    "Turkish licence plate",
                    r"\b(?:0[1-9]|[1-7][0-9]|8[01]) ?"
                    rf"(?:{letter} ?[0-9]{{4}}|{letter}{{2}} ?[0-9]{{3,4}}|"
                    rf"{letter}{{3}} ?[0-9]{{2,3}})\b",
                    0.3,
                )
            ],
            # Uppercase only: Presidio's default flags would add IGNORECASE.
            global_regex_flags=re.DOTALL | re.MULTILINE,
        )

    def validate_result(self, pattern_text: str) -> bool:
        letters = "".join(filter(str.isalpha, pattern_text))
        return letters not in self._NOT_PLATE_LETTERS


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
        ShimTurkishPlateRecognizer(),
        ShimWrittenAtEmailRecognizer(
            supported_language=_LANGUAGE,
            context=["email", "e-posta", "mail"],
        ),
    ]


def _build_registry() -> RecognizerRegistry:
    recognizers = [
        ShimEmailRecognizer(
            supported_language=_LANGUAGE,
            context=["email", "e-posta", "mail"],
        ),
        ShimPhoneRecognizer(
            supported_language=_LANGUAGE,
            supported_regions=(*PhoneRecognizer.DEFAULT_SUPPORTED_REGIONS, "TR"),
            context=[*PhoneRecognizer.CONTEXT, "telefon", "cep", "gsm"],
        ),
        CreditCardRecognizer(
            supported_language=_LANGUAGE,
            patterns=[
                *CreditCardRecognizer.PATTERNS,
                Pattern(
                    "Troy (weak)",
                    r"\b9792[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
                    0.3,
                ),
                Pattern(
                    "Mastercard 2-series (weak)",
                    r"\b(?:222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)"
                    r"[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
                    0.3,
                ),
            ],
        ),
        IbanRecognizer(supported_language=_LANGUAGE),
        ShimIbanRecognizer(),
        ShimIpRecognizer(supported_language=_LANGUAGE),
        MacAddressRecognizer(supported_language=_LANGUAGE),
        UsSsnRecognizer(supported_language=_LANGUAGE),
        TrNationalIdRecognizer(
            supported_language=_LANGUAGE,
            patterns=[
                *TrNationalIdRecognizer.PATTERNS,
                Pattern(
                    "TR_NATIONAL_ID in groups",
                    r"\b[1-9][0-9]{2}([ -])[0-9]{3}\1"
                    r"(?:[0-9]{3}\1[0-9]{2}|[0-9]{2}\1[0-9]{3})\b",
                    0.3,
                ),
            ],
            replacement_pairs=[(" ", ""), ("-", "")],
        ),
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
