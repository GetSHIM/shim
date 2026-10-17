"""Curated Presidio detection for the gateway privacy boundary."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from functools import cache, lru_cache
from importlib.resources import files
from typing import Any, Literal, cast
import unicodedata

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
import regex
import tldextract

from shim.rules.content import turkish_fold


_LANGUAGE = "tr"
_SCORE_THRESHOLD = 0.4


# A local part is read once per run of local-part characters, possessively; leading
# punctuation is read but left out of the match (\K). Starting at every word boundary
# inside a long dotted run, as Presidio's pattern does, rescans the run from each start:
# quadratic in the prompt.
_LOCAL_PART = (
    r"(?<![\w.!#$%&'*+/=?^`{|}~-])[.!#$%&'*+/=?^`{|}~-]*+\K\w[\w.!#$%&'*+/=?^`{|}~-]*+"
)


# The Public Suffix List bundled with tldextract, read once: no download and no disk cache.
# Presidio's default extractor fetches publicsuffix.org on first use, with no timeout,
# which a gateway with egress closed must never do. The snapshot is 2025-04-07 (5.3.1,
# still the one 5.4.0 ships); it decides only final labels that are not all letters.
_DOMAINS = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())


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
        # Recall first: a final label of two or more letters is a domain even when the list
        # does not know it (.hotel, .corp, .local, .internal). The list adds punycode TLDs
        # and keeps out a numeric or one-letter label (pkg@1.2.3, vue@3.x).
        tld = domain.rpartition(".")[2]
        return (len(tld) > 1 and tld.isalpha()) or _DOMAINS(f"shim@{domain}").fqdn != ""

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


# A word in front of a digit run that marks it as another kind of number than a phone or
# a tax ID: an order, a shipment, a time, an amount.
_NOT_ID_WORD = re.compile(
    r"\b(?:order|sipari[şs]|fatura|invoice|takip|tracking|ticket|ref|reference|sku|"
    r"kod|code|timestamp|epoch|ts|duration|created|updated|value|amount|total|count)"
    r"(?:[ _-]?(?:numara(?:s[ıi]|n[ıi]z|m[ıi]z|m)?|number|no|num|id|at|ms))*"
    r"[\"':=#. _-]{0,4}$",
    re.IGNORECASE,
)
_TAX_WORD = re.compile(r"vergi|vkn|tax", re.IGNORECASE)
_IDENTIFIER_TAIL = re.compile(r"[A-Za-z0-9_.-]*$")
_LETTER = re.compile(r"[A-Za-z]")


def _in_decimal(text: str, start: int, end: int) -> bool:
    # The matcher can start after "0.", leaving the fraction of a decimal literal.
    return (start >= 2 and text[start - 1] == "." and text[start - 2].isdigit()) or (
        text[end : end + 1] == "." and text[end + 1 : end + 2].isdigit()
    )


def after_tax_word(text: str, start: int) -> bool:
    return bool(_TAX_WORD.search(text, max(0, start - 24), start))


def _glued_to_identifier(text: str, start: int) -> bool:
    """SKU-ABC-4829104455, claude-sonnet-4-5-20250929, build_7.20250929."""
    if not start or text[start - 1] not in "-_.":
        return False
    tail = _IDENTIFIER_TAIL.search(text, max(0, start - 65), start - 1)
    return tail is not None and bool(_LETTER.search(tail.group()))


class ShimPhoneRecognizer(PhoneRecognizer):
    """A digit run is a phone unless something marks it as another kind of number.

    Recall first: a masked order number is restored in the answer, a missed phone
    number reaches the provider.
    """

    _BARE = re.compile(r"\d+")
    # 0532.1234567 is a dotted phone; 0.123 is a decimal.
    _DECIMAL = re.compile(r"(?!0\d)\d+\.\d+")
    _TURKISH = re.compile(r"(?:90)?0?5\d{9}|0[2-4]\d{9}")
    _NOT_DIGIT = re.compile(r"\D")
    _FORMATTED = re.compile(r"[\s()+]")
    # 05.03.2026 and 2026-03-05, the same separator twice.
    _DATE = re.compile(
        r"(?:0?[1-9]|[12]\d|3[01])(?P<a>[./-])(?:0?[1-9]|1[0-2])(?P=a)(?:19|20)\d\d"
        r"|(?:19|20)\d\d(?P<b>[./-])(?:0?[1-9]|1[0-2])(?P=b)(?:0?[1-9]|[12]\d|3[01])"
    )
    _CUE = re.compile(
        r"\b(?:tel|telefon|phone|gsm|cep|mobile|mobil|cell|fax|whatsapp|call|contact|"
        r"numara|num|no)"
        r"(?:[ _-]?(?:number|numaras[ıi]|numaram|no|num))?\b[\"':=. ]{0,4}$",
        re.IGNORECASE,
    )
    # Anywhere in the window and inside keys (customer_phone, mobilePhone): it overrules
    # a non-phone word, so "contact code 4155552671" stays a phone.
    _PHONE_WORD = re.compile(
        r"tel|phone|mobil|gsm|cell|msisdn|fax|whatsapp|contact|cep", re.IGNORECASE
    )

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
        if (
            self._DECIMAL.fullmatch(raw)
            or _in_decimal(text, start, end)
            or self._DATE.fullmatch(raw)
        ):
            return False
        bare = self._BARE.fullmatch(raw)
        window = max(0, start - 24)
        # "Fatura no:" and "takip no" name another number; "Tel no:" names a phone.
        other_number = _NOT_ID_WORD.search(
            text, window, start
        ) and not self._PHONE_WORD.search(text, window, start)
        if self._TURKISH.fullmatch(self._NOT_DIGIT.sub("", raw)) or (
            self._CUE.search(text, window, start) and not other_number
        ):
            return True
        # Digits joined by "-", "_" or "." can end a name, claude-sonnet-4-5-20250929;
        # a space, a bracket or a "+" makes a phone: "musteri-0532 123 45 67".
        if _glued_to_identifier(text, start) and not self._FORMATTED.search(raw):
            return False
        return not (bare and other_number)


class ShimIpRecognizer(IpRecognizer):
    """A version string, or a run of more than four numbers, is not an IP address."""

    # No "v": a glued "v1.2.3.4" never matches an address, and a lone one is a flag
    # or a letter, "curl -v 203.0.113.9" and "server v 192.168.1.1".
    # A bare "ver" after a word is the Turkish verb: "izin ver 10.0.0.5" is an address.
    _VERSION_CUE = re.compile(
        r"(?:\b(?:version|sürüm|ver\.)|(?<!\w\s)\bver)\W{0,2}$", re.IGNORECASE
    )

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
        return not (
            _in_decimal(text, start, end)
            or self._VERSION_CUE.search(text, max(0, start - 16), start)
        )


class ShimSecretRecognizer(EntityRecognizer):
    _SECRET_KEY = (
        r"password|passwd|pwd|api[_-]?key|secret|token|db[_-]?pass|"
        r"postgres_password"
    )
    _ASSIGNMENT_PREFIX = rf"[\"']?(?:{_SECRET_KEY})[\"']?\s*[=:]\s*"
    # A key and a value separated by a space alone: "password hunter2", "export API_KEY x".
    # The key starts a word and the value carries a digit or a symbol, so prose such as
    # "token budget" or "password protected" is not a finding.
    _SPACED_PREFIX = rf"(?<![^\W_])(?:{_SECRET_KEY})[\"']?\s+"
    _SPACED_VALUE = r"(?=[^\s,}\]\"']*[0-9!#$%&*+./;<=>?@^_|~-])"
    # An explicit separator, unlike the English keys, so "şifre unuttum" is not a finding,
    # and a word start, so "deşifre:" is not one either.
    _TURKISH_ASSIGNMENT_PREFIX = r"(?<![^\W\d_])[\"']?(?:[şs]ifre(?:si|m|n|niz)?|parola(?:s[ıi]|m|n|n[ıi]z)?)[\"']?\s*(?:=|:)\s*"
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
                rf"(?:{_ASSIGNMENT_PREFIX}|{_SPACED_PREFIX})(?P<quote>[\"'])"
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
                rf"{_SPACED_PREFIX}{_SPACED_VALUE}(?P<value>[^\s,}}\]\"']{{6,}})",
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
    """Ten digits with a valid checksum, unless the phone rule marks them as another number.

    About one ten-digit number in ten passes the checksum, so an invoice number, a
    timestamp or a decimal fraction would be masked; a tax word in front overrules.
    The scrubber gives a span the phone rule also claims to the phone, unless a tax
    word is in front.
    """

    COUNTRY_CODE = "tr"

    def __init__(self) -> None:
        super().__init__(
            name="ShimTurkishTaxIdRecognizer",
            supported_entity="TR_VKN",
            supported_language=_LANGUAGE,
            context=["vergi", "vkn", "tax", "vergi kimlik", "vergi numarası"],
            patterns=[Pattern("Turkish tax ID", r"(?<!\d)\d{10}(?!\d)", 0.4)],
        )

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
            if self._is_tax_id(text, result.start, result.end)
        ]

    def _is_tax_id(self, text: str, start: int, end: int) -> bool:
        return after_tax_word(text, start) or not (
            _in_decimal(text, start, end)
            or _glued_to_identifier(text, start)
            or _NOT_ID_WORD.search(text, max(0, start - 24), start)
        )

    def validate_result(self, pattern_text: str) -> bool:
        digits = [int(character) for character in pattern_text]
        if len(digits) != 10 or len(set(digits)) == 1:
            return False
        checksum = 0
        for index, digit in enumerate(digits[:9]):
            adjusted = (digit + 9 - index) % 10
            if adjusted:
                # python-stdnum's stdnum.tr.vkn: a term that is 0 mod 9 counts as 9.
                checksum += (adjusted * 2 ** (9 - index)) % 9 or 9
        return digits[-1] == (10 - checksum % 10) % 10


class ShimTurkishPlateRecognizer(PatternRecognizer):
    """A Turkish plate with the letter and digit counts plates use, not a unit or a currency.

    Presidio's recognizer accepts any province-coded shape, and its context words cannot help
    because the blank tokenizer gives them nothing to match. Lowercase counts only after a
    plate word, so "15 dk 30" and "12 ay 24" stay prose.
    """

    _NOT_PLATE_LETTERS = frozenset(
        "GB MB KB TB GHZ MHZ KM KG CM MM ML LT AM PM "
        "USD EUR TRY TL GBP CHF JPY CNY CAD AUD RUB SEK NOK DKK PLN AED SAR "
        "JAN FEB MAR APR MAY JUN JUL AUG SEP OCT NOV DEC "
        "OCA SUB NIS HAZ TEM AGU EYL EKI KAS ARA".split()
    )
    _CUE = re.compile(r"\b(?:plaka|plate)\w*\W{0,3}$", re.IGNORECASE)

    def __init__(self) -> None:
        letter = "[A-PR-VYZa-pr-vyz]"
        super().__init__(
            supported_entity="TR_LICENSE_PLATE",
            supported_language=_LANGUAGE,
            patterns=[
                Pattern(
                    "Turkish licence plate",
                    r"(?<![\w-])(?:0[1-9]|[1-7][0-9]|8[01])(?P<separator>[ -]?)"
                    rf"(?:{letter}(?P=separator)[0-9]{{4,5}}|"
                    rf"{letter}{{2}}(?P=separator)[0-9]{{3,4}}|"
                    rf"{letter}{{3}}(?P=separator)[0-9]{{2,3}})"
                    # Not a longer number, a date or a version, and not a quantity.
                    r"(?!\w|[-./:,]\d)(?!\s*(?:W|V|A|mA|mAh|kW|Hz|GB|MB|TB|rpm)\b)",
                    0.3,
                )
            ],
            # Case-sensitive units: Presidio's default flags would add IGNORECASE.
            global_regex_flags=re.DOTALL | re.MULTILINE,
        )

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
            if text[result.start : result.end].isupper()
            or self._CUE.search(text, max(0, result.start - 24), result.start)
        ]

    def validate_result(self, pattern_text: str) -> bool:
        letters = "".join(filter(str.isalpha, pattern_text))
        return letters.upper() not in self._NOT_PLATE_LETTERS


_UPPER = "A-ZÇĞİÖŞÜÂÎÛ"
_LOWER = "a-zçğıöşüâîû"
_NAME_ENTRY = re.compile(rf"[{_UPPER}{_LOWER}'’-]+").fullmatch
_STOPWORD_ENTRY = re.compile(rf"[{_UPPER}{_LOWER}'’.-]+").fullmatch
_LATIN_NAME_ENTRY = regex.compile(r"[\p{Latin}\p{M}'’-]+").fullmatch
_LATIN_STOPWORD_ENTRY = regex.compile(r"[\p{Latin}\p{M}'’.-]+").fullmatch
_LATIN_PHRASE_ENTRY = regex.compile(
    r"[\p{Latin}\p{M}'’-]+(?: [\p{Latin}\p{M}'’-]+)+"
).fullmatch
# A shorter stopword must match a whole word: "Muş" is not the start of "Musa".
_MIN_STOPWORD_PREFIX = 5
_NAME_JOINERS = str.maketrans("", "", "'’-")

# A pattern's fullmatch: (text) or (text, start, end).
type _Shape = Callable[..., object]


@dataclass(frozen=True, slots=True)
class PersonNames:
    first: frozenset[str]
    ambiguous: frozenset[str]
    surnames: frozenset[str]
    stop_words: frozenset[str]
    stop_prefixes: frozenset[str]
    stop_dotted: tuple[str, ...]
    fold: Callable[[str], str]
    title_word: _Shape
    capital_word: _Shape
    leading_cues: frozenset[str]
    trailing_cues: frozenset[str]
    # Cues a common word may follow: "Dear All", "Dear Sales Team".
    greetings: frozenset[str] = frozenset()
    # Surnames that are common words: "Rose Gold" is a colour, "Mark Down" a format.
    ambiguous_surnames: frozenset[str] = frozenset()
    # Names that are brands, characters or places: "Calvin Klein", "Harry Potter".
    not_names: frozenset[str] = frozenset()


def _name_lists(
    file: str, entry: _Shape, stop_entry: _Shape, **more: _Shape
) -> dict[str, Any]:
    data = json.loads(files("shim.privacy").joinpath(f"data/{file}").read_text("utf-8"))
    shapes = {
        "first_names": entry,
        "team_first_names": entry,
        "ambiguous_first_names": entry,
        "surnames": entry,
        "following_stopwords": stop_entry,
    } | more
    for key, shape in shapes.items():
        entries = data[key]
        if len(set(entries)) != len(entries) or not all(
            shape(item) and unicodedata.is_normalized("NFC", item) for item in entries
        ):
            raise ValueError(f"{file}: invalid {key}")
    return data


@cache
def person_names() -> PersonNames:
    """`data/tr_person_names.json`, validated and folded; read once per process."""
    data = _name_lists("tr_person_names.json", _NAME_ENTRY, _STOPWORD_ENTRY)
    stopwords = {turkish_fold(entry) for entry in data["following_stopwords"]}
    return PersonNames(
        first=frozenset(
            map(turkish_fold, data["first_names"] + data["team_first_names"])
        ),
        ambiguous=frozenset(map(turkish_fold, data["ambiguous_first_names"])),
        surnames=frozenset(map(turkish_fold, data["surnames"])),
        stop_words=frozenset(
            word
            for word in stopwords
            if "." not in word and len(word) < _MIN_STOPWORD_PREFIX
        ),
        stop_prefixes=frozenset(
            word
            for word in stopwords
            if "." not in word and len(word) >= _MIN_STOPWORD_PREFIX
        ),
        stop_dotted=tuple(sorted(word for word in stopwords if "." in word)),
        fold=turkish_fold,
        title_word=re.compile(
            rf"[{_UPPER}][{_LOWER}]+(?:-[{_UPPER}][{_LOWER}]+)*"
        ).fullmatch,
        capital_word=re.compile(rf"[{_UPPER}]{{2,}}(?:-[{_UPPER}]{{2,}})*").fullmatch,
        # Address forms and titles; folded, so "Doç" is "doc".
        leading_cues=frozenset(
            {
                "sayin",
                "sn",
                "bay",
                "bayan",
                "hn",
                "dr",
                "doc",
                "prof",
                "av",
                "op",
                "uzm",
            }
        ),
        trailing_cues=frozenset({"bey", "hanim", "hanimefendi"}),
    )


def english_fold(text: str) -> str:
    """Accents and case dropped, apostrophes and hyphens removed: "O'Connell" is the
    Census's "OCONNELL"."""

    if not text.isascii():
        text = "".join(
            character
            for character in unicodedata.normalize("NFKD", text)
            if not unicodedata.combining(character)
        )
    return text.casefold().translate(_NAME_JOINERS)


@cache
def english_person_names() -> PersonNames:
    """`data/en_person_names.json`, validated and folded; read once per process."""
    data = _name_lists(
        "en_person_names.json",
        _LATIN_NAME_ENTRY,
        _LATIN_STOPWORD_ENTRY,
        ambiguous_surnames=_LATIN_NAME_ENTRY,
        not_names=_LATIN_PHRASE_ENTRY,
    )
    stopwords = {english_fold(entry) for entry in data["following_stopwords"]}
    return PersonNames(
        first=frozenset(
            map(english_fold, data["first_names"] + data["team_first_names"])
        ),
        ambiguous=frozenset(map(english_fold, data["ambiguous_first_names"])),
        surnames=frozenset(map(english_fold, data["surnames"])),
        # English adds no suffixes: "Church" is not the start of "Churchill".
        stop_words=frozenset(word for word in stopwords if "." not in word),
        stop_prefixes=frozenset(),
        stop_dotted=tuple(sorted(word for word in stopwords if "." in word)),
        fold=english_fold,
        title_word=regex.compile(
            r"(?=\p{Latin})\p{Lu}(?=.*\p{Ll})[\p{Latin}'’-]+"
        ).fullmatch,
        capital_word=regex.compile(
            r"(?=\p{Latin})(?!.*\p{Ll})(?=.+\p{L})[\p{Latin}'’-]+"
        ).fullmatch,
        leading_cues=frozenset(
            {"mr", "mrs", "ms", "miss", "mx", "dr", "prof", "sir", "dame", "dear"}
        ),
        trailing_cues=frozenset(),
        greetings=frozenset({"dear"}),
        ambiguous_surnames=frozenset(map(english_fold, data["ambiguous_surnames"])),
        not_names=frozenset(
            " ".join(map(english_fold, entry.split())) for entry in data["not_names"]
        ),
    )


def _person_names(text: str, names: PersonNames) -> list[tuple[int, int, float]]:
    """(start, end, score) of each name; one pass over the words, set lookups only."""
    words: list[tuple[int, int]] = []
    for match in re.finditer(r"\w+", text):
        start, end = match.span()
        gap = text[words[-1][1] : start] if words else ""
        if (
            # "O'Brien", "O'BRIEN"; "Yılmaz'ın" and "YILMAZ'IN" end in a suffix.
            gap in ("'", "’")
            and text[start].isupper()
            and (words[-1][1] - words[-1][0] == 1 or not text[start:end].isupper())
        ) or (gap == "-" and text[words[-1][0]].isupper() and text[start].isupper()):
            words[-1] = (words[-1][0], end)
        else:
            words.append((start, end))
    dotted_length = max(map(len, names.stop_dotted), default=0)
    prefix_length = max(map(len, names.stop_prefixes), default=0)

    @cache
    def fold(index: int) -> str:
        start, end = words[index]
        return names.fold(text[start:end])

    @cache
    def parts(index: int) -> tuple[str, ...]:
        start, end = words[index]
        return tuple(map(names.fold, text[start:end].split("-")))

    def among(index: int, listed: frozenset[str]) -> bool:
        """ "Anna-Lena" is a first name when "Anna-Lena" is, or "Anna" and "Lena" are."""
        if fold(index) in listed:
            return True
        start, end = words[index]
        return "-" in text[start:end] and all(part in listed for part in parts(index))

    def suffix(index: int) -> bool:
        start = words[index][0]
        return start >= 2 and text[start - 1] in "'’" and text[start - 2].isalpha()

    @cache
    def form(index: int) -> Literal["title", "capitals"] | None:
        start, end = words[index]
        if suffix(index):
            return None
        if names.title_word(text, start, end):
            return "title"
        return "capitals" if names.capital_word(text, start, end) else None

    def next_to(index: int, after_dot: bool = False) -> bool:
        """The next word follows on the same line, after spaces only."""
        if index + 1 >= len(words):
            return False
        gap = text[words[index][1] : words[index + 1][0]]
        if after_dot and gap.startswith("."):
            gap = gap[1:]
        return bool(gap) and not gap.strip(" \t\u00a0")

    @cache
    def stop(index: int) -> bool:
        start, end = words[index]
        # Every dotted stopword has its first dot right after its first word: "A.Ş.".
        if text[end : end + 1] == "." and names.fold(
            text[start : start + dotted_length]
        ).startswith(names.stop_dotted):
            return True
        word = fold(index)
        return form(index) is not None and (
            word in names.stop_words
            or any(
                word[:length] in names.stop_prefixes
                for length in range(
                    _MIN_STOPWORD_PREFIX, min(len(word), prefix_length) + 1
                )
            )
        )

    def token(index: int) -> bool:
        return (
            index < len(words)
            and form(index) is not None
            and not stop(index)
            and fold(index) not in names.trailing_cues
            and fold(index) not in names.leading_cues
        )

    def cue_after(index: int) -> bool:
        return next_to(index) and fold(index + 1) in names.trailing_cues

    def listed(index: int) -> bool:
        return among(index, names.first) or among(index, names.surnames)

    def a_word(index: int) -> bool:
        """A surname that is also a common word, and no first name."""
        return among(index, names.ambiguous_surnames) and not among(index, names.first)

    def surname_after(index: int) -> int | None:
        """The end of "[first name] listed surname" right after `index`."""
        if not (next_to(index, after_dot=True) and token(index + 1)):
            return None
        given = index + 1
        if (
            among(given, names.first)
            and next_to(given)
            and token(given + 1)
            and among(given + 1, names.surnames)
        ):
            return given + 1
        return given if among(given, names.surnames) else None

    def name_at(index: int) -> tuple[int, int, float] | None:
        word = fold(index)
        if word in names.leading_cues and not suffix(index):
            last = index
            while (
                last - index < 3
                and next_to(last, after_dot=last == index)
                and token(last + 1)
            ):
                last += 1
            # "Sayın Yetkili" holds no name; "SAYIN AYŞE YILMAZ ADINA" ends at the surname.
            known = [
                part
                for part in range(index + 1, last + 1)
                if listed(part) and not (word in names.greetings and a_word(part))
            ]
            if not known:
                return None
            end = known[-1]
            if end < last and not among(end, names.surnames):
                end += 1
            return index + 1, end, 0.85
        start, end = words[index]
        if end - start == 1 and text[start].isupper() and text[end : end + 1] == ".":
            surname = surname_after(index)
            return None if surname is None else (index, surname, 0.85)
        if not token(index):
            return None
        if cue_after(index) and listed(index):
            return index, index, 0.8
        if next_to(index) and token(index + 1) and cue_after(index + 1):
            return (index, index + 1, 0.8) if among(index, names.first) else None
        if not among(index, names.first):
            return None
        middle = next_to(index) and token(index + 1) and among(index + 1, names.first)
        for given in (index + 1, index) if middle else (index,):
            surname = given + 1
            if not (next_to(given) and token(surname)):
                continue
            if among(surname, names.surnames) and not (
                among(index, names.ambiguous)
                and among(surname, names.ambiguous_surnames)
            ):
                second = next_to(surname) and token(surname + 1)
                if (
                    second
                    and among(surname + 1, names.surnames)
                    and not among(surname + 1, names.ambiguous_surnames)
                ):
                    return index, surname + 1, 0.85
                return index, surname, 0.85
            if (
                not among(index, names.ambiguous)
                and not among(surname, names.first)
                and len({form(part) for part in range(index, surname + 1)}) == 1
            ):
                # "Ahmet Necdet Sezer": with no middle first name, a third title-case word that is none.
                third = surname + 1
                if (
                    given == index
                    and form(index) == "title"
                    and next_to(surname)
                    and token(third)
                    and not among(third, names.first)
                    and form(third) == "title"
                ):
                    return index, third, 0.6
                return index, surname, 0.6
        return None

    def inside_a_place(last: int) -> bool:
        """A stopword within two words: "Ahmet Yılmaz Caddesi", "Ahmet Necdet Sezer Parkı"."""
        for after in (last + 1, last + 2):
            if not next_to(after - 1):
                return False
            if stop(after):
                return True
            if not token(after):
                return False
        return False

    def not_a_person(first: int, last: int) -> bool:
        """ "Calvin Klein", "Dr Pepper", "Johnnie Walker Black": a listed non-person
        starts at the name or at the word before it."""
        for start in (first - 1, first) if first else (first,):
            phrase = fold(start)
            for end in range(start + 1, min(last, start + 3) + 1):
                if not next_to(end - 1, after_dot=True):
                    break
                phrase += " " + fold(end)
                if phrase in names.not_names:
                    return True
        return False

    found: list[tuple[int, int, float]] = []
    index = 0
    while index < len(words):
        name = name_at(index)
        if name is None:
            index += 1
            continue
        first, last, score = name
        if not (inside_a_place(last) or not_a_person(first, last)):
            if any(form(part) == "capitals" for part in range(first, last + 1)):
                score = 0.6
            found.append((words[first][0], words[last][1], score))
        index = last + 1
    return found


class ShimPersonNameRecognizer(EntityRecognizer):
    """Full names from name lists and address cues; opt-in, never a first name alone."""

    def __init__(self, entity: str, names: Callable[[], PersonNames]) -> None:
        self._entity, self._names = entity, names()
        super().__init__(
            supported_entities=[entity],
            name=f"ShimPersonNameRecognizer[{entity}]",
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
        if self._entity not in entities:
            return []
        return [
            RecognizerResult(
                entity_type=self._entity, start=start, end=end, score=score
            )
            for start, end, score in _person_names(text, self._names)
        ]


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
        ShimPersonNameRecognizer("PERSON_NAME_TR", person_names),
        ShimPersonNameRecognizer("PERSON_NAME_EN", english_person_names),
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
