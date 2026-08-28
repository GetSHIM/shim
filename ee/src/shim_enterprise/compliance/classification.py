"""Static classification of privacy-engine findings for compliance reporting."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


Severity = Literal["low", "medium", "high", "critical"]
SEVERITY_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


@dataclass(frozen=True, slots=True)
class Classification:
    severity: Severity
    kvkk_category: str
    gdpr_category: str


_IDENTITY = Classification("critical", "Kimlik", "Identification data")
_FINANCIAL = Classification("critical", "Finansal", "Financial data")
_CONTACT = Classification("medium", "İletişim", "Contact data")
_ONLINE = Classification("low", "İşlem Güvenliği", "Online identifiers")
_SECRET = Classification("high", "Kimlik Doğrulama", "Authentication credentials")
_DEFAULT = Classification("medium", "Kişisel Veri", "Personal data")

_CLASSIFICATIONS: dict[str, Classification] = {
    "TR_NATIONAL_ID": _IDENTITY,
    "TR_TCKN": _IDENTITY,
    "US_SSN": _IDENTITY,
    "TR_VKN": Classification("high", "Kimlik", "Identification data"),
    "CREDIT_CARD": _FINANCIAL,
    "IBAN_CODE": Classification("high", "Finansal", "Financial data"),
    "IBAN_EU": Classification("high", "Finansal", "Financial data"),
    "EMAIL_ADDRESS": _CONTACT,
    "TR_PHONE": _CONTACT,
    "PHONE_NUMBER": _CONTACT,
    "IP_ADDRESS": _ONLINE,
    "MAC_ADDRESS": _ONLINE,
    "SECRET": _SECRET,
    "DB_URI": _SECRET,
    "FILE_PATH": Classification("low", "Diğer", "Other"),
}


def classify(entity_type: str) -> Classification:
    return _CLASSIFICATIONS.get(entity_type, _DEFAULT)


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity, -1)


def meets_threshold(severity: str, min_severity: str) -> bool:
    minimum = severity_rank(min_severity)
    return minimum >= 0 and severity_rank(severity) >= minimum
