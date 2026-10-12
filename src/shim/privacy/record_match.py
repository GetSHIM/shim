"""Customer records and confidential documents as keyed hashes, and text matched against them.

The gateway and the customer-side hashing tool both use this module, so both compute the
same bytes. Only hashes reach shim: a record's fields, normalized and hashed with the set's
key, and a document's winnowed word-shingle fingerprints. Stdlib only, as the community
package may not import `cryptography`.
"""

from __future__ import annotations

from array import array
from bisect import bisect_left, bisect_right
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from hashlib import blake2b
import math
import re
from time import perf_counter
from typing import Literal
import unicodedata

FieldKind = Literal["tckn", "vkn", "iban", "email", "phone", "digits", "token", "name"]
FIELD_KINDS: tuple[FieldKind, ...] = (
    "tckn",
    "vkn",
    "iban",
    "email",
    "phone",
    "digits",
    "token",
    "name",
)
# Shapes the gateway can find in text: the kinds a primary field may have.
PRIMARY_KINDS = frozenset(FIELD_KINDS) - {"name"}
KEY_BYTES = 32
# k = 8 words per shingle, winnowing window w = 4.
FINGERPRINT_VERSION = 1
_SHINGLE_WORDS = 8
_WINDOW = 4
MIN_DOCUMENT_WORDS = 40
# Characters on each side of a primary hit where a record's other fields count.
FIELD_WINDOW = 300
MAX_CANDIDATES = 2_000

_SHAPES: dict[FieldKind, re.Pattern[str]] = {
    # A space or hyphen may group the digits. Every start is tried (the value is
    # group 1 of a lookahead), so a run that borrows the first digits hides nothing.
    "tckn": re.compile(r"(?<!\d)(?=(\d(?:[ -]?\d){10})(?!\d))"),
    "vkn": re.compile(r"(?<!\d)(?=(\d(?:[ -]?\d){9})(?!\d))"),
    "iban": re.compile(r"(?<![A-Za-z0-9])TR\d{2}(?: ?\d{4}){5} ?\d{2}(?!\d)", re.I),
    # Starting only where a run starts keeps a long run without "@" linear.
    "email": re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[\w-]+(?:\.[\w-]+)+"),
    "phone": re.compile(r"(?<![\d+(])(?:\+?\(?\d[\d ().-]{8,16}\d)(?!\d)"),
    "digits": re.compile(r"(?<!\d)\d{4,34}(?!\d)"),
    "token": re.compile(
        r"(?<![A-Za-z0-9_-])[A-Za-z0-9][A-Za-z0-9_-]{5,63}(?![A-Za-z0-9_-])"
    ),
}
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{5,63}")
_LETTERS = re.compile(r"[^\W\d_]+")
# Between the words of one name: spaces, and at most one dash or apostrophe.
_NAME_GAP = re.compile(r"\s*[-'’‐‑‒–—]?\s*")
_NOT_WORD = re.compile(r"[^\w]+|_+")


def _fold(text: str) -> str:
    """NFKC, the Turkish I letters as one `i`, then lower case."""

    text = unicodedata.normalize("NFKC", text)
    return text.replace("İ", "i").replace("I", "i").replace("ı", "i").lower()


def normalize(
    kind: FieldKind, value: str, length: tuple[int, int] | None = None
) -> str | None:
    """The field's normal form, or None when the value is not of the kind."""

    text = unicodedata.normalize("NFKC", value).strip()
    if kind in {"tckn", "vkn", "digits", "phone", "iban"} and not text.isascii():
        # Any script's digits are the number a model reads: Arabic-Indic too.
        text = "".join(
            str(unicodedata.decimal(char)) if char.isdecimal() else char
            for char in text
        )
    if kind in {"tckn", "vkn", "digits"}:
        digits = re.sub(r"[\s-]", "", text)
        size = {"tckn": (11, 11), "vkn": (10, 10)}.get(kind) or length or (4, 34)
        ok = digits.isascii() and digits.isdigit() and size[0] <= len(digits) <= size[1]
        return digits if ok else None
    if kind == "iban":
        iban = re.sub(r"\s", "", text).upper()
        return iban if re.fullmatch(r"TR\d{24}", iban) else None
    if kind == "email":
        email = text.lower()
        return email if re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) else None
    if kind == "phone":
        digits = re.sub(r"\D", "", text)
        return digits[-10:] if len(digits) >= 10 else None
    if kind == "token":
        return text.upper() if _TOKEN.fullmatch(text) else None
    # Letter words only, so "Ayşe-Nur" and "Ayşe Nur" are one name; text never puts
    # a digit in a name, so a value with one is not a name.
    words = _LETTERS.findall(_fold(text))
    return (
        " ".join(words)
        if 1 <= len(words) <= 3 and not any(map(str.isdigit, text))
        else None
    )


def record_hash(key: bytes, kind: str, normalized: str) -> int:
    digest = blake2b(f"{kind}\x1f{normalized}".encode(), key=key, digest_size=8)
    return int.from_bytes(digest.digest(), "big")


def _words(text: str) -> list[str]:
    return _NOT_WORD.sub(" ", _fold(text)).split()


def fingerprints(key: bytes, text: str) -> set[int]:
    """Winnowed 8-word shingles: the minimum of every window of 4, rightmost on ties."""

    return _fingerprints(key, _words(text))


def _fingerprints(key: bytes, words: list[str]) -> set[int]:
    shingles = [
        record_hash(key, "shingle", " ".join(words[start : start + _SHINGLE_WORDS]))
        for start in range(len(words) - _SHINGLE_WORDS + 1)
    ]
    chosen: set[int] = set()
    for start in range(max(1, len(shingles) - _WINDOW + 1) if shingles else 0):
        window = shingles[start : start + _WINDOW]
        lowest = min(window)
        # Rightmost on ties, so a repeated shingle picks one position.
        chosen.add(window[len(window) - 1 - window[::-1].index(lowest)])
    return chosen


@dataclass(frozen=True, slots=True)
class RecordField:
    kind: FieldKind
    primary: bool = False
    length: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True)
class RecordSetIndex:
    """One set's hashes as packed sorted arrays: no Python object per record."""

    key: bytes
    kind: Literal["records", "fingerprints"]
    fields: tuple[RecordField, ...] = ()
    # The placeholder type of an enforced mask.
    label: str = "RECORD"
    # Records: every primary field's hash, sorted, and the record each belongs to.
    primary: array = field(default_factory=lambda: array("Q"))
    primary_records: array = field(default_factory=lambda: array("I"))
    # Records: `records x len(fields)` hashes in record order, 0 for an empty field.
    values: array = field(default_factory=lambda: array("Q"))
    # Fingerprints: sorted, and the document each belongs to.
    prints: array = field(default_factory=lambda: array("Q"))
    print_documents: array = field(default_factory=lambda: array("H"))

    @classmethod
    def records(
        cls,
        key: bytes,
        fields: Sequence[RecordField],
        values: array,
        label: str = "RECORD",
    ) -> RecordSetIndex:
        """`values`: every record's field hashes in field order, one after another."""
        width = len(fields)
        pairs = sorted(
            (values[record * width + index], record)
            for record in range(len(values) // width)
            for index, spec in enumerate(fields)
            if spec.primary and values[record * width + index]
        )
        return cls(
            key,
            "records",
            tuple(fields),
            label,
            primary=array("Q", (hash_ for hash_, _ in pairs)),
            primary_records=array("I", (record for _, record in pairs)),
            values=values,
        )

    @classmethod
    def documents(
        cls, key: bytes, documents: Iterable[Iterable[int]]
    ) -> RecordSetIndex:
        pairs = sorted(
            (print_, number)
            for number, prints in enumerate(documents)
            for print_ in set(prints)
        )
        return cls(
            key,
            "fingerprints",
            prints=array("Q", (print_ for print_, _ in pairs)),
            print_documents=array("H", (number for _, number in pairs)),
        )

    @property
    def size(self) -> int:
        """Bytes held, for the per-process cap."""
        return sum(
            len(values) * values.itemsize
            for values in (
                self.primary,
                self.primary_records,
                self.values,
                self.prints,
                self.print_documents,
            )
        )

    def _hashes(self, kind: FieldKind, spec: RecordField, text: str, offset: int):
        """(hash, start, end) of every value of the field's shape in `text`."""
        if kind == "name":
            words = list(_LETTERS.finditer(text))
            for first in range(len(words)):
                for last in range(first, min(first + 3, len(words))):
                    if last > first and not _NAME_GAP.fullmatch(
                        text, words[last - 1].end(), words[last].start()
                    ):
                        break
                    start, end = words[first].start(), words[last].end()
                    normalized = normalize("name", text[start:end])
                    if normalized:
                        yield (
                            record_hash(self.key, kind, normalized),
                            offset + start,
                            offset + end,
                        )
            return
        for found in _SHAPES[kind].finditer(text):
            # The value is the last group: the whole match, or a lookahead's group 1.
            group = found.re.groups
            normalized = normalize(kind, found.group(group), spec.length)
            if normalized:
                yield (
                    record_hash(self.key, kind, normalized),
                    offset + found.start(group),
                    offset + found.end(group),
                )

    def match_records(
        self, text: str, min_fields: int, deadline: float = math.inf
    ) -> tuple[set[int], list[tuple[int, int]], bool]:
        """Matched records, the spans of their found fields, and whether candidates ran out.

        Raises TimeoutError once `perf_counter()` passes `deadline`.
        """
        width = len(self.fields)
        candidates: list[tuple[int, int, int, int]] = []  # record, field, start, end
        truncated = False
        primary_kinds = {(f.kind, f.length): f for f in self.fields if f.primary}
        for spec in primary_kinds.values():
            for hash_, start, end in self._hashes(spec.kind, spec, text, 0):
                _check(deadline)
                low, high = (
                    bisect_left(self.primary, hash_),
                    bisect_right(self.primary, hash_),
                )
                for position in range(low, high):
                    record = self.primary_records[position]
                    index = next(
                        index
                        for index in range(width)
                        if self.fields[index].primary
                        and self.values[record * width + index] == hash_
                    )
                    candidates.append((record, index, start, end))
                if len(candidates) >= MAX_CANDIDATES:
                    truncated = True
                    break
            if truncated:
                candidates = candidates[:MAX_CANDIDATES]
                break
        matched: set[int] = set()
        spans: list[tuple[int, int]] = []
        windows: dict[tuple[int, int], dict[int, list[tuple[int, int]]]] = {}
        specs = {(f.kind, f.length): f for f in self.fields}.values()
        for record, primary_index, start, end in candidates:
            _check(deadline)
            if (start, end) not in windows:
                window_start = max(0, start - FIELD_WINDOW)
                window = text[window_start : end + FIELD_WINDOW]
                found: dict[int, list[tuple[int, int]]] = {}
                for spec in specs:
                    for hash_, field_start, field_end in self._hashes(
                        spec.kind, spec, window, window_start
                    ):
                        found.setdefault(hash_, []).append((field_start, field_end))
                windows[(start, end)] = found
            found = windows[(start, end)]
            hits = [(start, end)]
            for index in range(width):
                value = self.values[record * width + index]
                if index != primary_index and value and value in found:
                    hits.append(found[value][0])
            if len(hits) >= min_fields:
                matched.add(record)
                spans.extend(hits)
        return matched, spans, truncated

    def match_documents(
        self, text: str, min_shared: int, deadline: float = math.inf
    ) -> set[int]:
        words = _words(text)
        if len(words) < MIN_DOCUMENT_WORDS:
            return set()
        shared: Counter[int] = Counter()
        for print_ in _fingerprints(self.key, words):
            _check(deadline)
            low, high = (
                bisect_left(self.prints, print_),
                bisect_right(self.prints, print_),
            )
            shared.update(self.print_documents[low:high])
        return {document for document, count in shared.items() if count >= min_shared}


def _check(deadline: float) -> None:
    if perf_counter() > deadline:
        raise TimeoutError
