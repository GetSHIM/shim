"""Term and pattern rules: their match models, compiled matchers, and the match counter."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from time import perf_counter
from typing import TYPE_CHECKING, Annotated, Any, Literal
import re
import unicodedata

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError
import regex

from shim.observability.metrics import LABEL_VALUES
from shim.rules.model import ACTION_RANK, Rule, RuleSet
from shim.rules.patterns import PatternTimeout, SearchBudget, compile_safe
from shim.rules.tr_suffixes import TR_SUFFIX

if TYPE_CHECKING:
    from shim.privacy.record_match import RecordSetIndex


_WORD = r"[\p{L}\p{N}_]"
_START = rf"(?<!{_WORD})"
_END = rf"(?!{_WORD})"
# A run of letters or of digits: what a term's words are matched against. An
# underscore, a letter next to a digit and a lower-case letter before an upper-case
# one are word edges too: "atlas_rapor", "Atlas2024", "AtlasProje".
_RUN = re.compile(r"[^\W\d_]+|\d+")
_OTHER_DIGIT = re.compile(r"[^\D0-9]")
_CAMEL = regex.compile(r"\p{Ll}\p{Lu}")
_SPACES = re.compile(r"\s+")
_DASH = "-"
# Hyphen, non-breaking hyphen, figure, en and em dash, horizontal bar, minus sign.
_DASHES = "\u2010\u2011\u2012\u2013\u2014\u2015\u2212"
# Turkish letters typed without their marks, and every dash as a hyphen.
_ASCII = (
    ("ı", "i"),
    ("ş", "s"),
    ("ç", "c"),
    ("ğ", "g"),
    ("ö", "o"),
    ("ü", "u"),
) + tuple((dash, _DASH) for dash in _DASHES)
# U+02BC is a letter, so a run can carry it: "Atlasʼa".
_APOSTROPHE_LETTER = "ʼ"
_TURKISH_I = "İIıi"
_LABEL = r"^[A-Z][A-Z0-9]{1,15}(?:_[A-Z0-9]{1,15})?$"
_MIN_SUFFIXED_TERM = 4


def fold_digits(text: str) -> str:
    """Every script's decimal digits as 0-9 (Arabic-Indic, Devanagari, ...), one
    character for one: the number a model reads."""

    return _OTHER_DIGIT.sub(lambda digit: str(unicodedata.decimal(digit[0])), text)


def _fold(text: str) -> str:
    """The fold terms are compared in; one character for one, so offsets hold.

    Lower case with the four Turkish I letters as one, ş ç ğ ö ü as s c g o u,
    every dash as a hyphen and every digit as 0-9: "ŞİŞLİ", "Sisli" and "sişli"
    are one word.
    """

    # str.replace runs in C; a translate table walks a dict per character.
    folded = fold_digits(text).replace("İ", "i").lower()
    for letter, plain in _ASCII:
        folded = folded.replace(letter, plain)
    return folded


def turkish_fold(text: str) -> str:
    """The fold, then whitespace runs to one space."""

    return " ".join(_fold(text).split())


def _letter(character: str) -> str:
    if character in _TURKISH_I:
        return f"[{_TURKISH_I}]"
    return f"[-{_DASHES}]" if character == _DASH else regex.escape(character)


def _template_regex(template: str) -> str:
    parts: list[str] = []
    literal = False
    for character in template:
        if literal:
            parts.append(_letter(character))
            literal = False
        elif character == "\\":
            literal = True
        elif character == "#":
            parts.append("[0-9]")
        elif character == "@":
            parts.append(r"\p{L}")
        else:
            parts.append(_letter(character))
    if literal:
        raise ValueError("a template cannot end with a lone backslash")
    return f"{_START}{''.join(parts)}{_END}"


def _not_built_in(label: str) -> str:
    if label in LABEL_VALUES["entity_type"]:
        raise ValueError(f"{label} is a built-in entity type")
    return label


def _term(value: str) -> str:
    term = " ".join(unicodedata.normalize("NFKC", value).split())
    if not 3 <= len(term) <= 128:
        raise ValueError("a term is 3 to 128 characters after trimming")
    if not _RUN.search(term):
        raise ValueError("a term needs a letter or a digit")
    return term


def _template(value: str) -> str:
    _template_regex(value)
    return value


def _safe(value: str, info: ValidationInfo) -> str:
    flags = regex.IGNORECASE if info.data.get("ignore_case", True) else 0
    # A stored set was probed when it was written; a timed probe on load could flake.
    probe = not (info.context or {}).get("stored", False)
    if compile_safe(value, flags, probe=probe) is None:
        raise PydanticCustomError(
            "rule_pattern_unsafe",
            "the regex does not compile, can backtrack, or is too slow",
        )
    return value


_Label = Annotated[str, Field(pattern=_LABEL), AfterValidator(_not_built_in)]


class TermMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    terms: list[Annotated[str, AfterValidator(_term)]] = Field(
        min_length=1, max_length=200
    )
    label: _Label = "TERM"
    suffixes: Literal["tr", "none"] = "tr"

    @field_validator("terms")
    @classmethod
    def distinct_after_fold(cls, terms: list[str]) -> list[str]:
        if len({turkish_fold(term) for term in terms}) != len(terms):
            raise ValueError("terms repeat after the Turkish fold")
        return terms


class PatternMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Before regexes: their safety check runs with the flags they run with.
    ignore_case: bool = True
    templates: list[
        Annotated[
            str,
            StringConstraints(min_length=1, max_length=64),
            AfterValidator(_template),
        ]
    ] = Field(default=[], max_length=32)
    regexes: list[
        Annotated[
            str, StringConstraints(min_length=1, max_length=256), AfterValidator(_safe)
        ]
    ] = Field(default=[], max_length=32)
    label: _Label = "PATTERN"

    @model_validator(mode="after")
    def something_to_match(self) -> PatternMatch:
        if not self.templates and not self.regexes:
            raise ValueError("a pattern rule needs a template or a regex")
        return self


@dataclass(frozen=True, slots=True)
class ContentHit:
    start: int
    end: int
    rules: tuple[Rule, ...]

    @property
    def strength(self) -> int:
        """The strongest enforced action's rank; a monitor-state rule acts on nothing."""

        return max(
            (
                ACTION_RANK[rule.action]
                for rule in self.rules
                if rule.state == "enforced"
            ),
            default=0,
        )

    @property
    def label(self) -> str | None:
        """The placeholder type when any enforced rule masks, even if another holds."""

        masking = [
            rule
            for rule in self.rules
            if rule.state == "enforced" and rule.action == "mask"
        ]
        return (
            min(masking, key=lambda rule: rule.id).match["label"] if masking else None
        )


@dataclass(frozen=True, slots=True)
class _Term:
    lead: str
    trail: str
    short: bool
    owners: tuple[Rule, ...]


@dataclass(slots=True)
class _Node:
    """Terms by their words: the next word and separator, and the words a term ends with."""

    # A word, then the separator after it, to the node for the next word.
    next: dict[str, dict[str, _Node]] = field(default_factory=dict)
    ends: dict[str, list[_Term]] = field(default_factory=dict)
    lengths: tuple[int, ...] = ()


def _word_at(text: str, index: int) -> bool:
    return 0 <= index < len(text) and text[index].isalnum()


class Matchers:
    """One rule set's term index and pattern regexes, built once per RuleSet.

    A text is read once, word run by word run; a run whose first three characters
    start no term costs one set lookup, so the cost follows the text, not the terms.
    """

    def __init__(self, rule_set: RuleSet) -> None:
        owners: dict[str, list[Rule]] = {}
        self.patterns: dict[str, tuple[Any, ...]] = {}
        for rule in rule_set.rules:
            if rule.kind == "term":
                for term in rule.match["terms"]:
                    owners.setdefault(turkish_fold(term), []).append(rule)
            elif rule.kind == "pattern":
                flags = regex.IGNORECASE if rule.match["ignore_case"] else 0
                templates = rule.match["templates"]
                self.patterns[rule.id] = tuple(
                    regex.compile(source, flags)
                    for source in (
                        ["|".join(_template_regex(t) for t in templates)]
                        if templates
                        else []
                    )
                    + rule.match["regexes"]
                )
        self.root = _Node()
        for term, rules in owners.items():
            runs = list(_RUN.finditer(term))
            node = self.root
            for run, following in zip(runs, runs[1:]):
                separator = _SPACES.sub(" ", term[run.end() : following.start()])
                node = node.next.setdefault(run.group(), {}).setdefault(
                    separator, _Node()
                )
            node.ends.setdefault(runs[-1].group(), []).append(
                _Term(
                    term[: runs[0].start()],
                    term[runs[-1].end() :],
                    len(term) < _MIN_SUFFIXED_TERM,
                    tuple(rules),
                )
            )
        nodes = [self.root]
        for node in nodes:
            node.lengths = tuple(sorted({len(word) for word in node.ends}))
            nodes.extend(
                child for after in node.next.values() for child in after.values()
            )
        self.keys = frozenset(word[:3] for word in (*self.root.ends, *self.root.next))

    def terms(self, text: str, ids: set[str]) -> list[ContentHit]:
        """Every term of the rules `ids` in `text`, overlaps included."""

        folded = _fold(text)
        found: list[ContentHit] = []
        for run in _RUN.finditer(folded):
            start, end = run.span()
            if folded[start : min(start + 3, end)] in self.keys:
                found += self._walk(text, folded, start, end, ids)
        for edge in _CAMEL.finditer(text):
            run = _RUN.match(folded, edge.start() + 1)
            if run is not None and run.group()[:3] in self.keys:
                found += self._walk(text, folded, run.start(), run.end(), ids)
        return found

    # ponytail: each word run re-walks up to the longest term's word count (64 at most),
    # so terms of many repeated words cost that factor; Aho-Corasick over words if seen.
    def _walk(
        self, text: str, folded: str, start: int, end: int, ids: set[str]
    ) -> list[ContentHit]:
        found: list[ContentHit] = []
        node: _Node | None = self.root
        word_start = start
        while node is not None:
            word = folded[word_start:end]
            for length in node.lengths:
                if length > len(word):
                    break
                for term in node.ends.get(word[:length], ()):
                    hit = _accept(
                        text, folded, term, start, word_start + length, end, ids
                    )
                    if hit is not None:
                        found.append(hit)
            after = node.next.get(word)
            following = _RUN.search(folded, end) if after else None
            if after is None or following is None:
                break
            node = after.get(_SPACES.sub(" ", folded[end : following.start()]))
            word_start, end = following.span()
        return found


def _accept(
    text: str,
    folded: str,
    term: _Term,
    start: int,
    end: int,
    run_end: int,
    ids: set[str],
) -> ContentHit | None:
    """The hit of `term` from `start` to `end` when the text around it allows one."""

    if term.lead:
        start -= len(term.lead)
        if (
            start < 0
            or not folded.startswith(term.lead, start)
            or _word_at(folded, start - 1)
        ):
            return None
    rest = folded[end:run_end]
    if term.trail:
        if rest or not folded.startswith(term.trail, end):
            return None
        end += len(term.trail)
        if _word_at(folded, end):
            return None
    if rest and not rest[0].isalpha():
        # Inside a number: "PRJ-2024-0012" is not "PRJ-2024-001".
        return None
    if camel := _CAMEL.search(text, end - 1, run_end):
        rest = rest[: camel.start() + 1 - end]
    ending = (
        rest
        and (
            rest[0] == _APOSTROPHE_LETTER
            or TR_SUFFIX.fullmatch(rest) is not None
            # A short term takes an ending only written as an acronym: "BKMnin".
            and (
                not term.short
                or text[start:end].isupper()
                and text[end : end + len(rest)].islower()
            )
        )
    )
    owners = tuple(
        rule
        for rule in term.owners
        if rule.id in ids and (not rest or ending and rule.match["suffixes"] == "tr")
    )
    return ContentHit(start, end, owners) if owners else None


@dataclass(slots=True)
class ContentRules:
    """One request's term, pattern and record_set rules in scope, and what they found."""

    rule_set: RuleSet
    rules: tuple[Rule, ...]
    budget: SearchBudget = field(default_factory=SearchBudget)
    # Distinct matched values per rule id (record numbers for a record set); counting only.
    values: dict[str, set[str]] = field(default_factory=dict)
    errors: set[str] = field(default_factory=set)
    truncated: set[str] = field(default_factory=set)
    record_sets: Mapping[str, RecordSetIndex] = field(default_factory=dict)

    @property
    def protects(self) -> bool:
        return any(
            rule.state == "enforced"
            and rule.action in {"mask", "block", "require_approval"}
            for rule in self.rules
        )

    def count(self, hit: ContentHit, value: str) -> None:
        for rule in hit.rules:
            # A record set counts the records it matched, not the spans.
            if rule.kind != "record_set":
                self.values.setdefault(rule.id, set()).add(value)

    def search(self, text: str) -> list[ContentHit]:
        matchers = self.rule_set.matchers
        ids = {rule.id for rule in self.rules if rule.kind == "term"}
        hits = matchers.terms(text, ids) if ids else []
        for rule in self.rules:
            for pattern in matchers.patterns.get(rule.id, ()):
                try:
                    found = self.budget.finditer(pattern, text)
                except PatternTimeout:
                    self.errors.add(rule.id)
                    break
                hits.extend(
                    ContentHit(match.start(), match.end(), (rule,))
                    for match in found
                    if match.end() > match.start()
                )
            if rule.kind == "record_set":
                hits.extend(self._record_set(rule, text))
        # One hit per span, with every rule that found it.
        spans: dict[tuple[int, int], dict[str, Rule]] = {}
        for hit in hits:
            spans.setdefault((hit.start, hit.end), {}).update(
                (rule.id, rule) for rule in hit.rules
            )
        return [
            ContentHit(start, end, tuple(rules.values()))
            for (start, end), rules in spans.items()
        ]

    def _record_set(self, rule: Rule, text: str) -> list[ContentHit]:
        """The spans of the set's matched record fields; matched records are counted."""
        index = self.record_sets.get(str(rule.match["set_id"]))
        if index is None or self.budget.remaining <= 0:
            self.errors.add(rule.id)
            return []
        started = perf_counter()
        deadline = started + self.budget.remaining
        try:
            if index.kind == "records":
                matched, spans, truncated = index.match_records(
                    text, rule.match["min_fields"] or 2, deadline
                )
            else:
                matched, spans, truncated = (
                    index.match_documents(
                        text, rule.match["min_shared"] or 6, deadline
                    ),
                    [],
                    False,
                )
        except TimeoutError:
            self.errors.add(rule.id)
            return []
        finally:
            self.budget.remaining -= perf_counter() - started
        if truncated:
            self.truncated.add(rule.id)
            # Records past the cap were never read, so an enforced mask or block
            # cannot vouch for them: known values repeated as decoys would pass.
            if rule.state == "enforced" and rule.action in {"mask", "block"}:
                self.errors.add(rule.id)
        if matched:
            self.values.setdefault(rule.id, set()).update(map(str, matched))
        # The set's label is the placeholder type of an enforced mask.
        labelled = rule.model_copy(
            update={"match": {**rule.match, "label": index.label}}
        )
        return [ContentHit(start, end, (labelled,)) for start, end in set(spans)]


def content_rules(
    rule_set: RuleSet | None,
    in_scope,
    record_sets: Mapping[str, RecordSetIndex] | None = None,
) -> ContentRules | None:
    """The request's content rules for which `in_scope(rule)` holds, or None."""

    if rule_set is None:
        return None
    rules = tuple(
        rule
        for rule in rule_set.rules
        if rule.kind in {"term", "pattern", "record_set"} and in_scope(rule)
    )
    return (
        ContentRules(rule_set, rules, record_sets=record_sets or {}) if rules else None
    )


def first_fit(
    items: Iterable[Any],
    key: Callable[[Any], Any],
    keep: Callable[[Any], bool] = lambda _item: False,
) -> list[Any]:
    """The spans, in `key` order, that overlap none taken before; `keep` ones always."""

    taken: list[Any] = []
    # ponytail: O(n²) over one string's detections; an interval index if counts grow.
    for item in sorted(items, key=key):
        if keep(item) or not any(
            item.start < other.end and other.start < item.end for other in taken
        ):
            taken.append(item)
    return taken


def count_rule_matches(rule_set: RuleSet, text: str) -> dict[str, int]:
    """Distinct matched values per term and pattern rule, regardless of state, scope or action.

    A rule whose search timed out is -1. Nothing is logged or kept.
    """

    # Here, not at the top: importing shim.rules must not load the detector stack.
    from shim.privacy.pii_scrubber import PIIScrubberService

    # A record set needs its loaded index, which only the gateway has.
    found = content_rules(rule_set, lambda rule: rule.kind != "record_set")
    if found is None:
        return {}
    prepared = PIIScrubberService.preprocess(text)
    hits = found.search(prepared)
    # A rule's own nested terms ("Atlas" in "Atlas Proje") count once, as the longer.
    return {
        rule.id: -1
        if rule.id in found.errors
        else len(
            {
                prepared[hit.start : hit.end]
                for hit in first_fit(
                    (hit for hit in hits if any(o.id == rule.id for o in hit.rules)),
                    key=lambda hit: (hit.start - hit.end, hit.start),
                )
            }
        )
        for rule in found.rules
    }
