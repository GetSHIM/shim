"""Term and pattern rules: their match models, compiled matchers, and the match counter."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal
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
from shim.rules.tr_suffixes import TR_SUFFIXES


_WORD = r"[\p{L}\p{N}_]"
_START = rf"(?<!{_WORD})"
_END = rf"(?!{_WORD})"
# A run of word characters: what a term's words are matched against.
_RUN = re.compile(r"\w+")
_SPACES = re.compile(r"\s+")
# U+02BC is a letter, so a run can carry it: "Atlasʼa".
_APOSTROPHE_LETTER = "ʼ"
_TURKISH_I = "İIıi"
_LABEL = r"^[A-Z][A-Z0-9]{1,15}(?:_[A-Z0-9]{1,15})?$"
_MIN_SUFFIXED_TERM = 4


def _fold(text: str) -> str:
    """The case fold terms are compared in; one character for one, so offsets hold."""

    # str.replace runs in C; a translate table walks a dict per character.
    return text.replace("İ", "i").lower().replace("ı", "i")


def turkish_fold(text: str) -> str:
    """İ, I and ı to i, then lower case, then whitespace runs to one space."""

    return " ".join(_fold(text).split())


_SUFFIXES = frozenset(_fold(suffix) for suffix in TR_SUFFIXES)


def _letter(character: str) -> str:
    return f"[{_TURKISH_I}]" if character in _TURKISH_I else regex.escape(character)


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

    next: dict[tuple[str, str], _Node] = field(default_factory=dict)
    ends: dict[str, list[_Term]] = field(default_factory=dict)
    lengths: tuple[int, ...] = ()


def _word_at(text: str, index: int) -> bool:
    return 0 <= index < len(text) and (text[index].isalnum() or text[index] == "_")


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
                node = node.next.setdefault((run.group(), separator), _Node())
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
            nodes.extend(node.next.values())
        self.keys = frozenset(
            word[:3]
            for word in (*self.root.ends, *(word for word, _ in self.root.next))
        )

    def terms(self, text: str, ids: set[str]) -> list[ContentHit]:
        """Every term of the rules `ids` in `text`, overlaps included."""

        folded = _fold(text)
        found: list[ContentHit] = []
        for run in _RUN.finditer(folded):
            start, end = run.span()
            if folded[start : min(start + 3, end)] in self.keys:
                found += self._walk(folded, start, end, ids)
        return found

    # ponytail: each word run re-walks up to the longest term's word count (64 at most),
    # so terms of many repeated words cost that factor; Aho-Corasick over words if seen.
    def _walk(
        self, folded: str, start: int, end: int, ids: set[str]
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
                    hit = _accept(folded, term, start, word_start + length, end, ids)
                    if hit is not None:
                        found.append(hit)
            following = _RUN.search(folded, end) if node.next else None
            if following is None:
                break
            separator = _SPACES.sub(" ", folded[end : following.start()])
            node = node.next.get((word, separator))
            word_start, end = following.span()
        return found


def _accept(
    folded: str, term: _Term, start: int, end: int, run_end: int, ids: set[str]
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
    owners = tuple(
        rule
        for rule in term.owners
        if rule.id in ids
        and (
            not rest
            or rule.match["suffixes"] == "tr"
            and (rest[0] == _APOSTROPHE_LETTER or not term.short and rest in _SUFFIXES)
        )
    )
    return ContentHit(start, end, owners) if owners else None


@dataclass(slots=True)
class ContentRules:
    """One request's term and pattern rules in scope, and what they found."""

    rule_set: RuleSet
    rules: tuple[Rule, ...]
    budget: SearchBudget = field(default_factory=SearchBudget)
    # Distinct matched values per rule id; held for counting only.
    values: dict[str, set[str]] = field(default_factory=dict)
    errors: set[str] = field(default_factory=set)

    @property
    def protects(self) -> bool:
        return any(
            rule.state == "enforced"
            and rule.action in {"mask", "block", "require_approval"}
            for rule in self.rules
        )

    def count(self, hit: ContentHit, value: str) -> None:
        for rule in hit.rules:
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


def content_rules(rule_set: RuleSet | None, in_scope) -> ContentRules | None:
    """The request's term and pattern rules for which `in_scope(rule)` holds, or None."""

    if rule_set is None:
        return None
    rules = tuple(
        rule
        for rule in rule_set.rules
        if rule.kind in {"term", "pattern"} and in_scope(rule)
    )
    return ContentRules(rule_set, rules) if rules else None


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

    found = content_rules(rule_set, lambda _rule: True)
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
