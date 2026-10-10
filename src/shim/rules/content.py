"""Term and pattern rules: their match models, compiled matchers, and the match counter."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Annotated, Any, Literal
import unicodedata
import weakref

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError
import regex

from shim.observability.metrics import LABEL_VALUES
from shim.rules.evaluate import strongest
from shim.rules.model import Rule, RuleSet
from shim.rules.patterns import PatternTimeout, SearchBudget, compile_safe
from shim.rules.tr_suffixes import TR_SUFFIXES

_WORD = r"[\p{L}\p{N}_]"
_START = rf"(?<!{_WORD})"
_END = rf"(?!{_WORD})"
_END_AT = regex.compile(_END)
# U+02BC is a letter, so the boundary alone would refuse "Atlasʼa".
_APOSTROPHE_LETTER = "ʼ"
_TURKISH_I = "İIıi"
_FOLD = str.maketrans({"İ": "i", "I": "i", "ı": "i"})
_LABEL = r"^[A-Z][A-Z0-9]{1,15}(?:_[A-Z0-9]{1,15})?$"
_MIN_SUFFIXED_TERM = 4


def turkish_fold(text: str) -> str:
    """İ, I and ı to i, then lower case, then whitespace runs to one space."""

    return " ".join(text.translate(_FOLD).lower().split())


def _letter(character: str) -> str:
    return f"[{_TURKISH_I}]" if character in _TURKISH_I else regex.escape(character)


def _term_regex(term: str) -> str:
    return "".join(
        r"\s+" if character == " " else _letter(character) for character in term
    )


_AFTER_SUFFIX = f"(?={_APOSTROPHE_LETTER}|(?&suffix)?{_END})"
_AFTER_APOSTROPHE = f"(?={_APOSTROPHE_LETTER}|{_END})"


def _term_trie(terms: dict[str, str]) -> str:
    """Folded terms as a prefix tree, each ending in its lookahead.

    One branch per shared prefix keeps 200 terms near one comparison per character;
    where a term ends inside a longer one, the longer is tried first.
    """

    root: dict[str, Any] = {}
    for term, after in terms.items():
        node = root
        for character in term:
            node = node.setdefault(character, {})
        node[""] = after

    def emit(node: dict[str, Any]) -> str:
        branches = [
            _term_regex(character) + emit(child)
            for character, child in node.items()
            if character
        ]
        if "" in node:
            branches.append(node[""])
        return branches[0] if len(branches) == 1 else f"(?:{'|'.join(branches)})"

    return emit(root)


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
    return term


def _template(value: str) -> str:
    _template_regex(value)
    return value


def _safe(value: str) -> str:
    if compile_safe(value) is None:
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
    ignore_case: bool = True

    @model_validator(mode="after")
    def something_to_match(self) -> PatternMatch:
        if not self.templates and not self.regexes:
            raise ValueError("a pattern rule needs a template or a regex")
        return self


@dataclass(frozen=True, slots=True)
class _Compiled:
    terms: Any | None
    # Turkish-folded term to the rules that list it.
    owners: dict[str, tuple[Rule, ...]]
    patterns: dict[str, tuple[Any, ...]]


_COMPILED: dict[int, _Compiled] = {}


def _compile(rule_set: RuleSet) -> _Compiled:
    owners: dict[str, list[Rule]] = {}
    suffixed: set[str] = set()
    patterns: dict[str, tuple[Any, ...]] = {}
    for rule in rule_set.rules:
        if rule.kind == "term":
            for term in rule.match["terms"]:
                folded = turkish_fold(term)
                owners.setdefault(folded, []).append(rule)
                if rule.match.get("suffixes", "tr") == "tr":
                    suffixed.add(folded)
        elif rule.kind == "pattern":
            flags = regex.IGNORECASE if rule.match.get("ignore_case", True) else 0
            templates = rule.match.get("templates", [])
            patterns[rule.id] = tuple(
                regex.compile(source, flags)
                for source in (
                    ["|".join(_template_regex(t) for t in templates)]
                    if templates
                    else []
                )
                + list(rule.match.get("regexes", []))
            )
    terms = None
    if owners:
        suffix = "|".join(
            _term_regex(item) for item in sorted(TR_SUFFIXES, key=len, reverse=True)
        )
        # A term two rules list with different suffix modes takes the wider
        # lookahead; the search drops an owner its mode refuses.
        trie = _term_trie(
            {
                term: _END
                if term not in suffixed
                else _AFTER_SUFFIX
                if len(term) >= _MIN_SUFFIXED_TERM
                else _AFTER_APOSTROPHE
                for term in owners
            }
        )
        terms = regex.compile(
            f"(?(DEFINE)(?<suffix>{suffix})){_START}{trie}", regex.IGNORECASE
        )
    return _Compiled(
        terms, {key: tuple(value) for key, value in owners.items()}, patterns
    )


def _compiled(rule_set: RuleSet) -> _Compiled:
    """Compiled once per RuleSet object; the entry goes when the object does."""

    key = id(rule_set)
    found = _COMPILED.get(key)
    if found is None:
        found = _COMPILED[key] = _compile(rule_set)
        weakref.finalize(rule_set, _COMPILED.pop, key, None)
    return found


@dataclass(frozen=True, slots=True)
class ContentHit:
    start: int
    end: int
    rules: tuple[Rule, ...]


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

    def record(self, hit: ContentHit, value: str) -> str | None:
        """Count the value for every rule of the hit; the label to mask it with, or None.

        Only an enforced rule acts, the strongest action wins, and block or
        require_approval keep the text for the decision point to refuse or hold.
        """

        for rule in hit.rules:
            self.values.setdefault(rule.id, set()).add(value)
        enforced = [rule for rule in hit.rules if rule.state == "enforced"]
        if strongest(rule.action for rule in enforced) != "mask":
            return None
        return min(
            (rule for rule in enforced if rule.action == "mask"), key=lambda r: r.id
        ).match["label"]

    def search(self, text: str) -> list[ContentHit]:
        compiled = _compiled(self.rule_set)
        ids = {rule.id for rule in self.rules}
        hits: list[ContentHit] = []
        terms = [rule for rule in self.rules if rule.kind == "term"]
        if terms and compiled.terms is not None:
            try:
                found = self.budget.finditer(compiled.terms, text)
            except PatternTimeout:
                self.errors.update(rule.id for rule in terms)
                found = []
            for match in found:
                end_follows = _END_AT.match(text, match.end()) is not None
                owners = tuple(
                    rule
                    for rule in compiled.owners.get(turkish_fold(match.group()), ())
                    if rule.id in ids
                    and (end_follows or rule.match.get("suffixes", "tr") == "tr")
                )
                if owners:
                    hits.append(ContentHit(match.start(), match.end(), owners))
        for rule in self.rules:
            for pattern in compiled.patterns.get(rule.id, ()):
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
        return hits


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


def resolve_overlaps(hits: list[ContentHit]) -> list[ContentHit]:
    """Identical spans merge their rules; otherwise the longer span wins, then the earlier."""

    merged: dict[tuple[int, int], dict[str, Rule]] = {}
    for hit in hits:
        merged.setdefault((hit.start, hit.end), {}).update(
            (rule.id, rule) for rule in hit.rules
        )
    accepted: list[ContentHit] = []
    # ponytail: O(n²) over one string's hits; an interval index if hit counts grow.
    for (start, end), rules in sorted(
        merged.items(), key=lambda item: (item[0][0] - item[0][1], item[0][0])
    ):
        if not any(start < kept.end and kept.start < end for kept in accepted):
            accepted.append(ContentHit(start, end, tuple(rules.values())))
    return sorted(accepted, key=lambda hit: hit.start)


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
    values: dict[str, set[str]] = {rule.id: set() for rule in found.rules}
    for hit in found.search(prepared):
        for rule in hit.rules:
            values[rule.id].add(prepared[hit.start : hit.end])
    return {
        rule_id: -1 if rule_id in found.errors else len(matched)
        for rule_id, matched in values.items()
    }
