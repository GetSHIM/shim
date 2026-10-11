"""One-way import of a shim-security AIUC rule file into gateway rules."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from shim.privacy.policies import PII_CONFIG_DEFAULTS, effective_entity_actions
from shim.rules import LIMITS, RuleSet, RuleSetError, validate_rule_set
from shim.rules.content import turkish_fold

AIUC_IMPORT_VERSION = 1
NOTES = (
    "shim matches a term as a whole word with its Turkish endings; AIUC matches it "
    "as an escaped literal with Unicode simple case folding.",
    "shim's SECRET type covers more formats than AIUC's four (ghp_, github_pat_, "
    "sk-, AKIA).",
    "warn has no equivalent for a built-in type; built-in types are only raised "
    "from off to monitor.",
    "A masked term reaches the provider as <TERM_…> and is restored in the answer.",
)
_BUILT_IN = {"email": "EMAIL_ADDRESS", "secret": "SECRET"}
_IGNORED = ("offlineAction", "updatedAt", "expiresAt", "expectedRevision")

_Term = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=2, max_length=128)
]


class AiucRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=64)
    category: Literal["secret", "email", "term"]
    action: Literal["monitor", "warn", "mask", "block"]
    terms: list[_Term] = Field(default=[], max_length=100)

    @model_validator(mode="after")
    def terms_for_term_rules(self) -> AiucRule:
        if self.category == "term" and not self.terms:
            raise ValueError("a term rule needs terms")
        return self


class AiucPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[AiucRule] = Field(min_length=1, max_length=32)
    offlineAction: Literal["warn", "block"] | None = None
    schemaVersion: Literal[1] | None = None
    revision: int | None = Field(default=None, ge=0)
    updatedAt: str | None = None
    expiresAt: str | None = None
    expectedRevision: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def unique_ids(self) -> AiucPolicy:
        if len({rule.id for rule in self.rules}) != len(self.rules):
            raise ValueError("rule ids repeat")
        return self


_STRENGTH = {"monitor": 0, "warn": 1, "mask": 2, "block": 3}


def _slug(aiuc_id: str) -> str:
    plain = unicodedata.normalize("NFKD", turkish_fold(aiuc_id))
    plain = plain.encode("ascii", "ignore").decode("ascii").lower()
    return re.sub(r"[^a-z0-9]+", "_", plain).strip("_")[:43]


def _rule_id(aiuc_id: str, produced: set[str]) -> str:
    slug = _slug(aiuc_id) or hashlib.sha256(aiuc_id.encode("utf-8")).hexdigest()[:8]
    rule_id, number = f"aiuc_{slug}", 1
    while rule_id in produced:
        number += 1
        suffix = f"_{number}"
        rule_id = f"aiuc_{slug[: 43 - len(suffix)]}{suffix}"
    produced.add(rule_id)
    return rule_id


def _usable_term(term: str) -> str | None:
    """The term as a rule stores it, or None when the gateway refuses it."""
    try:
        [rule] = validate_rule_set(
            {
                "revision": 1,
                "rules": [
                    {
                        "id": "aiuc",
                        "name": "AIUC",
                        "kind": "term",
                        "action": "monitor",
                        "state": "monitor",
                        "match": {"terms": [term]},
                    }
                ],
            }
        ).rules
    except RuleSetError:
        return None
    return rule.match["terms"][0]


def map_policy(
    policy: AiucPolicy, stored: RuleSet | None, privacy: dict[str, Any]
) -> tuple[list[tuple[str, dict | None, dict]], dict | None, dict[str, Any]]:
    """Rule changes `(rule id, before, after)`, the privacy `after` or None, and the report.

    The report holds ids, positions, reasons and actions, never a term.
    """
    current = {rule.id: rule for rule in stored.rules} if stored is not None else {}
    held = {rule.id for rule in stored.unusable} if stored is not None else set()
    rules_total = len(current) + len(held)
    terms_total = sum(
        len(rule.match["terms"]) for rule in current.values() if rule.kind == "term"
    )
    produced: set[str] = set()
    changes: list[tuple[str, dict | None, dict]] = []
    mapped: list[dict[str, Any]] = []
    not_mapped: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    ignored = [name for name in _IGNORED if name in policy.model_fields_set]
    strongest: dict[str, str] = {}
    for position, aiuc in enumerate(policy.rules):
        if aiuc.category != "term":
            if aiuc.terms:
                ignored.append(f"rules[{position}].terms")
            previous = strongest.get(aiuc.category)
            if previous is None or _STRENGTH[aiuc.action] > _STRENGTH[previous]:
                strongest[aiuc.category] = aiuc.action
            continue
        terms: list[str] = []
        folded: set[str] = set()
        for index, raw in enumerate(aiuc.terms):
            term = _usable_term(raw)
            reason = None
            if term is None:
                reason = (
                    "term_too_short"
                    if len(" ".join(raw.split())) < 3
                    else "term_invalid"
                )
            elif turkish_fold(term) in folded:
                reason = "duplicate_after_fold"
            if reason is not None:
                dropped.append(
                    {"aiuc_rule_id": aiuc.id, "term_index": index, "reason": reason}
                )
                continue
            assert term is not None
            terms.append(term)
            folded.add(turkish_fold(term))
        rule_id = _rule_id(aiuc.id, produced)
        if not terms:
            not_mapped.append({"aiuc_rule_id": aiuc.id, "reason": "no_usable_terms"})
            continue
        existing = current.get(rule_id)
        if rule_id in held or (existing is not None and existing.kind != "term"):
            not_mapped.append(
                {"aiuc_rule_id": aiuc.id, "reason": "id_taken_by_other_kind"}
            )
            continue
        added_rules = 0 if existing is not None else 1
        added_terms = len(terms) - (
            len(existing.match["terms"]) if existing is not None else 0
        )
        if (
            rules_total + added_rules > LIMITS["rules_per_set"]
            or terms_total + added_terms > LIMITS["terms_per_set"]
        ):
            not_mapped.append({"aiuc_rule_id": aiuc.id, "reason": "set_limit_reached"})
            continue
        rules_total += added_rules
        terms_total += added_terms
        before = (
            existing.model_dump(mode="json", exclude={"id"})
            if existing is not None
            else None
        )
        after = {
            **(before or {"kind": "term", "scope": {}}),
            "name": f"AIUC {aiuc.id}"[:100],
            "action": aiuc.action,
            "state": "monitor",
            "match": {"terms": terms, "label": "TERM", "suffixes": "tr"},
        }
        [rule] = validate_rule_set(
            {"revision": 1, "rules": [{"id": rule_id, **after}]}
        ).rules
        after = rule.model_dump(mode="json", exclude={"id"})
        change = (
            "create" if before is None else "unchanged" if before == after else "update"
        )
        mapped.append({"aiuc_rule_id": aiuc.id, "rule_id": rule_id, "change": change})
        if change != "unchanged":
            changes.append((rule_id, before, after))
    effective = effective_entity_actions(
        {field: privacy[field] for field in PII_CONFIG_DEFAULTS},
        privacy["entity_actions"],
    )
    built_in = []
    overrides = dict(privacy["entity_actions"])
    for category, action in sorted(strongest.items()):
        entity_type = _BUILT_IN[category]
        raise_it = effective[entity_type] == "off"
        if raise_it:
            overrides[entity_type] = "monitor"
        built_in.append(
            {
                "category": category,
                "entity_type": entity_type,
                "current_action": effective[entity_type],
                "aiuc_action": action,
                "change": "set_monitor" if raise_it else "none",
            }
        )
    privacy_after = (
        {**privacy, "entity_actions": overrides}
        if overrides != privacy["entity_actions"]
        else None
    )
    report = {
        "format": "aiuc",
        "import_version": AIUC_IMPORT_VERSION,
        "schema_version": policy.schemaVersion,
        "source_revision": policy.revision,
        "mapped": mapped,
        "not_mapped": not_mapped,
        "dropped_terms": dropped,
        "built_in_types": built_in,
        "ignored_fields": ignored,
        "notes": list(NOTES),
    }
    return changes, privacy_after, report
