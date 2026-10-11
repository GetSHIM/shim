"""Tenant rules: one rule object, a fixed table of kinds and evaluation points."""

from shim.rules.content import count_rule_matches
from shim.rules.evaluate import in_scope, match_records
from shim.rules.kinds import KINDS, load_rule_set, validate_rule_set
from shim.rules.model import (
    ACTION_RANK,
    LIMITS,
    Rule,
    RuleAction,
    RuleKind,
    RuleMatch,
    RuleScope,
    RuleSet,
    RuleSetError,
    RuleState,
    UnusableRule,
)

__all__ = [
    "ACTION_RANK",
    "KINDS",
    "LIMITS",
    "Rule",
    "RuleAction",
    "RuleKind",
    "RuleMatch",
    "RuleScope",
    "RuleSet",
    "RuleSetError",
    "RuleState",
    "UnusableRule",
    "count_rule_matches",
    "in_scope",
    "load_rule_set",
    "match_records",
    "validate_rule_set",
]
