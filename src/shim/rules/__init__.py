"""Tenant rules: one rule object, a fixed table of kinds and evaluation points."""

from shim.rules.evaluate import in_scope, match_records
from shim.rules.kinds import KINDS, validate_rule_set
from shim.rules.model import (
    LIMITS,
    Rule,
    RuleAction,
    RuleKind,
    RuleMatch,
    RuleScope,
    RuleSet,
    RuleSetError,
    RuleState,
)

__all__ = [
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
    "in_scope",
    "match_records",
    "validate_rule_set",
]
