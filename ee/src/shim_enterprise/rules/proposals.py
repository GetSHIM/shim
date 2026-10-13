"""Rules an agent derived from the user's own sentence, checked without a model.

A rule is kept only when it is concrete: it catches the examples the user gave,
misses the counter-examples, and stays silent on ordinary office prose. The
sentence and the examples are never stored; the plan holds the rules an
administrator approves, all in monitor.
"""

from __future__ import annotations

from datetime import datetime, timezone
from functools import cache
import hashlib
import hmac
from importlib.resources import files
import logging
import re
import unicodedata
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim.rules import LIMITS, RuleSet, count_rule_matches
from shim.rules.content import turkish_fold
from shim_enterprise.api.enterprise_deps import require
from shim_enterprise.api.v1.management._common import bounded_body
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim_enterprise.observability.enterprise_metrics import RULE_PROPOSALS_TOTAL
from shim_enterprise.policy.api import PlanView, new_plan, plan_source, planned_change
from shim_enterprise.policy.models import PolicyPlan
from shim_enterprise.policy.plans import refuse_file_managed
from shim_enterprise.rules.models import OrganizationRuleSet
from shim_enterprise.rules.preview import checked_set, stored_rules
from shim_enterprise.rules.resource import RULES, rule_state
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim_enterprise.tenants.models import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/management/rules", tags=["rules"])

# Bumped whenever the stoplist, the corpus or the checks change.
PROPOSAL_CHECKS_VERSION = 1
MAX_OPEN_PROPOSALS = 20
_Example = Annotated[str, StringConstraints(min_length=1, max_length=500)]
_INDEX = re.compile(r"^rules\[\d+\]")


class Examples(BaseModel):
    model_config = ConfigDict(extra="forbid")

    match: list[_Example] = Field(default_factory=list, max_length=10)
    no_match: list[_Example] = Field(default_factory=list, max_length=10)


class ProposedRule(BaseModel):
    """S35's rule input without `state`: every proposed rule starts in monitor."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    kind: Literal["term", "pattern", "destination"]
    action: str
    scope: dict[str, Any] = Field(default_factory=dict)
    match: dict[str, Any] = Field(default_factory=dict)
    examples: Examples = Examples()

    def rule(self) -> dict[str, Any]:
        return {**self.model_dump(exclude={"examples"}), "state": "monitor"}


class ProposalInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sentence: str = Field(min_length=1, max_length=1000)
    language: Literal["tr", "en"] | None = None
    rules: list[ProposedRule] = Field(default_factory=list, max_length=20)


class ProposalView(BaseModel):
    status: Literal["proposed"]
    plan: PlanView


def _refused(code: str, message: str, hint: str, **fields: Any) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={"code": code, "message": message, "hint": hint, **fields},
    )


def _invalid(errors: list[dict[str, Any]]) -> HTTPException:
    RULE_PROPOSALS_TOTAL.labels(outcome="invalid").inc()
    return _refused(
        "RULE_PROPOSAL_INVALID",
        "The proposal is not valid.",
        "Fix the listed fields and call again.",
        errors=errors,
    )


def _path(loc: tuple[Any, ...]) -> str:
    path = ""
    for part in loc:
        path += (
            f"[{part}]" if isinstance(part, int) else f".{part}" if path else str(part)
        )
    return path


def _set_error(error: HTTPException, index: int | None = None) -> dict[str, Any]:
    """S35's own code and message, at the request's index of the rule."""
    detail = error.detail if isinstance(error.detail, dict) else {}
    path = str(detail.get("path", "rules"))
    if index is not None:
        path = _INDEX.sub(f"rules[{index}]", path)
    return {"path": path, "code": detail.get("code"), "message": detail.get("message")}


@cache
def _stoplist() -> frozenset[str]:
    text = files("shim_enterprise.rules").joinpath("proposal_stoplist.txt")
    return frozenset(
        turkish_fold(word) for word in text.read_text("utf-8").split() if word
    )


@cache
def _corpus() -> str:
    return (
        files("shim_enterprise.rules")
        .joinpath("proposal_corpus.txt")
        .read_text("utf-8")
    )


def _questions(
    index: int, proposed: ProposedRule, rule_set: RuleSet
) -> list[dict[str, Any]]:
    """Why the rule is not concrete enough, in the order the checks run."""
    if proposed.kind == "destination":
        # Entity types and a scope: concrete by construction.
        return []
    rule_id = proposed.id

    def question(reason: str, **at: int) -> dict[str, Any]:
        return {
            "rule_id": rule_id,
            "reason": reason,
            "term_index": at.get("term_index"),
            "example_index": at.get("example_index"),
        }

    def matches(text: str) -> int:
        # A search that timed out is -1.
        return count_rule_matches(rule_set, text).get(rule_id, 0)

    asked = []
    if not proposed.examples.match:
        asked.append(question("missing_examples"))
    if proposed.kind == "term":
        asked += [
            question("too_generic", term_index=position)
            for position, term in enumerate(proposed.match.get("terms", []))
            if turkish_fold(str(term)).strip() in _stoplist()
        ]
    if matches(_corpus()) != 0:
        asked.append(question("too_broad"))
    asked += [
        question("example_not_matched", example_index=position)
        for position, text in enumerate(proposed.examples.match)
        if matches(text) <= 0
    ]
    asked += [
        question("no_match_example_matched", example_index=position)
        for position, text in enumerate(proposed.examples.no_match)
        if matches(text) != 0
    ]
    return asked


def sentence_digest(sentence: str) -> str:
    """HMAC of the sentence with whitespace collapsed; the sentence itself is never kept."""
    base = (settings.COMPLIANCE_HASH_SALT or settings.SECRET_KEY).encode("utf-8")
    key = hmac.new(base, b"shim-rule-proposal-v1", hashlib.sha256).digest()
    text = " ".join(unicodedata.normalize("NFC", sentence).split())
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).hexdigest()


async def propose_rules(
    request: Request,
    payload: dict[str, Any] = Body(
        description="sentence, language and rules, each with examples: see "
        "ee/docs/COOKBOOK.md, Write rules from a sentence with your agent."
    ),
    user: User = Depends(require("plans.create")),
    session: AsyncSession = Depends(get_db),
) -> ProposalView:
    organization_id = user.organization_id
    assert organization_id is not None
    try:
        proposal = ProposalInput.model_validate(payload)
    except ValidationError as exc:
        raise _invalid(
            [
                {
                    "path": _path(item["loc"]),
                    "code": item["type"],
                    "message": item["msg"],
                }
                for item in exc.errors(include_url=False)
            ]
        ) from None
    errors = []
    sets: list[RuleSet] = []
    # The whole set first: its limits refuse in milliseconds what each rule's
    # regex probes would take seconds to reach.
    if proposal.rules:
        try:
            checked_set(1, [proposed.rule() for proposed in proposal.rules])
        except HTTPException as exc:
            raise _invalid([_set_error(exc)]) from None
    for index, proposed in enumerate(proposal.rules):
        try:
            sets.append(checked_set(1, [proposed.rule()]))
        except HTTPException as exc:
            errors.append(_set_error(exc, index))
    if errors:
        raise _invalid(errors)

    questions = (
        [
            q
            for i, (p, s) in enumerate(zip(proposal.rules, sets))
            for q in _questions(i, p, s)
        ]
        if proposal.rules
        else [
            {
                "rule_id": None,
                "reason": "no_rules",
                "term_index": None,
                "example_index": None,
            }
        ]
    )
    if questions:
        RULE_PROPOSALS_TOTAL.labels(outcome="needs_examples").inc()
        raise _refused(
            "RULE_PROPOSAL_NEEDS_EXAMPLES",
            "The sentence is not concrete enough to write a rule from.",
            "Ask the user for the exact names, codes or a sample sentence the rule "
            "must catch, and one it must not.",
            questions=questions,
        )

    row = await session.get(OrganizationRuleSet, organization_id)
    stored = stored_rules(row)
    stored_dicts = (
        [rule.model_dump(mode="json") for rule in stored.rules] if stored else []
    )
    # A rule this release cannot run keeps its id and its place in the set.
    unusable = {rule.id for rule in stored.unusable} if stored else set()
    taken = {rule["id"] for rule in stored_dicts} | unusable
    existing = [
        {
            "path": f"rules[{index}].id",
            "code": "RULE_ID_EXISTS",
            "message": "A rule with this id is already in the set; change it with a plan.",
        }
        for index, proposed in enumerate(proposal.rules)
        if proposed.id in taken
    ]
    if existing:
        raise _invalid(existing)
    proposed_rules = [proposed.rule() for proposed in proposal.rules]
    if (
        len(stored_dicts) + len(unusable) + len(proposed_rules)
        > LIMITS["rules_per_set"]
    ):
        raise _invalid(
            [
                {
                    "path": "rules",
                    "code": "RULE_SET_INVALID",
                    "message": "A rule set holds at most 100 rules, with the "
                    f"{len(unusable)} this release cannot run.",
                }
            ]
        )
    try:
        checked_set(1, stored_dicts + proposed_rules)
    except HTTPException as exc:
        raise _invalid([_set_error(exc)]) from None

    validated = [
        {"id": rule.id, **rule_state(rule)} for one in sets for rule in one.rules
    ]
    try:
        await refuse_file_managed(session, organization_id, ["rules"], "proposal")
    except HTTPException as exc:
        RULE_PROPOSALS_TOTAL.labels(outcome="file_managed").inc()
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        raise HTTPException(
            status_code=409, detail={**detail, "validated_rules": validated}
        ) from None
    open_plans = int(
        await session.scalar(
            select(func.count()).where(
                PolicyPlan.organization_id == organization_id,
                PolicyPlan.source == "proposal",
                PolicyPlan.status == "draft",
                PolicyPlan.expires_at > datetime.now(timezone.utc),
            )
        )
        or 0
    )
    if open_plans >= MAX_OPEN_PROPOSALS:
        RULE_PROPOSALS_TOTAL.labels(outcome="limited").inc()
        raise HTTPException(
            status_code=409,
            detail={
                "code": "RULE_PROPOSAL_LIMIT",
                "open": open_plans,
                "message": "Too many rule proposals wait for an administrator.",
                "hint": "Apply or let the open proposals expire first.",
            },
        )

    changes = []
    for state in validated:
        rule_id = state["id"]
        # Each rule is previewed within the set it will join: stored and proposed.
        others = stored_dicts + [
            rule for rule in proposed_rules if rule["id"] != rule_id
        ]
        after = {key: value for key, value in state.items() if key != "id"}
        impact = await RULES.impact(
            session, organization_id, rule_id, None, after, 7, others=others
        )
        changes.append(
            await planned_change(
                session, organization_id, "rules", rule_id, None, after, 7, impact
            )
        )
    channel = plan_source(request, user)
    plan = await new_plan(
        session,
        user,
        organization_id,
        changes,
        source="proposal",
        reason="rule proposal",
        context={
            "proposal": {
                "checks_version": PROPOSAL_CHECKS_VERSION,
                "sentence_digest": sentence_digest(proposal.sentence),
                "sentence_chars": len(proposal.sentence),
                "language": proposal.language,
                "channel": channel,
                "rules": {
                    proposed.id: {
                        "match_examples": len(proposed.examples.match),
                        "no_match_examples": len(proposed.examples.no_match),
                    }
                    for proposed in proposal.rules
                },
            }
        },
    )
    kinds: dict[str, int] = {}
    for proposed in proposal.rules:
        kinds[proposed.kind] = kinds.get(proposed.kind, 0) + 1
    await _audit(
        session,
        user,
        "tenant.rule_proposal_created",
        str(plan.id),
        details={
            "plan_id": str(plan.id),
            "rules": len(proposal.rules),
            "kinds": kinds,
            "terms": sum(len(p.match.get("terms", [])) for p in proposal.rules),
            "channel": channel,
        },
    )
    await session.commit()
    RULE_PROPOSALS_TOTAL.labels(outcome="proposed").inc()
    logger.info(
        "Rule proposal created rules=%d channel=%s", len(proposal.rules), channel
    )
    return ProposalView(status="proposed", plan=PlanView.model_validate(plan))


router.add_api_route(
    "/proposals",
    propose_rules,
    methods=["POST"],
    response_model=ProposalView,
    status_code=201,
    route_class_override=bounded_body(256 * 1024, "A rule proposal is at most 256 KB."),
)
