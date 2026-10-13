"""The rule set as a managed policy resource, and the one code path that writes it."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from datetime import datetime, timezone
import logging
from uuid import UUID

from fastapi import HTTPException, Request
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim.gateway.contracts.ids import TenantId
from shim.rules import LIMITS, Rule, RuleScope, RuleSet
from shim.rules.route import owned
from shim_enterprise.cache.redis_index import CacheManager, CacheService
from shim_enterprise.compliance.services.forwarder import ComplianceForwarderService
from shim_enterprise.policy.plans import (
    WRITE_SOURCE,
    Impact,
    Risk,
    Source,
    State,
    version_detail,
)
from shim_enterprise.rules.changes import classify_rule_changes, rule_direction
from shim_enterprise.rules.models import OrganizationRuleSet, RuleDefinition
from shim_enterprise.rules.preview import (
    checked_set,
    definition_digest,
    has_preview,
    preview_rule,
    stored_rules,
)
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim_enterprise.tenants.models import (
    ApiKey,
    ModelDeployment,
    RecordSet,
    Team,
    User,
)
from shim_enterprise.tenants.permissions import Permission

logger = logging.getLogger(__name__)

_APPLY_WILL_REFUSE = (
    "apply will refuse: new rules start in monitor (RULE_MUST_START_IN_MONITOR)"
)


def _refused(code: str, path: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=422, detail={"code": code, "path": path, "message": message}
    )


def _rule_audit(rule: Rule, before: Rule | None) -> dict[str, object]:
    # Ids, kinds and counts only: never a term, a pattern, a name or a match hash.
    return {
        "id": rule.id,
        "kind": rule.kind,
        "action": rule.action,
        "state": rule.state,
        "scope": [
            field for field in RuleScope.model_fields if getattr(rule.scope, field)
        ],
        "match_changed": before is not None and before.match != rule.match,
        "counts": {
            key: len(value)
            for key, value in rule.match.items()
            if isinstance(value, list)
        },
    }


def rule_state(rule: Rule) -> State:
    return rule.model_dump(mode="json", exclude={"id"})


def _rule(item_id: str, state: State | None) -> Rule | None:
    return None if state is None else Rule.model_validate({"id": item_id, **state})


async def rule_set_row(
    session: AsyncSession, organization_id: UUID
) -> OrganizationRuleSet:
    """The tenant's row, created when missing, locked for this transaction."""
    # The locked re-read below must see what this transaction already changed.
    await session.flush()
    await session.execute(
        insert(OrganizationRuleSet)
        .values(organization_id=organization_id)
        .on_conflict_do_nothing()
    )
    row = await session.get(
        OrganizationRuleSet,
        organization_id,
        with_for_update=True,
        populate_existing=True,
    )
    assert row is not None
    return row


async def _record_definitions(
    session: AsyncSession,
    row: OrganizationRuleSet,
    stored: dict[str, Rule],
    after: RuleSet,
    kept: Collection[str],
) -> None:
    now = datetime.now(timezone.utc)
    known = {
        definition.rule_id: definition
        for definition in await session.scalars(
            select(RuleDefinition).where(
                RuleDefinition.organization_id == row.organization_id
            )
        )
    }
    for rule in after.rules:
        digest = definition_digest(rule)
        definition = known.pop(rule.id, None)
        if definition is None:
            # A rule written before definitions were recorded changed no later
            # than the set did.
            unchanged = (
                rule.id in stored and definition_digest(stored[rule.id]) == digest
            )
            session.add(
                RuleDefinition(
                    organization_id=row.organization_id,
                    rule_id=rule.id,
                    definition_digest=digest,
                    defined_at=row.updated_at if unchanged else now,
                )
            )
        elif definition.definition_digest != digest:
            definition.definition_digest = digest
            definition.defined_at = now
    removed = [rule_id for rule_id in known if rule_id not in kept]
    if removed:
        await session.execute(
            delete(RuleDefinition).where(
                RuleDefinition.organization_id == row.organization_id,
                RuleDefinition.rule_id.in_(removed),
            )
        )


def _check_record_set_rule(
    rule: Rule, index: int, record_sets: Mapping[str, tuple[str, int, int]]
) -> None:
    """The set exists here, is active, and is of the kind the match and action imply."""

    found = record_sets.get(str(rule.match["set_id"]))
    kind = found[0] if found is not None else None
    if found is None or found[1] < 1:
        problem = (
            "names a record set this organization does not have, or one not activated"
        )
    elif (rule.match["min_fields"] is not None and kind != "records") or (
        rule.match["min_shared"] is not None and kind != "fingerprints"
    ):
        problem = "min_fields is for a records set, min_shared for a fingerprints set"
    elif (rule.match["min_fields"] or 0) > found[2]:
        problem = "min_fields is more than the fields the set has"
    else:
        problem = None
    if problem is not None:
        raise _refused("RULE_MATCH_INVALID", f"rules[{index}].match.set_id", problem)
    # Masking a pasted fragment would change the request beyond what the user wrote.
    if kind == "fingerprints" and rule.action == "mask":
        raise _refused(
            "RULE_ACTION_UNAVAILABLE",
            f"rules[{index}].action",
            "a fingerprints set cannot mask; use monitor, warn or block",
        )


def _check_route_rule(rule: Rule, index: int, providers: Mapping[str, str]) -> None:
    """`to` is a registered alias of the provider of every registered `from` alias."""

    provider = providers.get(rule.match["to"])
    if provider is None:
        problem = "to names a model alias this organization has not registered"
    elif any(
        providers.get(model, provider) != provider for model in rule.match["from"]
    ):
        problem = "to is an alias of another provider than a from alias"
    else:
        return
    raise _refused("RULE_MATCH_INVALID", f"rules[{index}].match.to", problem)


async def store_rule_set(
    session: AsyncSession,
    actor: User,
    row: OrganizationRuleSet,
    after: RuleSet,
    *,
    source: Source,
    policy_version: int | None,
) -> None:
    """The only writer of `organization_rule_sets`; `row` is locked and `after` valid."""
    organization_id = row.organization_id
    before = stored_rules(row)
    stored = {rule.id: rule for rule in before.rules} if before is not None else {}
    # This release cannot read them, so it keeps them as they are.
    kept = before.unusable if before is not None else ()
    if len(after.rules) + len(kept) > LIMITS["rules_per_set"]:
        raise _refused(
            "RULE_SET_INVALID",
            "rules",
            "A rule set holds at most 100 rules, with the "
            f"{len(kept)} this release cannot run.",
        )
    known: dict[str, set[str]] = {}
    for field, model in (("api_key_ids", ApiKey), ("team_ids", Team)):
        ids = {value for rule in after.rules for value in getattr(rule.scope, field)}
        known[field] = (
            {
                str(value)
                for value in await session.scalars(
                    select(model.id).where(
                        model.organization_id == organization_id, model.id.in_(ids)
                    )
                )
            }
            if ids
            else set()
        )
    kept_ids = {rule.id for rule in kept}
    record_sets = {
        str(set_id): (kind, active, len(fields))
        for set_id, kind, active, fields in await session.execute(
            select(
                RecordSet.id,
                RecordSet.kind,
                RecordSet.active_revision,
                RecordSet.fields,
            ).where(RecordSet.organization_id == organization_id)
        )
    }
    routes = {
        rule.id for rule in after.rules if rule.kind == "route" and owned(rule.match)
    }
    providers: dict[str, str] = (
        {
            alias: provider
            for alias, provider in await session.execute(
                select(ModelDeployment.alias, ModelDeployment.provider).where(
                    ModelDeployment.organization_id == organization_id
                )
            )
        }
        if routes
        else {}
    )
    for index, rule in enumerate(after.rules):
        if rule.kind == "record_set":
            _check_record_set_rule(rule, index, record_sets)
        if rule.id in routes:
            _check_route_rule(rule, index, providers)
        if rule.id in kept_ids:
            raise _refused(
                "RULE_ID_DUPLICATE",
                f"rules[{index}].id",
                f"rule id {rule.id} is held by a stored rule this release cannot run.",
            )
        for field, values in known.items():
            for position, value in enumerate(getattr(rule.scope, field)):
                if value not in values:
                    raise _refused(
                        "RULE_SCOPE_UNKNOWN",
                        f"rules[{index}].scope.{field}[{position}]",
                        f"{field} names an id this organization does not have.",
                    )
        # A restore brings back a rule exactly as it was; anything else new needs
        # a preview to start enforced.
        if (
            rule.id not in stored
            and rule.state != "monitor"
            and source != "restore"
            and not await has_preview(session, organization_id, rule)
        ):
            raise _refused(
                "RULE_MUST_START_IN_MONITOR",
                f"rules[{index}].state",
                "A new rule starts in state monitor.",
            )
    current = {rule.id: rule for rule in after.rules}
    await _audit(
        session,
        actor,
        "tenant.rules_updated",
        str(organization_id),
        details={
            "revision": after.revision,
            "added": [
                _rule_audit(rule, None) for rule in after.rules if rule.id not in stored
            ],
            "changed": [
                _rule_audit(rule, stored[rule.id])
                for rule in after.rules
                if rule.id in stored and stored[rule.id] != rule
            ],
            "removed": [
                _rule_audit(rule, None)
                for rule in stored.values()
                if rule.id not in current
            ],
            **version_detail(policy_version),
        },
    )
    relaxed = classify_rule_changes(before, after)
    if relaxed:
        event_id = await _audit(
            session,
            actor,
            "tenant.privacy_protection_relaxed",
            str(organization_id),
            details={"relaxed": relaxed, **version_detail(policy_version)},
        )
        await ComplianceForwarderService().send_privacy_protection_relaxed(
            session,
            TenantId(organization_id),
            fields=relaxed,
            actor=str(actor.id),
            actor_email=actor.email,
            event_id=event_id,
        )
    await _record_definitions(session, row, stored, after, kept_ids)
    row.rules = [rule.model_dump(mode="json") for rule in after.rules] + [
        rule.stored for rule in kept
    ]
    row.revision = after.revision
    row.updated_by = str(actor.id)


class _RuleResource:
    name = "rules"
    permission: Permission = "rules.write"
    creatable = True
    deletable = True

    def new_item(self, proposed: State) -> str:
        return str(proposed.get("id", ""))

    async def snapshot(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_ids: Collection[str] | None,
    ) -> dict[str, State]:
        stored = stored_rules(await session.get(OrganizationRuleSet, organization_id))
        return {
            rule.id: rule_state(rule)
            for rule in (stored.rules if stored is not None else ())
            if item_ids is None or rule.id in item_ids
        }

    async def validate(
        self,
        session: AsyncSession,
        actor: User,
        item_id: str | None,
        before: State | None,
        proposed: State,
    ) -> State:
        rule_id = item_id if item_id is not None else proposed.get("id")
        if proposed.get("id", rule_id) != rule_id:
            raise _refused("RULE_SET_INVALID", "id", "A rule keeps its id.")
        if item_id is None and rule_id in await self.snapshot(
            session, actor.organization_id, None
        ):
            raise _refused(
                "RULE_ID_DUPLICATE", "id", f"rule id {rule_id} is already in the set"
            )
        merged = {**(before or {}), **proposed, "id": rule_id}
        [rule] = checked_set(1, [merged]).rules
        return rule_state(rule)

    async def apply(
        self,
        session: AsyncSession,
        actor: User,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        *,
        policy_version: int | None,
    ) -> None:
        row = await rule_set_row(session, organization_id)
        stored = stored_rules(row)
        rules = [
            rule.model_dump(mode="json")
            for rule in (stored.rules if stored is not None else ())
        ]
        changed = {"id": item_id, **after} if after is not None else None
        position = next(
            (index for index, rule in enumerate(rules) if rule["id"] == item_id), None
        )
        if position is None:
            rules.append(changed)
        else:
            rules[position] = changed
        await store_rule_set(
            session,
            actor,
            row,
            checked_set(row.revision + 1, [rule for rule in rules if rule is not None]),
            source=WRITE_SOURCE.get(),
            policy_version=policy_version,
        )

    def classify(self, before: State | None, after: State | None) -> Risk:
        return rule_direction(_rule("rule", before), _rule("rule", after))

    async def impact(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        window_days: int,
    ) -> Impact:
        state = after if after is not None else before
        assert state is not None
        rule, preview = await preview_rule(
            session, organization_id, {"id": item_id, **state}, window_days
        )
        note = preview["note"]
        if (
            before is None
            and rule.state == "enforced"
            and not await has_preview(session, organization_id, rule)
        ):
            note = _APPLY_WILL_REFUSE
        return {
            "requests": preview["requests"],
            "basis": preview["basis"],
            "window_days": window_days,
            "note": note,
        }

    async def after_commit(self, request: Request, organization_id: UUID) -> None:
        try:
            cache: CacheService = request.app.state.cache
            await CacheManager(cache).invalidate_pii_config(str(organization_id))
        except Exception as exc:
            logger.warning(
                "Rule set cache invalidation failed type=%s", type(exc).__name__
            )


RULES = _RuleResource()


def rule_changes(
    stored: dict[str, State], after: RuleSet
) -> list[tuple[_RuleResource, str, State | None, State | None]]:
    """One managed change per rule a whole-set write adds, changes or removes."""
    current = {rule.id: rule_state(rule) for rule in after.rules}
    return [
        (RULES, rule_id, stored.get(rule_id), current.get(rule_id))
        for rule_id in sorted(stored.keys() | current.keys())
    ]
