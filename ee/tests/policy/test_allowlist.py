from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.core.config import settings
from shim_enterprise.policy import allowlist
from shim_enterprise.policy.allowlist import AllowlistEntry, PlanRefusal, check_plan
from shim_enterprise.tenants.models import Organization

PRIVACY = {
    "block_email": True,
    "block_phone": True,
    "block_credit_card": True,
    "block_secrets": True,
    "block_pii_tr": True,
    "entity_actions": {"EMAIL_ADDRESS": "monitor"},
    "bulk_threshold": None,
    "response_scan": "off",
    "placeholder_mode": "random",
    "embeddings_monitor_types": [],
}


def _email(action: str, **fields) -> dict:
    return {**PRIVACY, "entity_actions": {"EMAIL_ADDRESS": action}, **fields}


def _masks_email(before: dict, after: dict) -> bool:
    return after["entity_actions"].get("EMAIL_ADDRESS") in {"mask", "block"}


MASK_EMAIL = AllowlistEntry(
    id="test.mask_email",
    resource="privacy",
    fields=frozenset({"entity_actions"}),
    accepts=_masks_email,
    max_impact_requests=1,
)


def _change(before: dict | None, after: dict | None, resource: str = "privacy") -> dict:
    return {"resource": resource, "item": "_", "before": before, "after": after}


async def _organization(db):
    organization = Organization(
        id=uuid4(), name="Allowlist", slug=f"allowlist-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    return organization.id


def _seen_email(db, organization_id, count: int) -> None:
    for _ in range(count):
        db.add(
            RequestLifecycle(
                request_id=f"req_allow_{uuid4().hex}",
                organization_id=organization_id,
                actor_type="internal",
                source_endpoint="chat.completions",
                status="completed",
                requested_model="gpt-5-mini",
                stream=False,
                started_at=datetime.now(timezone.utc) - timedelta(hours=1),
                lifecycle_metadata={"monitored_entities": {"EMAIL_ADDRESS": 1}},
            )
        )


async def _check(db, organization_id, *changes, risk="tightening", source="api"):
    check = await check_plan(
        db, organization_id, list(changes), risk=risk, source=source
    )
    return check.refusals


@pytest.mark.asyncio
async def test_the_empty_allowlist_refuses_every_change(db, monkeypatch) -> None:
    monkeypatch.setattr(allowlist, "ALLOWLIST", ())
    organization_id = await _organization(db)

    refused = await _check(
        db,
        organization_id,
        _change(_email("monitor"), _email("mask")),
        _change({"enabled": True}, {"enabled": False}, "deployments"),
    )

    assert refused == [
        PlanRefusal(0, "privacy", "_", "not_allowlisted"),
        PlanRefusal(1, "deployments", "_", "not_allowlisted"),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (_change(None, _email("mask")), "create_or_delete"),
        (_change(_email("monitor"), None), "create_or_delete"),
        (_change({"a": 1}, {"a": 2}, "rules"), "not_allowlisted"),
        (_change(_email("monitor"), _email("mask", block_phone=False)), "extra_fields"),
        (_change(_email("mask"), _email("monitor")), "wrong_direction"),
        # The type was off: the history cannot say what masking it would touch.
        (_change(_email("off"), _email("mask")), "impact_unknown"),
        (_change(_email("monitor"), _email("mask")), "impact_too_large"),
    ],
)
async def test_each_refusal_reason_on_its_own(db, monkeypatch, change, reason) -> None:
    monkeypatch.setattr(allowlist, "ALLOWLIST", (MASK_EMAIL,))
    organization_id = await _organization(db)
    _seen_email(db, organization_id, 2)
    await db.flush()

    assert await _check(db, organization_id, change) == [
        PlanRefusal(0, change["resource"], "_", reason)
    ]


@pytest.mark.asyncio
async def test_the_impact_is_measured_now_and_the_plan_must_tighten(
    db, monkeypatch
) -> None:
    monkeypatch.setattr(allowlist, "ALLOWLIST", (MASK_EMAIL,))
    organization_id = await _organization(db)
    change = _change(_email("monitor"), _email("mask"))

    quiet = await _check(db, organization_id, change)
    _seen_email(db, organization_id, 2)
    await db.flush()
    busy = await _check(db, organization_id, change)
    neutral = await _check(db, organization_id, risk="neutral")
    proposed = await _check(db, organization_id, source="proposal")

    assert quiet == []
    assert busy == [PlanRefusal(0, "privacy", "_", "impact_too_large")]
    assert neutral == [PlanRefusal(None, None, None, "plan_not_tightening")]
    assert proposed == [PlanRefusal(None, None, None, "proposal_needs_human")]


@pytest.mark.asyncio
async def test_any_entry_of_a_resource_may_accept_a_change(db, monkeypatch) -> None:
    unbounded = AllowlistEntry(
        id="test.block_email",
        resource="privacy",
        fields=frozenset({"entity_actions"}),
        accepts=lambda before, after: (
            after["entity_actions"]["EMAIL_ADDRESS"] == "block"
        ),
    )
    monkeypatch.setattr(allowlist, "ALLOWLIST", (MASK_EMAIL, unbounded))
    organization_id = await _organization(db)
    _seen_email(db, organization_id, 2)
    await db.flush()

    # The first entry refuses (too many requests), the second accepts.
    assert (
        await _check(db, organization_id, _change(_email("monitor"), _email("block")))
        == []
    )
    # Neither accepts: the first entry's reason is the one given.
    assert await _check(
        db, organization_id, _change(_email("block"), _email("monitor"))
    ) == [PlanRefusal(0, "privacy", "_", "wrong_direction")]


def test_an_entry_names_a_known_resource_and_a_bounded_id() -> None:
    for entry_id, resource in (
        ("Bad", "privacy"),
        ("ok", "nothing"),
        ("a" * 65, "privacy"),
    ):
        with pytest.raises(ValueError):
            AllowlistEntry(
                id=entry_id,
                resource=resource,
                fields=frozenset(),
                accepts=lambda before, after: True,
            )
    assert set(allowlist.REFUSAL_REASONS) == {
        "create_or_delete",
        "not_allowlisted",
        "extra_fields",
        "wrong_direction",
        "impact_unknown",
        "impact_too_large",
        "plan_not_tightening",
        "proposal_needs_human",
        "too_many_changes",
        "proof_unavailable",
    }


def _entry(entry_id: str) -> AllowlistEntry:
    return next(entry for entry in allowlist.ALLOWLIST if entry.id == entry_id)


@pytest.mark.parametrize(
    ("entry_id", "before", "after", "accepted"),
    [
        ("deployment.disable", {"enabled": True}, {"enabled": False}, True),
        ("deployment.disable", {"enabled": False}, {"enabled": True}, False),
        (
            "api_key.narrow_models",
            {"allowed_models": None},
            {"allowed_models": ["a"]},
            True,
        ),
        (
            "api_key.narrow_models",
            {"allowed_models": ["a", "b"]},
            {"allowed_models": ["a"]},
            True,
        ),
        (
            "api_key.narrow_models",
            {"allowed_models": ["a"]},
            {"allowed_models": ["a"]},
            False,
        ),
        (
            "api_key.narrow_models",
            {"allowed_models": ["a"]},
            {"allowed_models": []},
            False,
        ),
        (
            "api_key.narrow_models",
            {"allowed_models": ["a"]},
            {"allowed_models": None},
            False,
        ),
        (
            "api_key.narrow_models",
            {"allowed_models": ["a"]},
            {"allowed_models": ["a", "b"]},
            False,
        ),
        (
            "team.lower_limit",
            {"daily_request_limit": 10},
            {"daily_request_limit": 5},
            True,
        ),
        (
            "team.lower_limit",
            {"daily_request_limit": None},
            {"daily_request_limit": 5},
            True,
        ),
        (
            "team.lower_limit",
            {"daily_request_limit": 5},
            {"daily_request_limit": 10},
            False,
        ),
        (
            "team.lower_limit",
            {"daily_request_limit": 5},
            {"daily_request_limit": None},
            False,
        ),
        (
            "budget.lower",
            {"limit_usd": "10", "enabled": False},
            {"limit_usd": "5", "enabled": True},
            True,
        ),
        ("budget.lower", {"limit_usd": "10"}, {"limit_usd": None}, False),
        ("budget.lower", {"limit_usd": None}, {"limit_usd": "5"}, False),
        ("budget.lower", {"enabled": True}, {"enabled": False}, False),
        ("privacy.start_counting", _email("off"), _email("monitor"), True),
        ("privacy.start_counting", _email("off"), _email("mask"), False),
        ("privacy.start_counting", _email("monitor"), _email("off"), False),
        ("privacy.start_counting", _email("off"), _email("off"), False),
    ],
)
def test_each_entry_accepts_its_direction_only(
    entry_id, before, after, accepted
) -> None:
    assert _entry(entry_id).accepts(before, after) is accepted


def test_the_list_tightens_or_cheapens_and_never_touches_rules_or_settings() -> None:
    assert [entry.id for entry in allowlist.ALLOWLIST] == [
        "deployment.disable",
        "api_key.narrow_models",
        "team.lower_limit",
        "budget.lower",
        "privacy.start_counting",
    ]
    # No automatic change may write a rule (route rules included) or a gateway setting.
    assert not {entry.resource for entry in allowlist.ALLOWLIST} & {
        "rules",
        "gateway_settings",
    }
    assert [entry.id for entry in allowlist.ALLOWLIST if entry.proof] == [
        "deployment.disable",
        "api_key.narrow_models",
        "team.lower_limit",
    ]


@pytest.mark.asyncio
async def test_six_changes_are_too_many_and_audit_off_leaves_no_proof(
    db, monkeypatch
) -> None:
    organization_id = await _organization(db)
    budgets = [
        _change({"limit_usd": "10"}, {"limit_usd": "5"}, "budgets") for _ in range(6)
    ]
    disable = _change({"enabled": True}, {"enabled": False}, "deployments")

    many = await _check(db, organization_id, *budgets)
    five = await _check(db, organization_id, *budgets[:5])
    monkeypatch.setattr(settings, "AI_ACT_AUDIT_ENABLED", False)
    blind = await _check(db, organization_id, disable)
    counting = await _check(db, organization_id, budgets[0])

    assert many == [PlanRefusal(None, None, None, "too_many_changes")]
    assert five == []
    assert blind == [PlanRefusal(0, "deployments", "_", "proof_unavailable")]
    assert counting == []
