from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from unittest.mock import patch
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete, func, insert, select, text, update
from sqlalchemy.ext.asyncio import async_sessionmaker

from shim.gateway.contracts.context import (
    AuditPolicy,
    GatewayContext,
    PrivacyPolicy,
    TierPolicy,
)
from shim.gateway.contracts.ids import ProviderId
from shim.gateway.kernel.result import AdmissionState, PreparedInference
from shim.gateway.request_policy import RequestPolicyContext
from shim.privacy.policies import PrivacyAction, PrivacyOutcome
from shim.rules.approval import ApprovalRequest
from shim.rules.model import RuleMatch
from shim_enterprise.approvals import gate as gate_module
from shim_enterprise.approvals.gate import (
    APPROVAL_PENDING_LIMIT,
    EnterpriseApprovalGate,
    request_digest,
)
from shim_enterprise.approvals.models import RequestApproval
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.tenants.models import ApiKey, Organization, Team, User

TERM = "Kasa Atlas"


@pytest_asyncio.fixture
async def tenants(async_engine):
    """Two committed tenants, each with an owner, a team and two keys; removed afterwards."""
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    made = []
    async with factory() as session:
        for _ in range(2):
            organization = Organization(
                id=uuid4(), name="Approvals", slug=f"apr-{uuid4().hex}"
            )
            session.add(organization)
            await session.flush()
            user = User(
                id=uuid4(),
                organization_id=organization.id,
                email=f"apr-{uuid4().hex}@example.com",
                role="member",
                is_active=True,
                is_verified=True,
            )
            team = Team(id=uuid4(), organization_id=organization.id, name="risk")
            session.add_all([user, team])
            await session.flush()
            keys = [
                ApiKey(
                    id=uuid4(),
                    organization_id=organization.id,
                    user_id=user.id,
                    key_hash=uuid4().hex,
                    prefix="sk-shim-apr",
                    name=f"app-{index}",
                    is_active=True,
                )
                for index in range(2)
            ]
            session.add_all(keys)
            made.append((organization, user, team, keys))
        await session.commit()
    yield made
    async with factory() as session:
        for organization, *_ in made:
            for model in (RequestApproval, OutboxEvent, ApiKey, Team, User):
                await session.execute(
                    delete(model).where(model.organization_id == organization.id)
                )
            await session.execute(
                delete(Organization).where(Organization.id == organization.id)
            )
        await session.commit()


def _prepared(
    key: ApiKey,
    *,
    team: Team | None = None,
    content: str = f"{TERM} raporu",
    model: str = "gpt-5.6-luna",
    stream: bool = False,
) -> tuple[PreparedInference, dict]:
    payload = {"model": model, "messages": [{"role": "user", "content": content}]}
    prepared = PreparedInference(
        context=GatewayContext(
            request_id=f"req_apr_{uuid4().hex}",
            tenant_id=key.organization_id,
            actor_type="api_key",
            api_key_id=key.id,
            user_id=None,
            endpoint="/v1/chat/completions",
            started_at=datetime.now(timezone.utc),
            tier_policy=TierPolicy(
                rate_limit_rpm=60, rate_limit_tpm=None, monthly_token_limit=None
            ),
            privacy_policy=PrivacyPolicy(pii_mode="scrub"),
            audit_policy=AuditPolicy(mode="off"),
        ),
        payload=payload,
        provider=ProviderId("openai"),
        protocol="chat",
        model=model,
        stream=stream,
        policy=RequestPolicyContext(
            rate_limit_key_hash="key-hash",
            tier="free",
            team_id=None if team is None else str(team.id),
        ),
        pii_config=None,
        admission=AdmissionState(
            estimated_input_tokens=12,
            maximum_output_tokens=100,
            cost_center="untagged",
            tags=(),
        ),
        privacy=PrivacyOutcome(
            action=PrivacyAction.SCRUBBED,
            pii_detected=True,
            pii_entities={"EMAIL_ADDRESS": 1},
            monitored_entities={"PERSON": 2},
        ),
        rule_matches=[
            RuleMatch(
                rule_id="kasa",
                kind="term",
                action="require_approval",
                state="enforced",
                count=2,
            )
        ],
    )
    return prepared, payload


def _ask(payload: dict, presented: str | None = None) -> ApprovalRequest:
    return ApprovalRequest(
        rule_ids=("kasa",), presented_id=presented, admitted_payload=payload
    )


@pytest.fixture
def gate(async_engine) -> EnterpriseApprovalGate:
    return EnterpriseApprovalGate(
        async_sessionmaker(async_engine, expire_on_commit=False)
    )


async def _rows(async_engine, organization_id) -> list[RequestApproval]:
    async with async_sessionmaker(async_engine)() as session:
        return list(
            await session.scalars(
                select(RequestApproval)
                .where(RequestApproval.organization_id == organization_id)
                .order_by(RequestApproval.created_at)
            )
        )


async def _set(async_engine, approval_id, **values) -> None:
    async with async_sessionmaker(async_engine).begin() as session:
        await session.execute(
            update(RequestApproval)
            .where(RequestApproval.id == approval_id)
            .values(**values)
        )


def _digest(**changes) -> str:
    values = {
        "tenant_id": "11111111-1111-1111-1111-111111111111",
        "api_key_id": "22222222-2222-2222-2222-222222222222",
        "protocol": "chat",
        "model": "gpt-5.6-luna",
        "stream": False,
        "payload": {"model": "gpt-5.6-luna", "messages": [{"content": "a"}]},
        **changes,
    }
    return request_digest(b"k" * 32, **values)[0]


def test_the_digest_is_pinned_and_ignores_key_order_and_whitespace() -> None:
    spaced = json.loads(
        '{ "messages" : [ {"content":"a"} ],\n "model": "gpt-5.6-luna" }'
    )

    assert _digest() == (
        "bf554a4a6832d488e191e38d815f6334cc01caf782993e0b5d253c35cdce7e15"
    )
    assert _digest(payload=spaced) == _digest()
    assert request_digest(
        b"k" * 32,
        **{
            "tenant_id": "t",
            "api_key_id": "k",
            "protocol": "chat",
            "model": "m",
            "stream": False,
            "payload": {"a": "ü"},
        },
    )[1] == len('{"a":"ü"}'.encode())


@pytest.mark.parametrize(
    "change",
    [
        {"stream": True},
        {"model": "gpt-5.6-terra"},
        {"api_key_id": "33333333-3333-3333-3333-333333333333"},
        {"tenant_id": "44444444-4444-4444-4444-444444444444"},
        {"protocol": "responses"},
    ],
)
def test_the_digest_changes_with_each_request_fact(change) -> None:
    assert _digest(**change) != _digest()


@pytest.mark.asyncio
async def test_the_digest_is_computed_off_the_event_loop(tenants, gate) -> None:
    _, _, _, [key, _] = tenants[0]
    prepared, payload = _prepared(key)

    with patch.object(
        gate_module.asyncio, "to_thread", wraps=asyncio.to_thread
    ) as to_thread:
        await gate.check(prepared, _ask(payload))

    assert to_thread.call_args.args[0] is request_digest


@pytest.mark.asyncio
async def test_a_held_request_is_one_row_with_counts_and_no_content(
    tenants, gate, async_engine
) -> None:
    organization, user, team, [key, _] = tenants[0]
    prepared, payload = _prepared(key, team=team)

    first = await gate.check(prepared, _ask(payload))
    again = await gate.check(_prepared(key, team=team)[0], _ask(payload))

    [row] = await _rows(async_engine, organization.id)
    assert (first.outcome, first.approval_id) == ("required", str(row.id))
    assert (again.outcome, again.approval_id) == ("required", str(row.id))
    assert (row.api_key_id, row.requested_by, row.team_id) == (key.id, user.id, team.id)
    assert (row.protocol, row.provider, row.model, row.stream) == (
        "chat",
        "openai",
        "gpt-5.6-luna",
        False,
    )
    assert row.rule_ids == ["kasa"]
    assert row.detected == {
        "entities": {"EMAIL_ADDRESS": 1, "PERSON": 2},
        "rules": {"kasa": 2},
    }
    assert row.input_bytes == len(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    )
    assert row.estimated_input_tokens == 12
    assert row.request_id == str(prepared.request_id)
    async with async_sessionmaker(async_engine)() as session:
        stored = await session.scalar(
            text("SELECT row_to_json(r)::text FROM request_approvals r WHERE id = :id"),
            {"id": row.id},
        )
    assert TERM not in stored and "Kasa" not in stored


@pytest.mark.asyncio
async def test_an_approval_is_consumed_once(tenants, gate, async_engine) -> None:
    organization, _, _, [key, _] = tenants[0]
    prepared, payload = _prepared(key)
    held = await gate.check(prepared, _ask(payload))
    await _set(
        async_engine,
        held.approval_id,
        status="approved",
        use_by=func.now() + gate_module.APPROVAL_USE_TTL,
    )

    sent = _prepared(key)[0]
    used = await gate.check(sent, _ask(payload, held.approval_id))
    third = await gate.check(_prepared(key)[0], _ask(payload, held.approval_id))

    rows = {str(row.id): row for row in await _rows(async_engine, organization.id)}
    assert (used.outcome, used.approval_id) == ("approved", held.approval_id)
    assert rows[held.approval_id].status == "used"
    assert rows[held.approval_id].used_request_id == str(sent.request_id)
    assert third.outcome == "required" and third.approval_id != held.approval_id
    assert rows[third.approval_id].status == "pending"


@pytest.mark.asyncio
async def test_a_presented_id_that_does_not_fit_is_ignored(
    tenants, gate, async_engine
) -> None:
    organization, _, _, [key, other_key] = tenants[0]
    _, _, _, [foreign_key, _] = tenants[1]
    prepared, payload = _prepared(key)
    held = await gate.check(prepared, _ask(payload))
    await _set(
        async_engine,
        held.approval_id,
        status="approved",
        use_by=func.now() + gate_module.APPROVAL_USE_TTL,
    )

    wrong_key = await gate.check(
        _prepared(other_key)[0], _ask(payload, held.approval_id)
    )
    changed = _prepared(key, content=f"{TERM} başka")
    wrong_digest = await gate.check(changed[0], _ask(changed[1], held.approval_id))
    other_tenant = await gate.check(
        _prepared(foreign_key)[0], _ask(payload, held.approval_id)
    )
    malformed = await gate.check(_prepared(key)[0], _ask(payload, "not-a-uuid"))
    await _set(async_engine, held.approval_id, use_by=func.now())
    late = await gate.check(_prepared(key)[0], _ask(payload, held.approval_id))

    for decision in (wrong_key, wrong_digest, other_tenant, malformed, late):
        assert decision.outcome == "required"
        assert decision.approval_id != held.approval_id
    statuses = {
        str(row.id): row.status for row in await _rows(async_engine, organization.id)
    }
    assert statuses[held.approval_id] == "expired"


@pytest.mark.asyncio
async def test_a_rejected_id_is_refused(tenants, gate, async_engine) -> None:
    _, _, _, [key, _] = tenants[0]
    prepared, payload = _prepared(key)
    held = await gate.check(prepared, _ask(payload))
    await _set(async_engine, held.approval_id, status="rejected")

    decision = await gate.check(_prepared(key)[0], _ask(payload, held.approval_id))

    assert (decision.outcome, decision.approval_id) == ("rejected", held.approval_id)


@pytest.mark.asyncio
async def test_a_pending_row_past_its_lifetime_expires_and_a_new_one_is_held(
    tenants, gate, async_engine
) -> None:
    organization, _, _, [key, _] = tenants[0]
    prepared, payload = _prepared(key)
    held = await gate.check(prepared, _ask(payload))
    await _set(
        async_engine,
        held.approval_id,
        expires_at=func.now() - gate_module.APPROVAL_PENDING_TTL,
    )

    renewed = await gate.check(_prepared(key)[0], _ask(payload))

    statuses = {
        str(row.id): row.status for row in await _rows(async_engine, organization.id)
    }
    assert renewed.approval_id != held.approval_id
    assert statuses == {held.approval_id: "expired", renewed.approval_id: "pending"}


@pytest.mark.asyncio
async def test_two_hundred_pending_fill_the_queue(tenants, gate, async_engine) -> None:
    organization, _, _, [key, _] = tenants[0]
    async with async_sessionmaker(async_engine).begin() as session:
        await session.execute(
            insert(RequestApproval),
            [
                {
                    "organization_id": organization.id,
                    "api_key_id": key.id,
                    "request_digest": f"{index:064x}",
                    "request_id": f"req_fill_{index}",
                    "protocol": "chat",
                    "provider": "openai",
                    "model": "gpt-5.6-luna",
                    "stream": False,
                    "rule_ids": ["kasa"],
                    "input_bytes": 1,
                    "expires_at": datetime(2999, 1, 1, tzinfo=timezone.utc),
                }
                for index in range(APPROVAL_PENDING_LIMIT - 1)
            ],
        )
    last = _prepared(key, content=f"{TERM} 200")

    held = await gate.check(last[0], _ask(last[1]))
    over = _prepared(key, content=f"{TERM} 201")
    full = await gate.check(over[0], _ask(over[1]))

    assert held.outcome == "required"
    assert (full.outcome, full.approval_id) == ("queue_full", None)
    assert len(await _rows(async_engine, organization.id)) == APPROVAL_PENDING_LIMIT


@pytest.mark.asyncio
async def test_concurrent_twins_make_one_row_and_one_notice(
    tenants, gate, async_engine
) -> None:
    organization, _, _, [key, _] = tenants[0]
    payload = _prepared(key)[1]

    decisions = await asyncio.gather(
        *(gate.check(_prepared(key)[0], _ask(payload)) for _ in range(2))
    )

    [row] = await _rows(async_engine, organization.id)
    assert {decision.approval_id for decision in decisions} == {str(row.id)}
    async with async_sessionmaker(async_engine)() as session:
        notices = list(
            await session.scalars(
                select(OutboxEvent).where(
                    OutboxEvent.organization_id == organization.id,
                    OutboxEvent.event_type == "request.approval_requested",
                )
            )
        )
    assert [notice.aggregate_id for notice in notices] == [str(row.id)]
    assert notices[0].payload["rule_ids"] == ["kasa"]
    assert TERM not in json.dumps(notices[0].payload)
