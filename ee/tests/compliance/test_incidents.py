from datetime import datetime, timedelta, timezone
import json
from typing import get_args
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import shim_enterprise.core.database as database
from shim_enterprise.ai_act.audit_writer import write_audit_row
from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.compliance.models import ComplianceForwardTarget
from shim_enterprise.core.database import get_db
from shim_enterprise.findings.models import Finding
from shim_enterprise.incidents import service
from shim_enterprise.incidents.api import Breach, BreachField, Links
from shim_enterprise.incidents.api import router as incidents_router
from shim_enterprise.incidents.models import STATUSES, Incident, IncidentNotification
from shim_enterprise.outbox.handlers import (
    COMPLIANCE_DELIVERY,
    INCIDENT_DEADLINE_APPROACHING,
    INCIDENT_DEADLINE_MISSED,
    _compliance_text,
    build_publisher,
)
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.outbox.publisher import OutboxMessage
from shim_enterprise.tenants.models import Organization, User

URL = "/api/v1/compliance/incidents"
ROLES = ("owner", "admin", "auditor", "member")


async def _org(db, name: str = "Incidents") -> tuple[Organization, dict[str, User]]:
    organization = Organization(
        id=uuid4(), name=name, slug=f"incidents-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    users = {
        role: User(
            id=uuid4(),
            organization_id=organization.id,
            email=f"{role}-{uuid4().hex}@example.com",
            role=role,
            is_active=True,
            is_verified=True,
        )
        for role in ROLES
    }
    db.add_all(users.values())
    await db.flush()
    return organization, users


class _Client:
    """One app per test; `as_user` switches the caller between requests."""

    def __init__(self, db, user: User) -> None:
        self.user = user
        app = FastAPI()
        app.include_router(incidents_router, prefix="/api/v1")
        app.dependency_overrides[get_current_user] = lambda: self.user
        app.dependency_overrides[get_db] = lambda: db
        self.http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        )

    def as_user(self, user: User) -> "_Client":
        self.user = user
        return self

    async def __aenter__(self) -> "_Client":
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.http.aclose()

    async def request(self, method: str, path: str = "", **kwargs) -> httpx.Response:
        return await self.http.request(method, f"{URL}{path}", **kwargs)


def _hours_ago(hours: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def _finding(organization_id, **fields) -> Finding:
    now = datetime.now(timezone.utc)
    return Finding(
        organization_id=organization_id,
        rule_id=fields.get("rule_id", "gateway.retry_storm"),
        rule_version=1,
        subject_key=f"api_key:{uuid4()}",
        subject={},
        title=fields.get("title", "Retry storm from one API key"),
        summary="s",
        severity_id=fields.get("severity_id", 3),
        first_seen_at=now,
        last_seen_at=now,
        evidence={},
        remediation={},
    )


def _lifecycle(organization_id, metadata: dict, *, provider: str = "openai"):
    return RequestLifecycle(
        request_id=f"req_incident_{uuid4().hex}",
        organization_id=organization_id,
        actor_type="internal",
        source_endpoint="chat.completions",
        status="completed",
        provider=provider,
        provider_model="gpt-5-mini",
        requested_model="gpt-5-mini",
        stream=False,
        started_at=datetime.now(timezone.utc),
        lifecycle_metadata=metadata,
    )


def _savepoints(connection) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        connection,
        class_=AsyncSession,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )


@pytest.mark.asyncio
async def test_the_tables_default_and_check_their_values(db) -> None:
    organization, _ = await _org(db)
    incident_id = uuid4()
    await db.execute(
        text(
            "INSERT INTO incidents (id, organization_id, title, severity_id, opened_by, "
            "aware_at) VALUES (:id, :org, 't', 3, 'u', now())"
        ),
        {"id": incident_id, "org": organization.id},
    )
    defaults = (
        await db.execute(
            text(
                "SELECT status, description, is_suspected_breach, breach, links "
                "FROM incidents WHERE id = :id"
            ),
            {"id": incident_id},
        )
    ).one()
    notification = (
        "INSERT INTO incident_notifications (id, organization_id, incident_id, regime) "
        "VALUES (gen_random_uuid(), :org, :id, :regime)"
    )
    await db.execute(
        text(notification),
        {"org": organization.id, "id": incident_id, "regime": "kvkk_board"},
    )
    row = (
        await db.execute(
            text(
                "SELECT due_at, required, submissions, reminded "
                "FROM incident_notifications WHERE incident_id = :id"
            ),
            {"id": incident_id},
        )
    ).one()

    assert tuple(defaults) == ("new", "", False, {}, {})
    assert tuple(row) == (None, True, [], [])
    for statement, values in (
        ("UPDATE incidents SET severity_id = 6 WHERE id = :id", {}),
        ("UPDATE incidents SET status = 'open' WHERE id = :id", {}),
        (notification, {"org": organization.id, "regime": "kvkk_board"}),
        (notification, {"org": organization.id, "regime": "ccpa"}),
    ):
        with pytest.raises(IntegrityError):
            async with db.begin_nested():
                await db.execute(text(statement), {"id": incident_id, **values})


def test_every_breach_field_and_link_list_has_its_limit() -> None:
    for field, value in (
        ("data_categories", ["x"] * 21),
        ("data_categories", ["x" * 101]),
        ("approx_subjects", "x" * 101),
        ("approx_records", "x" * 101),
        ("likely_consequences", "x" * 2001),
        ("measures_taken", "x" * 2001),
        ("measures_planned", "x" * 2001),
        ("contact_person", "x" * 201),
        ("subjects_informed_how", "x" * 501),
        ("free_text", "x"),
    ):
        with pytest.raises(ValidationError):
            Breach.model_validate({field: value})
    for name, value in (
        ("finding_ids", [str(uuid4())] * 101),
        ("request_ids", ["req"] * 101),
        ("audit_seqs", [1] * 101),
    ):
        with pytest.raises(ValidationError):
            Links.model_validate({name: value})
    assert (
        Breach.model_validate(
            {"approx_subjects": "about 1,200", "data_categories": ["Kimlik"] * 20}
        ).approx_subjects
        == "about 1,200"
    )
    assert set(get_args(BreachField)) == set(Breach.model_fields)


@pytest.mark.asyncio
async def test_links_dates_and_owner_must_belong_to_the_organization(db) -> None:
    organization, users = await _org(db)
    other, other_users = await _org(db, "Other")
    references = {}
    # Audit seqs count per organization: the other one gets a seq this one lacks.
    for tenant, rows in ((organization, 1), (other, 2)):
        finding = _finding(tenant.id)
        lifecycle = _lifecycle(tenant.id, {})
        db.add_all([finding, lifecycle])
        for _ in range(rows):
            audit = await write_audit_row(
                {"organization_id": tenant.id, "request_id": f"req-{uuid4().hex}"}, db
            )
        references[tenant.id] = {
            "finding_ids": [str(finding.id)],
            "request_ids": [lifecycle.request_id],
            "audit_seqs": [audit.seq],
        }
    await db.flush()
    own, foreign = references[organization.id], references[other.id]
    body = {"title": "Leak", "severity_id": 4}

    async with _Client(db, users["admin"]) as client:
        accepted = await client.request("POST", json={**body, "links": own})
        refused = {
            name: await client.request(
                "POST", json={**body, "links": {**own, name: foreign[name]}}
            )
            for name in own
        }
        future = await client.request("POST", json={**body, "aware_at": _hours_ago(-1)})
        reversed_dates = await client.request(
            "POST",
            json={**body, "aware_at": _hours_ago(2), "occurred_at": _hours_ago(1)},
        )
        too_many = await client.request(
            "POST", json={**body, "links": {"request_ids": ["r"] * 101}}
        )
        stranger = await client.request(
            "POST", json={**body, "owner_user_id": str(other_users["admin"].id)}
        )

    assert accepted.status_code == 201
    assert accepted.json()["links"] == own
    for name, response in refused.items():
        assert response.status_code == 422
        assert f"links.{name}" in response.json()["detail"]
        assert str(other.id) not in response.text
    assert [r.status_code for r in (future, reversed_dates, too_many, stranger)] == [
        422
    ] * 4


def _rows(response: httpx.Response) -> dict[str, dict]:
    return {row["regime"]: row for row in response.json()["notifications"]}


@pytest.mark.asyncio
async def test_the_clock_runs_from_awareness(db) -> None:
    organization, users = await _org(db)
    aware = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=71)

    async with _Client(db, users["owner"]) as client:
        opened = await client.request(
            "POST",
            json={
                "title": "TCKN in a prompt",
                "severity_id": 4,
                "aware_at": aware.isoformat(),
                "is_suspected_breach": True,
            },
        )
        incident = f"/{opened.json()['id']}"
        gdpr = await client.request(
            "PUT", f"{incident}/notifications/gdpr_authority", json={}
        )
        submitted = await client.request(
            "POST",
            f"{incident}/notifications/gdpr_authority/submissions",
            json={"reference": "EDPB-1", "fields_sent": ["data_categories"]},
        )
        moved = await client.request(
            "PATCH",
            incident,
            json={"aware_at": (aware - timedelta(hours=2)).isoformat()},
        )
        late = await client.request(
            "POST",
            f"{incident}/notifications/kvkk_board/submissions",
            json={"reference": "K-1"},
        )
        explained = await client.request(
            "POST",
            f"{incident}/notifications/kvkk_board/submissions",
            json={
                "reference": "K-1",
                "late_reason": "The scope took a day to confirm.",
            },
        )
        no_reason = await client.request(
            "PUT",
            f"{incident}/notifications/kvkk_data_subjects",
            json={"required": False},
        )
        not_required = await client.request(
            "PUT",
            f"{incident}/notifications/kvkk_data_subjects",
            json={"required": False, "not_required_reason": "Masked before it left."},
        )
        await db.execute(
            text(
                "UPDATE incident_notifications SET submissions = CAST(:items AS jsonb) "
                "WHERE regime = 'gdpr_authority' AND incident_id = :id"
            ),
            {
                "items": json.dumps([{"reference": f"EDPB-{n}"} for n in range(20)]),
                "id": opened.json()["id"],
            },
        )
        twenty_first = await client.request(
            "POST",
            f"{incident}/notifications/gdpr_authority/submissions",
            json={"reference": "EDPB-21"},
        )
        unflagged = await client.request(
            "PATCH", incident, json={"is_suspected_breach": False}
        )

    first = _rows(opened)
    assert set(first) == {"kvkk_board", "kvkk_data_subjects"}
    assert first["kvkk_board"]["due_at"] == (
        aware + timedelta(hours=72)
    ).isoformat().replace("+00:00", "Z")
    assert (first["kvkk_board"]["state"], first["kvkk_data_subjects"]["due_at"]) == (
        "open",
        None,
    )
    assert _rows(gdpr)["gdpr_authority"]["state"] == "open"
    assert _rows(submitted)["gdpr_authority"]["state"] == "submitted"
    after = _rows(moved)
    assert after["kvkk_board"]["state"] == "overdue"
    assert after["kvkk_board"]["due_at"] == (
        aware + timedelta(hours=70)
    ).isoformat().replace("+00:00", "Z")
    # A met deadline does not move.
    assert after["gdpr_authority"]["due_at"] == _rows(gdpr)["gdpr_authority"]["due_at"]
    assert (late.status_code, explained.status_code) == (422, 201)
    assert _rows(explained)["kvkk_board"]["state"] == "submitted"
    assert no_reason.status_code == 422
    assert _rows(not_required)["kvkk_data_subjects"]["state"] == "not_required"
    assert twenty_first.status_code == 422
    assert set(_rows(unflagged)) == {
        "kvkk_board",
        "kvkk_data_subjects",
        "gdpr_authority",
    }


@pytest.mark.parametrize(("hours", "state"), [(71, "open"), (73, "overdue")])
def test_a_deadline_is_open_until_it_passes(hours: int, state: str) -> None:
    now = datetime.now(timezone.utc)
    row = IncidentNotification(
        regime="kvkk_board",
        due_at=service.due_at("kvkk_board", now - timedelta(hours=hours)),
        required=True,
        submissions=[],
    )

    assert service.notification_state(row, now) == state


@pytest.mark.asyncio
async def test_the_status_moves_and_a_closed_incident_is_final(db) -> None:
    organization, users = await _org(db)

    async with _Client(db, users["admin"]) as client:

        async def opened() -> str:
            response = await client.request(
                "POST", json={"title": "t", "severity_id": 2}
            )
            return f"/{response.json()['id']}"

        path = await opened()
        walked = []
        for target in (
            "in_progress",
            "on_hold",
            "in_progress",
            "resolved",
            "in_progress",
            "resolved",
            "closed",
        ):
            response = await client.request(
                "POST", f"{path}/status", json={"status": target}
            )
            walked.append((response.status_code, response.json().get("status")))
        closed_writes = [
            (await client.request(method, f"{path}{suffix}", json=body)).status_code
            for method, suffix, body in (
                ("PATCH", "", {"title": "new"}),
                ("POST", "/status", {"status": "in_progress"}),
                ("PUT", "/notifications/gdpr_authority", {}),
                (
                    "POST",
                    "/notifications/gdpr_authority/submissions",
                    {"reference": "r"},
                ),
            )
        ]
        forbidden = []
        for start in STATUSES:
            for target in STATUSES:
                if target in service.STATUS_MOVES[start]:
                    continue
                path = await opened()
                await db.execute(
                    text("UPDATE incidents SET status = :status WHERE id = :id"),
                    {"status": start, "id": path[1:]},
                )
                response = await client.request(
                    "POST", f"{path}/status", json={"status": target}
                )
                forbidden.append((start, target, response.status_code))
        detail = (await client.request("GET", path)).json()

    assert walked == [
        (200, "in_progress"),
        (200, "on_hold"),
        (200, "in_progress"),
        (200, "resolved"),
        (200, "in_progress"),
        (200, "resolved"),
        (200, "closed"),
    ]
    assert closed_writes == [409] * 4
    assert forbidden and all(code == 409 for _, _, code in forbidden)
    assert len(forbidden) == len(STATUSES) ** 2 - sum(
        map(len, service.STATUS_MOVES.values())
    )
    assert detail["status"] in STATUSES


@pytest.mark.asyncio
async def test_owners_and_admins_manage_auditors_read_members_do_neither(db) -> None:
    organization, users = await _org(db)

    async with _Client(db, users["owner"]) as client:
        created = {
            role: (
                await client.as_user(users[role]).request(
                    "POST", json={"title": role, "severity_id": 1}
                )
            ).status_code
            for role in ROLES
        }
        path = f"/{(await client.as_user(users['owner']).request('GET')).json()['items'][0]['id']}"
        reads = {
            role: [
                (await client.as_user(users[role]).request("GET", suffix)).status_code
                for suffix in ("", "/export", path)
            ]
            for role in ROLES
        }
        patched = {
            role: (
                await client.as_user(users[role]).request(
                    "PATCH", path, json={"severity_id": 2}
                )
            ).status_code
            for role in ROLES
        }

    assert created == {"owner": 201, "admin": 201, "auditor": 403, "member": 403}
    assert reads == {
        "owner": [200] * 3,
        "admin": [200] * 3,
        "auditor": [200] * 3,
        "member": [403] * 3,
    }
    assert patched == {"owner": 200, "admin": 200, "auditor": 403, "member": 403}


@pytest.mark.asyncio
async def test_every_write_is_audited_by_field_name_without_breach_text(
    db, audit_events
) -> None:
    organization, users = await _org(db)
    secret = "Ayşe Yılmaz's records leaked"

    async with _Client(db, users["admin"]) as client:
        opened = await client.request(
            "POST",
            json={
                "title": "t",
                "severity_id": 3,
                "is_suspected_breach": True,
                "breach": {"likely_consequences": secret, "contact_person": secret},
            },
        )
        path = f"/{opened.json()['id']}"
        await client.request(
            "PATCH", path, json={"title": "t2", "breach": {"measures_taken": secret}}
        )
        await client.request("POST", f"{path}/status", json={"status": "in_progress"})
        await client.request(
            "POST",
            f"{path}/notifications/kvkk_board/submissions",
            json={"reference": "K-9"},
        )

    events = await audit_events(organization.id)
    assert [event["endpoint"] for event in events] == [
        "tenant.incident_opened",
        "tenant.incident_updated",
        "tenant.incident_status_changed",
        "tenant.incident_notification_recorded",
    ]
    assert events[1]["extra"]["fields"] == ["breach", "title"]
    assert (events[2]["extra"]["before"], events[2]["extra"]["after"]) == (
        "new",
        "in_progress",
    )
    assert (events[3]["extra"]["regime"], events[3]["extra"]["reference"]) == (
        "kvkk_board",
        "K-9",
    )
    assert secret not in json.dumps(events, ensure_ascii=False)


@pytest.mark.asyncio
async def test_the_evidence_summary_is_computed_from_the_linked_rows(db) -> None:
    organization, users = await _org(db)
    other, _ = await _org(db, "Other")
    rows = [
        _lifecycle(
            organization.id,
            {
                "pii_entities": {"TR_NATIONAL_ID": 2, "EMAIL_ADDRESS": 1},
                "monitored_entities": {"EMAIL_ADDRESS": 2},
                "blocked_entities": {},
            },
        ),
        _lifecycle(
            organization.id,
            {
                "pii_entities": {"TR_NATIONAL_ID": 1},
                "blocked_entities": {"TR_NATIONAL_ID": 1},
            },
            provider="anthropic",
        ),
        _lifecycle(organization.id, {"pii_entities": {"IBAN_CODE": 4}}),
    ]
    finding = _finding(organization.id, rule_id="gateway.byok_usage", severity_id=3)
    db.add_all(
        [*rows, finding, _lifecycle(other.id, {"pii_entities": {"IBAN_CODE": 9}})]
    )
    await db.flush()

    async with _Client(db, users["admin"]) as client:
        opened = await client.request(
            "POST",
            json={
                "title": "t",
                "severity_id": 3,
                "links": {
                    "request_ids": [rows[0].request_id, rows[1].request_id],
                    "finding_ids": [str(finding.id)],
                },
            },
        )
        detail = (await client.request("GET", f"/{opened.json()['id']}")).json()

    assert detail["evidence_summary"] == {
        "entity_types": [
            {
                "entity_type": "EMAIL_ADDRESS",
                "kvkk_category": "İletişim",
                "masked": 1,
                "monitored": 2,
                "blocked": 0,
            },
            {
                "entity_type": "TR_NATIONAL_ID",
                "kvkk_category": "Kimlik",
                "masked": 3,
                "monitored": 0,
                "blocked": 1,
            },
        ],
        "providers": ["anthropic", "openai"],
        "models": ["gpt-5-mini"],
        "findings": [
            {"id": str(finding.id), "rule_id": "gateway.byok_usage", "severity_id": 3}
        ],
    }
    assert detail["breach"] == {}


@pytest.mark.asyncio
async def test_the_export_is_one_ocsf_incident_finding_per_incident(db) -> None:
    organization, users = await _org(db)
    finding = _finding(organization.id, title="Retry storm")
    db.add(finding)
    await db.flush()
    occurred = datetime.now(timezone.utc) - timedelta(hours=5)

    async with _Client(db, users["owner"]) as client:
        linked = await client.request(
            "POST",
            json={
                "title": "linked",
                "description": "what happened",
                "severity_id": 5,
                "owner_user_id": str(users["admin"].id),
                "occurred_at": occurred.isoformat(),
                "aware_at": _hours_ago(1),
                "is_suspected_breach": True,
                "breach": {"contact_person": "DPO Mehmet"},
                "links": {
                    "finding_ids": [str(finding.id)],
                    "request_ids": [],
                    "audit_seqs": [],
                },
            },
        )
        await client.request(
            "POST",
            f"/{linked.json()['id']}/notifications/kvkk_board/submissions",
            json={"reference": "KVKK-2026-1"},
        )
        alone = await client.request("POST", json={"title": "alone", "severity_id": 1})
        exported = await client.request("GET", "/export")

    lines = [json.loads(line) for line in exported.text.splitlines()]
    by_title = {line["finding_info_list"][0]["title"]: line for line in lines}
    record, single = by_title["Retry storm"], by_title["alone"]
    assert exported.headers["content-type"] == "application/x-ndjson"
    assert record["class_uid"] == 2005 and record["category_uid"] == 2
    assert (record["activity_id"], record["type_uid"]) == (1, 200501)
    assert (record["status_id"], record["status"]) == (1, "New")
    assert record["severity_id"] == 5 and isinstance(record["time"], int)
    assert record["metadata"] == {
        "version": "1.3.0",
        "uid": linked.json()["id"],
        "product": {"name": "shim", "vendor_name": "shim"},
    }
    assert record["finding_info_list"] == [
        {"uid": str(finding.id), "title": "Retry storm"}
    ]
    assert record["desc"] == "what happened"
    assert record["start_time"] == int(occurred.timestamp() * 1000)
    assert record["is_suspected_breach"] is True
    assert record["assignee"] == {"uid": str(users["admin"].id)}
    notifications = {row["regime"]: row for row in record["unmapped"]["notifications"]}
    assert notifications["kvkk_board"]["state"] == "submitted"
    assert notifications["kvkk_board"]["references"] == ["KVKK-2026-1"]
    assert notifications["kvkk_data_subjects"]["due_at"] is None
    assert (
        record["unmapped"]["request_ids"] == []
        and record["unmapped"]["audit_seqs"] == []
    )
    assert single["finding_info_list"] == [
        {"uid": alone.json()["id"], "title": "alone"}
    ]
    assert "start_time" not in single and "assignee" not in single
    assert "DPO Mehmet" not in exported.text and "contact_person" not in exported.text


@pytest.mark.parametrize(
    ("status", "activity", "status_id", "caption"),
    [
        ("new", 1, 1, "New"),
        ("in_progress", 2, 2, "In Progress"),
        ("on_hold", 2, 3, "On Hold"),
        ("resolved", 3, 4, "Resolved"),
        ("closed", 3, 5, "Closed"),
    ],
)
def test_each_status_maps_to_its_ocsf_activity_and_status(
    status: str, activity: int, status_id: int, caption: str
) -> None:
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=uuid4(),
        title="t",
        description="",
        severity_id=2,
        status=status,
        aware_at=now,
        is_suspected_breach=False,
        links={},
        updated_at=now,
    )

    record = service.ocsf_incident_finding(incident, [], {}, now=now)

    assert (record["activity_id"], record["type_uid"]) == (activity, 200500 + activity)
    assert (record["status_id"], record["status"]) == (status_id, caption)


async def _flagged(
    db, organization_id, aware_hours: float, **row
) -> IncidentNotification:
    now = datetime.now(timezone.utc)
    incident = Incident(
        organization_id=organization_id,
        title=f"t{aware_hours}",
        severity_id=3,
        opened_by="u",
        aware_at=now - timedelta(hours=aware_hours),
        is_suspected_breach=True,
    )
    db.add(incident)
    await db.flush()
    notification = IncidentNotification(
        organization_id=organization_id,
        incident_id=incident.id,
        regime="kvkk_board",
        due_at=service.due_at("kvkk_board", incident.aware_at),
        **row,
    )
    db.add_all(
        [
            notification,
            IncidentNotification(
                organization_id=organization_id,
                incident_id=incident.id,
                regime="kvkk_data_subjects",
            ),
        ]
    )
    await db.flush()
    return notification


async def _reminders(db, organization_id) -> list[tuple[str, str]]:
    rows = await db.scalars(
        select(OutboxEvent).where(
            OutboxEvent.organization_id == organization_id,
            OutboxEvent.event_type.in_(
                [INCIDENT_DEADLINE_APPROACHING, INCIDENT_DEADLINE_MISSED]
            ),
        )
    )
    return sorted((row.event_type, row.idempotency_key) for row in rows)


@pytest.mark.asyncio
async def test_reminders_are_written_once_per_stage(db, monkeypatch) -> None:
    organization, _ = await _org(db)
    failing, _ = await _org(db, "Failing")
    soon = await _flagged(db, organization.id, 50)
    missed = await _flagged(db, organization.id, 73)
    await _flagged(db, organization.id, 73, required=False, not_required_reason="r")
    await _flagged(db, organization.id, 73, submissions=[{"reference": "r"}])
    await _flagged(db, failing.id, 73)
    factory = _savepoints(await db.connection())
    now = datetime.now(timezone.utc)
    original = service._remind_organization

    async def fail_one(session, tenant_id, at):
        if tenant_id == failing.id:
            raise RuntimeError("boom")
        return await original(session, tenant_id, at)

    monkeypatch.setattr(service, "_remind_organization", fail_one)
    first = await service.remind_incident_deadlines(factory, now=now)
    second = await service.remind_incident_deadlines(factory, now=now)
    monkeypatch.setattr(service, "_remind_organization", original)
    later = await service.remind_incident_deadlines(
        factory, now=now + timedelta(hours=23)
    )

    assert (first, second, later) == ((2, 1), (0, 1), (2, 0))
    assert await _reminders(db, organization.id) == sorted(
        [
            (
                INCIDENT_DEADLINE_APPROACHING,
                f"incident:{soon.incident_id}:kvkk_board:24h",
            ),
            (
                INCIDENT_DEADLINE_MISSED,
                f"incident:{missed.incident_id}:kvkk_board:missed",
            ),
            (
                INCIDENT_DEADLINE_MISSED,
                f"incident:{soon.incident_id}:kvkk_board:missed",
            ),
        ]
    )
    await db.refresh(soon)
    assert soon.reminded == ["24h", "missed"]


@pytest.mark.parametrize("targets", [0, 2])
@pytest.mark.asyncio
async def test_a_reminder_reaches_every_enabled_forward_target(
    db, monkeypatch, targets: int
) -> None:
    organization, _ = await _org(db)
    db.add_all(
        ComplianceForwardTarget(
            organization_id=organization.id,
            kind="slack",
            endpoint_origin="https://hooks.slack.com",
            secret_ref=f"fernet:v2:{index}",
            secret_backend="fernet",
            secret_version="v2",
            enabled=True,
        )
        for index in range(targets)
    )
    await db.flush()
    monkeypatch.setattr(
        database, "AsyncSessionLocal", _savepoints(await db.connection())
    )
    incident_id = str(uuid4())
    message = OutboxMessage(
        id=uuid4(),
        organization_id=organization.id,
        event_type=INCIDENT_DEADLINE_APPROACHING,
        aggregate_type="incident",
        aggregate_id=incident_id,
        idempotency_key=f"incident:{incident_id}:kvkk_board:24h",
        payload={
            "organization_id": str(organization.id),
            "incident_id": incident_id,
            "title": "TCKN in a prompt",
            "regime": "kvkk_board",
            "due_at": "2026-10-12T09:00:00+00:00",
            "stage": "24h",
        },
        attempt_count=0,
        created_at=datetime.now(timezone.utc),
    )

    await build_publisher().publish(message)

    deliveries = (
        await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == organization.id,
                OutboxEvent.event_type == COMPLIANCE_DELIVERY,
            )
        )
    ).all()
    assert len(deliveries) == targets
    for delivery in deliveries:
        body = delivery.payload["body"]
        assert body["kind"] == "incident_deadline_approaching"
        assert (body["incident_id"], body["regime"]) == (incident_id, "kvkk_board")
    assert _compliance_text(
        {
            "kind": "incident_deadline_missed",
            "title": "TCKN in a prompt",
            "regime": "kvkk_board",
            "due_at": "2026-10-12T09:00:00+00:00",
        }
    ) == (
        "shim incident TCKN in a prompt: the kvkk_board notification was due at "
        "2026-10-12T09:00:00+00:00 and has no submission"
    )
