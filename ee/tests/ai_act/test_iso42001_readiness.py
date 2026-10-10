import base64
import csv
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
import io
from importlib import resources
from pathlib import Path
import re
from uuid import uuid4
import zlib

import httpx
import pytest
import yaml
from fastapi import FastAPI, HTTPException
from sqlalchemy import text
from starlette.requests import Request

import shim_enterprise.api.enterprise_deps as enterprise_deps
from shim_enterprise.ai_act.api import router as compliance_router
from shim_enterprise.ai_act.audit_writer import write_audit_row
from shim_enterprise.ai_act.readiness import report as readiness
from shim_enterprise.ai_act.report import load_frameworks
from shim_enterprise.ai_act.models import AIActAuditAnchor, ReadinessDeclaration
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.billing.read_models import BillingBreakdown
from shim_enterprise.core.database import get_db
from shim_enterprise.tenants.models import (
    ApiKey,
    ModelDeployment,
    Organization,
    ProviderSecret,
    Team,
    User,
)
from shim_enterprise.tenants.plans import activate_organization_plan


def _pdf_text(pdf: bytes) -> str:
    strings = []
    for match in re.finditer(
        rb"/Filter \[ (/ASCII85Decode )?/FlateDecode \][^>]*>>\s*stream\r?\n(.*?)endstream",
        pdf,
        re.S,
    ):
        data = match.group(2).strip()
        if match.group(1):
            data = base64.a85decode(data.removesuffix(b"~>"))
        strings += [
            item.decode("latin-1")
            for item in re.findall(rb"\(((?:[^()\\]|\\.)*)\) Tj", zlib.decompress(data))
        ]
    return re.sub(r"\\([()\\])", r"\1", " ".join(strings))


def test_the_mapping_has_38_controls_with_sources_and_known_evidence() -> None:
    packaged = yaml.safe_load(
        resources.files("shim_enterprise.ai_act.readiness")
        .joinpath("iso42001.yaml")
        .read_text(encoding="utf-8")
    )
    mapping = readiness.load_mapping()

    assert packaged["verified_against_standard"] is False
    assert mapping.verified_against_standard is False
    assert len({control.identifier for control in mapping.controls}) == 38
    by_source = {
        source: sorted(c.identifier for c in mapping.controls if c.source == source)
        for source in readiness.SOURCES
    }
    assert by_source["measured"] == sorted(
        ["A.4.2", "A.4.4", "A.6.2.6", "A.6.2.8", "A.9.2", "A.10.3"]
    )
    assert by_source["input"] == ["A.2.2", "A.4.3", "A.5.4", "A.9.4"]
    assert len(by_source["declared"]) == 28
    assert {"A.6.2.4", "A.8.3", "A.8.4"} <= set(by_source["declared"])
    for control in mapping.controls:
        if control.source == "declared":
            assert (control.evidence, control.rule) == (None, None)
        else:
            assert control.evidence in readiness.EVIDENCE and control.rule
    assert set(load_frameworks()) == {"ai_act", "gdpr", "iso27001", "kvkk", "soc2"}


_TEXTS = {"gap": "g", "next_steps": [{"type": "organization", "text": "t"}]}


def _anchor(heading: str) -> str:
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def test_every_control_has_a_gap_and_steps_that_resolve() -> None:
    docs = Path(__file__).parents[2] / "docs"
    anchors = {
        path.name: {
            _anchor(line.lstrip("#"))
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.startswith("#")
        }
        for path in docs.glob("*.md")
    }
    forbidden = re.compile(r"compliant|certified|conformity|score|%", re.I)

    for control in readiness.load_mapping().controls:
        assert 0 < len(control.gap) <= readiness.GAP_LIMIT, control.identifier
        assert not forbidden.search(control.gap), control.identifier
        assert 1 <= len(control.next_steps) <= readiness.MAX_STEPS
        types = [step.type for step in control.next_steps]
        assert types == sorted(types, key=readiness.STEP_TYPES.index)
        for step in control.next_steps:
            assert 0 < len(step.text) <= readiness.STEP_LIMIT, control.identifier
            assert not forbidden.search(step.text), control.identifier
            if step.type == "in_shim":
                assert step.doc is not None
                name, _, anchor = step.doc.partition("#")
                assert anchor in anchors[name], (control.identifier, step.doc)
            else:
                assert step.doc is None
    a84 = readiness.load_mapping().control("A.8.4")
    assert a84 is not None and a84.source == "declared"
    assert [(s.type, s.doc) for s in a84.next_steps] == [
        ("in_shim", "COOKBOOK.md#record-an-incident"),
        ("organization", None),
    ]


def _step(**fields) -> dict:
    return {"type": "organization", "text": "t", **fields}


@pytest.mark.parametrize(
    "texts",
    [
        {"next_steps": [_step()]},
        {"gap": "g" * 301, "next_steps": [_step()]},
        {"gap": "g", "next_steps": []},
        {"gap": "g", "next_steps": [_step()] * 5},
        {"gap": "g", "next_steps": [_step(type="vendor")]},
        {"gap": "g", "next_steps": [_step(type="in_shim")]},
        {"gap": "g", "next_steps": [_step(doc="COOKBOOK.md#x")]},
        {"gap": "g", "next_steps": [_step(text="t" * 241)]},
        {"gap": "g", "next_steps": ["organization: t"]},
    ],
)
def test_a_control_without_valid_texts_is_refused_by_id(
    monkeypatch: pytest.MonkeyPatch, texts
) -> None:
    mapping = {
        "framework": "iso42001",
        "verified_against_standard": False,
        "controls": [{"id": "A.1", "title": "t", "source": "declared", **texts}],
    }
    monkeypatch.setattr(readiness.yaml, "safe_load", lambda _: mapping)
    readiness.load_mapping.cache_clear()
    try:
        with pytest.raises(ValueError, match="for A.1$"):
            readiness.load_mapping()
    finally:
        readiness.load_mapping.cache_clear()


@pytest.mark.parametrize(
    ("source", "present", "declared", "status"),
    [
        ("measured", True, None, "ready"),
        ("measured", False, None, "gap"),
        ("measured", False, "implemented", "gap"),
        ("input", True, "implemented", "ready"),
        ("input", True, "not_applicable", "ready"),
        ("input", True, "partial", "partial"),
        ("input", True, None, "partial"),
        ("input", True, "not_implemented", "gap"),
        ("input", False, "implemented", "gap"),
        ("input", False, None, "gap"),
        ("declared", False, "implemented", "ready"),
        ("declared", False, "not_applicable", "ready"),
        ("declared", False, "partial", "partial"),
        ("declared", False, "not_implemented", "gap"),
        ("declared", False, None, "gap"),
    ],
)
def test_the_status_follows_source_evidence_and_declaration(
    source: str, present: bool, declared: str | None, status: str
) -> None:
    assert readiness.readiness_status(source, present, declared) == status


@pytest.mark.parametrize(
    "broken",
    [
        {"verified_against_standard": "no"},
        {"framework": "iso27001"},
        {"controls": [{"id": "A.1", "title": "t", "source": "guessed"}]},
        {
            "controls": [
                {
                    "id": "A.1",
                    "title": "t",
                    "source": "declared",
                    "evidence": "operation",
                }
            ]
        },
        {
            "controls": [
                {
                    "id": "A.1",
                    "title": "t",
                    "source": "measured",
                    "evidence": "operation",
                }
            ]
        },
        {
            "controls": [
                {
                    "id": "A.1",
                    "title": "t",
                    "source": "input",
                    "evidence": "vibes",
                    "rule": "r",
                }
            ]
        },
        {"controls": [{"id": "A.1", "title": "t", "source": "declared"}] * 2},
    ],
)
def test_a_broken_mapping_is_refused(monkeypatch: pytest.MonkeyPatch, broken) -> None:
    valid = {
        "framework": "iso42001",
        "verified_against_standard": False,
        "controls": [],
    }
    # Each case fails for its own reason, not for missing texts.
    broken = {
        **broken,
        "controls": [{**_TEXTS, **item} for item in broken.get("controls", [])],
    }
    monkeypatch.setattr(readiness.yaml, "safe_load", lambda _: {**valid, **broken})
    readiness.load_mapping.cache_clear()
    try:
        with pytest.raises(ValueError):
            readiness.load_mapping()
    finally:
        readiness.load_mapping.cache_clear()


async def _tenant(db, name: str = "Readiness"):
    organization = Organization(id=uuid4(), name=name, slug=f"ready-{uuid4().hex}")
    db.add(organization)
    await db.flush()
    owner = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"ready-{uuid4().hex}@example.com",
        role="owner",
        is_active=True,
        is_verified=True,
    )
    db.add(owner)
    await db.flush()
    await activate_organization_plan(db, organization.id, "enterprise")
    key = ApiKey(
        id=uuid4(),
        organization_id=organization.id,
        user_id=owner.id,
        key_hash=uuid4().hex,
        prefix="sk-shim-ready",
        tier="enterprise",
        is_active=True,
    )
    db.add(key)
    await db.flush()
    return organization, owner, key


def _request(db, key, started_at, metadata, *, model="gpt-5-mini", cost=None) -> str:
    request_id = f"req_ready_{uuid4().hex}"
    db.add(
        RequestLifecycle(
            request_id=request_id,
            organization_id=key.organization_id,
            actor_type="api_key",
            api_key_id=key.id,
            source_endpoint="chat.completions",
            status="completed",
            provider="openai",
            provider_model=model,
            requested_model=model,
            stream=False,
            started_at=started_at,
            reconciled_at=started_at,
            lifecycle_metadata=metadata,
        )
    )
    if cost is not None:
        common = {
            "request_id": request_id,
            "organization_id": key.organization_id,
            "api_key_id": key.id,
            "requested_model": model,
            "created_at": started_at,
        }
        quota, spend = uuid4(), uuid4()
        db.add_all(
            [
                UsageLedger(
                    id=quota,
                    event_type="quota_reservation",
                    idempotency_key=f"{request_id}:q",
                    **common,
                ),
                UsageLedger(
                    event_type="quota_settlement",
                    idempotency_key=f"{request_id}:qs",
                    reservation_event_id=quota,
                    request_count=1,
                    **common,
                ),
                UsageLedger(
                    id=spend,
                    event_type="spend_reservation",
                    idempotency_key=f"{request_id}:s",
                    provider="openai",
                    provider_model=model,
                    cost_usd=Decimal(cost),
                    **common,
                ),
                UsageLedger(
                    event_type="spend_settlement",
                    idempotency_key=f"{request_id}:ss",
                    reservation_event_id=spend,
                    provider="openai",
                    provider_model=model,
                    cost_usd=Decimal(cost),
                    **common,
                ),
            ]
        )
    return request_id


async def _evidence(db, name: str, organization_id, start, end):
    traffic = await readiness.measure_traffic(db, organization_id, start, end)
    return await readiness.EVIDENCE[name](db, organization_id, start, end, traffic)


@pytest.mark.asyncio
async def test_anchors_are_counted_by_their_utc_date(db) -> None:
    organization, _, _ = await _tenant(db)
    db.add(
        AIActAuditAnchor(
            organization_id=organization.id,
            anchor_date=date(2026, 9, 9),
            root_hash="0" * 64,
            row_count=0,
        )
    )
    await db.flush()
    istanbul = timezone(timedelta(hours=3))

    # 01:00 to 02:00 in Istanbul on 10 September is the evening of the 9th in UTC.
    event_logs = await _evidence(
        db,
        "event_logs",
        organization.id,
        datetime(2026, 9, 10, 1, tzinfo=istanbul),
        datetime(2026, 9, 10, 2, tzinfo=istanbul),
    )

    assert "1 daily anchor(s)" in event_logs.summary


@pytest.mark.asyncio
async def test_every_admission_rule_counts_as_an_admission_verdict(db) -> None:
    organization, _, key = await _tenant(db)
    now = datetime.now(timezone.utc)
    _request(
        db,
        key,
        now - timedelta(hours=1),
        {
            "policy_verdicts": [
                {
                    "rule_id": "api_key.access",
                    "stage": "admission",
                    "outcome": "deny",
                    "reason_code": "API_KEY_ACCESS_DENIED",
                }
            ]
        },
    )
    await db.flush()

    use = await _evidence(
        db, "responsible_use", organization.id, now - timedelta(days=1), now
    )

    assert "1 of 1 (100.0%) with an admission verdict" in use.summary


@pytest.mark.asyncio
async def test_every_evidence_function_reads_only_its_tenant_and_window(db) -> None:
    organization, owner, key = await _tenant(db)
    _, _, other_key = await _tenant(db, "Other")
    now = datetime.now(timezone.utc)
    start, middle = now - timedelta(days=1), now - timedelta(hours=1)
    team = Team(organization_id=organization.id, name="risk")
    db.add(team)
    secret = ProviderSecret(
        id=uuid4(),
        organization_id=organization.id,
        provider="openai",
        secret_ref=f"ref-{uuid4().hex}",
        secret_backend="fernet",
        secret_version="v2",
        masked_key="masked",
    )
    db.add(secret)
    await db.flush()
    db.add(
        ModelDeployment(
            organization_id=organization.id,
            alias="support-llm",
            provider="openai",
            upstream_model="llama",
            base_url="https://a.internal/v1",
            provider_secret_id=secret.id,
            timeout_seconds=5,
            deployment_kind="internal",
            declared_version="2026-09-30",
            owner="Platform",
            enabled=True,
        )
    )
    verdicts = [
        {"rule_id": "privacy.input", "stage": "privacy", "outcome": "mask"},
        {
            "rule_id": "quota.requests_and_tokens",
            "stage": "admission",
            "outcome": "allow",
        },
    ]
    audited = _request(
        db,
        key,
        middle,
        {
            "tags": ["checkout"],
            "cost_center": "checkout",
            "team_id": str(team.id),
            "deployment_kind": "unknown",
            "policy_verdicts": verdicts,
            "pii_entities": {"TR_NATIONAL_ID": 2},
        },
        cost="0.5",
    )
    _request(
        db,
        key,
        middle,
        {"cost_center": "untagged", "tags": []},
        model="support-llm",
        cost="0.25",
    )
    _request(
        db,
        key,
        start - timedelta(days=3),
        {"tags": ["old"], "pii_entities": {"IBAN_CODE": 1}},
    )
    _request(
        db,
        other_key,
        middle,
        {"tags": ["x"], "pii_entities": {"EMAIL_ADDRESS": 7}},
        model="other-model",
        cost="9",
    )
    await db.flush()
    await write_audit_row(
        {
            "organization_id": organization.id,
            "request_id": audited,
            "policy_verdicts": [
                {
                    "rule_id": "privacy.input",
                    "outcome": "deny",
                    "reason_code": "PII_BLOCKED",
                }
            ],
        },
        db,
    )

    async def run(name: str, window_start=start, window_end=None):
        return await _evidence(
            db,
            name,
            organization.id,
            window_start,
            window_end or datetime.now(timezone.utc),
        )

    operation = await run("operation")
    assert operation.present is True
    assert "2 request(s); 1 of 2 (50.0%) with an audit row" in operation.summary
    event_logs = await run("event_logs")
    assert event_logs.present is True and "chain verified" in event_logs.summary
    use = await run("responsible_use")
    assert use.present is True
    assert "1 of 2 (50.0%) request(s) with a privacy.input verdict" in use.summary
    assert "privacy.input PII_BLOCKED: 1" in use.summary
    suppliers = await run("suppliers")
    assert suppliers.present is True
    assert "openai 2 request(s) 0.750000 USD" in suppliers.summary
    assert "other-model" not in suppliers.summary
    tooling = await run("tooling")
    assert "Registered deployments in use: support-llm." in tooling.summary
    documentation = await run("resource_documentation")
    assert documentation.present is True
    assert "support-llm (owner Platform, version 2026-09-30)" in documentation.summary
    assert "outside the registry: gpt-5-mini." in documentation.summary
    intended = await run("intended_use")
    assert intended.summary == "1 of 2 (50.0%) request(s) carry a tag or a cost center."
    personal = await run("personal_data")
    assert "TR_NATIONAL_ID via openai 2" in personal.summary
    assert (
        "IBAN_CODE" not in personal.summary and "EMAIL_ADDRESS" not in personal.summary
    )
    inventory = await run("inventory")
    assert "Teams: risk." in inventory.summary
    assert (
        "TR_NATIONAL_ID" in inventory.summary and "other-model" not in inventory.summary
    )

    empty_end = start - timedelta(days=10)
    for name in readiness.EVIDENCE:
        empty = await run(name, empty_end - timedelta(days=1), empty_end)
        if name != "resource_documentation":
            assert empty.present is False, name


def _client(db, user) -> httpx.AsyncClient:
    application = FastAPI()
    application.include_router(compliance_router, prefix="/api/v1")
    application.dependency_overrides[enterprise_deps.get_current_user] = lambda: user
    application.dependency_overrides[get_db] = lambda: db
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    )


@pytest.mark.asyncio
async def test_declarations_are_read_by_readers_and_written_by_admins(
    db, audit_events
) -> None:
    organization, owner, _ = await _tenant(db)
    url = "/api/v1/compliance/readiness/iso42001/declarations"
    async with _client(db, owner) as client:
        first = await client.put(
            f"{url}/A.3.2", json={"status": "partial", "note": "RACI draft"}
        )
        second = await client.put(
            f"{url}/A.3.2", json={"status": "implemented", "note": "RACI draft"}
        )
        unknown = await client.put(f"{url}/A.99", json={"status": "partial"})
        invalid = [
            (await client.put(f"{url}/A.3.3", json=body)).status_code
            for body in (
                {"status": "done"},
                {"status": "partial", "note": "x" * 2001},
                {},
            )
        ]
        owner.role = "auditor"
        listed = await client.get(url)
        auditor_put = await client.put(f"{url}/A.3.3", json={"status": "partial"})
        owner.role = "member"
        member_get = await client.get(url)

    assert (first.status_code, second.status_code) == (200, 200)
    assert second.json()["status"] == "implemented"
    assert unknown.status_code == 404
    assert invalid == [422, 422, 422]
    assert [(row["control_id"], row["status"]) for row in listed.json()] == [
        ("A.3.2", "implemented")
    ]
    assert (auditor_put.status_code, member_get.status_code) == (403, 403)
    events = [
        event["extra"]
        for event in await audit_events(organization.id)
        if event["endpoint"] == "tenant.readiness_declared"
    ]
    assert events == [
        {
            "subject_id": str(organization.id),
            "actor_type": "user_jwt",
            "framework": "iso42001",
            "control_id": "A.3.2",
            "after": {"status": "partial"},
            "note_changed": True,
        },
        {
            "subject_id": str(organization.id),
            "actor_type": "user_jwt",
            "framework": "iso42001",
            "control_id": "A.3.2",
            "before": {"status": "partial"},
            "after": {"status": "implemented"},
            "note_changed": False,
        },
    ]


@pytest.mark.asyncio
async def test_the_report_has_38_rows_its_cover_and_is_paid(
    db, monkeypatch: pytest.MonkeyPatch
) -> None:
    organization, owner, key = await _tenant(db)
    now = datetime.now(timezone.utc)
    _request(db, key, now - timedelta(hours=1), {"tags": ["checkout"]})
    await db.flush()
    url = "/api/v1/compliance/reports/readiness"

    def body(fmt: str, **window) -> dict:
        return {"framework": "iso42001", "format": fmt, **window}

    async with _client(db, owner) as client:
        await client.put(
            "/api/v1/compliance/readiness/iso42001/declarations/A.3.2",
            json={"status": "implemented", "note": "=HYPERLINK(1)"},
        )
        owner.role = "auditor"
        # Shipped off until the control numbering is verified; an operator grants it.
        not_yet = await client.post(url, json=body("csv"))
        await db.execute(
            text(
                "UPDATE tier_definitions SET features = features || "
                "'{\"readiness_report\": true}'::jsonb WHERE slug = 'enterprise'"
            )
        )
        csv_report = await client.post(url, json=body("csv"))
        pdf_report = await client.post(url, json=body("pdf"))
        too_long = await client.post(
            url,
            json=body(
                "csv",
                start=(now - timedelta(days=367)).isoformat(),
                end=now.isoformat(),
            ),
        )
        other_framework = await client.post(url, json={"framework": "iso27001"})
        verified = replace(readiness.load_mapping(), verified_against_standard=True)
        monkeypatch.setattr(readiness, "load_mapping", lambda: verified)
        verified_pdf = await client.post(url, json=body("pdf"))
        await activate_organization_plan(db, organization.id, "free")
        unpaid = await client.post(url, json=body("csv"))

    assert not_yet.status_code == 403
    assert not_yet.json()["detail"]["eligible_plans"] == []
    assert csv_report.status_code == 200
    preamble, table = csv_report.content.decode("utf-8-sig").split("\r\n\r\n", 1)
    assert list(csv.reader(io.StringIO(preamble))) == [
        [readiness.COVER],
        [readiness.UNVERIFIED],
    ]
    rows = list(csv.DictReader(io.StringIO(table)))
    assert len(rows) == 38
    by_id = {row["control_id"]: row for row in rows}
    assert by_id["A.3.2"]["declaration"] == "implemented"
    assert by_id["A.3.2"]["note"] == "'=HYPERLINK(1)"
    assert by_id["A.2.3"]["declaration"] == "not declared"
    assert by_id["A.9.4"]["source"] == "input"
    assert "1 of 1" in by_id["A.9.4"]["evidence"]
    assert by_id["A.6.2.6"]["evidence_present"] in {"true", "false"}
    pdf_text = _pdf_text(pdf_report.content)
    assert readiness.COVER in pdf_text
    assert readiness.UNVERIFIED in pdf_text
    assert readiness.UNVERIFIED not in _pdf_text(verified_pdf.content)
    assert (too_long.status_code, other_framework.status_code) == (422, 422)
    assert unpaid.status_code == 403
    assert unpaid.json()["detail"]["code"] == "PLAN_UPGRADE_REQUIRED"
    assert unpaid.json()["detail"]["eligible_plans"] == ["enterprise"]


@pytest.mark.asyncio
async def test_an_auditor_may_post_the_readiness_report(
    db, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, auditor, _ = await _tenant(db)
    auditor.role = "auditor"

    async def as_auditor(request, bearer, session):
        return auditor

    monkeypatch.setattr(enterprise_deps, "get_invite_user", as_auditor)

    async def resolve(method: str, path: str):
        request = Request(
            {"type": "http", "method": method, "path": path, "headers": []}
        )
        return await enterprise_deps.get_current_user(request, None, db)

    assert await resolve("POST", "/api/v1/compliance/reports/readiness") is auditor
    with pytest.raises(HTTPException) as refused:
        await resolve("PUT", "/api/v1/compliance/readiness/iso42001/declarations/A.3.2")
    assert refused.value.status_code == 403


def _long_rows(note: str) -> list:
    usage = readiness._usage(
        [
            BillingBreakdown(f"provider-model-{index:03d}", 1, 0, 0, Decimal("0.5"))
            for index in range(200)
        ]
    )
    summary = f"Providers: {usage}. Models: {usage}."
    return [
        readiness.ReadinessRow(
            control,
            None if control.evidence is None else readiness.Evidence(True, summary),
            ReadinessDeclaration(status="partial", note=note),
        )
        for control in readiness.load_mapping().controls
    ]


@pytest.mark.parametrize("note", [("Wide words " * 200)[:2000], "W" * 2000])
def test_a_2000_character_note_and_a_200_entry_inventory_render(note: str) -> None:
    rows = _long_rows(note)
    now = datetime.now(timezone.utc)

    pdf = readiness.render_pdf(
        rows, tenant_id=uuid4(), start=now - timedelta(days=30), end=now, verified=False
    )
    table = list(
        csv.reader(
            io.StringIO(readiness.render_csv(rows, verified=False).decode("utf-8-sig"))
        )
    )

    text = _pdf_text(pdf)
    assert readiness.COVER in text
    assert "(truncated, see CSV)" in text
    assert "provider-model-199" not in text
    # The CSV keeps every word.
    assert table[-1][7] == note
    assert all("provider-model-199" in row[4] for row in table[4:] if row[4])


def test_the_csv_leads_with_the_cover_and_the_unverified_sentence() -> None:
    rows = _long_rows("short")

    unverified = list(
        csv.reader(
            io.StringIO(readiness.render_csv(rows, verified=False).decode("utf-8-sig"))
        )
    )
    verified = list(
        csv.reader(
            io.StringIO(readiness.render_csv(rows, verified=True).decode("utf-8-sig"))
        )
    )

    assert unverified[:3] == [[readiness.COVER], [readiness.UNVERIFIED], []]
    assert unverified[3][0] == "control_id" and len(unverified) == 3 + 1 + 38
    assert verified[:2] == [[readiness.COVER], []]
    assert verified[2][0] == "control_id" and len(verified) == 2 + 1 + 38


def _mixed_rows() -> list:
    evidence = {"A.4.2": True, "A.2.2": True, "A.4.3": True, "A.9.4": True}
    declared = {
        "A.2.2": "implemented",
        "A.9.4": "not_implemented",
        "A.3.2": "implemented",
        "A.2.3": "partial",
        "A.8.4": "not_applicable",
    }
    return [
        readiness.ReadinessRow(
            control,
            None
            if control.evidence is None
            else readiness.Evidence(evidence.get(control.identifier, False), "s"),
            None
            if control.identifier not in declared
            else ReadinessDeclaration(status=declared[control.identifier], note=None),
        )
        for control in readiness.load_mapping().controls
    ]


def test_the_gap_list_holds_every_partial_and_gap_control_in_order() -> None:
    rows = _mixed_rows()
    now = datetime.now(timezone.utc)
    ready = {"A.4.2", "A.2.2", "A.3.2", "A.8.4"}
    order = [r.control.identifier for r in rows if r.control.identifier not in ready]
    expected = [i for i in order if i not in {"A.2.3", "A.4.3"}] + ["A.2.3", "A.4.3"]

    text = _pdf_text(
        readiness.render_pdf(
            rows, tenant_id=uuid4(), start=now, end=now, verified=False
        )
    )
    verified_text = _pdf_text(
        readiness.render_pdf(rows, tenant_id=uuid4(), start=now, end=now, verified=True)
    )
    table = list(
        csv.reader(
            io.StringIO(readiness.render_csv(rows, verified=False).decode("utf-8-sig"))
        )
    )

    gap_list = text[text.index("Gap list and next steps") :]
    listed = re.findall(r"(A\.[\d.]+\d) [^()]+ \((gap|partial)\)", gap_list)
    assert [identifier for identifier, _ in listed] == expected
    assert dict(listed)["A.2.3"] == "partial" and dict(listed)["A.5.2"] == "gap"
    assert readiness.GAP_LIST_NOTE in gap_list
    a43 = gap_list[gap_list.index("A.4.3 ") :]
    assert a43.index("In shim: ") < a43.index("Organization: ")
    assert readiness.UNVERIFIED in text and readiness.UNVERIFIED not in verified_text
    header, *body = table[3:]
    assert header == [*header[:8], "status", "next_steps"]
    assert header[:8] == list(readiness._CSV_FIELDS[:8])
    by_id = {row[0]: dict(zip(header, row)) for row in body}
    assert {i for i, row in by_id.items() if row["status"] == "ready"} == ready
    assert by_id["A.4.2"]["next_steps"] == ""
    assert by_id["A.4.3"]["next_steps"].startswith("in_shim: Use the personal data")
    assert " | organization: " in by_id["A.4.3"]["next_steps"]
    forbidden = re.compile(r"compliant|certified|conformity|score|%", re.I)
    assert not forbidden.search(gap_list)
    assert not any(forbidden.search(row["next_steps"]) for row in by_id.values())
