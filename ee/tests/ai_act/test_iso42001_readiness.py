import base64
import csv
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import io
from importlib import resources
import re
from uuid import uuid4
import zlib

import httpx
import pytest
import yaml
from fastapi import FastAPI, HTTPException
from starlette.requests import Request

import shim_enterprise.api.enterprise_deps as enterprise_deps
from shim_enterprise.ai_act.api import router as compliance_router
from shim_enterprise.ai_act.audit_writer import write_audit_row
from shim_enterprise.ai_act.readiness import report as readiness
from shim_enterprise.ai_act.report import load_frameworks
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
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
        {"rule_id": "privacy.input", "outcome": "mask"},
        {"rule_id": "quota.requests_and_tokens", "outcome": "allow"},
    ]
    audited = _request(
        db,
        key,
        middle,
        {
            "tags": ["checkout"],
            "cost_center": "checkout",
            "team_id": str(team.id),
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
        return await readiness.EVIDENCE[name](
            db, organization.id, window_start, window_end or datetime.now(timezone.utc)
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

    assert csv_report.status_code == 200
    rows = list(csv.DictReader(io.StringIO(csv_report.content.decode("utf-8-sig"))))
    assert len(rows) == 38
    by_id = {row["control_id"]: row for row in rows}
    assert by_id["A.3.2"]["declaration"] == "implemented"
    assert by_id["A.3.2"]["note"] == "'=HYPERLINK(1)"
    assert by_id["A.2.3"]["declaration"] == "not declared"
    assert by_id["A.9.4"]["source"] == "input"
    assert "1 of 1" in by_id["A.9.4"]["evidence"]
    assert by_id["A.6.2.6"]["evidence_present"] in {"true", "false"}
    text = _pdf_text(pdf_report.content)
    assert readiness.COVER in text
    assert readiness.UNVERIFIED in text
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
