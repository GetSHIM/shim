from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from ee.tests.findings.test_findings import _deployment, _evaluate
from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.core.database import get_db
from shim_enterprise.findings import service
from shim_enterprise.findings.models import Finding
from shim_enterprise.findings.service import RULES, rule_doc
from shim_enterprise.tenants.models import Organization, User

DOCS = Path(__file__).parents[2] / "docs" / "FINDINGS.md"
PACKAGED = Path(service.__file__).with_name("FINDINGS.md")


def test_the_packaged_copy_is_the_documentation() -> None:
    assert PACKAGED.read_bytes() == DOCS.read_bytes(), (
        "cp ee/docs/FINDINGS.md ee/src/shim_enterprise/findings/FINDINGS.md"
    )


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_every_rule_has_its_own_section(rule_id: str) -> None:
    doc = rule_doc(rule_id)

    assert doc is not None and doc.startswith(f"## {rule_id}\n")
    assert "\n## " not in doc
    assert len(doc.encode()) <= 16 * 1024


def test_a_missing_section_is_none_and_a_long_one_is_cut_at_a_line(monkeypatch) -> None:
    long = "## gateway.long\n" + "".join(f"line {n} {'x' * 60}\n" for n in range(400))
    monkeypatch.setattr(service, "_findings_doc", lambda: f"# T\n{long}## next\n")

    cut = rule_doc("gateway.long")

    assert rule_doc("gateway.nothing") is None
    assert cut is not None and cut.endswith("\n...")
    assert len(cut.encode()) <= 16 * 1024 + 3
    assert cut[:-4] == long[: len(cut) - 4]


@pytest.mark.asyncio
async def test_explain_returns_the_finding_and_its_rule_facts(
    db, test_api_key, test_user_with_org
) -> None:
    await _deployment(db, test_api_key, age=timedelta(days=40))
    await _evaluate(db, test_api_key)
    finding = await db.scalar(
        select(Finding).where(Finding.organization_id == test_api_key.organization_id)
    )
    stranger_org = Organization(
        id=uuid4(), name="Other", slug=f"other-{uuid4().hex}", tier="enterprise"
    )
    db.add(stranger_org)
    await db.flush()
    stranger = User(
        id=uuid4(),
        organization_id=stranger_org.id,
        email=f"other-{uuid4().hex}@example.com",
        role="owner",
        is_active=True,
        is_verified=True,
    )
    db.add(stranger)
    await db.flush()
    test_user_with_org.role = "auditor"

    async def get(user: User) -> httpx.Response:
        app = FastAPI()
        app.include_router(management_router, prefix="/api/v1")
        app.dependency_overrides[get_current_user] = lambda: user
        app.dependency_overrides[get_db] = lambda: db
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            return await client.get(f"/api/v1/management/findings/{finding.id}/explain")

    read = await get(test_user_with_org)
    foreign = await get(stranger)

    assert read.status_code == 200, read.text
    body = read.json()
    assert body["finding"]["id"] == str(finding.id)
    assert body["rule"]["rule_id"] == finding.rule_id == "gateway.unused_deployment"
    assert body["rule"]["action_kind"] == "deployment.disable"
    assert body["rule"]["doc"].startswith("## gateway.unused_deployment\n")
    assert foreign.status_code == 404
