from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import event, select

from shim.findings import Finding as FindingV1
from shim.jsonschema_subset import check
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.findings import service
from shim_enterprise.findings.models import Finding
from shim_enterprise.tenants.models import ApiKey, Organization, User

NOW = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)
HASH = "hmac-sha256:v1:" + "a" * 64
SCHEMA = json.loads(
    (Path(__file__).parents[3] / "docs" / "schemas" / "finding-v1.json").read_text()
)


def _row(
    key: ApiKey,
    analysis: dict,
    *,
    outcome: str | None = "complete",
    model: str = "gpt-5-mini",
    started_at: datetime = NOW - timedelta(hours=1),
    **metadata,
) -> RequestLifecycle:
    return RequestLifecycle(
        request_id=f"req_quality_{uuid4().hex}",
        organization_id=key.organization_id,
        actor_type="api_key",
        api_key_id=key.id,
        source_endpoint="chat.completions",
        status="completed",
        requested_model=model,
        stream=False,
        started_at=started_at,
        lifecycle_metadata={
            "completion_outcome": outcome,
            "response_analysis": analysis,
            **metadata,
        },
    )


def _language(request: str = "tr", answer: str = "tr") -> dict:
    return {"language": {"request": request, "answer": answer}}


def _schema(valid: bool | None, expected: str = "json_schema", **values) -> dict:
    return {
        "schema": {
            "expected": expected,
            "valid": valid,
            "error_path": None if valid else "/items/0/customer_name",
            "unsupported": False,
            **values,
        }
    }


def _refusal(soft: bool, marker: str | None = None) -> dict:
    return {"refusal": {"soft_refusal": soft, "marker": marker}}


async def _detections(db, key: ApiKey, rule) -> list[service.Detection]:
    await db.flush()
    return await rule(db, key.organization_id, NOW)


async def _other_key(db) -> ApiKey:
    organization = Organization(
        id=uuid4(), name="Other", slug=f"quality-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    owner = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"quality-{uuid4().hex}@example.com",
        role="owner",
        is_active=True,
        is_verified=True,
    )
    db.add(owner)
    await db.flush()
    key = ApiKey(
        id=uuid4(),
        organization_id=organization.id,
        user_id=owner.id,
        key_hash=uuid4().hex,
        prefix="sk-shim-qua",
        tier="enterprise",
        is_active=True,
    )
    db.add(key)
    await db.flush()
    return key


def _published(detection: service.Detection, key: ApiKey) -> FindingV1:
    row = Finding(
        id=uuid4(),
        organization_id=key.organization_id,
        rule_id=detection.rule_id,
        rule_version=1,
        subject_key=detection.subject_key,
        subject=detection.subject,
        title=service.RULES[detection.rule_id].TITLE,
        summary="",
        severity_id=service.RULES[detection.rule_id].SEVERITY_ID,
        status_id=1,
        first_seen_at=NOW,
        last_seen_at=NOW,
        occurrences=1,
        evidence=detection.evidence,
        impact=detection.impact,
        remediation={"text": "", "doc": ""},
        source="gateway",
    )
    finding = service.finding_from_row(row)
    result = check(finding.model_dump(mode="json"), SCHEMA)
    assert result.valid is None, result
    return finding


@pytest.mark.parametrize(
    ("analysed", "drifts", "fires"), [(20, 2, True), (19, 2, False), (101, 10, False)]
)
@pytest.mark.asyncio
async def test_language_drift_fires_at_20_turkish_questions_and_10_percent(
    db, test_api_key, analysed: int, drifts: int, fires: bool
) -> None:
    db.add_all(
        _row(test_api_key, _language(answer="en"), system_prompt_hash=HASH)
        for _ in range(drifts)
    )
    db.add_all(_row(test_api_key, _language()) for _ in range(analysed - drifts))
    # Never counted: English questions, other and unknown answers, rows without the key.
    db.add_all(
        [
            _row(test_api_key, _language("en", "en")),
            _row(test_api_key, _language("en", "tr")),
            _row(test_api_key, _language("tr", "other")),
            _row(test_api_key, _language("tr", "unknown")),
            _row(test_api_key, {"shape": {"turns": 1}}),
        ]
    )

    found = await _detections(db, test_api_key, service._language_drift)

    assert bool(found) is fires
    if fires:
        [detection] = found
        assert detection.subject == {"api_key_id": str(test_api_key.id)}
        assert detection.evidence["analysed_requests"] == analysed
        assert detection.evidence["drifts"] == drifts
        assert detection.evidence["prompt_versions"] == [HASH]
        assert detection.evidence["models"] == [
            {"model": "gpt-5-mini", "analysed": analysed, "drifts": drifts}
        ]
        assert len(detection.evidence["request_ids"]) == drifts
        assert _published(detection, test_api_key).measurements["drifts"] == drifts


@pytest.mark.asyncio
async def test_language_drift_keeps_five_prompt_versions_and_drops_other_text(
    db, test_api_key
) -> None:
    hashes = [f"hmac-sha256:v1:{index:064x}" for index in range(7)]
    db.add_all(
        _row(test_api_key, _language(answer="en"), system_prompt_hash=value)
        for value in [*hashes, "not a digest"]
    )
    db.add_all(_row(test_api_key, _language()) for _ in range(12))

    [detection] = await _detections(db, test_api_key, service._language_drift)

    assert detection.evidence["prompt_versions"] == sorted(hashes)[:5]


@pytest.mark.parametrize(
    ("checked", "invalid", "fires"), [(20, 1, True), (19, 1, False), (21, 1, False)]
)
@pytest.mark.asyncio
async def test_schema_errors_fire_at_20_checked_and_5_percent(
    db, test_api_key, checked: int, invalid: int, fires: bool
) -> None:
    db.add_all(_row(test_api_key, _schema(False)) for _ in range(invalid))
    db.add_all(_row(test_api_key, _schema(True)) for _ in range(checked - invalid))
    # Never counted: unsupported schemas, truncated answers, unchecked and no schema.
    db.add_all(
        [
            _row(test_api_key, _schema(False, unsupported=True)),
            _row(test_api_key, _schema(False), outcome="truncated"),
            _row(test_api_key, _schema(None)),
            _row(test_api_key, _schema(None, expected="none")),
        ]
    )

    found = await _detections(db, test_api_key, service._schema_errors)

    assert bool(found) is fires
    if fires:
        [detection] = found
        assert detection.evidence["checked_requests"] == checked
        assert detection.evidence["invalid"] == invalid
        assert detection.evidence["checked_json_schema"] == checked
        assert detection.evidence["invalid_json_schema"] == invalid
        assert "customer_name" not in json.dumps(detection.evidence)
        assert _published(detection, test_api_key).severity == "medium"


@pytest.mark.asyncio
async def test_schema_errors_split_by_kind_and_model(db, test_api_key) -> None:
    db.add_all(
        _row(test_api_key, _schema(False, "tool_args"), model="m-1") for _ in range(2)
    )
    db.add_all(
        _row(test_api_key, _schema(True, "json_object"), model="m-2") for _ in range(18)
    )

    [detection] = await _detections(db, test_api_key, service._schema_errors)

    assert {
        key: value
        for key, value in detection.evidence.items()
        if key.startswith(("checked_", "invalid_"))
    } == {
        "checked_json_object": 18,
        "checked_requests": 20,
        "checked_tool_args": 2,
        "invalid_json_object": 0,
        "invalid_tool_args": 2,
    }
    assert detection.evidence["models"] == [
        {"model": "m-2", "checked": 18, "invalid": 0},
        {"model": "m-1", "checked": 2, "invalid": 2},
    ]


@pytest.mark.parametrize(
    ("analysed", "refused", "fires"), [(60, 3, True), (49, 3, False), (61, 3, False)]
)
@pytest.mark.asyncio
async def test_soft_refusals_fire_at_50_answers_and_5_percent(
    db, test_api_key, analysed: int, refused: int, fires: bool
) -> None:
    db.add_all(
        _row(test_api_key, _refusal(True, "tr.yardimci_olamam"))
        for _ in range(refused - 1)
    )
    db.add(_row(test_api_key, _refusal(True, "en.cant_help")))
    db.add_all(_row(test_api_key, _refusal(False)) for _ in range(analysed - refused))
    # Never counted: answers that did not end complete.
    db.add_all(
        _row(test_api_key, _refusal(True, "tr.yardimci_olamam"), outcome="truncated")
        for _ in range(5)
    )

    found = await _detections(db, test_api_key, service._soft_refusals)

    assert bool(found) is fires
    if fires:
        [detection] = found
        assert detection.evidence["analysed_requests"] == analysed
        assert detection.evidence["soft_refusals"] == refused
        measured = _published(detection, test_api_key).measurements
        assert measured["marker_tr_yardimci_olamam"] == refused - 1
        assert measured["marker_en_cant_help"] == 1
        assert "olamam" not in detection.evidence.get("note", "")
        assert "yardımcı" not in json.dumps(detection.evidence)


@pytest.mark.asyncio
async def test_a_marker_outside_the_vocabulary_is_dropped(db, test_api_key) -> None:
    db.add_all(_row(test_api_key, _refusal(True, "Sorry, I can't")) for _ in range(5))
    db.add_all(_row(test_api_key, _refusal(False)) for _ in range(45))

    [detection] = await _detections(db, test_api_key, service._soft_refusals)

    assert detection.evidence["soft_refusals"] == 5
    assert not any(key.startswith("marker_") for key in detection.evidence)
    assert "Sorry" not in json.dumps(detection.evidence)


@pytest.mark.asyncio
async def test_a_tenant_without_analysis_rows_gets_nothing_in_one_query_a_rule(
    db, test_api_key
) -> None:
    other = await _other_key(db)
    db.add_all(_row(other, _language(answer="en")) for _ in range(20))
    db.add_all(_row(test_api_key, {}) for _ in range(60))
    await db.flush()
    connection = await db.connection()
    sent: list[str] = []

    def capture(_conn, _cursor, statement, *_args) -> None:
        sent.append(statement)

    event.listen(connection.sync_connection, "before_cursor_execute", capture)
    try:
        for rule in (
            service._language_drift,
            service._schema_errors,
            service._soft_refusals,
        ):
            assert await rule(db, test_api_key.organization_id, NOW) == []
    finally:
        event.remove(connection.sync_connection, "before_cursor_execute", capture)

    assert len(sent) == 3


@pytest.mark.asyncio
async def test_the_worker_raises_the_three_findings_in_observe(
    db, test_api_key
) -> None:
    db.add_all(_row(test_api_key, _language(answer="en")) for _ in range(20))
    db.add_all(_row(test_api_key, _schema(False)) for _ in range(20))
    db.add_all(
        _row(test_api_key, _refusal(True, "tr.yardimci_olamam")) for _ in range(50)
    )
    await db.flush()

    await service.evaluate_organization(db, test_api_key.organization_id, now=NOW)
    rows = list(
        await db.scalars(
            select(Finding).where(
                Finding.organization_id == test_api_key.organization_id
            )
        )
    )

    assert {row.rule_id for row in rows} == {
        service.LANGUAGE_DRIFT,
        service.SCHEMA_ERRORS,
        service.SOFT_REFUSALS,
    }
    for row in rows:
        assert service.LADDER[row.rule_id] == service.RuleLadder("observe", None)
        assert (row.remediation["mode"], row.remediation["action"]) == ("observe", None)
        assert (
            check(service.finding_from_row(row).model_dump(mode="json"), SCHEMA).valid
            is None
        )
