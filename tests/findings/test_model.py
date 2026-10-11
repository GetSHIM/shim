from __future__ import annotations

from copy import deepcopy
import math

from pydantic import ValidationError
import pytest

from shim.findings import Finding


def _valid() -> dict:
    return {
        "schema_version": "1",
        "id": "3f2c9e1a-0b7d-4c5e-9a1f-1234567890ab",
        "source": "gateway",
        "rule_id": "gateway.retry_storm",
        "rule_version": 1,
        "title": "Retry storm from one API key",
        "summary": {
            "en": "One key sent 20 repeated requests.",
            "tr": "Bir anahtar 20 tekrarlanan istek gönderdi.",
        },
        "severity": "medium",
        "status": "open",
        "status_detail": "new",
        "subject": {"kind": "key", "id": "11111111-1111-1111-1111-111111111111"},
        "window": {"start": "2026-10-08T12:00:00Z", "end": "2026-10-08T12:15:00Z"},
        "occurrences": 1,
        "evidence": [{"kind": "request", "id": "req_0123456789abcdef"}],
        "measurements": {"repeated_requests": 20, "share": 0.25},
        "impact": {
            "requests": 20,
            "tokens": None,
            "usd": "0.20000000",
            "risk_class": "cost",
        },
        "remediation": {
            "mode": "observe",
            "max_mode": "suggest",
            "action": {
                "kind": "client.backoff",
                "params": {"max_retries": 3, "codes": ["429"]},
            },
            "reversible": True,
            "blast_radius": "key",
            "proof_after": {
                "metric": "repeated_requests",
                "window_hours": 24,
                "baseline": 20,
                "threshold": 5,
                "comparison": "lte",
            },
            "text": {"en": "Make the client back off.", "tr": "İstemciyi geri çekin."},
        },
        "playbook": "ee/docs/FINDINGS.md#gatewayretry_storm",
    }


def _with(path: str, value: object) -> dict:
    data = deepcopy(_valid())
    *parents, last = path.split(".")
    target = data
    for name in parents:
        target = target[name]
    if value is _DROP:
        del target[last]
    else:
        target[last] = value
    return data


_DROP = object()


def test_the_example_round_trips() -> None:
    finding = Finding.model_validate(_valid())

    assert Finding.model_validate(finding.model_dump(mode="json")) == finding
    assert Finding.model_validate_json(finding.model_dump_json()) == finding


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("id", "a" * 128),
        ("id", "gateway:finding.1-2_3"),
        ("rule_id", "a." + "b" * 94),
        ("rule_id", "litellm.error_rate"),
        ("rule_version", 1),
        ("title", "t"),
        ("title", "t" * 200),
        ("summary.en", "s" * 500),
        ("status_detail", None),
        ("subject.id", "s" * 200),
        ("window.end", "2026-10-08T12:00:00Z"),
        ("occurrences", None),
        ("evidence", [{"kind": "ledger_row", "id": "x" * 200}] * 50),
        ("evidence", []),
        ("measurements", {f"m{index}": index for index in range(32)}),
        ("impact.usd", "12"),
        ("impact.usd", None),
        ("impact.requests", 0),
        ("remediation.mode", "suggest"),
        ("remediation.action", None),
        ("remediation.action.params", {f"p{index}": None for index in range(16)}),
        ("remediation.proof_after", None),
        ("remediation.proof_after.window_hours", 1),
        ("remediation.proof_after.window_hours", 720),
        ("playbook", "docs/FINDINGS_SCHEMA.md#fields"),
    ],
)
def test_values_on_the_bound_are_accepted(path, value) -> None:
    Finding.model_validate(_with(path, value))


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("schema_version", "2"),
        ("id", "a" * 129),
        ("id", "has space"),
        ("source", "proxy"),
        ("rule_id", "a." + "b" * 95),
        ("rule_id", "retry_storm"),
        ("rule_id", "Gateway.retry"),
        ("rule_version", 0),
        ("title", ""),
        ("title", "t" * 201),
        ("summary.tr", ""),
        ("summary.en", "s" * 501),
        ("summary", {"en": "only english"}),
        ("severity", "severe"),
        ("status", "new"),
        ("status_detail", "open"),
        ("subject.kind", "user"),
        ("subject.id", ""),
        ("subject.id", "s" * 201),
        ("window.start", "2026-10-08T12:30:00Z"),
        ("window.start", "2026-10-08T12:00:00"),
        ("window.start", "2026-10-08T15:00:00+03:00"),
        ("occurrences", 0),
        ("evidence", [{"kind": "request", "id": "x"}] * 51),
        ("evidence", [{"kind": "prompt", "id": "x"}]),
        ("evidence", [{"kind": "request", "id": "has space"}]),
        ("evidence", [{"kind": "request", "id": "x", "value": "y"}]),
        ("measurements", {f"m{index}": index for index in range(33)}),
        ("measurements", {"Bad": 1}),
        ("measurements", {"rate": math.nan}),
        ("measurements", {"rate": math.inf}),
        ("measurements", {"label": "text"}),
        ("impact.usd", "-1"),
        ("impact.usd", "1e-7"),
        ("impact.requests", -1),
        ("impact.risk_class", "money"),
        ("remediation.mode", "auto"),
        ("remediation.blast_radius", "world"),
        ("remediation.action.kind", "Bad"),
        ("remediation.action.params", {f"p{index}": None for index in range(17)}),
        ("remediation.action.params", {"nested": {"a": 1}}),
        ("remediation.proof_after.window_hours", 0),
        ("remediation.proof_after.window_hours", 721),
        ("remediation.proof_after.comparison", "eq"),
        ("remediation.text", {"en": "x", "tr": ""}),
        ("playbook", "https://example.com/doc.md#x"),
        ("playbook", "ee/docs/FINDINGS.md"),
        ("impact", _DROP),
    ],
)
def test_values_past_the_bound_are_refused(path, value) -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate(_with(path, value))


@pytest.mark.parametrize(
    "path",
    ["", "summary", "subject", "window", "impact", "remediation", "remediation.text"],
)
def test_an_extra_key_is_refused_on_every_closed_object(path) -> None:
    data = deepcopy(_valid())
    target = data
    for name in filter(None, path.split(".")):
        target = target[name]
    target["unexpected"] = 1

    with pytest.raises(ValidationError):
        Finding.model_validate(data)
