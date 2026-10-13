from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from types import MethodType, SimpleNamespace
from uuid import uuid4

import pytest

from shim.gateway.kernel.attempts import AttemptOutcome
from shim.gateway.kernel.result import PreparedInference
from shim.gateway.pipeline.provider_execution import ProviderCallError
from shim_enterprise.core.config import settings
from shim_enterprise.gateway.attempts import AttemptCandidate, TenantAttemptPolicy
from shim_enterprise.tenants.models import ApiKey, ModelDeployment, ProviderSecret


class _Strategy:
    def __init__(self, name: str, candidate: AttemptCandidate | None) -> None:
        self.name = name
        self.candidate = candidate
        self.asked = 0

    async def after_privacy(self, prepared):
        self.asked += 1
        return self.candidate

    async def after_outcome(self, outcome):
        self.asked += 1
        return self.candidate


def _prepared(api_key: ApiKey, provider: str = "openai") -> SimpleNamespace:
    prepared = SimpleNamespace(
        api_key_id=api_key.id,
        tenant_id=api_key.organization_id,
        provider=provider,
        target=None,
        deployment_kind="unknown",
        policy_verdicts=[],
    )
    prepared.record_verdict = MethodType(PreparedInference.record_verdict, prepared)
    return prepared


async def _deployment(db, api_key: ApiKey, alias: str, **values) -> ModelDeployment:
    secret = ProviderSecret(
        id=uuid4(),
        organization_id=api_key.organization_id,
        provider=values.get("provider", "openai"),
        secret_ref=f"reference-{uuid4().hex}",
        secret_backend="fernet",
        secret_version="v2",
        masked_key="masked",
    )
    db.add(secret)
    await db.flush()
    row = ModelDeployment(
        **{
            "organization_id": api_key.organization_id,
            "alias": alias,
            "provider": "openai",
            "upstream_model": f"{alias}-upstream",
            "base_url": "https://a.internal/v1",
            "provider_secret_id": secret.id,
            "timeout_seconds": 5,
            "deployment_kind": "internal",
            "declared_version": "v1",
            "owner": "Platform",
            **values,
        }
    )
    db.add(row)
    await db.flush()
    return row


def _factory(db, opened: list[int]):
    @asynccontextmanager
    async def session():
        opened.append(1)
        yield db

    return session


@pytest.fixture
def origins(monkeypatch):
    monkeypatch.setattr(
        settings, "MODEL_DEPLOYMENT_ALLOWED_ORIGINS", ["https://a.internal"]
    )
    monkeypatch.setattr(
        settings, "MODEL_DEPLOYMENT_INTERNAL_ORIGINS", ["https://a.internal"]
    )


def _skips(prepared) -> list[str]:
    return [
        verdict.reason_code
        for verdict in prepared.policy_verdicts
        if verdict.rule_id == "gateway.attempt"
    ]


@pytest.mark.asyncio
async def test_with_no_strategy_the_policy_does_no_io() -> None:
    def factory():
        raise AssertionError("no strategy, no session")

    policy = TenantAttemptPolicy(factory, strategies=())

    assert await policy.choose_target_after_privacy(object()) is None
    assert await policy.next_attempt(object()) is None


@pytest.mark.asyncio
async def test_a_listed_deployment_becomes_a_target_and_the_first_candidate_wins(
    db, test_api_key, origins
) -> None:
    row = await _deployment(db, test_api_key, "spare-llm")
    first = _Strategy("first", AttemptCandidate("spare-llm", "fallback", "spare"))
    second = _Strategy("second", AttemptCandidate("other-llm", "overflow", "other"))
    opened: list[int] = []
    policy = TenantAttemptPolicy(_factory(db, opened), strategies=(first, second))

    target = await policy.choose_target_after_privacy(_prepared(test_api_key))

    assert (first.asked, second.asked, len(opened)) == (1, 0, 1)
    assert target.provider_target.deployment_id == str(row.id)
    assert target.provider_target.upstream_model == "spare-llm-upstream"
    assert target.provider_target.credential_reference == str(row.provider_secret_id)
    assert (target.deployment_kind, target.reason, target.rule_id) == (
        "internal",
        "fallback",
        "spare",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("values", "allowed", "code"),
    [
        ({}, ["gpt-5-nano"], "ATTEMPT_TARGET_NOT_ALLOWED"),
        ({"enabled": False}, None, "ATTEMPT_TARGET_UNAVAILABLE"),
        (
            {"health": "unhealthy", "health_checked_at": datetime.now(timezone.utc)},
            None,
            "ATTEMPT_TARGET_UNAVAILABLE",
        ),
        ({"provider": "anthropic"}, None, "ATTEMPT_TARGET_UNAVAILABLE"),
        ({"base_url": "https://b.internal/v1"}, None, "ATTEMPT_TARGET_UNAVAILABLE"),
        (None, None, "ATTEMPT_TARGET_UNAVAILABLE"),
    ],
)
async def test_a_deployment_the_key_or_the_registry_refuses_is_skipped(
    db, test_api_key, origins, values, allowed, code
) -> None:
    if values is not None:
        await _deployment(db, test_api_key, "spare-llm", **values)
    test_api_key.allowed_models = allowed
    await db.flush()
    prepared = _prepared(test_api_key)
    policy = TenantAttemptPolicy(
        _factory(db, []),
        strategies=(
            _Strategy("s", AttemptCandidate("spare-llm", "fallback", "spare")),
        ),
    )

    assert await policy.choose_target_after_privacy(prepared) is None
    assert _skips(prepared) == [code]


@pytest.mark.asyncio
async def test_the_current_target_is_offered_after_an_answer_never_after_an_error(
    test_api_key,
) -> None:
    prepared = _prepared(test_api_key)
    policy = TenantAttemptPolicy(
        _factory(None, []),
        strategies=(_Strategy("s", AttemptCandidate(None, "format_retry", "schema")),),
    )

    answered = await policy.next_attempt(
        AttemptOutcome(prepared, 1, None, True, {"choices": []})
    )
    failed = await policy.next_attempt(
        AttemptOutcome(
            prepared,
            1,
            ProviderCallError(503, "PROVIDER_UNAVAILABLE", True, provider="openai"),
            True,
            None,
        )
    )

    assert answered is not None and answered.provider_target is None
    assert (answered.reason, answered.rule_id) == ("format_retry", "schema")
    assert failed is None and _skips(prepared) == ["ATTEMPT_TARGET_UNAVAILABLE"]
