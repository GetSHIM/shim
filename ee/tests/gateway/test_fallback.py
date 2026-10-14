"""Fallback rules through the real kernel, resolver, registry and ledger."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from ee.tests.tenants.test_deployments import (  # noqa: F401
    _deployments,
    _gateway,
    _success,
    db,
    origins,
    test_org,
)
from shim.rules import validate_rule_set
from shim_enterprise.application import tenant_target_circuit
from shim_enterprise.billing.models import (
    QuotaPeriodUsage,
    RequestLifecycle,
)
from shim_enterprise.core.config import settings
from shim_enterprise.gateway.attempts import TenantAttemptPolicy
from shim_enterprise.gateway.fallback import CanaryFallback, UnavailableFallback
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.tenants.models import ModelDeployment, ProviderSecret

CHAT = "/v1/chat/completions"
pytestmark = pytest.mark.usefixtures("origins")


def _rule(
    state: str = "enforced",
    to: tuple[str, ...] = ("internal-b",),
    triggers: tuple[str, ...] = ("health_flag", "circuit_open", "provider_error"),
    rule_id: str = "llama_a_yedek",
) -> dict:
    return {
        "id": rule_id,
        "name": "A down: use B",
        "kind": "route",
        "action": "route",
        "state": state,
        "match": {
            "on": "unavailable",
            "from": "internal-a",
            "to": list(to),
            "triggers": list(triggers),
        },
    }


def _rules(*rules: dict):
    return validate_rule_set({"revision": 3, "rules": list(rules)})


async def _row(db, key, host: str, **values) -> ModelDeployment:  # noqa: F811
    secret = ProviderSecret(
        id=uuid4(),
        organization_id=key.organization_id,
        provider="openai",
        secret_ref=f"reference-{host}",
        secret_backend="fernet",
        secret_version="v2",
        masked_key="masked",
    )
    db.add(secret)
    await db.flush()
    row = ModelDeployment(
        **{
            "organization_id": key.organization_id,
            "alias": f"internal-{host}",
            "provider": "openai",
            "upstream_model": f"model-{host}",
            "base_url": f"https://{host}.internal/v1",
            "provider_secret_id": secret.id,
            "timeout_seconds": 5,
            "deployment_kind": "internal",
            "declared_version": "v1",
            "owner": "Platform",
            "enabled": True,
            **values,
        }
    )
    db.add(row)
    await db.flush()
    return row


def _unhealthy(row: ModelDeployment) -> None:
    row.health, row.health_checked_at = "unhealthy", datetime.now(timezone.utc)


class _Redis:
    """Circuit keys only: counts every read per key."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.reads: list[str] = []

    async def mget(self, *keys):
        self.reads.extend(keys[:1])
        return [self.values.get(key) for key in keys]

    async def set(self, *args, **kwargs):
        return True

    async def delete(self, *keys):
        return len(keys)

    async def eval(self, *args):
        return 1


def _circuit_key(cache, key, host: str) -> str:
    target = SimpleNamespace(
        tenant_id=key.organization_id,
        target=SimpleNamespace(base_url=f"https://{host}.internal/v1"),
    )
    return tenant_target_circuit("openai", cache)(target)._keys[0]


def _open(cache, redis: _Redis, key, host: str) -> None:
    failures = _circuit_key(cache, key, host)
    prefix = failures.removesuffix(":failures")
    redis.values |= {
        failures: "5",
        f"{prefix}:state": "open",
        f"{prefix}:open_until": str(datetime.now(timezone.utc).timestamp() + 60),
    }


@asynccontextmanager
async def _fallback_gateway(db, key, handler, rules, *, actions=None, cache=None):  # noqa: F811
    async with _gateway(db, key, handler, rules) as (client, app, _):
        factory = async_sessionmaker(db.bind, expire_on_commit=False)
        opened = []

        @asynccontextmanager
        async def session():
            opened.append(1)
            async with factory() as opened_session:
                yield opened_session

        kernel = app.state.gateway_service.kernel
        circuit_for = {}
        if cache is not None:
            circuit_for = {"openai": tenant_target_circuit("openai", cache)}
            kernel.executions["openai"].circuit_for = circuit_for["openai"]
        kernel.attempt_policy = TenantAttemptPolicy(
            session, (UnavailableFallback(session, circuit_for), CanaryFallback())
        )
        if actions is not None:
            resolve = kernel.policy_resolver.resolve
            resolve.return_value = resolve.return_value.model_copy(
                update={"entity_actions": actions}
            )
        yield client, opened


def _hosts(calls: list[str], status_by_host: dict[str, object]):
    def upstream(request):
        host = request.url.host[0]
        calls.append(host)
        answer = status_by_host.get(host, 200)
        if isinstance(answer, Exception):
            raise answer
        if answer != 200:
            return httpx.Response(answer, json={"error": {"message": "upstream"}})
        return _success(request, False, "chat")

    return upstream


def _body(content: str = "hello") -> dict:
    return {"model": "internal-a", "messages": [{"role": "user", "content": content}]}


async def _rows(db, key) -> list[RequestLifecycle]:  # noqa: F811
    return list(
        (
            await db.scalars(
                select(RequestLifecycle)
                .where(RequestLifecycle.organization_id == key.organization_id)
                .order_by(RequestLifecycle.started_at)
                .execution_options(populate_existing=True)
            )
        ).all()
    )


def _verdicts(row: RequestLifecycle) -> dict[str, tuple[str, str]]:
    return {
        verdict["rule_id"]: (verdict["outcome"], verdict["reason_code"])
        for verdict in (row.lifecycle_metadata or {}).get("policy_verdicts", [])
    }


async def _event_verdicts(db, key) -> dict[str, tuple[str, str]]:  # noqa: F811
    return {
        verdict["rule_id"]: (verdict["outcome"], verdict["reason_code"])
        for event in (
            await db.scalars(
                select(OutboxEvent).where(
                    OutboxEvent.organization_id == key.organization_id
                )
            )
        ).all()
        for verdict in event.payload.get("policy_verdicts", [])
    }


async def _settled_requests(db, key) -> tuple[int, int]:  # noqa: F811
    monthly = (
        await db.scalars(
            select(QuotaPeriodUsage)
            .where(
                QuotaPeriodUsage.organization_id == key.organization_id,
                QuotaPeriodUsage.api_key_id == key.id,
                QuotaPeriodUsage.period_type == "monthly",
            )
            .execution_options(populate_existing=True)
        )
    ).one()
    return monthly.settled_requests, monthly.reserved_requests


@pytest.fixture
def three_hosts(origins, monkeypatch):  # noqa: F811
    monkeypatch.setattr(
        settings,
        "MODEL_DEPLOYMENT_ALLOWED_ORIGINS",
        ["https://a.internal", "https://b.internal", "https://c.internal"],
    )


@pytest.mark.asyncio
async def test_an_unhealthy_alias_is_served_by_the_first_usable_fallback(
    db,  # noqa: F811
    test_api_key,
    three_hosts,
) -> None:
    a = await _row(db, test_api_key, "a")
    b = await _row(db, test_api_key, "b", upstream_model="gpt-5.6-luna")
    c = await _row(db, test_api_key, "c")
    _unhealthy(a)
    _unhealthy(c)
    calls = []

    async with _fallback_gateway(
        db,
        test_api_key,
        _hosts(calls, {}),
        _rules(_rule(to=("internal-c", "internal-b"))),
    ) as (client, _):
        answered = await client.post(CHAT, json=_body())

    assert answered.status_code == 200, answered.text
    assert "x-shim-attempts" not in answered.headers
    assert calls == ["b"]
    [row] = await _rows(db, test_api_key)
    assert answered.headers["x-shim-request-id"] == row.request_id
    assert row.status == "completed"
    # Priced and recorded at the deployment that answered.
    assert row.provider_model == "gpt-5.6-luna"
    decision = row.lifecycle_metadata["route_decision"]
    assert (decision["from"], decision["to"], decision["reason"]) == (
        str(a.id),
        str(b.id),
        "fallback",
    )
    assert row.lifecycle_metadata["deployment_id"] == str(b.id)
    verdicts = _verdicts(row)
    assert verdicts["deployment.registry"] == ("skip", "DEPLOYMENT_UNHEALTHY")
    assert verdicts["rule.llama_a_yedek"] == ("allow", "FALLBACK_UNHEALTHY")
    assert verdicts["gateway.attempt"] == ("skip", "ATTEMPT_TARGET_UNAVAILABLE")
    assert [
        (match["rule_id"], match["count"])
        for match in row.lifecycle_metadata["rule_matches"]
    ] == [("llama_a_yedek", 1)]
    assert c.health == "unhealthy"


@pytest.mark.asyncio
async def test_without_a_usable_fallback_the_unhealthy_answer_is_unchanged(
    db,  # noqa: F811
    test_api_key,
) -> None:
    a, b = await _deployments(db, test_api_key)
    _unhealthy(a)
    _unhealthy(b)
    calls = []
    body = {**_body(), "model": "internal-a"}

    async with _fallback_gateway(db, test_api_key, _hosts(calls, {}), None) as (
        client,
        opened,
    ):
        today = await client.post(CHAT, json=body)
    assert opened == []
    async with _fallback_gateway(
        db, test_api_key, _hosts(calls, {}), _rules(_rule())
    ) as (client, _):
        refused = await client.post(CHAT, json=body)

    assert (refused.status_code, refused.json()) == (503, today.json())
    assert refused.json()["error"]["code"] == "DEPLOYMENT_UNHEALTHY"
    assert 295 <= int(refused.headers["retry-after"]) <= 300
    assert refused.headers["x-should-retry"] == "false"
    assert calls == []
    # Now after admission: a refunded row instead of a pre-admission refusal.
    [row] = await _rows(db, test_api_key)
    assert row.status == "failed"
    assert refused.headers["x-shim-request-id"] == row.request_id
    verdicts = _verdicts(row)
    assert verdicts["rule.llama_a_yedek"] == ("skip", "FALLBACK_NO_CANDIDATE")
    assert verdicts["gateway.attempt"] == ("skip", "ATTEMPT_TARGET_UNAVAILABLE")
    assert await _settled_requests(db, test_api_key) == (0, 0)


@pytest.mark.asyncio
async def test_a_monitor_rule_records_the_fallback_on_the_refusal_only(
    db,  # noqa: F811
    test_api_key,
) -> None:
    a, _ = await _deployments(db, test_api_key)
    _unhealthy(a)
    calls = []

    async with _fallback_gateway(
        db, test_api_key, _hosts(calls, {}), _rules(_rule("monitor"))
    ) as (client, _):
        refused = await client.post(CHAT, json=_body())

    assert refused.status_code == 503
    assert refused.json()["error"]["code"] == "DEPLOYMENT_UNHEALTHY"
    assert calls == []
    assert await _rows(db, test_api_key) == []
    verdicts = await _event_verdicts(db, test_api_key)
    assert verdicts["rule.llama_a_yedek"] == ("allow", "RULE_WOULD_ROUTE")
    assert verdicts["deployment.registry"] == ("deny", "DEPLOYMENT_UNHEALTHY")


@pytest.mark.asyncio
async def test_a_disabled_source_is_refused_and_never_falls_back(
    db,  # noqa: F811
    test_api_key,
) -> None:
    a, _ = await _deployments(db, test_api_key)
    a.enabled = False
    calls = []

    async with _fallback_gateway(
        db, test_api_key, _hosts(calls, {}), _rules(_rule())
    ) as (client, _):
        refused = await client.post(CHAT, json=_body())

    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "MODEL_NOT_ALLOWED"
    assert calls == []


@pytest.mark.asyncio
async def test_a_fallback_outside_the_key_allowlist_is_skipped(
    db,  # noqa: F811
    test_api_key,
) -> None:
    a, _ = await _deployments(db, test_api_key)
    _unhealthy(a)
    test_api_key.allowed_models = ["internal-a"]
    calls = []

    async with _fallback_gateway(
        db, test_api_key, _hosts(calls, {}), _rules(_rule())
    ) as (client, _):
        refused = await client.post(CHAT, json=_body())

    assert refused.status_code == 503
    assert calls == []
    [row] = await _rows(db, test_api_key)
    assert _verdicts(row)["gateway.attempt"] == ("skip", "ATTEMPT_TARGET_NOT_ALLOWED")


_TERM = {
    "id": "falcon",
    "name": "Project names",
    "kind": "term",
    "action": "monitor",
    "state": "monitor",
    "match": {"terms": ["Project Falcon"]},
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("content", "actions", "extra", "chosen"),
    [
        ("Kimlik 10000000146", {"TR_NATIONAL_ID": "mask"}, (), False),
        ("write to alice@example.com", {"EMAIL_ADDRESS": "monitor"}, (), False),
        ("about Project Falcon", None, (_TERM,), False),
        ("hello", None, (), True),
    ],
)
async def test_an_internal_request_leaves_for_an_external_fallback_only_when_clean(
    db,  # noqa: F811
    test_api_key,
    content,
    actions,
    extra,
    chosen,
) -> None:
    a, b = await _deployments(db, test_api_key)
    _unhealthy(a)
    b.deployment_kind = "external"
    calls = []

    async with _fallback_gateway(
        db,
        test_api_key,
        _hosts(calls, {}),
        _rules(_rule(), *extra),
        actions=actions,
    ) as (client, _):
        response = await client.post(CHAT, json=_body(content))

    [row] = await _rows(db, test_api_key)
    if chosen:
        assert response.status_code == 200, response.text
        assert calls == ["b"]
        assert _verdicts(row)["rule.llama_a_yedek"] == ("allow", "FALLBACK_UNHEALTHY")
    else:
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "DEPLOYMENT_UNHEALTHY"
        assert calls == []
        assert _verdicts(row)["gateway.attempt"] == (
            "skip",
            "ATTEMPT_WOULD_LEAVE_INTERNAL",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("rules", "model", "reads_of_a"),
    [
        # Closed circuit: the strategy reads it once, the execution once.
        (_rules(_rule()), "internal-a", 2),
        (_rules(_rule(triggers=("health_flag",))), "internal-a", 1),
        (_rules(_rule("monitor")), "internal-a", 1),
        (_rules(_rule()), "internal-b", 0),
    ],
)
async def test_the_circuit_is_read_once_and_only_for_a_covered_alias(
    db,  # noqa: F811
    test_api_key,
    rules,
    model,
    reads_of_a,
) -> None:
    await _deployments(db, test_api_key)
    redis = _Redis()
    cache = SimpleNamespace(redis=redis)

    async with _fallback_gateway(
        db, test_api_key, _hosts([], {}), rules, cache=cache
    ) as (client, _):
        answered = await client.post(CHAT, json={**_body(), "model": model})

    assert answered.status_code == 200, answered.text
    assert redis.reads.count(_circuit_key(cache, test_api_key, "a")) == reads_of_a


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("state", "to_open", "status", "calls", "reason"),
    [
        ("enforced", False, 200, ["b"], ("allow", "FALLBACK_CIRCUIT_OPEN")),
        ("enforced", True, 503, [], ("skip", "FALLBACK_NO_CANDIDATE")),
        ("monitor", False, 503, [], ("allow", "RULE_WOULD_ROUTE")),
    ],
)
async def test_an_open_circuit_falls_back_before_the_call(
    db,  # noqa: F811
    test_api_key,
    state,
    to_open,
    status,
    calls,
    reason,
) -> None:
    await _deployments(db, test_api_key)
    redis = _Redis()
    cache = SimpleNamespace(redis=redis)
    _open(cache, redis, test_api_key, "a")
    if to_open:
        _open(cache, redis, test_api_key, "b")
    seen = []

    async with _fallback_gateway(
        db, test_api_key, _hosts(seen, {}), _rules(_rule(state)), cache=cache
    ) as (client, _):
        response = await client.post(CHAT, json=_body())

    assert response.status_code == status, response.text
    assert seen == calls
    if status == 503:
        assert response.json()["error"]["code"] == "PROVIDER_UNAVAILABLE"
    assert "x-shim-attempts" not in response.headers
    [row] = await _rows(db, test_api_key)
    assert _verdicts(row)["rule.llama_a_yedek"] == reason


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        500,
        502,
        503,
        504,
        httpx.ReadTimeout("slow"),
        httpx.ConnectError("refused"),
    ],
)
async def test_a_provider_error_is_answered_by_a_second_attempt(
    db,  # noqa: F811
    test_api_key,
    failure,
) -> None:
    a, b = await _deployments(db, test_api_key)
    calls = []

    async with _fallback_gateway(
        db, test_api_key, _hosts(calls, {"a": failure}), _rules(_rule())
    ) as (client, _):
        answered = await client.post(CHAT, json=_body())

    assert answered.status_code == 200, answered.text
    assert answered.headers["x-shim-attempts"] == "2"
    assert calls == ["a", "b"]
    first, second = await _rows(db, test_api_key)
    assert answered.headers["x-shim-request-id"] == second.request_id
    assert (first.status, second.status) == ("failed", "completed")
    assert _verdicts(first)["rule.llama_a_yedek"] == (
        "allow",
        "FALLBACK_PROVIDER_ERROR",
    )
    assert second.lifecycle_metadata["attempt_group_id"] == first.request_id
    assert second.lifecycle_metadata["attempt_reason"] == "fallback"
    assert second.lifecycle_metadata["attempt_rule_id"] == "llama_a_yedek"
    assert await _settled_requests(db, test_api_key) == (1, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "triggers", "answered", "calls"),
    [
        (429, ("provider_error", "rate_limited"), 200, ["a", "b"]),
        (429, ("provider_error",), 429, ["a"]),
        (400, ("provider_error", "rate_limited"), 400, ["a"]),
        (401, ("provider_error", "rate_limited"), 401, ["a"]),
    ],
)
async def test_a_rate_limit_falls_back_only_when_listed_and_a_4xx_never(
    db,  # noqa: F811
    test_api_key,
    status,
    triggers,
    answered,
    calls,
) -> None:
    await _deployments(db, test_api_key)
    seen = []

    async with _fallback_gateway(
        db,
        test_api_key,
        _hosts(seen, {"a": status}),
        _rules(_rule(triggers=triggers)),
    ) as (client, _):
        response = await client.post(CHAT, json=_body())

    assert response.status_code == answered, response.text
    assert seen == calls
    first = (await _rows(db, test_api_key))[0]
    verdict = _verdicts(first).get("rule.llama_a_yedek")
    assert verdict == (("allow", "FALLBACK_RATE_LIMITED") if answered == 200 else None)


@pytest.mark.asyncio
async def test_a_monitor_rule_records_the_provider_error_and_adds_no_attempt(
    db,  # noqa: F811
    test_api_key,
) -> None:
    await _deployments(db, test_api_key)
    calls = []

    async with _fallback_gateway(
        db, test_api_key, _hosts(calls, {"a": 503}), _rules(_rule("monitor"))
    ) as (client, _):
        refused = await client.post(CHAT, json=_body())

    assert refused.status_code == 503
    assert calls == ["a"]
    [row] = await _rows(db, test_api_key)
    assert _verdicts(row)["rule.llama_a_yedek"] == ("allow", "RULE_WOULD_ROUTE")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("to", "calls"),
    [(("internal-b",), ["a", "b"]), (("internal-b", "internal-c"), ["a", "b", "c"])],
)
async def test_each_fallback_is_tried_once_in_order(
    db,  # noqa: F811
    test_api_key,
    three_hosts,
    to,
    calls,
) -> None:
    for host in "abc":
        await _row(db, test_api_key, host)
    seen = []

    async with _fallback_gateway(
        db,
        test_api_key,
        _hosts(seen, {"a": 503, "b": 503, "c": 503}),
        _rules(_rule(to=to)),
    ) as (client, _):
        refused = await client.post(CHAT, json=_body())

    assert refused.status_code == 503
    assert seen == calls
    rows = await _rows(db, test_api_key)
    assert [row.status for row in rows] == ["failed"] * len(calls)
    assert _verdicts(rows[-1])["rule.llama_a_yedek"] == (
        "skip",
        "FALLBACK_NO_CANDIDATE",
    )


@pytest.mark.asyncio
async def test_without_a_rule_the_strategy_opens_no_session(
    db,  # noqa: F811
    test_api_key,
) -> None:
    await _deployments(db, test_api_key)

    async with _fallback_gateway(db, test_api_key, _hosts([], {"a": 503}), None) as (
        client,
        opened,
    ):
        healthy = await client.post(CHAT, json={**_body(), "model": "internal-b"})
        failed = await client.post(CHAT, json=_body())

    assert (healthy.status_code, failed.status_code) == (200, 503)
    assert opened == []


@pytest.mark.asyncio
async def test_an_unhealthy_alias_the_rule_no_longer_covers_after_admission_is_refused(
    db,  # noqa: F811
    test_api_key,
    monkeypatch,
) -> None:
    a, _ = await _deployments(db, test_api_key)
    _unhealthy(a)
    # The row says internal; the operator list makes it external for the request.
    monkeypatch.setattr(
        settings, "MODEL_DEPLOYMENT_INTERNAL_ORIGINS", ["https://b.internal"]
    )
    scoped = {**_rule(), "scope": {"deployment_kinds": ["internal"]}}
    calls = []

    async with _fallback_gateway(
        db, test_api_key, _hosts(calls, {}), _rules(scoped)
    ) as (client, _):
        refused = await client.post(CHAT, json=_body())

    assert refused.status_code == 503
    assert refused.json()["error"]["code"] == "DEPLOYMENT_UNHEALTHY"
    assert calls == []


@pytest.mark.asyncio
async def test_a_token_count_never_reaches_an_unhealthy_deployment(
    db,  # noqa: F811
    test_api_key,
) -> None:
    rows = [await _row(db, test_api_key, host, provider="anthropic") for host in "ab"]
    for row in rows:
        (await db.get(ProviderSecret, row.provider_secret_id)).provider = "anthropic"
    _unhealthy(rows[0])
    await db.flush()
    calls = []

    def upstream(request):
        calls.append(request.url.host[0])
        return httpx.Response(200, json={"input_tokens": 3})

    async with _fallback_gateway(db, test_api_key, upstream, _rules(_rule())) as (
        client,
        _,
    ):
        counted = await client.post(
            "/v1/messages/count_tokens",
            json={
                "model": "internal-a",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )

    # Retargeting runs after privacy, which a token count never reaches.
    assert counted.status_code == 503, counted.text
    assert calls == []


@pytest.mark.asyncio
async def test_a_failed_canary_candidate_goes_to_stable_not_to_the_fallback_of_from(
    db,  # noqa: F811
    test_api_key,
    three_hosts,
) -> None:
    for host in "abc":
        await _row(db, test_api_key, host)
    split = {
        "id": "kanarya",
        "name": "Candidate b",
        "kind": "route",
        "action": "route",
        "state": "enforced",
        "match": {
            "on": "split",
            "from": "internal-a",
            "to": "internal-b",
            "share_percent": 100,
            "fallback_to_stable": True,
        },
    }
    calls = []

    async with _fallback_gateway(
        db,
        test_api_key,
        _hosts(calls, {"b": 503}),
        _rules(split, _rule(to=("internal-c",))),
    ) as (client, _):
        answered = await client.post(CHAT, json=_body())

    assert answered.status_code == 200, answered.text
    assert calls == ["b", "a"]


@pytest.mark.asyncio
async def test_a_long_request_moved_to_its_lane_is_not_moved_again_by_a_fallback(
    db,  # noqa: F811
    test_api_key,
    three_hosts,
) -> None:
    a = await _row(db, test_api_key, "a")
    await _row(db, test_api_key, "b", upstream_model="model-a")
    await _row(db, test_api_key, "c")
    _unhealthy(a)
    lane = {
        "id": "uzun",
        "name": "Long to b",
        "kind": "route",
        "action": "route",
        "state": "enforced",
        "match": {
            "on": "size",
            "from": "internal-a",
            "to": "internal-b",
            "min_input_tokens": 256,
        },
    }
    calls = []

    async with _fallback_gateway(
        db,
        test_api_key,
        _hosts(calls, {}),
        _rules(lane, _rule(to=("internal-c",))),
    ) as (client, _):
        answered = await client.post(CHAT, json=_body("x" * 2_000))

    assert answered.status_code == 200, answered.text
    assert calls == ["b"]


@pytest.mark.asyncio
async def test_a_fallback_rule_scoped_to_its_source_tries_every_listed_alias(
    db,  # noqa: F811
    test_api_key,
    three_hosts,
) -> None:
    for host in "abc":
        await _row(db, test_api_key, host)
    scoped = {
        **_rule(to=("internal-b", "internal-c")),
        "scope": {"models": ["model-a"]},
    }
    calls = []

    async with _fallback_gateway(
        db, test_api_key, _hosts(calls, {"a": 503, "b": 503}), _rules(scoped)
    ) as (client, _):
        answered = await client.post(CHAT, json=_body())

    assert answered.status_code == 200, answered.text
    assert calls == ["a", "b", "c"]
