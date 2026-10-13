"""Bedrock destinations, the tenant's region lock and the operator's ceiling."""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from ee.tests.aws.test_bedrock_management import (
    DEPLOYMENTS,
    _admin,
    _aws_secret,
    _call,
    _deployment,
    aws_origins,  # noqa: F401  (autouse fixture)
)
from shim.gateway.kernel.result import ProviderTarget
from shim_enterprise.aws.regions import (
    bedrock_record,
    ceiling_allows,
    fetch_destinations,
    lock_reasons,
    profile_scope,
)
from shim_enterprise.tenants.deployments import DeploymentResolver
from shim_enterprise.tenants.gateway_settings import (
    BedrockAttribution,
    BedrockRegionLock,
    GatewaySettings,
    _region_lock_direction,
)
from shim_enterprise.tenants.models import (
    ModelDeployment,
    OrganizationGatewaySettings,
    ProviderSecret,
    Team,
    TierDefinition,
)

EU = "eu.anthropic.fixture-v1:0"
US = "us.anthropic.fixture-v1:0"


@pytest.mark.parametrize(
    ("model", "scope"),
    [
        ("anthropic.claude-haiku-4-5-20251001-v1:0", "in_region"),
        ("openai.gpt-oss-120b-1:0", "in_region"),
        (EU, "eu"),
        ("global.anthropic.claude-sonnet-4-5-20250929-v1:0", "global"),
        ("apac.anthropic.claude-x-v1:0", "apac"),
        (
            "arn:aws:bedrock:eu-central-1::foundation-model/anthropic.claude-x-v1:0",
            "in_region",
        ),
        (
            "arn:aws:bedrock:eu-central-1:000000000000:inference-profile/eu.anthropic.x-v1:0",
            "eu",
        ),
    ],
)
def test_the_scope_is_in_region_or_the_profile_prefix(model, scope) -> None:
    assert profile_scope(model) == scope


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_destinations_come_from_get_inference_profile() -> None:
    seen: list[httpx.Request] = []

    def profile(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "models": [
                    {"modelArn": "arn:aws:bedrock:eu-west-1::foundation-model/a"},
                    {"modelArn": "arn:aws:bedrock:eu-central-1::foundation-model/a"},
                    {"modelArn": "arn:aws:bedrock:eu-west-1::foundation-model/a"},
                ]
            },
        )

    async with _client(profile) as client:
        found = await fetch_destinations(client, "token", "eu-central-1", EU)
        model = await fetch_destinations(
            client, "token", "eu-central-1", "anthropic.claude-x-v1:0"
        )

    assert found == ["eu-central-1", "eu-west-1"]
    assert model == ["eu-central-1"]
    assert len(seen) == 1
    assert seen[0].headers["authorization"] == "Bearer token"


@pytest.mark.parametrize(
    "answer",
    [
        lambda request: httpx.Response(403, json={}),
        lambda request: httpx.Response(
            200, json={"models": [{"modelArn": "not-an-arn"}]}
        ),
        lambda request: httpx.Response(200, text="not json"),
        lambda request: (_ for _ in ()).throw(
            httpx.ReadTimeout("slow", request=request)
        ),
    ],
)
@pytest.mark.asyncio
async def test_unknown_destinations_are_null(answer) -> None:
    async with _client(answer) as client:
        assert await fetch_destinations(client, "token", "eu-central-1", EU) is None


@pytest.mark.parametrize(
    ("regions", "destinations", "reasons"),
    [
        (["eu"], ["eu-central-1", "eu-west-1"], []),
        (["eu-central-1"], ["eu-central-1"], []),
        (["eu"], ["eus-north-1"], ["region"]),
        (["eu"], ["eu-central-1", "us-east-1"], ["region"]),
        (["eu"], None, ["unknown_destinations"]),
        ([], None, []),
    ],
)
def test_the_region_matcher_wants_every_destination_inside(
    regions, destinations, reasons
) -> None:
    lock = BedrockRegionLock(mode="enforce", regions=regions)

    assert lock_reasons(lock, "eu", destinations) == reasons


def test_scopes_and_the_ceiling() -> None:
    lock = BedrockRegionLock(mode="enforce", scopes=["eu", "in_region"])

    assert lock_reasons(lock, "us", ["us-east-1"]) == ["scope"]
    assert lock_reasons(lock, "in_region", ["us-east-1"]) == []
    assert ceiling_allows([], None)
    assert ceiling_allows(["eu"], ["eu-west-1"])
    assert not ceiling_allows(["eu"], None)
    assert not ceiling_allows(["eu"], ["eu-west-1", "us-east-1"])


@pytest.mark.parametrize(
    ("before", "after", "direction"),
    [
        ({}, {"mode": "monitor"}, "tightening"),
        ({"mode": "monitor"}, {"mode": "enforce"}, "tightening"),
        ({"mode": "enforce"}, {"mode": "off"}, "relaxing"),
        ({"mode": "enforce"}, {"mode": "enforce", "regions": ["eu"]}, "tightening"),
        (
            {"mode": "enforce", "regions": ["eu", "us"]},
            {"mode": "enforce", "regions": ["eu"]},
            "tightening",
        ),
        (
            {"mode": "enforce", "regions": ["eu"]},
            {"mode": "enforce", "regions": ["eu", "us"]},
            "relaxing",
        ),
        ({"mode": "enforce", "regions": ["eu"]}, {"mode": "enforce"}, "relaxing"),
        ({"mode": "monitor"}, {"mode": "enforce", "scopes": ["eu"]}, "relaxing"),
        ({}, {"regions": ["eu"]}, "neutral"),
    ],
)
def test_lock_directions(before, after, direction) -> None:
    assert (
        _region_lock_direction(BedrockRegionLock(**before), BedrockRegionLock(**after))
        == direction
    )


@pytest.mark.parametrize(
    "fields",
    [
        {"scopes": ["EU"]},
        {"scopes": ["eu", "eu"]},
        {"regions": ["europe-1"]},
        {"scopes": [f"s{i:02d}" for i in range(21)]},
        {"mode": "on"},
    ],
)
def test_a_malformed_lock_is_refused(fields) -> None:
    with pytest.raises(ValidationError):
        BedrockRegionLock(**fields)


@pytest.mark.parametrize(
    "fields", [{"tag_key": "aws:team"}, {"tag_key": "a b"}, {"unassigned_value": "a|b"}]
)
def test_a_malformed_attribution_is_refused(fields) -> None:
    with pytest.raises(ValidationError):
        BedrockAttribution(**fields)


class _Prepared(SimpleNamespace):
    """What the resolver reads of a prepared request, verdicts recorded."""

    def record_verdict(self, rule_id, **fields) -> None:
        self.policy_verdicts.append(SimpleNamespace(rule_id=rule_id, **fields))


async def _bedrock_row(
    db, tenant, *, model: str, destinations, kind: str = "aws_access_key"
):
    secret = ProviderSecret(
        id=uuid4(),
        organization_id=tenant,
        provider=kind,
        **(
            {"aws_role_arn": "arn:aws:iam::000000000000:role/x"}
            if kind == "aws_role"
            else {
                "secret_ref": f"fernet:v2:{uuid4().hex}",
                "secret_backend": "fernet",
                "secret_version": "v2",
            }
        ),
        masked_key="aws:...",
    )
    db.add(secret)
    await db.flush()
    return ModelDeployment(
        organization_id=tenant,
        alias=f"bedrock-{uuid4().hex[:6]}",
        provider="anthropic",
        upstream_model=model,
        base_url="https://bedrock-runtime.eu-central-1.amazonaws.com/anthropic",
        provider_secret_id=secret.id,
        upstream="aws_bedrock",
        aws_region="eu-central-1",
        aws_destination_regions=destinations,
        timeout_seconds=30,
        deployment_kind="external",
        declared_version="v1",
        owner="Platform",
    )


async def _admission(db, deployment, key, gateway: GatewaySettings):
    connection = await db.connection()
    opened: list[int] = []

    def factory() -> AsyncSession:
        opened.append(1)
        return AsyncSession(bind=connection, join_transaction_mode="create_savepoint")

    prepared = _Prepared(tenant_gateway_settings=gateway, policy_verdicts=[])
    try:
        tag = await DeploymentResolver(factory)._bedrock_admission(
            prepared, deployment, key
        )
        refused = None
    except HTTPException as error:
        tag, refused = None, error
    verdicts = [(v.rule_id, v.outcome, v.reason_code) for v in prepared.policy_verdicts]
    return tag, refused, verdicts, opened


@pytest.mark.parametrize(
    ("lock", "ceiling", "verdict", "refused"),
    [
        ({}, [], [], False),
        (
            {"mode": "enforce", "regions": ["eu"]},
            [],
            [("aws.region_lock", "allow", "BEDROCK_REGION_ALLOWED")],
            False,
        ),
        (
            {"mode": "monitor", "scopes": ["us"]},
            [],
            [("aws.region_lock", "allow", "BEDROCK_REGION_OUTSIDE_LOCK")],
            False,
        ),
        (
            {"mode": "enforce", "scopes": ["us"]},
            [],
            [("aws.region_lock", "deny", "BEDROCK_REGION_NOT_ALLOWED")],
            True,
        ),
        (
            {"mode": "monitor", "scopes": ["us"]},
            ["us"],
            [("aws.region_lock", "deny", "BEDROCK_REGION_NOT_ALLOWED")],
            True,
        ),
        ({}, ["eu"], [("aws.region_lock", "allow", "BEDROCK_REGION_ALLOWED")], False),
    ],
)
@pytest.mark.asyncio
async def test_the_lock_table(
    db, test_api_key, lock, ceiling, verdict, refused
) -> None:
    tenant = test_api_key.organization_id
    tier = f"tier-{uuid4().hex[:8]}"
    db.add(
        TierDefinition(
            slug=tier,
            name=tier,
            rate_limit_rpm=1_000,
            rate_limit_tpm=1_000_000,
            monthly_request_limit=1_000,
            monthly_token_limit=1_000_000,
            features={"provider_policy": {"allowed_regions": ceiling}}
            if ceiling
            else {},
        )
    )
    test_api_key.tier = tier
    deployment = await _bedrock_row(
        db, tenant, model=EU, destinations=["eu-central-1", "eu-west-1"]
    )
    await db.flush()

    _, error, verdicts, _ = await _admission(
        db,
        deployment,
        test_api_key,
        GatewaySettings(bedrock_region_lock=BedrockRegionLock(**lock)),
    )

    assert verdicts == verdict
    assert (error is not None) == refused
    if error is not None:
        assert (error.status_code, error.detail["code"]) == (
            403,
            "BEDROCK_REGION_NOT_ALLOWED",
        )


@pytest.mark.asyncio
async def test_a_role_deployment_tags_the_session_with_the_keys_team(
    db, test_api_key
) -> None:
    tenant = test_api_key.organization_id
    team = Team(
        id=uuid4(), organization_id=tenant, name="payments", aws_cost_tag="payments"
    )
    db.add(team)
    role = await _bedrock_row(db, tenant, model=EU, destinations=None, kind="aws_role")
    access = await _bedrock_row(db, tenant, model=EU, destinations=None)
    await db.flush()
    on = GatewaySettings(bedrock_attribution=BedrockAttribution(mode="session_tags"))

    untagged, _, _, _ = await _admission(db, role, test_api_key, on)
    test_api_key.team_id = team.id
    tagged, _, _, _ = await _admission(db, role, test_api_key, on)
    stored_key, _, _, _ = await _admission(db, access, test_api_key, on)
    off, _, _, _ = await _admission(db, role, test_api_key, GatewaySettings())

    assert (untagged, tagged, stored_key, off) == (
        "shim-team=unassigned",
        "shim-team=payments",
        None,
        None,
    )


def test_the_record_key_names_region_scope_lock_and_tag() -> None:
    def prepared(reference: str, verdicts=()) -> SimpleNamespace:
        return SimpleNamespace(
            target=ProviderTarget(
                deployment_id="d",
                base_url="https://b",
                upstream_model=EU,
                credential_reference=reference,
                timeout_seconds=5,
                declared_version="v1",
            ),
            policy_verdicts=list(verdicts),
        )

    secret = str(uuid4())
    outside = SimpleNamespace(
        rule_id="aws.region_lock", reason_code="BEDROCK_REGION_OUTSIDE_LOCK"
    )
    allowed = SimpleNamespace(
        rule_id="aws.region_lock", reason_code="BEDROCK_REGION_ALLOWED"
    )

    assert bedrock_record(prepared(secret)) is None
    assert bedrock_record(SimpleNamespace(target=None, policy_verdicts=[])) is None
    assert bedrock_record(prepared(f"{secret}|eu-central-1|")) == {
        "region": "eu-central-1",
        "model": EU,
        "scope": "eu",
        "lock": "off",
        "session_tag": None,
    }
    assert (
        bedrock_record(
            prepared(f"{secret}|eu-central-1|shim-team=payments", [outside])
        )["lock"]
        == "outside"
    )
    tagged = bedrock_record(
        prepared(f"{secret}|eu-central-1|shim-team=payments", [allowed])
    )
    assert (tagged["lock"], tagged["session_tag"]) == ("pass", "payments")


@pytest.mark.asyncio
async def test_registration_answers_422_when_an_enforced_lock_refuses(db) -> None:
    user = await _admin(db)
    secret = await _aws_secret(db, user)
    db.add(
        OrganizationGatewaySettings(
            organization_id=user.organization_id,
            settings={"bedrock_region_lock": {"mode": "enforce", "scopes": ["eu"]}},
        )
    )
    await db.flush()

    def profile(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "models": [
                    {"modelArn": "arn:aws:bedrock:us-east-1::foundation-model/a"}
                ]
            },
        )

    refused = await _call(
        db,
        user,
        "POST",
        DEPLOYMENTS,
        profile,
        json=_deployment(secret, upstream_model=US),
    )
    allowed = await _call(
        db,
        user,
        "POST",
        DEPLOYMENTS,
        profile,
        json=_deployment(secret, upstream_model=EU),
    )

    assert (refused.status_code, refused.json()["detail"]["code"]) == (
        422,
        "BEDROCK_REGION_NOT_ALLOWED",
    )
    assert allowed.status_code == 201, allowed.text
    assert allowed.json()["aws_profile_scope"] == "eu"
    assert allowed.json()["aws_destination_regions"] == ["us-east-1"]


@pytest.mark.asyncio
async def test_the_preview_shows_what_a_candidate_lock_would_refuse(db) -> None:
    from datetime import datetime, timedelta, timezone

    from shim_enterprise.billing.models import RequestLifecycle

    user = await _admin(db)
    tenant = user.organization_id
    eu = await _bedrock_row(
        db, tenant, model=EU, destinations=["eu-central-1", "eu-west-1"]
    )
    us = await _bedrock_row(
        db, tenant, model=US, destinations=["us-east-1", "us-west-2"]
    )
    db.add_all([eu, us])
    await db.flush()
    for days_ago in (1, 2, 9):
        db.add(
            RequestLifecycle(
                request_id=f"req_preview_{uuid4().hex}",
                organization_id=tenant,
                actor_type="internal",
                source_endpoint="messages",
                status="completed",
                requested_model=us.alias,
                stream=False,
                started_at=datetime.now(timezone.utc) - timedelta(days=days_ago),
                lifecycle_metadata={"deployment_id": str(us.id)},
            )
        )
    await db.flush()

    current = await _call(db, user, "GET", "/api/v1/management/aws/region-lock/preview")
    candidate = await _call(
        db,
        user,
        "GET",
        "/api/v1/management/aws/region-lock/preview",
        params={"mode": "enforce", "scopes": "eu", "regions": "eu"},
    )
    bad = await _call(
        db,
        user,
        "GET",
        "/api/v1/management/aws/region-lock/preview",
        params={"regions": "Europe"},
    )

    rows = {row["alias"]: row for row in candidate.json()["deployments"]}
    assert all(row["allowed"] for row in current.json()["deployments"])
    assert candidate.json()["lock"] == {
        "mode": "enforce",
        "scopes": ["eu"],
        "regions": ["eu"],
    }
    assert (rows[eu.alias]["allowed"], rows[eu.alias]["requests_7d"]) == (True, 0)
    assert (
        rows[us.alias]["allowed"],
        rows[us.alias]["reasons"],
        rows[us.alias]["requests_7d"],
    ) == (
        False,
        ["scope", "region"],
        2,
    )
    assert bad.status_code == 422


@pytest.mark.asyncio
async def test_a_bedrock_update_asks_bedrock_before_the_tenant_lock(
    db, tenant_lock
) -> None:
    user = await _admin(db)
    secret = await _aws_secret(db, user)
    created = await _call(
        db,
        user,
        "POST",
        DEPLOYMENTS,
        json=_deployment(
            secret, upstream_model="anthropic.claude-haiku-4-5-20251001-v1:0"
        ),
    )
    assert created.status_code == 201, created.text
    locked: list[bool] = []

    def profile(request: httpx.Request) -> httpx.Response:
        locked.append(tenant_lock())
        return httpx.Response(
            200,
            json={
                "models": [
                    {"modelArn": "arn:aws:bedrock:eu-west-1::foundation-model/a"}
                ]
            },
        )

    moved = await _call(
        db,
        user,
        "PUT",
        f"{DEPLOYMENTS}/{created.json()['id']}",
        profile,
        json=_deployment(secret, alias=created.json()["alias"], upstream_model=EU),
    )

    assert moved.status_code == 200, moved.text
    assert moved.json()["aws_destination_regions"] == ["eu-west-1"]
    # A request's reservation waits on the tenant lock; Bedrock is asked without it.
    assert locked == [False]
