"""AWS credentials and Bedrock deployments through the management routes."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from sqlalchemy import func, update
from sqlalchemy.ext.asyncio import AsyncSession

from shim.gateway.api.errors import gateway_exception_handler
from shim_enterprise.api import enterprise_deps
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim_enterprise.secrets.store import provider_secret_query
from shim_enterprise.tenants.models import Organization, ProviderSecret, User

PROVIDERS = "/api/v1/management/providers"
DEPLOYMENTS = "/api/v1/management/model-deployments"
RUNTIME = "https://bedrock-runtime.eu-central-1.amazonaws.com"
CONTROL = "https://bedrock.eu-central-1.amazonaws.com"
STS = "https://sts.us-east-1.amazonaws.com"
AWS_KEY = {"access_key_id": "AKIA0000000000000000", "secret_access_key": "0" * 40}
PROFILE = "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"


@pytest.fixture(autouse=True)
def aws_origins(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "MODEL_DEPLOYMENT_ALLOWED_ORIGINS",
        [RUNTIME, CONTROL, "https://a.internal"],
    )


async def _admin(db) -> User:
    organization = Organization(
        id=uuid4(), name="Bedrock", slug=f"bedrock-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    user = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"bedrock-{uuid4().hex}@example.com",
        role="owner",
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await db.flush()
    return user


async def _call(
    db,
    user: User,
    method: str,
    path: str,
    upstream: Callable[[httpx.Request], httpx.Response] | None = None,
    **kwargs,
) -> httpx.Response:
    connection = await db.connection()

    async def request_session():
        async with AsyncSession(
            bind=connection,
            join_transaction_mode="create_savepoint",
            expire_on_commit=False,
        ) as session:
            yield session

    app = FastAPI()
    app.include_router(management_router, prefix="/api/v1")
    # As the enterprise app does: a refused body is never echoed back.
    app.add_exception_handler(RequestValidationError, gateway_exception_handler)
    app.dependency_overrides[enterprise_deps.get_current_user] = lambda: user
    app.dependency_overrides[get_db] = request_session
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(upstream or (lambda request: httpx.Response(500)))
    ) as outbound:
        app.state.http_client = outbound
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            return await client.request(method, path, **kwargs)


async def _aws_secret(db, user: User, provider: str = "anthropic") -> dict:
    created = await _call(
        db,
        user,
        "POST",
        PROVIDERS,
        json={
            "provider": provider,
            "credential_kind": "aws_access_key",
            "aws_access_key": AWS_KEY,
        },
    )
    assert created.status_code == 201, created.text
    return created.json()


def _deployment(secret: dict, **fields) -> dict:
    return {
        "alias": f"bedrock-{uuid4().hex[:8]}",
        "provider": "anthropic",
        "upstream_model": PROFILE,
        "provider_secret_id": secret["id"],
        "deployment_kind": "external",
        "declared_version": "bedrock",
        "owner": "Platform",
        "upstream": "aws_bedrock",
        "aws_region": "eu-central-1",
        **fields,
    }


@pytest.mark.asyncio
async def test_an_aws_access_key_is_stored_masked_and_verified_through_sts(db) -> None:
    user = await _admin(db)
    secret = await _aws_secret(db, user)
    seen: list[httpx.Request] = []

    def sts(answer: int) -> Callable[[httpx.Request], httpx.Response]:
        def handle(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            if answer == 200:
                return httpx.Response(
                    200,
                    text="<GetCallerIdentityResponse><GetCallerIdentityResult>"
                    "<Arn>arn:aws:iam::000000000000:user/shim</Arn>"
                    "</GetCallerIdentityResult></GetCallerIdentityResponse>",
                )
            return httpx.Response(
                answer,
                text="<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>",
            )

        return handle

    verified = await _call(
        db, user, "POST", f"{PROVIDERS}/{secret['id']}/verify", sts(200)
    )
    rejected = await _call(
        db, user, "POST", f"{PROVIDERS}/{secret['id']}/verify", sts(403)
    )
    unavailable = await _call(
        db, user, "POST", f"{PROVIDERS}/{secret['id']}/verify", sts(500)
    )

    assert (secret["credential_kind"], secret["masked_key"]) == (
        "aws_access_key",
        "aws:AKIA...0000",
    )
    assert verified.status_code == 200 and verified.json()["verified_at"]
    assert rejected.status_code == 400
    assert unavailable.status_code == 503
    assert str(seen[0].url) == STS + "/"
    assert "0" * 40 not in verified.text + rejected.text


@pytest.mark.asyncio
async def test_a_bedrock_api_key_is_checked_by_a_health_check_only(db) -> None:
    user = await _admin(db)
    created = await _call(
        db,
        user,
        "POST",
        PROVIDERS,
        json={
            "provider": "openai",
            "credential_kind": "aws_bedrock_api_key",
            "key": "bedrock-long-term-key",
        },
    )

    verify = await _call(db, user, "POST", f"{PROVIDERS}/{created.json()['id']}/verify")

    assert created.status_code == 201
    assert verify.status_code == 409
    assert "health check" in verify.json()["detail"]


@pytest.mark.parametrize(
    "body",
    [
        {
            "provider": "google",
            "credential_kind": "aws_access_key",
            "aws_access_key": AWS_KEY,
        },
        {"provider": "anthropic", "credential_kind": "aws_access_key", "key": "x" * 20},
        {
            "provider": "anthropic",
            "credential_kind": "aws_access_key",
            "aws_access_key": {**AWS_KEY, "access_key_id": "ASIA0000000000000000"},
        },
        {
            "provider": "anthropic",
            "credential_kind": "aws_access_key",
            "aws_access_key": {**AWS_KEY, "secret_access_key": "short"},
        },
        {"provider": "anthropic", "credential_kind": "aws_bedrock_api_key"},
    ],
)
@pytest.mark.asyncio
async def test_aws_credentials_take_exactly_their_fields(db, body) -> None:
    user = await _admin(db)

    refused = await _call(db, user, "POST", PROVIDERS, json=body)

    assert refused.status_code == 422
    assert "0" * 40 not in refused.text


@pytest.mark.asyncio
async def test_a_bedrock_deployment_derives_its_url_and_pairs_with_an_aws_secret(
    db,
) -> None:
    user = await _admin(db)
    secret = await _aws_secret(db, user)
    plain = await _call(
        db,
        user,
        "POST",
        PROVIDERS,
        json={"provider": "anthropic", "key": "sk-ant-" + "0" * 20},
    )

    created = await _call(db, user, "POST", DEPLOYMENTS, json=_deployment(secret))
    openai_side = await _call(
        db,
        user,
        "POST",
        PROVIDERS,
        json={
            "provider": "openai",
            "credential_kind": "aws_access_key",
            "aws_access_key": AWS_KEY,
        },
    )
    gpt = await _call(
        db,
        user,
        "POST",
        DEPLOYMENTS,
        json=_deployment(
            openai_side.json(),
            provider="openai",
            upstream_model="openai.gpt-oss-120b-1:0",
        ),
    )
    refusals = {
        name: await _call(db, user, "POST", DEPLOYMENTS, json=body)
        for name, body in {
            "no_region": _deployment(secret, aws_region=None),
            "internal": _deployment(secret, deployment_kind="internal"),
            "other_url": _deployment(secret, base_url="https://a.internal/anthropic"),
            "bad_model": _deployment(secret, upstream_model="claude sonnet"),
            "app_profile_openai": _deployment(
                openai_side.json(),
                provider="openai",
                upstream_model="arn:aws:bedrock:eu-central-1:000000000000:"
                "application-inference-profile/abc123",
            ),
            "plain_secret": _deployment(plain.json()),
            "region_elsewhere": _deployment(secret, aws_region="us-east-1"),
            "region_on_generic": {
                **_deployment(plain.json()),
                "upstream": "generic",
                "base_url": "https://a.internal/v1",
            },
        }.items()
    }
    generic_with_aws = await _call(
        db,
        user,
        "POST",
        DEPLOYMENTS,
        json={
            **_deployment(secret),
            "upstream": "generic",
            "aws_region": None,
            "base_url": "https://a.internal/v1",
        },
    )

    assert created.status_code == 201, created.text
    assert created.json()["base_url"] == RUNTIME + "/anthropic"
    assert gpt.json()["base_url"] == RUNTIME + "/openai/v1"
    assert {name: response.status_code for name, response in refusals.items()} == {
        name: 422 for name in refusals
    }
    assert generic_with_aws.status_code == 422


@pytest.mark.asyncio
async def test_a_put_keeps_the_region_and_a_new_region_moves_the_url(
    db, monkeypatch
) -> None:
    user = await _admin(db)
    secret = await _aws_secret(db, user)
    created = (
        await _call(db, user, "POST", DEPLOYMENTS, json=_deployment(secret))
    ).json()
    # A client that predates Bedrock sends neither upstream nor region, and the
    # base_url it read back.
    body = {
        key: value
        for key, value in _deployment(secret, alias=created["alias"]).items()
        if key not in {"aws_region", "upstream"}
    } | {"base_url": created["base_url"]}

    kept = await _call(db, user, "PUT", f"{DEPLOYMENTS}/{created['id']}", json=body)
    monkeypatch.setattr(
        settings,
        "MODEL_DEPLOYMENT_ALLOWED_ORIGINS",
        [RUNTIME, "https://bedrock-runtime.eu-west-1.amazonaws.com"],
    )
    moved = await _call(
        db,
        user,
        "PUT",
        f"{DEPLOYMENTS}/{created['id']}",
        json={
            **body,
            "upstream": "aws_bedrock",
            "aws_region": "eu-west-1",
            "base_url": None,
        },
    )

    assert kept.status_code == 200, kept.text
    assert kept.json()["aws_region"] == "eu-central-1"
    assert (
        moved.json()["base_url"]
        == "https://bedrock-runtime.eu-west-1.amazonaws.com/anthropic"
    )


@pytest.mark.parametrize(
    ("model", "path", "answer", "health"),
    [
        (PROFILE, f"/inference-profiles/{PROFILE.replace(':', '%3A')}", 200, "healthy"),
        (
            "anthropic.claude-haiku-4-5-20251001-v1:0",
            "/foundation-models/anthropic.claude-haiku-4-5-20251001-v1%3A0",
            200,
            "healthy",
        ),
        (
            "arn:aws:bedrock:eu-central-1::inference-profile/eu.anthropic.claude-x-v1:0",
            "/inference-profiles/arn%3Aaws%3Abedrock%3Aeu-central-1%3A%3Ainference-profile%2Feu.anthropic.claude-x-v1%3A0",
            403,
            "unhealthy",
        ),
    ],
)
@pytest.mark.asyncio
async def test_the_health_check_asks_the_control_plane_with_a_minted_key(
    db, model, path, answer, health
) -> None:
    user = await _admin(db)
    secret = await _aws_secret(db, user)
    created = (
        await _call(
            db,
            user,
            "POST",
            DEPLOYMENTS,
            json=_deployment(secret, upstream_model=model),
        )
    ).json()
    seen: list[httpx.Request] = []

    def control(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(answer, json={})

    checked = await _call(
        db, user, "POST", f"{DEPLOYMENTS}/{created['id']}/health", control
    )

    assert checked.json()["health"] == health
    [request] = seen
    assert request.url.raw_path.decode() == path
    assert request.headers["authorization"].startswith("Bearer bedrock-api-key-")


@pytest.mark.asyncio
async def test_catalog_routes_never_pick_an_aws_credential(db) -> None:
    user = await _admin(db)
    plain = await _call(
        db,
        user,
        "POST",
        PROVIDERS,
        json={"provider": "anthropic", "key": "sk-ant-" + "0" * 20},
    )
    newer = await _aws_secret(db, user)
    # One transaction shares now(): make the AWS secret the provider's newest.
    await db.execute(
        update(ProviderSecret)
        .where(ProviderSecret.id == UUID(newer["id"]))
        .values(created_at=func.now() + timedelta(minutes=1))
    )

    catalog = await db.scalar(
        provider_secret_query(user.organization_id, "anthropic", None)
    )
    named = await db.scalar(
        provider_secret_query(
            user.organization_id, "anthropic", f"{newer['id']}|eu-central-1|"
        )
    )

    assert str(catalog.id) == plain.json()["id"]
    assert str(named.id) == newer["id"]
