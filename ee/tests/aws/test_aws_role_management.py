"""AWS role secrets: a per-tenant external id, no stored secret, and a stepwise check."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ee.tests.aws.test_bedrock_management import (
    CONTROL,
    DEPLOYMENTS,
    PROVIDERS,
    _admin,
    _call,
    _deployment,
    aws_origins,  # noqa: F401  (autouse fixture)
)
from shim_enterprise.api.v1.management import providers
from shim_enterprise.core.config import settings
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.tenants.models import ProviderSecret

IDENTITY = "/api/v1/management/aws/identity"
ROLE = "arn:aws:iam::000000000000:role/shim-bedrock"
DENIED = "arn:aws:iam::000000000000:role/deny"


@pytest.fixture(autouse=True)
def env_identity(monkeypatch) -> None:
    monkeypatch.setattr(settings, "AWS_GATEWAY_IDENTITY", "env")
    monkeypatch.setattr(
        settings, "AWS_STS_URL_TEMPLATE", "https://sts.{region}.amazonaws.com"
    )
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA0000000000000000")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "0" * 40)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)


@pytest_asyncio.fixture(autouse=True)
async def check_sessions(db, monkeypatch) -> None:
    connection = await db.connection()
    # The check reads the external id in its own session, as the gateway does.
    monkeypatch.setattr(
        providers,
        "AsyncSessionLocal",
        lambda: AsyncSession(bind=connection, join_transaction_mode="create_savepoint"),
    )


def _no_store():
    raise AssertionError("a role must not touch the secret store")


def aws(answers: dict[str, int]):
    """STS answers AssumeRole by the role's name; the control plane answers 200."""

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.host.startswith("sts."):
            form = dict(httpx.QueryParams(request.content.decode()))
            status = answers.get(form["RoleArn"].rsplit("/", 1)[1], 200)
            if status != 200:
                code = "AccessDenied" if status == 403 else "InternalFailure"
                return httpx.Response(
                    status,
                    text=f"<ErrorResponse><Error><Code>{code}</Code></Error></ErrorResponse>",
                )
            expires = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            return httpx.Response(
                200,
                text="<AssumeRoleResponse><AssumeRoleResult><Credentials>"
                "<AccessKeyId>ASIA0000000000000009</AccessKeyId>"
                f"<SecretAccessKey>{'r' * 40}</SecretAccessKey>"
                "<SessionToken>role-session</SessionToken>"
                f"<Expiration>{expires}</Expiration></Credentials></AssumeRoleResult>"
                "</AssumeRoleResponse>",
            )
        return httpx.Response(200, json={})

    return handle


async def _role(db, user, arn: str = ROLE) -> dict:
    created = await _call(
        db,
        user,
        "POST",
        PROVIDERS,
        json={
            "provider": "anthropic",
            "credential_kind": "aws_role",
            "aws_role_arn": arn,
        },
    )
    assert created.status_code == 201, created.text
    return created.json()


@pytest.mark.asyncio
async def test_the_identity_is_created_once_and_shows_its_trust_policy(db) -> None:
    user = await _admin(db)
    other = await _admin(db)

    before = await _call(db, user, "GET", IDENTITY)
    created = await _call(db, user, "POST", IDENTITY)
    again = await _call(db, user, "POST", IDENTITY)
    shown = await _call(db, user, "GET", IDENTITY)
    foreign = await _call(db, other, "GET", IDENTITY)

    body = created.json()
    statement = body["trust_policy"]["Statement"][0]
    assert (before.status_code, before.json()["detail"]["code"]) == (
        404,
        "AWS_IDENTITY_NOT_CREATED",
    )
    assert (created.status_code, again.status_code) == (201, 200)
    assert (
        again.json()["external_id"]
        == body["external_id"]
        == shown.json()["external_id"]
    )
    assert body["external_id"].startswith("shim-") and len(body["external_id"]) == 37
    assert statement["Action"] == ["sts:AssumeRole", "sts:TagSession"]
    assert statement["Principal"] == {"AWS": "REPLACE_WITH_GATEWAY_PRINCIPAL_ARN"}
    assert statement["Condition"] == {
        "StringEquals": {"sts:ExternalId": body["external_id"]}
    }
    assert body["web_identity_audience"] is None
    assert (
        "bedrock:CallWithBearerToken"
        in body["permissions_policy"]["Statement"][0]["Action"]
    )
    assert foreign.status_code == 404


@pytest.mark.asyncio
async def test_the_hosted_cloud_trusts_a_google_token_with_the_tenants_audience(
    db, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "AWS_GATEWAY_IDENTITY", "gcp_metadata")
    monkeypatch.setattr(settings, "AWS_GCP_SERVICE_ACCOUNT_ID", "000000000000000000000")
    user = await _admin(db)

    body = (await _call(db, user, "POST", IDENTITY)).json()

    statement, chained = body["trust_policy"]["Statement"]
    audience = f"shim-aws:{body['external_id']}"
    assert body["web_identity_audience"] == audience
    assert statement["Principal"] == {"Federated": "accounts.google.com"}
    assert statement["Action"] == "sts:AssumeRoleWithWebIdentity"
    assert statement["Condition"]["StringEquals"] == {
        "accounts.google.com:aud": "000000000000000000000",
        "accounts.google.com:sub": "000000000000000000000",
        "accounts.google.com:oaud": audience,
    }
    # Session tags chain the web-identity session into the role itself.
    assert chained == {
        "Effect": "Allow",
        "Action": ["sts:AssumeRole", "sts:TagSession"],
        "Condition": {"StringEquals": {"sts:ExternalId": body["external_id"]}},
        "Principal": {"AWS": "REPLACE_WITH_THIS_ROLE_ARN"},
    }


@pytest.mark.asyncio
async def test_a_role_secret_stores_nothing_and_needs_the_identity(
    db, monkeypatch
) -> None:
    user = await _admin(db)
    monkeypatch.setattr(providers, "get_secret_store", _no_store)
    body = {
        "provider": "anthropic",
        "credential_kind": "aws_role",
        "aws_role_arn": ROLE,
    }

    without = await _call(db, user, "POST", PROVIDERS, json=body)
    await _call(db, user, "POST", IDENTITY)
    created = await _call(db, user, "POST", PROVIDERS, json=body)
    bad_arn = await _call(
        db,
        user,
        "POST",
        PROVIDERS,
        json={**body, "aws_role_arn": "arn:aws:iam::1:role/x"},
    )
    with_key = await _call(db, user, "POST", PROVIDERS, json={**body, "key": "x" * 20})
    secret = created.json()
    key_patch = await _call(
        db, user, "PUT", f"{PROVIDERS}/{secret['id']}", json={"key": "x" * 20}
    )
    moved = await _call(
        db,
        user,
        "PUT",
        f"{PROVIDERS}/{secret['id']}",
        json={"aws_role_arn": "arn:aws:iam::000000000000:role/other"},
    )
    deleted = await _call(db, user, "DELETE", f"{PROVIDERS}/{secret['id']}")

    assert (without.status_code, without.json()["detail"]["code"]) == (
        409,
        "AWS_IDENTITY_NOT_CREATED",
    )
    assert created.status_code == 201
    assert (secret["stores_secret"], secret["masked_key"], secret["aws_role_arn"]) == (
        False,
        "role/shim-bedrock",
        ROLE,
    )
    assert (bad_arn.status_code, with_key.status_code, key_patch.status_code) == (
        422,
        422,
        422,
    )
    assert (moved.json()["masked_key"], moved.json()["verified_at"]) == (
        "role/other",
        None,
    )
    assert deleted.status_code == 204


@pytest.mark.asyncio
async def test_the_check_goes_from_the_gateway_identity_to_bedrock(db) -> None:
    user = await _admin(db)
    await _call(db, user, "POST", IDENTITY)
    secret = await _role(db, user)
    await _call(db, user, "POST", DEPLOYMENTS, json=_deployment(secret))

    checked = await _call(
        db, user, "POST", f"{PROVIDERS}/{secret['id']}/aws-check", aws({}), json={}
    )
    verified = await _call(
        db, user, "POST", f"{PROVIDERS}/{secret['id']}/verify", aws({})
    )

    assert checked.status_code == 200, checked.text
    assert checked.json() == {
        "ok": True,
        "region": "eu-central-1",
        "steps": [
            {"step": "gateway_identity", "status": "ok", "aws_error": None},
            {"step": "assume_role", "status": "ok", "aws_error": None},
            {"step": "token", "status": "ok", "aws_error": None},
            {"step": "bedrock_access", "status": "ok", "aws_error": None},
        ],
    }
    assert verified.status_code == 200 and verified.json()["verified_at"]
    assert CONTROL.startswith("https://bedrock.")


@pytest.mark.asyncio
async def test_a_refused_role_clears_the_check_and_an_unavailable_sts_changes_nothing(
    db,
) -> None:
    user = await _admin(db)
    await _call(db, user, "POST", IDENTITY)
    secret = await _role(db, user, DENIED)
    await _call(
        db, user, "POST", f"{PROVIDERS}/{secret['id']}/aws-check", aws({}), json={}
    )
    row = await db.get(ProviderSecret, secret["id"])
    assert row is not None
    row.verified_at = datetime.now(timezone.utc)
    await db.flush()

    unavailable = await _call(
        db,
        user,
        "POST",
        f"{PROVIDERS}/{secret['id']}/aws-check",
        aws({"deny": 500}),
        json={},
    )
    await db.refresh(row)
    still = row.verified_at
    refused = await _call(
        db,
        user,
        "POST",
        f"{PROVIDERS}/{secret['id']}/aws-check",
        aws({"deny": 403}),
        json={"region": "us-east-1"},
    )
    await db.refresh(row)
    verify = await _call(
        db, user, "POST", f"{PROVIDERS}/{secret['id']}/verify", aws({"deny": 403})
    )
    rejected = [
        event.payload["extra"]
        for event in await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == user.organization_id,
                OutboxEvent.event_type == "audit.chain_append_requested",
            )
        )
        if event.payload["endpoint"] == "tenant.provider_secret_rejected"
    ]

    assert unavailable.json()["ok"] is False and still is not None
    assert refused.json()["region"] == "us-east-1"
    assert refused.json()["steps"] == [
        {"step": "gateway_identity", "status": "ok", "aws_error": None},
        {"step": "assume_role", "status": "failed", "aws_error": "AccessDenied"},
        {"step": "bedrock_access", "status": "skipped", "aws_error": None},
    ]
    assert row.verified_at is None
    assert verify.status_code == 400
    assert (rejected[0]["step"], rejected[0]["aws_error"]) == (
        "assume_role",
        "AccessDenied",
    )


@pytest.mark.asyncio
async def test_without_a_deployment_bedrock_access_is_skipped(db) -> None:
    user = await _admin(db)
    await _call(db, user, "POST", IDENTITY)
    secret = await _role(db, user)

    checked = await _call(
        db, user, "POST", f"{PROVIDERS}/{secret['id']}/aws-check", aws({}), json={}
    )

    assert checked.json()["region"] == "us-east-1"
    assert checked.json()["steps"][-1] == {
        "step": "bedrock_access",
        "status": "skipped",
        "aws_error": None,
    }
    assert checked.json()["ok"] is True


@pytest.mark.asyncio
async def test_archiving_a_workspace_skips_the_role_in_the_store(
    db, monkeypatch
) -> None:
    from shim_enterprise.tenants import service

    user = await _admin(db)
    await _call(db, user, "POST", IDENTITY)
    await _role(db, user)
    plain = await _call(
        db,
        user,
        "POST",
        PROVIDERS,
        json={"provider": "anthropic", "key": "sk-ant-" + "0" * 20},
    )
    organization = await db.get(service.Organization, user.organization_id)

    secrets, _ = await service._archive_workspace(db, organization, user)

    assert plain.status_code == 201
    # Only the API key is deleted from the store: the role has nothing there.
    assert [purpose for _, purpose in secrets if purpose.startswith("provider:")] == [
        "provider:anthropic:api-key"
    ]


@pytest.mark.asyncio
async def test_with_attribution_on_the_check_tags_a_session(db) -> None:
    from shim_enterprise.tenants.models import OrganizationGatewaySettings

    user = await _admin(db)
    await _call(db, user, "POST", IDENTITY)
    db.add(
        OrganizationGatewaySettings(
            organization_id=user.organization_id,
            settings={"bedrock_attribution": {"mode": "session_tags"}},
        )
    )
    await db.flush()
    ok = await _role(db, user)
    notag = await _role(db, user, "arn:aws:iam::000000000000:role/notag")

    def sts(request: httpx.Request) -> httpx.Response:
        form = dict(httpx.QueryParams(request.content.decode()))
        if form.get("RoleArn", "").endswith("/notag") and "Tags.member.1.Key" in form:
            return httpx.Response(
                403,
                text="<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>",
            )
        return aws({})(request)

    passed = await _call(
        db, user, "POST", f"{PROVIDERS}/{ok['id']}/aws-check", sts, json={}
    )
    refused = await _call(
        db, user, "POST", f"{PROVIDERS}/{notag['id']}/aws-check", sts, json={}
    )

    def tag_step(response) -> dict:
        return next(s for s in response.json()["steps"] if s["step"] == "tag_session")

    assert tag_step(passed) == {
        "step": "tag_session",
        "status": "ok",
        "aws_error": None,
    }
    assert tag_step(refused) == {
        "step": "tag_session",
        "status": "failed",
        "aws_error": "AccessDenied",
    }
    assert refused.json()["ok"] is False
