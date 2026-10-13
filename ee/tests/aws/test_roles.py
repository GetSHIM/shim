from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import logging
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from shim.gateway.contracts.ids import TenantId
from shim.gateway.pipeline.provider_execution import ProviderCallError
from shim_enterprise.aws.roles import AwsRoles
from shim_enterprise.core.config import settings
from shim_enterprise.secrets.references import CredentialReference
from shim_enterprise.secrets.store import ManagedProviderCredentialResolver
from shim_enterprise.tenants.models import Organization, OrganizationAwsIdentity

ROLE = "arn:aws:iam::000000000000:role/shim-bedrock"


def _answer(seconds: int) -> httpx.Response:
    expires = (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return httpx.Response(
        200,
        text="<AssumeRoleResponse><AssumeRoleResult><Credentials>"
        "<AccessKeyId>ASIA0000000000000009</AccessKeyId>"
        f"<SecretAccessKey>{'r' * 40}</SecretAccessKey>"
        "<SessionToken>role-session-token</SessionToken>"
        f"<Expiration>{expires}</Expiration></Credentials></AssumeRoleResult>"
        "</AssumeRoleResponse>",
    )


@pytest.fixture
def env_identity(monkeypatch) -> None:
    monkeypatch.setattr(settings, "AWS_GATEWAY_IDENTITY", "env")
    monkeypatch.setattr(settings, "AWS_STS_URL_TEMPLATE", "https://sts.{region}.test")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA0000000000000000")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "0" * 40)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)


async def _tenant(db) -> tuple[Organization, str]:
    organization = Organization(
        id=uuid4(), name="Roles", slug=f"roles-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    external_id = f"shim-{uuid4().hex}"
    db.add(
        OrganizationAwsIdentity(
            organization_id=organization.id, external_id=external_id
        )
    )
    await db.flush()
    return organization, external_id


async def _roles(db, handler) -> tuple[AwsRoles, httpx.AsyncClient]:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    connection = await db.connection()
    # Each session a savepoint of the test's transaction, as the gateway's are.
    return AwsRoles(
        client,
        lambda: AsyncSession(bind=connection, join_transaction_mode="create_savepoint"),
    ), client


@pytest.mark.asyncio
async def test_assume_role_is_signed_with_the_tenants_external_id(
    db, env_identity
) -> None:
    organization, external_id = await _tenant(db)
    secret_id = uuid4()
    seen: list[httpx.Request] = []

    def sts(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _answer(3_600)

    roles, client = await _roles(db, sts)
    async with client:
        first = await roles.credentials(
            organization.id, secret_id, ROLE, "eu-central-1"
        )
        again = await roles.credentials(
            organization.id, secret_id, ROLE, "eu-central-1"
        )

    [request] = seen
    form = dict(httpx.QueryParams(request.content.decode()))
    assert first is again
    assert str(request.url) == "https://sts.eu-central-1.test/"
    assert form == {
        "Action": "AssumeRole",
        "RoleArn": ROLE,
        "RoleSessionName": f"shim-{organization.id.hex[:8]}-{secret_id.hex[:8]}",
        "ExternalId": external_id,
        "DurationSeconds": "3600",
        "Version": "2011-06-15",
    }
    assert (
        "/eu-central-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date,"
        in (request.headers["authorization"])
    )
    assert first.session_token is not None


@pytest.mark.asyncio
async def test_a_session_close_to_its_end_is_assumed_again(db, env_identity) -> None:
    organization, _ = await _tenant(db)
    calls: list[int] = []

    def sts(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return _answer(250)

    roles, client = await _roles(db, sts)
    async with client:
        await roles.credentials(organization.id, uuid4(), ROLE, "eu-central-1")
        secret = uuid4()
        await roles.credentials(organization.id, secret, ROLE, "eu-central-1")
        await roles.credentials(organization.id, secret, ROLE, "eu-central-1")

    assert len(calls) == 3


@pytest.mark.asyncio
async def test_the_hosted_cloud_trades_a_google_token_for_the_role(
    db, monkeypatch
) -> None:
    organization, external_id = await _tenant(db)
    monkeypatch.setattr(settings, "AWS_GATEWAY_IDENTITY", "gcp_metadata")
    monkeypatch.setattr(settings, "AWS_GCP_METADATA_URL", "http://metadata.test")
    monkeypatch.setattr(settings, "AWS_STS_URL_TEMPLATE", "https://sts.{region}.test")
    seen: list[httpx.Request] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "metadata.test":
            return httpx.Response(200, text="e30.e30.sig")
        return _answer(3_600)

    roles, client = await _roles(db, answer)
    async with client:
        await roles.credentials(organization.id, uuid4(), ROLE, "eu-central-1")

    metadata, sts = seen
    form = dict(httpx.QueryParams(sts.content.decode()))
    assert metadata.url.params["audience"] == f"shim-aws:{external_id}"
    assert "authorization" not in sts.headers
    assert (form["Action"], form["WebIdentityToken"]) == (
        "AssumeRoleWithWebIdentity",
        "e30.e30.sig",
    )


@pytest.mark.parametrize(
    ("status", "code", "error", "http"),
    [
        (403, "AccessDenied", "INVALID_PROVIDER_CREDENTIAL", 401),
        (400, "InvalidIdentityToken", "INVALID_PROVIDER_CREDENTIAL", 401),
        (400, "ExpiredTokenException", "INVALID_PROVIDER_CREDENTIAL", 401),
        (500, "InternalFailure", "PROVIDER_UNAVAILABLE", 503),
        (200, None, "PROVIDER_UNAVAILABLE", 503),
    ],
)
@pytest.mark.asyncio
async def test_aws_answers_map_to_provider_errors_and_log_no_secret(
    db, env_identity, caplog, status, code, error, http
) -> None:
    organization, external_id = await _tenant(db)

    def sts(request: httpx.Request) -> httpx.Response:
        if code is None:
            return httpx.Response(200, text="not xml")
        return httpx.Response(
            status,
            text=f"<ErrorResponse><Error><Code>{code}</Code></Error></ErrorResponse>",
        )

    roles, client = await _roles(db, sts)
    row = SimpleNamespace(id=uuid4(), credential_kind="aws_role", aws_role_arn=ROLE)
    resolver = ManagedProviderCredentialResolver(
        "anthropic", SimpleNamespace(), None, aws_roles=roles
    )
    caplog.set_level(logging.INFO)
    async with client:
        with pytest.raises(ProviderCallError) as raised:
            await resolver.resolve_row(
                TenantId(organization.id),
                row,
                CredentialReference(row.id, "eu-central-1"),
            )

    assert (raised.value.status_code, raised.value.error_code) == (http, error)
    for secret in (ROLE, external_id, "0" * 40, "role-session-token"):
        assert secret not in caplog.text


@pytest.mark.asyncio
async def test_no_gateway_identity_is_not_configured_and_calls_nothing(db) -> None:
    organization, _ = await _tenant(db)
    seen: list[httpx.Request] = []
    roles, client = await _roles(
        db, lambda request: seen.append(request) or httpx.Response(500)
    )
    row = SimpleNamespace(id=uuid4(), credential_kind="aws_role", aws_role_arn=ROLE)
    resolver = ManagedProviderCredentialResolver(
        "anthropic", SimpleNamespace(), None, aws_roles=roles
    )

    async with client:
        with pytest.raises(ProviderCallError) as raised:
            await resolver.resolve_row(
                TenantId(organization.id),
                row,
                CredentialReference(row.id, "eu-central-1"),
            )

    assert (raised.value.status_code, raised.value.error_code) == (
        503,
        "PROVIDER_NOT_CONFIGURED",
    )
    assert seen == []


@pytest.mark.asyncio
async def test_the_bedrock_key_never_outlives_the_role_session(
    db, env_identity
) -> None:
    organization, _ = await _tenant(db)
    roles, client = await _roles(db, lambda request: _answer(600))
    row = SimpleNamespace(id=uuid4(), credential_kind="aws_role", aws_role_arn=ROLE)
    resolver = ManagedProviderCredentialResolver(
        "anthropic", SimpleNamespace(), None, aws_roles=roles
    )

    async with client:
        token = await resolver.resolve_row(
            TenantId(organization.id), row, CredentialReference(row.id, "eu-central-1")
        )

    url = base64.b64decode(token.removeprefix("bedrock-api-key-")).decode()
    expires = int(url.split("X-Amz-Expires=")[1].split("&")[0])
    assert "X-Amz-Credential=ASIA0000000000000009" in url
    assert "X-Amz-Security-Token=role-session-token" in url
    assert 500 <= expires <= 540
