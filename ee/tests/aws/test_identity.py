from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timedelta, timezone
import json

import httpx
import pytest
from pydantic import ValidationError

from shim_enterprise.aws.identity import GatewayIdentity, IdentityUnavailable
from shim_enterprise.core.config import Settings, settings
from ee.tests.core.test_enterprise_config import ENTERPRISE_REQUIRED_VALUES

LATER = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
ANSWER = {
    "AccessKeyId": "ASIA0000000000000001",
    "SecretAccessKey": "s" * 40,
    "Token": "session-token",
    "Expiration": LATER,
}


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_env_keys_are_read_as_they_are(monkeypatch) -> None:
    monkeypatch.setattr(settings, "AWS_GATEWAY_IDENTITY", "env")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA0000000000000000")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "0" * 40)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)

    async with _client(lambda request: httpx.Response(500)) as client:
        found = await GatewayIdentity(client).credentials("eu-central-1")

    assert (found.access_key_id, found.session_token, found.expires_at) == (
        "AKIA0000000000000000",
        None,
        None,
    )


@pytest.mark.asyncio
async def test_imds_takes_a_token_then_the_first_role(monkeypatch) -> None:
    monkeypatch.setattr(settings, "AWS_GATEWAY_IDENTITY", "imds")
    monkeypatch.setattr(settings, "AWS_IMDS_URL", "http://imds.test")
    seen: list[httpx.Request] = []

    def imds(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "PUT":
            return httpx.Response(200, text="imds-token")
        if request.url.path.endswith("security-credentials/"):
            return httpx.Response(200, text="gateway-role\nother")
        return httpx.Response(200, json=ANSWER)

    async with _client(imds) as client:
        identity = GatewayIdentity(client, client)
        first = await identity.credentials("eu-central-1")
        again = await identity.credentials("eu-central-1")

    assert first is again
    assert [(r.method, r.url.path) for r in seen] == [
        ("PUT", "/latest/api/token"),
        ("GET", "/latest/meta-data/iam/security-credentials/"),
        ("GET", "/latest/meta-data/iam/security-credentials/gateway-role"),
    ]
    assert seen[0].headers["x-aws-ec2-metadata-token-ttl-seconds"] == "21600"
    assert seen[1].headers["x-aws-ec2-metadata-token"] == "imds-token"
    assert first.session_token is not None
    assert first.session_token.get_secret_value() == "session-token"


@pytest.mark.asyncio
async def test_the_container_source_sends_the_token_file(monkeypatch, tmp_path) -> None:
    token = tmp_path / "token"
    token.write_text("pod-token\n")
    monkeypatch.setattr(settings, "AWS_GATEWAY_IDENTITY", "container")
    monkeypatch.setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://pod.test/creds")
    monkeypatch.setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", str(token))
    seen: list[httpx.Request] = []

    def pod(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=ANSWER)

    async with _client(pod) as client:
        found = await GatewayIdentity(client, client).credentials("eu-central-1")

    assert found.access_key_id == "ASIA0000000000000001"
    assert seen[0].headers["authorization"] == "pod-token"


@pytest.mark.asyncio
async def test_a_web_identity_file_is_exchanged_unsigned(monkeypatch, tmp_path) -> None:
    token = tmp_path / "token"
    token.write_text("oidc-token")
    monkeypatch.setattr(settings, "AWS_GATEWAY_IDENTITY", "web_identity_file")
    monkeypatch.setattr(settings, "AWS_STS_URL_TEMPLATE", "https://sts.{region}.test")
    monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", str(token))
    monkeypatch.setenv("AWS_ROLE_ARN", "arn:aws:iam::000000000000:role/gateway")
    monkeypatch.delenv("AWS_ROLE_SESSION_NAME", raising=False)
    seen: list[httpx.Request] = []

    def sts(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            text="<AssumeRoleWithWebIdentityResponse><Credentials>"
            "<AccessKeyId>ASIA0000000000000002</AccessKeyId>"
            f"<SecretAccessKey>{'t' * 40}</SecretAccessKey>"
            "<SessionToken>web-session</SessionToken>"
            f"<Expiration>{LATER}</Expiration></Credentials>"
            "</AssumeRoleWithWebIdentityResponse>",
        )

    async with _client(sts) as client:
        found = await GatewayIdentity(client).credentials("eu-west-1")

    form = dict(httpx.QueryParams(seen[0].content.decode()))
    assert found.access_key_id == "ASIA0000000000000002"
    assert str(seen[0].url) == "https://sts.eu-west-1.test/"
    assert "authorization" not in seen[0].headers
    assert (form["Action"], form["WebIdentityToken"], form["RoleSessionName"]) == (
        "AssumeRoleWithWebIdentity",
        "oidc-token",
        "shim-gateway",
    )


@pytest.mark.asyncio
async def test_a_google_id_token_is_cached_per_audience_until_its_expiry(
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "AWS_GATEWAY_IDENTITY", "gcp_metadata")
    monkeypatch.setattr(settings, "AWS_GCP_METADATA_URL", "http://metadata.test")
    seen: list[httpx.Request] = []

    def metadata(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        claims = {
            "aud": request.url.params["audience"],
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
        }
        payload = (
            base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        )
        return httpx.Response(200, text=f"e30.{payload}.sig")

    async with _client(metadata) as client:
        identity = GatewayIdentity(client, client)
        tokens = await asyncio.gather(
            identity.google_id_token("shim-aws:a"),
            identity.google_id_token("shim-aws:a"),
        )
        other = await identity.google_id_token("shim-aws:b")

    assert tokens[0] == tokens[1] != other
    assert [r.url.params["audience"] for r in seen] == ["shim-aws:a", "shim-aws:b"]
    assert all(r.headers["metadata-flavor"] == "Google" for r in seen)


@pytest.mark.asyncio
async def test_a_metadata_answer_that_fails_or_hangs_is_unavailable(
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "AWS_GATEWAY_IDENTITY", "imds")
    monkeypatch.setattr(settings, "AWS_IMDS_URL", "http://imds.test")

    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    async with _client(slow) as client:
        with pytest.raises(IdentityUnavailable) as failed:
            await GatewayIdentity(client, client).credentials("eu-central-1")

    assert failed.value.source == "imds"


@pytest.mark.parametrize(
    ("source", "variables"),
    [
        ("env", {}),
        ("web_identity_file", {"AWS_ROLE_ARN": "arn:aws:iam::000000000000:role/x"}),
        ("container", {}),
        ("gcp_metadata", {}),
    ],
)
def test_startup_fails_without_the_sources_variables(
    monkeypatch, source, variables
) -> None:
    for name in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in variables.items():
        monkeypatch.setenv(name, value)

    with pytest.raises(ValidationError, match="AWS_GATEWAY_IDENTITY"):
        Settings(
            **ENTERPRISE_REQUIRED_VALUES, AWS_GATEWAY_IDENTITY=source, _env_file=None
        )

    assert (
        Settings(**ENTERPRISE_REQUIRED_VALUES, _env_file=None).AWS_GATEWAY_IDENTITY
        == "none"
    )


@pytest.mark.asyncio
async def test_metadata_calls_never_cross_a_proxy_or_a_redirect(monkeypatch) -> None:
    monkeypatch.setattr(settings, "AWS_GATEWAY_IDENTITY", "imds")
    monkeypatch.setattr(settings, "AWS_IMDS_URL", "http://imds.test")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.bank.test:3128")
    made: list[dict] = []
    real = httpx.AsyncClient

    def imds(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            return httpx.Response(200, text="imds-token")
        if request.url.path.endswith("security-credentials/"):
            return httpx.Response(200, text="gateway-role")
        return httpx.Response(200, json=ANSWER)

    def client(**kwargs) -> httpx.AsyncClient:
        made.append(kwargs)
        return real(transport=httpx.MockTransport(imds), **kwargs)

    async with _client(lambda request: httpx.Response(500)) as shared:
        monkeypatch.setattr(httpx, "AsyncClient", client)
        found = await GatewayIdentity(shared).credentials("eu-central-1")

    assert found.access_key_id == "ASIA0000000000000001"
    assert made and all(
        (kwargs["trust_env"], kwargs["follow_redirects"]) == (False, False)
        for kwargs in made
    )


@pytest.mark.asyncio
async def test_the_gateways_own_web_identity_refusal_is_unavailable(
    monkeypatch, tmp_path
) -> None:
    token = tmp_path / "token"
    token.write_text("oidc-token")
    monkeypatch.setattr(settings, "AWS_GATEWAY_IDENTITY", "web_identity_file")
    monkeypatch.setattr(settings, "AWS_STS_URL_TEMPLATE", "https://sts.{region}.test")
    monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", str(token))
    monkeypatch.setenv("AWS_ROLE_ARN", "arn:aws:iam::000000000000:role/gateway")

    def sts(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            text="<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error>"
            "</ErrorResponse>",
        )

    async with _client(sts) as client:
        with pytest.raises(IdentityUnavailable) as refused:
            await GatewayIdentity(client).credentials("eu-central-1")
        token.unlink()
        with pytest.raises(IdentityUnavailable) as missing:
            await GatewayIdentity(client).credentials("eu-central-1")

    assert (refused.value.source, refused.value.status) == ("web_identity_file", 403)
    assert missing.value.source == "web_identity_file"
