"""The gateway's own AWS identity: the credentials that assume tenants' roles.

The operator picks one source (`AWS_GATEWAY_IDENTITY`); nothing is probed. Base
credentials are cached until 300 seconds before they expire; a Google ID token, used
by the hosted cloud instead of AWS credentials, is cached per audience the same way.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path

import httpx
from pydantic import SecretStr

from shim_enterprise.aws.sigv4 import AwsCredentials
from shim_enterprise.aws.sts import assume_role_with_web_identity
from shim_enterprise.aws.tokens import ExpiringCache
from shim_enterprise.core.config import settings

METADATA_TIMEOUT = 2
# A source that answers without an expiry (environment keys) is re-read this often.
UNDATED = timedelta(seconds=600)


class IdentityUnavailable(Exception):
    """The configured source did not answer usable credentials."""

    def __init__(self, source: str, status: int | None = None) -> None:
        super().__init__(f"{source} {status}")
        self.source = source
        self.status = status


def _container_credentials(response: httpx.Response) -> AwsCredentials:
    try:
        answer = response.json()
        expiration = datetime.fromisoformat(answer["Expiration"].replace("Z", "+00:00"))
        return AwsCredentials(
            access_key_id=answer["AccessKeyId"],
            secret_access_key=SecretStr(answer["SecretAccessKey"]),
            session_token=SecretStr(answer["Token"]),
            expires_at=expiration,
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        raise IdentityUnavailable("credentials_answer") from None


def _token_expiry(token: str, now: datetime) -> datetime:
    """`exp` from the unverified payload (AWS verifies the token); 300 s when unreadable."""
    try:
        payload = token.split(".")[1]
        claims = json.loads(
            base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        )
        return datetime.fromtimestamp(int(claims["exp"]), timezone.utc)
    except (IndexError, ValueError, KeyError, TypeError):
        # Kept 300 s: the cache renews 300 s before the time given here.
        return now + timedelta(seconds=600)


class GatewayIdentity:
    def __init__(self, http_client: httpx.AsyncClient) -> None:
        self.http_client = http_client
        self.source = settings.AWS_GATEWAY_IDENTITY
        self._credentials: ExpiringCache[AwsCredentials] = ExpiringCache(1)
        self._tokens: ExpiringCache[str] = ExpiringCache(64)

    async def credentials(self, region: str) -> AwsCredentials:
        """Base credentials that sign AssumeRole (every source but gcp_metadata)."""
        now = datetime.now(timezone.utc)

        async def mint() -> tuple[AwsCredentials, datetime]:
            found = await self._read(region)
            return found, found.expires_at or now + UNDATED

        return await self._credentials.get(self.source, mint, now=now)

    async def google_id_token(self, audience: str) -> str:
        """A Google ID token for `audience` from the metadata server (gcp_metadata)."""
        now = datetime.now(timezone.utc)

        async def mint() -> tuple[str, datetime]:
            response = await self._get(
                f"{settings.AWS_GCP_METADATA_URL}/computeMetadata/v1/instance/"
                "service-accounts/default/identity",
                params={"audience": audience, "format": "full"},
                headers={"Metadata-Flavor": "Google"},
                source="gcp_metadata",
            )
            token = response.text.strip()
            return token, _token_expiry(token, now)

        return await self._tokens.get(audience, mint, now=now)

    async def _get(self, url: str, *, source: str, **kwargs) -> httpx.Response:
        try:
            response = await self.http_client.get(
                url, timeout=METADATA_TIMEOUT, **kwargs
            )
        except httpx.HTTPError:
            raise IdentityUnavailable(source) from None
        if response.status_code != 200:
            raise IdentityUnavailable(source, response.status_code)
        return response

    async def _read(self, region: str) -> AwsCredentials:
        environ = os.environ
        if self.source == "env":
            token = environ.get("AWS_SESSION_TOKEN")
            return AwsCredentials(
                access_key_id=environ["AWS_ACCESS_KEY_ID"],
                secret_access_key=SecretStr(environ["AWS_SECRET_ACCESS_KEY"]),
                session_token=SecretStr(token) if token else None,
            )
        if self.source == "web_identity_file":
            token = Path(environ["AWS_WEB_IDENTITY_TOKEN_FILE"]).read_text().strip()
            return await assume_role_with_web_identity(
                self.http_client,
                region=region,
                role_arn=environ["AWS_ROLE_ARN"],
                session_name=environ.get("AWS_ROLE_SESSION_NAME") or "shim-gateway",
                web_identity_token=token,
                duration_seconds=settings.AWS_ROLE_SESSION_SECONDS,
            )
        if self.source == "container":
            url = environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI") or (
                "http://169.254.170.2"
                + environ["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"]
            )
            token_file = environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
            authorization = (
                Path(token_file).read_text().strip()
                if token_file
                else environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN")
            )
            response = await self._get(
                url,
                headers={"Authorization": authorization} if authorization else {},
                source="container",
            )
            return _container_credentials(response)
        if self.source == "imds":
            try:
                token = await self.http_client.put(
                    f"{settings.AWS_IMDS_URL}/latest/api/token",
                    headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                    timeout=METADATA_TIMEOUT,
                )
            except httpx.HTTPError:
                raise IdentityUnavailable("imds") from None
            if token.status_code != 200:
                raise IdentityUnavailable("imds", token.status_code)
            headers = {"X-aws-ec2-metadata-token": token.text}
            base = f"{settings.AWS_IMDS_URL}/latest/meta-data/iam/security-credentials/"
            listed = await self._get(base, headers=headers, source="imds")
            names = listed.text.split()
            if not names:
                raise IdentityUnavailable("imds")
            response = await self._get(base + names[0], headers=headers, source="imds")
            return _container_credentials(response)
        raise IdentityUnavailable(self.source)
