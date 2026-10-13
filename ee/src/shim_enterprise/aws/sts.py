"""AWS Security Token Service calls, signed in house."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from urllib.parse import urlencode
from xml.etree import ElementTree

import httpx
from pydantic import SecretStr

from shim_enterprise.aws.sigv4 import AwsCredentials, sign_headers
from shim_enterprise.core.config import settings

STS_VERSION = "2011-06-15"
MAX_ANSWER_BYTES = 64 * 1024
_FORM = "application/x-www-form-urlencoded; charset=utf-8"
_CODE = re.compile(r"[A-Za-z][A-Za-z0-9.]{0,63}")


class StsError(Exception):
    """STS refused (`status` 4xx) or could not answer."""

    def __init__(self, status: int, code: str | None = None) -> None:
        super().__init__(code or str(status))
        self.status = status
        self.code = code


async def _call(
    http_client: httpx.AsyncClient,
    credentials: AwsCredentials | None,
    *,
    region: str,
    parameters: dict[str, str],
) -> ElementTree.Element:
    """One form POST, signed unless `credentials` is None, no retry, the XML answer at
    most 64 KB."""
    url = settings.AWS_STS_URL_TEMPLATE.format(region=region) + "/"
    body = urlencode({**parameters, "Version": STS_VERSION}).encode()
    headers = {"content-type": _FORM}
    if credentials is not None:
        headers = sign_headers(
            "POST",
            url,
            headers,
            body,
            service="sts",
            region=region,
            credentials=credentials,
            now=datetime.now(timezone.utc),
        )
    try:
        async with http_client.stream(
            "POST", url, content=body, headers=headers, timeout=10
        ) as response:
            data = b""
            async for chunk in response.aiter_bytes():
                data += chunk
                if len(data) > MAX_ANSWER_BYTES:
                    raise StsError(502, "ANSWER_TOO_LARGE")
    except httpx.HTTPError:
        raise StsError(503) from None
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError:
        raise StsError(502, "ANSWER_NOT_XML") from None
    if response.status_code != 200:
        code = _text(root, "Code")
        # A bounded vocabulary: it reaches audits, logs and the check view.
        if code is not None and not _CODE.fullmatch(code):
            code = "unrecognized"
        raise StsError(response.status_code, code)
    return root


async def get_caller_identity(
    http_client: httpx.AsyncClient, credentials: AwsCredentials, *, region: str
) -> str:
    """The calling identity's ARN; AWS requires no permission for it."""
    root = await _call(
        http_client,
        credentials,
        region=region,
        parameters={"Action": "GetCallerIdentity"},
    )
    arn = _text(root, "Arn")
    if not arn:
        raise StsError(502, "ANSWER_WITHOUT_ARN")
    return arn


def _text(root: ElementTree.Element, name: str) -> str | None:
    return next((node.text for node in root.iter() if node.tag.endswith(name)), None)


def _credentials(root: ElementTree.Element) -> AwsCredentials:
    key, secret, token, expiration = (
        _text(root, name)
        for name in ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration")
    )
    if not (key and secret and token and expiration):
        raise StsError(502, "ANSWER_WITHOUT_CREDENTIALS")
    try:
        expires_at = datetime.fromisoformat(expiration)
    except ValueError:
        raise StsError(502, "ANSWER_WITHOUT_CREDENTIALS") from None
    return AwsCredentials(
        access_key_id=key,
        secret_access_key=SecretStr(secret),
        session_token=SecretStr(token),
        expires_at=expires_at
        if expires_at.tzinfo is not None
        else expires_at.replace(tzinfo=timezone.utc),
    )


async def assume_role(
    http_client: httpx.AsyncClient,
    credentials: AwsCredentials,
    *,
    region: str,
    role_arn: str,
    session_name: str,
    external_id: str,
    duration_seconds: int,
    tags: tuple[tuple[str, str], ...] = (),
) -> AwsCredentials:
    """Temporary credentials of a tenant's role, asked with the gateway's own; `tags`
    become session tags (the trust policy must allow sts:TagSession)."""
    tagged = {
        f"Tags.member.{index}.{part}": value
        for index, (key, value) in enumerate(tags, start=1)
        for part, value in (("Key", key), ("Value", value))
    }
    root = await _call(
        http_client,
        credentials,
        region=region,
        parameters={
            "Action": "AssumeRole",
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "ExternalId": external_id,
            "DurationSeconds": str(duration_seconds),
            **tagged,
        },
    )
    return _credentials(root)


async def assume_role_with_web_identity(
    http_client: httpx.AsyncClient,
    *,
    region: str,
    role_arn: str,
    session_name: str,
    web_identity_token: str,
    duration_seconds: int,
) -> AwsCredentials:
    """Temporary credentials for an identity provider's token; the call is unsigned."""
    root = await _call(
        http_client,
        None,
        region=region,
        parameters={
            "Action": "AssumeRoleWithWebIdentity",
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "WebIdentityToken": web_identity_token,
            "DurationSeconds": str(duration_seconds),
        },
    )
    return _credentials(root)
