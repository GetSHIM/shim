"""AWS Security Token Service calls, signed in house."""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlencode
from xml.etree import ElementTree

import httpx

from shim_enterprise.aws.sigv4 import AwsCredentials, sign_headers
from shim_enterprise.core.config import settings

STS_VERSION = "2011-06-15"
MAX_ANSWER_BYTES = 64 * 1024
_FORM = "application/x-www-form-urlencoded; charset=utf-8"


class StsError(Exception):
    """STS refused (`status` 4xx) or could not answer."""

    def __init__(self, status: int, code: str | None = None) -> None:
        super().__init__(code or str(status))
        self.status = status
        self.code = code


async def _call(
    http_client: httpx.AsyncClient,
    credentials: AwsCredentials,
    *,
    region: str,
    parameters: dict[str, str],
) -> ElementTree.Element:
    """One signed form POST, no retry, the XML answer at most 64 KB."""
    url = settings.AWS_STS_URL_TEMPLATE.format(region=region) + "/"
    body = urlencode({**parameters, "Version": STS_VERSION}).encode()
    headers = sign_headers(
        "POST",
        url,
        {"content-type": _FORM},
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
        code = next(
            (node.text for node in root.iter() if node.tag.endswith("Code")), None
        )
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
    arn = next((node.text for node in root.iter() if node.tag.endswith("Arn")), None)
    if not arn:
        raise StsError(502, "ANSWER_WITHOUT_ARN")
    return arn
