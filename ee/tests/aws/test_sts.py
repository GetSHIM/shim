from __future__ import annotations

from urllib.parse import parse_qsl

import httpx
import pytest
from pydantic import SecretStr

from shim_enterprise.aws.sigv4 import AwsCredentials
from shim_enterprise.aws.sts import StsError, get_caller_identity
from shim_enterprise.core.config import settings

KEY = AwsCredentials("AKIA0000000000000000", SecretStr("0" * 40))
IDENTITY = (
    '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
    "<GetCallerIdentityResult><Arn>arn:aws:iam::000000000000:user/shim</Arn>"
    "<UserId>AIDA0000</UserId><Account>000000000000</Account>"
    "</GetCallerIdentityResult></GetCallerIdentityResponse>"
)
REFUSED = (
    '<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error>'
    "<Type>Sender</Type><Code>InvalidClientTokenId</Code>"
    "<Message>The security token included in the request is invalid.</Message>"
    "</Error></ErrorResponse>"
)


async def _call(status: int, body: bytes, seen: list[httpx.Request] | None = None):
    def answer(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return httpx.Response(status, content=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as client:
        return await get_caller_identity(client, KEY, region="us-east-1")


@pytest.mark.asyncio
async def test_the_identity_is_a_signed_form_post(monkeypatch) -> None:
    monkeypatch.setattr(
        settings, "AWS_STS_URL_TEMPLATE", "https://sts.{region}.amazonaws.com"
    )
    seen: list[httpx.Request] = []

    arn = await _call(200, IDENTITY.encode(), seen)

    [request] = seen
    assert arn == "arn:aws:iam::000000000000:user/shim"
    assert str(request.url) == "https://sts.us-east-1.amazonaws.com/"
    assert dict(parse_qsl(request.content.decode())) == {
        "Action": "GetCallerIdentity",
        "Version": "2011-06-15",
    }
    assert request.headers["authorization"].startswith(
        "AWS4-HMAC-SHA256 Credential=AKIA0000000000000000/"
    )
    assert (
        "/us-east-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date,"
        in (request.headers["authorization"])
    )


@pytest.mark.asyncio
async def test_a_refusal_carries_its_code() -> None:
    with pytest.raises(StsError) as refused:
        await _call(403, REFUSED.encode())

    assert (refused.value.status, refused.value.code) == (403, "InvalidClientTokenId")


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b"<a>" + b"x" * (64 * 1024) + b"</a>", "ANSWER_TOO_LARGE"),
        (b"not xml", "ANSWER_NOT_XML"),
        (b"<GetCallerIdentityResponse/>", "ANSWER_WITHOUT_ARN"),
    ],
)
@pytest.mark.asyncio
async def test_an_answer_that_is_too_large_or_not_xml_is_refused(body, code) -> None:
    with pytest.raises(StsError) as refused:
        await _call(200, body)

    assert refused.value.code == code


@pytest.mark.asyncio
async def test_a_code_outside_the_vocabulary_is_unrecognized() -> None:
    body = (
        "<ErrorResponse><Error><Code>Bad code &lt;script&gt; "
        + "x" * 500
        + "</Code></Error></ErrorResponse>"
    ).encode()

    with pytest.raises(StsError) as refused:
        await _call(403, body)

    assert (refused.value.status, refused.value.code) == (403, "unrecognized")
