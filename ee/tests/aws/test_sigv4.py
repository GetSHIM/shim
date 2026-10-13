from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import re

import pytest
from pydantic import SecretStr

from shim_enterprise.aws.sigv4 import (
    AwsCredentials,
    _canonical_query,
    bedrock_bearer_token,
    sign_headers,
)

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)
KEY = AwsCredentials("AKIA0000000000000000", SecretStr("0" * 40))
SESSION = AwsCredentials(
    "AKIA0000000000000000", SecretStr("0" * 40), SecretStr("0" * 64)
)
ASSUME_ROLE = (
    b"Action=AssumeRole&DurationSeconds=3600&ExternalId=shim-0000000000000000"
    b"&RoleArn=arn%3Aaws%3Aiam%3A%3A000000000000%3Arole%2Fshim-bedrock"
    b"&RoleSessionName=shim-00000000&Version=2011-06-15"
)
FORM = "application/x-www-form-urlencoded; charset=utf-8"


def _token_url(token: str) -> str:
    assert token.startswith("bedrock-api-key-")
    return base64.b64decode(token.removeprefix("bedrock-api-key-")).decode()


@pytest.mark.parametrize(
    ("credentials", "signature"),
    [
        (KEY, "915081ee35caf8511a0a2594703a45ea5f8bed6fca6895f8c30722be9c5fad15"),
        (SESSION, "cb84ef1a36667ee2120bad188a27f2c113aec127ba54e386a5411359331c1247"),
    ],
)
def test_the_bedrock_token_matches_botocore(credentials, signature) -> None:
    url = _token_url(
        bedrock_bearer_token(
            credentials, region="eu-central-1", now=NOW, expires_seconds=3600
        )
    )

    assert url.startswith("bedrock.amazonaws.com/?Action=CallWithBearerToken&")
    assert url.endswith(f"&X-Amz-Signature={signature}&Version=1")
    assert (
        "X-Amz-Credential=AKIA0000000000000000%2F20261008%2Feu-central-1%2Fbedrock%2Faws4_request"
        in url
    )
    assert ("X-Amz-Security-Token=" in url) == (credentials is SESSION)


@pytest.mark.parametrize(
    ("credentials", "signed", "signature"),
    [
        (
            KEY,
            "content-type;host;x-amz-date",
            "312f92b211d5b85dd66ce05e8524483744f5a3218ee52f79e05c5ca6ea64b546",
        ),
        (
            SESSION,
            "content-type;host;x-amz-date;x-amz-security-token",
            "ca4fc4cc86911b47ddb34af6ee42a3048f21f577526d80d76af44a253e121248",
        ),
    ],
)
def test_the_sts_header_signature_matches_botocore(
    credentials, signed, signature
) -> None:
    headers = sign_headers(
        "POST",
        "https://sts.eu-central-1.amazonaws.com/",
        {"Content-Type": FORM},
        ASSUME_ROLE,
        service="sts",
        region="eu-central-1",
        credentials=credentials,
        now=NOW,
    )

    assert headers["authorization"] == (
        "AWS4-HMAC-SHA256 Credential=AKIA0000000000000000/20261008/eu-central-1/sts/"
        f"aws4_request, SignedHeaders={signed}, Signature={signature}"
    )
    assert headers["x-amz-date"] == "20261008T120000Z"
    assert headers["content-type"] == FORM
    assert ("x-amz-security-token" in headers) == (credentials is SESSION)


def test_an_extra_header_is_signed_and_queries_are_rfc3986_encoded() -> None:
    plain = sign_headers(
        "GET",
        "https://example.amazonaws.com/",
        {},
        b"",
        service="s",
        region="eu-central-1",
        credentials=KEY,
        now=NOW,
    )
    extra = sign_headers(
        "GET",
        "https://example.amazonaws.com/",
        {"X-Extra": "  a   b "},
        b"",
        service="s",
        region="eu-central-1",
        credentials=KEY,
        now=NOW,
    )

    assert "SignedHeaders=host;x-amz-date," in plain["authorization"]
    assert "SignedHeaders=host;x-amz-date;x-extra," in extra["authorization"]
    assert _canonical_query([("b", "a b"), ("a", "x/y:z+")]) == "a=x%2Fy%3Az%2B&b=a%20b"


@pytest.mark.parametrize("seconds", [0, 43_201])
def test_a_token_lifetime_outside_one_second_to_twelve_hours_is_refused(
    seconds,
) -> None:
    with pytest.raises(ValueError):
        bedrock_bearer_token(
            KEY, region="eu-central-1", now=NOW, expires_seconds=seconds
        )


def test_the_token_has_its_shape_and_no_secret_is_printed() -> None:
    token = bedrock_bearer_token(
        SESSION, region="eu-central-1", now=NOW, expires_seconds=43_200
    )

    assert re.fullmatch(r"bedrock-api-key-[A-Za-z0-9+/=]+", token)
    assert "X-Amz-Expires=43200" in _token_url(token)
    assert "0" * 40 not in repr(SESSION) and "0" * 64 not in repr(SESSION)


def test_a_time_in_another_zone_signs_the_same_utc_instant() -> None:
    istanbul = NOW.astimezone(timezone(timedelta(hours=3)))
    sign = {
        "method": "POST",
        "url": "https://sts.eu-central-1.amazonaws.com/",
        "headers": {"Content-Type": FORM},
        "body": ASSUME_ROLE,
    }

    assert sign_headers(
        sign["method"],
        sign["url"],
        sign["headers"],
        sign["body"],
        service="sts",
        region="eu-central-1",
        credentials=KEY,
        now=istanbul,
    ) == sign_headers(
        sign["method"],
        sign["url"],
        sign["headers"],
        sign["body"],
        service="sts",
        region="eu-central-1",
        credentials=KEY,
        now=NOW,
    )
    assert bedrock_bearer_token(
        KEY, region="eu-central-1", now=istanbul, expires_seconds=60
    ) == bedrock_bearer_token(KEY, region="eu-central-1", now=NOW, expires_seconds=60)
