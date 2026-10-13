"""AWS Signature Version 4, stdlib only.

Two uses: signing an STS call's headers, and presigning the query that becomes a
short-term Bedrock API key (the algorithm of aws-bedrock-token-generator 1.1.0).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
from urllib.parse import parse_qsl, quote, urlsplit

from pydantic import SecretStr

ALGORITHM = "AWS4-HMAC-SHA256"
BEDROCK_TOKEN_HOST = "bedrock.amazonaws.com"
BEDROCK_TOKEN_PREFIX = "bedrock-api-key-"
MAX_TOKEN_SECONDS = 43_200


@dataclass(frozen=True)
class AwsCredentials:
    access_key_id: str
    secret_access_key: SecretStr
    session_token: SecretStr | None = None
    expires_at: datetime | None = None


def _encode(value: str) -> str:
    return quote(value, safe="-_.~")


def _canonical_query(pairs: list[tuple[str, str]]) -> str:
    return "&".join(
        f"{_encode(name)}={_encode(value)}" for name, value in sorted(pairs)
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _scope(now: datetime, region: str, service: str) -> str:
    return f"{now:%Y%m%d}/{region}/{service}/aws4_request"


def _signature(
    credentials: AwsCredentials,
    now: datetime,
    region: str,
    service: str,
    canonical_request: str,
) -> str:
    string_to_sign = "\n".join(
        (
            ALGORITHM,
            f"{now:%Y%m%dT%H%M%SZ}",
            _scope(now, region, service),
            _sha256(canonical_request.encode()),
        )
    )
    key = f"AWS4{credentials.secret_access_key.get_secret_value()}".encode()
    for part in (f"{now:%Y%m%d}", region, service, "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    return hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()


def _canonical_request(
    method: str,
    path: str,
    query: str,
    headers: dict[str, str],
    payload_hash: str,
) -> tuple[str, str]:
    names = sorted(headers)
    canonical_headers = "".join(
        f"{name}:{' '.join(headers[name].split())}\n" for name in names
    )
    signed = ";".join(names)
    return (
        "\n".join(
            (
                method,
                quote(path or "/", safe="/~"),
                query,
                canonical_headers,
                signed,
                payload_hash,
            )
        ),
        signed,
    )


def sign_headers(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    *,
    service: str,
    region: str,
    credentials: AwsCredentials,
    now: datetime,
) -> dict[str, str]:
    """`headers` plus `x-amz-date`, the session token if any, and `authorization`."""
    now = now.astimezone(timezone.utc)
    parts = urlsplit(url)
    signed_headers = {name.lower(): value for name, value in headers.items()}
    signed_headers["host"] = parts.netloc
    signed_headers["x-amz-date"] = f"{now:%Y%m%dT%H%M%SZ}"
    if credentials.session_token is not None:
        signed_headers["x-amz-security-token"] = (
            credentials.session_token.get_secret_value()
        )
    canonical, signed = _canonical_request(
        method.upper(),
        parts.path,
        _canonical_query(parse_qsl(parts.query, keep_blank_values=True)),
        signed_headers,
        _sha256(body),
    )
    signature = _signature(credentials, now, region, service, canonical)
    return {
        **{name: value for name, value in signed_headers.items() if name != "host"},
        "authorization": f"{ALGORITHM} Credential={credentials.access_key_id}/"
        f"{_scope(now, region, service)}, SignedHeaders={signed}, Signature={signature}",
    }


def bedrock_bearer_token(
    credentials: AwsCredentials, *, region: str, now: datetime, expires_seconds: int
) -> str:
    """A short-term Bedrock API key for `region`, minted locally from the credentials."""
    if not 1 <= expires_seconds <= MAX_TOKEN_SECONDS:
        raise ValueError(f"expires_seconds is 1 to {MAX_TOKEN_SECONDS}")
    now = now.astimezone(timezone.utc)
    query = [
        ("Action", "CallWithBearerToken"),
        ("X-Amz-Algorithm", ALGORITHM),
        (
            "X-Amz-Credential",
            f"{credentials.access_key_id}/{_scope(now, region, 'bedrock')}",
        ),
        ("X-Amz-Date", f"{now:%Y%m%dT%H%M%SZ}"),
        ("X-Amz-Expires", str(expires_seconds)),
        ("X-Amz-SignedHeaders", "host"),
    ]
    if credentials.session_token is not None:
        query.append(
            ("X-Amz-Security-Token", credentials.session_token.get_secret_value())
        )
    canonical_query = _canonical_query(query)
    canonical, _ = _canonical_request(
        "POST", "/", canonical_query, {"host": BEDROCK_TOKEN_HOST}, _sha256(b"")
    )
    signature = _signature(credentials, now, region, "bedrock", canonical)
    url = (
        f"{BEDROCK_TOKEN_HOST}/?{canonical_query}&X-Amz-Signature={signature}&Version=1"
    )
    return BEDROCK_TOKEN_PREFIX + base64.b64encode(url.encode()).decode()
