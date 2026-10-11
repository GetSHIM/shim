import asyncio
import logging
from uuid import UUID

import httpx
import pytest

from shim.gateway.contracts.ids import TenantId
from shim.gateway.pipeline.provider_execution import ProviderCallError
from shim.secrets.azure import (
    AzureCredentialResolver,
    EntraClientCredential,
    EntraTokenCache,
)
from shim.secrets.credentials import EphemeralProviderCredential

TENANT = TenantId(UUID(int=1))
CREDENTIAL = EntraClientCredential(
    tenant="contoso.onmicrosoft.com",
    client_id="00000000-0000-0000-0000-0000000000a1",
    client_secret="very-secret-value",
)


def _entra(answers: list[httpx.Response], seen: list[httpx.Request], **options):
    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        await asyncio.sleep(0)
        return answers.pop(0) if len(answers) > 1 else answers[0]

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client, EntraTokenCache(
        client, authority_host="https://login.test/", **options
    )


def _token(value: str = "token-1", expires_in: int = 3600) -> httpx.Response:
    return httpx.Response(
        200,
        json={"access_token": value, "token_type": "Bearer", "expires_in": expires_in},
    )


@pytest.mark.asyncio
async def test_a_token_is_cached_and_one_request_serves_concurrent_callers() -> None:
    seen: list[httpx.Request] = []
    client, cache = _entra([_token()], seen)
    async with client:
        first = await asyncio.gather(*(cache.token("k", CREDENTIAL) for _ in range(5)))
        again = await cache.token("k", CREDENTIAL)

    assert first == ["token-1"] * 5 and again == "token-1"
    [request] = seen
    assert request.url == "https://login.test/contoso.onmicrosoft.com/oauth2/v2.0/token"
    form = dict(httpx.QueryParams(request.content.decode()))
    assert form == {
        "grant_type": "client_credentials",
        "client_id": "00000000-0000-0000-0000-0000000000a1",
        "client_secret": "very-secret-value",
        "scope": "https://cognitiveservices.azure.com/.default",
    }


@pytest.mark.asyncio
async def test_concurrent_callers_share_one_failure_and_the_next_one_retries() -> None:
    seen: list[httpx.Request] = []
    client, cache = _entra([httpx.Response(500), _token("token-2")], seen)
    async with client:
        failed = await asyncio.gather(
            *(cache.token("k", CREDENTIAL) for _ in range(5)), return_exceptions=True
        )
        retried = await cache.token("k", CREDENTIAL)

    assert all(isinstance(error, ProviderCallError) for error in failed)
    assert retried == "token-2"
    assert len(seen) == 2, "one request for the five callers, one for the retry"


@pytest.mark.asyncio
async def test_a_token_inside_the_refresh_margin_is_renewed() -> None:
    seen: list[httpx.Request] = []
    client, cache = _entra([_token("old", 299), _token("new")], seen)
    async with client:
        tokens = [await cache.token("k", CREDENTIAL) for _ in range(3)]

    assert tokens == ["old", "new", "new"] and len(seen) == 2


@pytest.mark.asyncio
async def test_the_oldest_key_is_evicted_above_the_bound() -> None:
    seen: list[httpx.Request] = []
    client, cache = _entra([_token()], seen, max_entries=2)
    async with client:
        for key in ("a", "b", "c"):
            await cache.token(key, CREDENTIAL)
        await cache.token("a", CREDENTIAL)

    assert list(cache.tokens) == ["c", "a"] and len(seen) == 4


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("answer", "status", "code"),
    [
        (
            httpx.Response(
                400,
                json={
                    "error": "invalid_client",
                    "error_description": "AADSTS7000215 secret",
                },
            ),
            401,
            "INVALID_PROVIDER_CREDENTIAL",
        ),
        (
            httpx.Response(401, json={"error": "unauthorized_client"}),
            401,
            "INVALID_PROVIDER_CREDENTIAL",
        ),
        (httpx.Response(500, text="oops"), 503, "PROVIDER_UNAVAILABLE"),
        (
            httpx.Response(
                200, json={"access_token": "t", "token_type": "mac", "expires_in": 3600}
            ),
            503,
            "PROVIDER_UNAVAILABLE",
        ),
        (
            httpx.Response(
                200,
                json={"access_token": "t", "token_type": "Bearer", "expires_in": 30},
            ),
            503,
            "PROVIDER_UNAVAILABLE",
        ),
        (
            httpx.Response(200, json={"token_type": "Bearer", "expires_in": 3600}),
            503,
            "PROVIDER_UNAVAILABLE",
        ),
    ],
)
async def test_a_refusal_is_a_credential_error_and_anything_else_unavailable(
    answer, status, code, caplog
) -> None:
    seen: list[httpx.Request] = []
    client, cache = _entra([answer], seen)
    caplog.set_level(logging.WARNING)
    async with client:
        with pytest.raises(ProviderCallError) as error:
            await cache.token("k", CREDENTIAL)

    assert (error.value.status_code, error.value.error_code) == (status, code)
    assert "very-secret-value" not in caplog.text
    assert "AADSTS" not in caplog.text and "token-" not in caplog.text


@pytest.mark.asyncio
async def test_a_timeout_or_transport_error_is_unavailable() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("slow", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        cache = EntraTokenCache(client, authority_host="https://login.test")
        with pytest.raises(ProviderCallError) as error:
            await cache.token("k", CREDENTIAL)

    assert (error.value.status_code, error.value.retryable) == (503, True)


@pytest.mark.parametrize(
    "values",
    [
        {"tenant": "bad tenant!"},
        {"client_id": "not-a-guid"},
        {"scope": "http://cognitiveservices.azure.com/.default"},
        {"scope": "https://cognitiveservices.azure.com/"},
        {"client_secret": ""},
    ],
)
def test_a_credential_is_validated(values) -> None:
    with pytest.raises(ValueError):
        EntraClientCredential.model_validate(
            {**CREDENTIAL.model_dump(), "client_secret": "s", **values}
        )


@pytest.mark.asyncio
async def test_the_resolver_prefers_the_invocation_then_the_key_then_entra() -> None:
    seen: list[httpx.Request] = []
    client, cache = _entra([_token("entra-token")], seen)
    async with client:
        invocation = AzureCredentialResolver(api_key="azure-key")
        keyed = AzureCredentialResolver(api_key="azure-key")
        entra = AzureCredentialResolver(entra=(cache, CREDENTIAL))
        values = [
            await invocation.resolve(
                TENANT, EphemeralProviderCredential("openai", "caller-key")
            ),
            await keyed.resolve(TENANT, None),
            await entra.resolve(TENANT, None),
        ]
        with pytest.raises(ValueError):
            await keyed.resolve(TENANT, None, reference="managed")

    assert values == ["caller-key", "azure-key", "entra-token"]
