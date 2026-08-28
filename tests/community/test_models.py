from __future__ import annotations

from io import StringIO

from anthropic import AsyncAnthropic
from anthropic import NotFoundError as AnthropicNotFoundError
import httpx
from openai import AsyncOpenAI
from openai import NotFoundError as OpenAINotFoundError
import pytest

from shim.billing.pricing import DEFAULT_PRICE_BOOK
from shim.application import create_community_app
from shim.core.community_config import CommunitySettings


GATEWAY_KEY = "shim-gateway-key-123"


def _application():
    return create_community_app(
        CommunitySettings(
            BACKEND_CORS_ORIGINS=[],
            SHIM_API_KEY=GATEWAY_KEY,
            _env_file=None,
        ),
        event_stream=StringIO(),
    )


@pytest.mark.asyncio
async def test_openai_sdk_selects_openai_catalog_and_codex_selector() -> None:
    requests: list[httpx.Request] = []

    async def record(request: httpx.Request) -> None:
        requests.append(request)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_application()),
        base_url="http://shim.test",
        event_hooks={"request": [record]},
    ) as gateway_http:
        client = AsyncOpenAI(
            api_key=GATEWAY_KEY,
            base_url="http://shim.test/v1",
            http_client=gateway_http,
            max_retries=0,
        )
        page = await client.models.list()
        model = await client.models.retrieve("gpt-5.6-luna")
        codex = await gateway_http.get(
            "/v1/models",
            params={"client_version": "0.145.0"},
            headers={"authorization": f"Bearer {GATEWAY_KEY}"},
        )

    assert page.object == "list"
    assert {item.id for item in page.data} == set(DEFAULT_PRICE_BOOK.prices)
    assert model.id == "gpt-5.6-luna"
    assert model.object == "model"
    assert model.owned_by == "openai"
    assert codex.json() == {"models": []}
    assert all(
        request.headers["authorization"] == f"Bearer {GATEWAY_KEY}"
        for request in requests
    )


@pytest.mark.asyncio
async def test_anthropic_sdk_selects_anthropic_catalog_and_paginates() -> None:
    requests: list[httpx.Request] = []

    async def record(request: httpx.Request) -> None:
        requests.append(request)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_application()),
        base_url="http://shim.test",
        event_hooks={"request": [record]},
    ) as gateway_http:
        client = AsyncAnthropic(
            api_key=GATEWAY_KEY,
            base_url="http://shim.test",
            http_client=gateway_http,
            max_retries=0,
        )
        page = await client.models.list(limit=1)
        next_page = await page.get_next_page()
        model = await client.models.retrieve("claude-sonnet-4-6")
        beta_model = await client.beta.models.retrieve(
            "claude-sonnet-4-6",
            extra_headers={"anthropic-beta": "feature-a"},
        )

    catalog = DEFAULT_PRICE_BOOK.models("anthropic")
    assert len(page.data) == len(next_page.data) == 1
    assert page.has_more is True
    assert [page.data[0].id, next_page.data[0].id] == list(catalog[:2])
    assert model.id == beta_model.id == "claude-sonnet-4-6"
    assert model.display_name == "Claude Sonnet 4.6"
    assert all(request.headers["x-api-key"] == GATEWAY_KEY for request in requests)
    assert all("anthropic-version" in request.headers for request in requests)
    assert requests[-1].headers["anthropic-beta"] == "feature-a"
    assert requests[-1].url.query == b"beta=true"


@pytest.mark.asyncio
async def test_missing_models_raise_native_sanitized_sdk_errors() -> None:
    openai_missing = "gpt-5.6-luna-private-secret-123"
    anthropic_missing = "claude-sonnet-4-6-private-secret-123"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_application()),
        base_url="http://shim.test",
    ) as gateway_http:
        openai = AsyncOpenAI(
            api_key=GATEWAY_KEY,
            base_url="http://shim.test/v1",
            http_client=gateway_http,
            max_retries=0,
        )
        anthropic = AsyncAnthropic(
            api_key=GATEWAY_KEY,
            base_url="http://shim.test",
            http_client=gateway_http,
            max_retries=0,
        )
        with pytest.raises(OpenAINotFoundError) as openai_error:
            await openai.models.retrieve(openai_missing)
        with pytest.raises(AnthropicNotFoundError) as anthropic_error:
            await anthropic.models.retrieve(anthropic_missing)

    assert openai_error.value.response.json() == {
        "error": {
            "message": "The requested model is not in the public catalog.",
            "type": "not_found_error",
            "param": None,
            "code": "MODEL_NOT_FOUND",
        }
    }
    assert anthropic_error.value.response.json() == {
        "type": "error",
        "error": {
            "type": "not_found_error",
            "message": "The requested model is not in the public catalog.",
        },
    }
    assert openai_missing not in openai_error.value.response.text
    assert anthropic_missing not in anthropic_error.value.response.text
