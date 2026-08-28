from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI

from shim.application import create_community_app
from shim.core.community_config import CommunitySettings


GATEWAY_KEY = "shim-gateway-key-123"


def _application() -> FastAPI:
    return create_community_app(
        CommunitySettings(
            BACKEND_CORS_ORIGINS=[],
            SHIM_API_KEY=GATEWAY_KEY,
            _env_file=None,
        )
    )


@pytest.mark.asyncio
async def test_local_scan_requires_gateway_authentication() -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_application()),
        base_url="http://shim.test",
    ) as client:
        missing = await client.post("/v1/scan", json={"text": ""})
        accepted = await client.post(
            "/v1/scan",
            headers={"x-shim-key": GATEWAY_KEY},
            json={"text": ""},
        )

    assert missing.status_code == 401
    assert accepted.status_code == 200


@pytest.mark.asyncio
async def test_local_scan_returns_only_the_public_privacy_result() -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_application()),
        base_url="http://shim.test",
    ) as client:
        response = await client.post(
            "/v1/scan",
            headers={"authorization": f"Bearer {GATEWAY_KEY}"},
            json={"text": "Contact alice@example.com", "source": "chatgpt"},
        )

    body = response.json()
    assert response.status_code == 200
    assert set(body) == {
        "request_id",
        "verdict",
        "entities",
        "entity_types",
        "policy",
    }
    assert body["request_id"].startswith("scan_")
    assert response.headers["x-shim-request-id"] == body["request_id"]
    assert body["verdict"] == body["policy"] == "block"
    assert body["entity_types"] == ["EMAIL_ADDRESS"]
    assert body["entities"][0]["type"] == "EMAIL_ADDRESS"
    assert set(body["entities"][0]) == {"type", "score", "start", "end"}


@pytest.mark.asyncio
async def test_local_scan_accepts_empty_text_without_a_usage_route() -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_application()),
        base_url="http://shim.test",
    ) as client:
        response = await client.post(
            "/v1/scan",
            headers={"x-shim-key": GATEWAY_KEY},
            json={"text": ""},
        )
        usage = await client.get(
            "/v1/scan/usage",
            headers={"x-shim-key": GATEWAY_KEY},
        )

    body = response.json()
    assert response.status_code == 200
    assert body | {"request_id": "ignored"} == {
        "request_id": "ignored",
        "verdict": "clean",
        "entities": [],
        "entity_types": [],
        "policy": "block",
    }
    assert usage.status_code == 404


@pytest.mark.asyncio
async def test_local_scan_sanitizes_analysis_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_text: str, **_kwargs: object) -> list[dict[str, object]]:
        raise RuntimeError("private analyzer details")

    application = _application()
    monkeypatch.setattr(application.state.scan_privacy.scrubber, "analyze", fail)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://shim.test",
    ) as client:
        response = await client.post(
            "/v1/scan",
            headers={"x-shim-key": GATEWAY_KEY},
            json={"text": "private"},
        )

    assert response.status_code == 503
    assert response.json() == {
        "detail": {
            "code": "INTERNAL_ERROR",
            "message": "PII analysis could not be completed.",
        }
    }
    assert "private analyzer details" not in response.text
