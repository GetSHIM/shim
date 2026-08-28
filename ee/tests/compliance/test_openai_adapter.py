from __future__ import annotations

from ipaddress import ip_address

import httpx
import pytest
from fastapi import HTTPException

from shim_enterprise.compliance.adapters.base import ProviderConfigError
from shim_enterprise.compliance.adapters.openai import OpenAIComplianceAdapter
from shim_enterprise.compliance.api import _validate_config
from shim_enterprise.compliance.url_guard import UnsafeForwardURL


INVALID_EVENT_TYPE_CONFIGS = (
    {"event_types": "AUTH_LOG"},
    {"event_types": None},
    {"event_types": 1},
    {"event_types": []},
    {"event_types": [""]},
    {"event_types": [1]},
    {"content_event_types": "CHAT_LOG"},
    {"content_event_types": None},
    {"content_event_types": 1},
    {"content_event_types": [""]},
    {"content_event_types": [1]},
)


def _adapter(client: httpx.AsyncClient) -> OpenAIComplianceAdapter:
    return OpenAIComplianceAdapter(
        "secret-token",
        {"scope_id": "workspace-1"},
        client=client,
    )


@pytest.mark.parametrize("config", INVALID_EVENT_TYPE_CONFIGS)
def test_invalid_event_type_config_is_rejected_at_both_boundaries(
    config: dict[str, object],
) -> None:
    with pytest.raises(ProviderConfigError):
        OpenAIComplianceAdapter(
            "secret-token",
            {"scope_id": "workspace-1", **config},
        )

    with pytest.raises(HTTPException) as captured:
        _validate_config("openai", {"scope_id": "workspace-1", **config})

    assert captured.value.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("location", "error"),
    [
        ("http://downloads.example/log.jsonl", httpx.UnsupportedProtocol),
        ("https://127.0.0.1/log.jsonl", UnsafeForwardURL),
    ],
)
async def test_download_rejects_unsafe_redirect(
    location: str,
    error: type[Exception],
) -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            302,
            headers={"location": location},
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = _adapter(client)
        with pytest.raises(error):
            await anext(adapter._download_lines("file-1"))
    assert requests == 1


@pytest.mark.asyncio
async def test_download_strips_authorization_and_pins_cross_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_requests: list[tuple[str, str | None, str | None]] = []
    resolved: list[str] = []

    async def resolve(url: str):
        resolved.append(url)
        return ip_address("8.8.8.8")

    monkeypatch.setattr(
        "shim_enterprise.compliance.adapters.openai.assert_safe_forward_url",
        resolve,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        observed_requests.append(
            (
                request.url.host,
                request.headers.get("host"),
                request.headers.get("authorization"),
            )
        )
        if request.url.host == "api.chatgpt.com":
            return httpx.Response(
                302,
                headers={"location": "https://downloads.example/log.jsonl"},
                request=request,
            )
        return httpx.Response(200, content=b'{"id":"event-1"}\n', request=request)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as client:
        adapter = _adapter(client)
        lines = [line async for line in adapter._download_lines("file-1")]
        await adapter.close()

        assert lines == ['{"id":"event-1"}']
        assert resolved == ["https://downloads.example/log.jsonl"]
        assert observed_requests == [
            ("api.chatgpt.com", "api.chatgpt.com", "Bearer secret-token"),
            ("8.8.8.8", "downloads.example", None),
        ]
        assert not client.is_closed


@pytest.mark.asyncio
async def test_owned_client_is_closed() -> None:
    adapter = OpenAIComplianceAdapter("secret-token", {"scope_id": "workspace-1"})

    await adapter.close()

    assert adapter.client.is_closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "data",
    [
        None,
        [None],
        [{}],
        [{"id": ""}],
    ],
)
async def test_list_logs_rejects_malformed_descriptors(data: object) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": data,
                "has_more": False,
                "last_end_time": "2026-07-25T12:00:00Z",
            },
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="data|descriptor"):
            await _adapter(client).list_logs("AUTH_LOG", None)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"data": [], "has_more": "false", "last_end_time": None},
        {"data": [], "has_more": True, "last_end_time": "not-a-timestamp"},
    ],
)
async def test_list_logs_rejects_malformed_pagination(
    payload: dict[str, object],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="has_more|last_end_time"):
            await _adapter(client).list_logs("AUTH_LOG", None)
