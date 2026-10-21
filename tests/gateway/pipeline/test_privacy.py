from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

from fastapi import HTTPException
import httpx
import pytest

from shim.application import create_community_app
from shim.core.community_config import CommunitySettings
from shim.core.isolation import REQUEST_SECONDS
from shim.gateway.contracts.context import (
    AuditPolicy,
    GatewayContext,
    PrivacyPolicy,
    TierPolicy,
)
from shim.gateway.contracts.ids import ApiKeyId, ProviderId, RequestId, TenantId
from shim.gateway.kernel.result import AdmissionState, PreparedInference
from shim.gateway.pipeline import privacy
from shim.gateway.pipeline.privacy import (
    MAX_REQUEST_TEXT_CHARS,
    MAX_REQUEST_TEXTS,
    PrivacyStage,
)
from shim.gateway.request_policy import RequestPolicyContext
from shim.privacy import pii_scrubber
from shim.privacy.pii_scrubber import (
    MAX_ANALYZABLE_TEXT_LENGTH,
    WINDOW,
    PIIScrubberService,
)

_GATEWAY_KEY = "shim-privacy-budget-key-0123456789"


class _RecordingScrubber:
    def __init__(self, on_scrub=None) -> None:
        self.calls: list[str] = []
        self.on_scrub = on_scrub

    def scrub(self, text: str, *args, **kwargs) -> tuple[str, dict[str, str]]:
        self.calls.append(text)
        if self.on_scrub is not None:
            self.on_scrub()
        return text, {}


def _prepared(
    payload: dict, *, protocol: str = "chat", size: int | None = None
) -> PreparedInference:
    context = GatewayContext(
        request_id=RequestId("req_privacy_budget"),
        tenant_id=TenantId(UUID("11111111-1111-1111-1111-111111111111")),
        actor_type="api_key",
        api_key_id=ApiKeyId(UUID("22222222-2222-2222-2222-222222222222")),
        user_id=None,
        endpoint="/v1/chat/completions",
        started_at=datetime(2026, 10, 21, tzinfo=UTC),
        tier_policy=TierPolicy(),
        privacy_policy=PrivacyPolicy(pii_mode="scrub"),
        audit_policy=AuditPolicy(mode="best_effort"),
    )
    return PreparedInference(
        context=context,
        payload=payload,
        provider=ProviderId("openai"),
        protocol=protocol,
        model="gpt-5.6-luna",
        stream=False,
        policy=RequestPolicyContext(rate_limit_key_hash="key-hash", tier="managed"),
        pii_config=None,
        admission=None
        if size is None
        else AdmissionState(
            estimated_input_tokens=size,
            maximum_output_tokens=16,
            cost_center="default",
            tags=(),
        ),
    )


def _stage(scrubber: _RecordingScrubber) -> PrivacyStage:
    store = SimpleNamespace(load=AsyncMock(), ensure_available=AsyncMock())
    return PrivacyStage(scrubber, store)  # type: ignore[arg-type]


def _messages(texts: list[str]) -> dict:
    return {
        "model": "gpt-5.6-luna",
        "messages": [{"role": "user", "content": text} for text in texts],
    }


def _dense(serial: int, length: int) -> str:
    # Match-dense text, the input whose scan grows fastest with its length.
    unit = f"10.0.{serial}.5 "
    return (unit * (length // len(unit) + 1))[:length]


@pytest.mark.asyncio
async def test_text_over_the_request_budget_is_refused_before_any_scan() -> None:
    # Each text is under the analyzer's own limit; together they are over the budget.
    count = MAX_REQUEST_TEXT_CHARS // MAX_ANALYZABLE_TEXT_LENGTH + 1
    texts = [_dense(serial, MAX_ANALYZABLE_TEXT_LENGTH) for serial in range(count)]
    scrubber = _RecordingScrubber()

    with pytest.raises(HTTPException) as refused:
        await _stage(scrubber).run(_prepared(_messages(texts)))

    assert refused.value.status_code == 413
    assert refused.value.detail["code"] == "PRIVACY_SCAN_TOO_LARGE"
    assert refused.value.detail["param"] == "characters"
    assert scrubber.calls == []
    # Counts only: no text of the request in the message.
    assert "10.0." not in refused.value.detail["message"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "texts",
    [
        # The documented budget: 4,000,000 characters and 50,000 strings a request.
        [_dense(serial, 999_000) for serial in range(4)],
        [f"note {index}" for index in range(49_990)],
    ],
    ids=["characters", "texts"],
)
async def test_a_request_just_under_the_documented_budget_is_scanned(
    texts: list[str],
) -> None:
    scrubber = _RecordingScrubber()

    await _stage(scrubber).run(_prepared(_messages(texts)))

    assert set(texts) <= set(scrubber.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("where", ["values", "keys"])
async def test_more_texts_than_the_request_budget_are_refused_before_any_scan(
    where: str,
) -> None:
    texts = [f"note {index}" for index in range(MAX_REQUEST_TEXTS + 1)]
    # A key is read as an identifier, one analyzer pass each, like a value.
    payload = (
        _messages(texts)
        if where == "values"
        else _messages(["hi"]) | {"metadata": dict.fromkeys(texts, "")}
    )
    scrubber = _RecordingScrubber()

    with pytest.raises(HTTPException) as refused:
        await _stage(scrubber).run(_prepared(payload))

    assert refused.value.status_code == 413
    assert refused.value.detail["code"] == "PRIVACY_SCAN_TOO_LARGE"
    assert refused.value.detail["param"] == "texts"
    assert scrubber.calls == []


def _clocked(
    monkeypatch: pytest.MonkeyPatch, window_seconds: float
) -> tuple[list[float], list[int]]:
    """A fake clock for the stage and the scrubber, which the analyzer advances by
    `window_seconds` for every `WINDOW` characters it reads.

    Returns the clock, and the length of every text the analyzer reads in order.
    """
    clock = [1_000.0]
    monkeypatch.setattr(pii_scrubber, "monotonic", lambda: clock[0])
    monkeypatch.setattr(privacy, "request_deadline", lambda: clock[0] + REQUEST_SECONDS)
    analyzer = PIIScrubberService()._analyzer
    analyze = analyzer.analyze
    read: list[int] = []

    def timed(text: str, entities: object) -> object:
        read.append(len(text))
        clock[0] += window_seconds * len(text) / WINDOW
        return analyze(text, entities)

    monkeypatch.setattr(analyzer, "analyze", timed)
    return clock, read


def _prose(length: int) -> str:
    return ("Plain words for a long note. " * (length // 29 + 1))[:length]


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["chat", "embeddings"])
async def test_one_long_text_is_stopped_at_the_request_deadline(
    monkeypatch: pytest.MonkeyPatch, protocol: str
) -> None:
    # One text needing eight windows, or two embedded in one analyzer pass.
    length = 8 * WINDOW
    payload = (
        _messages([_prose(length)])
        if protocol == "chat"
        else {
            "model": "text-embedding-3-small",
            "input": [_prose(length // 2), "Second. " + _prose(length // 2)],
        }
    )
    clock, read = _clocked(monkeypatch, REQUEST_SECONDS / 4)

    with pytest.raises(HTTPException) as refused:
        await _stage(PIIScrubberService()).run(_prepared(payload, protocol=protocol))

    assert refused.value.status_code == 413
    assert refused.value.detail["code"] == "PRIVACY_SCAN_TIMEOUT"
    windows = [size for size in read if size > 1_000]
    # Stopped inside the text, at most one window past the deadline.
    assert 1 < len(windows) < length // WINDOW
    assert clock[0] - 1_000.0 <= REQUEST_SECONDS * 5 / 4


@pytest.mark.asyncio
async def test_a_scan_waiting_for_a_thread_spends_its_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock, read = _clocked(monkeypatch, 0.0)
    loop = asyncio.get_running_loop()
    release = threading.Event()
    executor = privacy._EXECUTOR
    blockers = [
        loop.run_in_executor(executor, release.wait)
        for _ in range(executor._max_workers)
    ]
    try:
        scan = asyncio.create_task(
            _stage(PIIScrubberService()).run(_prepared(_messages(["hello"]), size=64))
        )
        await asyncio.sleep(0.1)
        assert not scan.done()
        clock[0] += REQUEST_SECONDS + 1
    finally:
        release.set()
        await asyncio.gather(*blockers)
    with pytest.raises(HTTPException) as refused:
        await scan

    assert refused.value.detail["code"] == "PRIVACY_SCAN_TIMEOUT"
    assert read == []


@pytest.mark.asyncio
async def test_a_short_scan_is_not_held_behind_long_ones() -> None:
    loop = asyncio.get_running_loop()
    release = threading.Event()
    executor = privacy._LONG_EXECUTOR
    blockers = [
        loop.run_in_executor(executor, release.wait)
        for _ in range(executor._max_workers)
    ]
    stage = _stage(_RecordingScrubber())
    long = asyncio.create_task(
        stage.run(_prepared(_messages(["long"]), size=WINDOW + 1))
    )
    try:
        await asyncio.wait_for(
            stage.run(_prepared(_messages(["short"]), size=WINDOW)), timeout=5
        )
        await asyncio.sleep(0.1)
        assert not long.done()
    finally:
        release.set()
        await asyncio.gather(*blockers)
    await long


@pytest.mark.asyncio
async def test_a_saturated_default_executor_cannot_hold_the_privacy_scan() -> None:
    release = threading.Event()
    # More blocked jobs than the default executor has threads: the rest queue.
    blockers = [asyncio.create_task(asyncio.to_thread(release.wait)) for _ in range(64)]
    try:
        await asyncio.sleep(0.1)
        scrubber = _RecordingScrubber()
        await asyncio.wait_for(
            _stage(scrubber).run(_prepared(_messages(["safe text"]))), timeout=5
        )
        assert "safe text" in scrubber.calls
    finally:
        release.set()
        await asyncio.gather(*blockers)


@pytest.mark.asyncio
async def test_two_long_scans_run_at_once_and_the_rest_wait() -> None:
    release = threading.Event()
    # One entry a scan: each waits in its first analyzer pass.
    running: list[str] = []

    def hold() -> None:
        running.append(threading.current_thread().name)
        release.wait()

    stage = _stage(_RecordingScrubber(hold))
    scans = [
        asyncio.create_task(
            stage.run(_prepared(_messages([f"long {index}"]), size=WINDOW + 1))
        )
        for index in range(4)
    ]
    try:
        await asyncio.sleep(0.3)
        # Scanning holds the GIL: more long scans at once would only slow each one.
        assert len(running) == 2
    finally:
        release.set()
        await asyncio.gather(*scans)


def _request(route: str, texts: list[str]) -> tuple[str, dict[str, str], dict]:
    if route == "chat":
        return (
            "/v1/chat/completions",
            {"authorization": f"Bearer {_GATEWAY_KEY}"},
            {
                "model": "gpt-5-nano",
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "text", "text": t} for t in texts],
                    }
                ],
            },
        )
    if route == "messages":
        return (
            "/v1/messages",
            {"x-api-key": _GATEWAY_KEY},
            {
                "model": "claude-sonnet-4-6",
                "max_tokens": 16,
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "text", "text": t} for t in texts],
                    }
                ],
            },
        )
    return (
        "/v1beta/models/gemini-3.5-flash:generateContent",
        {"x-goog-api-key": _GATEWAY_KEY},
        {"contents": [{"role": "user", "parts": [{"text": t} for t in texts]}]},
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["chat", "messages", "gemini"])
async def test_each_route_refuses_an_unscannable_request_in_its_own_shape(
    route: str,
) -> None:
    calls: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(500)

    path, auth, body = _request(
        route, [f"n{index}" for index in range(MAX_REQUEST_TEXTS + 1)]
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as outbound:
        app = create_community_app(
            CommunitySettings(_env_file=None, SHIM_API_KEY=_GATEWAY_KEY),
            http_client=outbound,
        )
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app), base_url="http://shim.test"
            ) as inbound:
                response = await inbound.post(
                    path,
                    headers={**auth, "x-provider-key": "provider-secret"},
                    json=body,
                )

    assert response.status_code == 413
    assert calls == []
    assert response.headers["x-shim-error-code"] == "PRIVACY_SCAN_TOO_LARGE"
    error = response.json()["error"]
    if route == "gemini":
        assert error["status"] == "INVALID_ARGUMENT"
        [info] = error["details"]
        assert info["reason"] == "PRIVACY_SCAN_TOO_LARGE"
        assert info["metadata"]["hint"]
    else:
        assert error["code"] == "PRIVACY_SCAN_TOO_LARGE"
        assert error["hint"]
        if route == "messages":
            assert response.json()["type"] == "error"
            assert error["type"] == "request_too_large"
        else:
            assert error["param"] == "texts"
