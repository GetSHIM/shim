"""A warning set after privacy reaches JSON and stream responses; the upstream call is unchanged."""

from __future__ import annotations

import json

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from ee.tests.tenants.test_deployments import (  # noqa: F401
    _deployments,
    _gateway,
    _success,
    db,
    origins,
    test_org,
)
from shim_enterprise.gateway.attempts import TenantAttemptPolicy

pytestmark = pytest.mark.usefixtures("origins")


class _Warns:
    """Stands in for the semantic check: it warns and never chooses a target."""

    name = "semantic_check"

    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def after_privacy(self, prepared):
        self.events.append("check")
        prepared.warn("SEMANTIC_WARN")

    async def after_outcome(self, outcome):
        return None


async def _send(db, key, stream: bool, checked: bool):  # noqa: F811
    events: list[str] = []
    sent: list[dict] = []

    def upstream(request):
        events.append("upstream")
        sent.append(json.loads(request.content))
        return _success(request, stream, "chat")

    async with _gateway(db, key, upstream) as (client, app, _):
        if checked:
            app.state.gateway_service.kernel.attempt_policy = TenantAttemptPolicy(
                async_sessionmaker(db.bind), (_Warns(events),)
            )
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "internal-a",
                "stream": stream,
                "messages": [{"role": "user", "content": "hello"}],
            },
        )
    return response, events, sent


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [False, True])
async def test_the_warning_reaches_the_response_and_the_payload_is_unchanged(
    db,  # noqa: F811
    test_api_key,
    stream,
) -> None:
    await _deployments(db, test_api_key)

    plain, _, plain_sent = await _send(db, test_api_key, stream, checked=False)
    checked, events, checked_sent = await _send(db, test_api_key, stream, checked=True)

    assert (plain.status_code, checked.status_code) == (200, 200)
    assert "SEMANTIC_WARN" not in plain.headers.get("x-shim-warnings", "")
    assert "SEMANTIC_WARN" in checked.headers["x-shim-warnings"].split(",")
    assert events == ["check", "upstream"]
    assert checked_sent == plain_sent
    assert checked.text.count("data:") == plain.text.count("data:")
