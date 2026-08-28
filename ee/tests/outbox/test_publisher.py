import asyncio
from dataclasses import replace
from datetime import datetime, timezone
import json
import socket
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx
import pytest

from shim_enterprise.outbox import handlers
from shim_enterprise.outbox.handlers import report_reconciliation
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.outbox.publisher import (
    OutboxIdentityConflict,
    OutboxMessage,
    OutboxPublisher,
    OutboxWriter,
    UnknownEventTypeError,
)


def message(event_type: str = "test.created") -> OutboxMessage:
    return OutboxMessage(
        id=uuid4(),
        organization_id=uuid4(),
        event_type=event_type,
        aggregate_type="test",
        aggregate_id="aggregate-1",
        idempotency_key="test:aggregate-1:created",
        payload={"value": 1},
        attempt_count=1,
        created_at=datetime.now(timezone.utc),
    )


def _result(value: object) -> SimpleNamespace:
    return SimpleNamespace(scalar_one_or_none=lambda: value)


def _outbox_values(now: datetime) -> dict[str, object]:
    return {
        "event_type": "test.created",
        "aggregate_type": "test",
        "aggregate_id": "aggregate-1",
        "idempotency_key": "test:aggregate-1:created",
        "payload": {"credential_reference": "sensitive-secret-ref", "value": 1},
        "status": "pending",
        "next_attempt_at": now,
    }


def test_cancelling_delivery_clears_its_lease_and_makes_it_terminal() -> None:
    now = datetime.now(timezone.utc)
    event = OutboxEvent(
        status="processing",
        locked_by="worker-1",
        lease_expires_at=now,
        last_error="previous failure",
    )

    event.cancel(now=now)

    assert event.status == "processed"
    assert event.processed_at == now
    assert event.locked_by is None
    assert event.lease_expires_at is None
    assert event.last_error is None


@pytest.mark.asyncio
async def test_publisher_dispatches_to_the_owned_event_handler() -> None:
    handler = AsyncMock()
    publisher = OutboxPublisher()
    publisher.register("test.created", handler)
    event = message()

    await publisher.publish(event)

    handler.assert_awaited_once_with(event)


@pytest.mark.asyncio
async def test_publisher_rejects_unknown_event_types() -> None:
    with pytest.raises(UnknownEventTypeError, match="unknown.created"):
        await OutboxPublisher().publish(message("unknown.created"))


def test_publisher_rejects_duplicate_handler_ownership() -> None:
    publisher = OutboxPublisher()
    publisher.register("test.created", AsyncMock())

    with pytest.raises(ValueError, match="already registered"):
        publisher.register("test.created", AsyncMock())


@pytest.mark.parametrize("delivery_status", ["failed", "processed"])
@pytest.mark.asyncio
async def test_writer_returns_exact_intent_replay_after_delivery_state_changes(
    delivery_status: str,
) -> None:
    now = datetime.now(timezone.utc)
    organization_id = uuid4()
    values = _outbox_values(now)
    existing = SimpleNamespace(
        id=uuid4(),
        organization_id=organization_id,
        idempotency_key=values["idempotency_key"],
        event_type=values["event_type"],
        aggregate_type=values["aggregate_type"],
        aggregate_id=values["aggregate_id"],
        payload=values["payload"],
        status=delivery_status,
        attempt_count=4,
        next_attempt_at=datetime(2026, 7, 13, tzinfo=timezone.utc),
        last_error="bounded delivery error",
        processed_at=now if delivery_status == "processed" else None,
    )
    session = SimpleNamespace(
        execute=AsyncMock(side_effect=[_result(None), _result(existing)])
    )

    replayed = await OutboxWriter().append(
        session,
        organization_id=organization_id,
        values=values,
    )

    assert replayed is existing
    assert replayed.status == delivery_status
    assert replayed.attempt_count == 4


@pytest.mark.parametrize(
    ("field", "different_value"),
    [
        ("event_type", "test.updated"),
        ("aggregate_type", "different"),
        ("aggregate_id", "aggregate-2"),
        ("payload", {"value": 2}),
    ],
)
@pytest.mark.asyncio
async def test_writer_rejects_conflicting_immutable_intent_replay(
    field: str,
    different_value: object,
) -> None:
    now = datetime.now(timezone.utc)
    organization_id = uuid4()
    values = _outbox_values(now)
    existing_values = {
        "event_type": values["event_type"],
        "aggregate_type": values["aggregate_type"],
        "aggregate_id": values["aggregate_id"],
        "payload": values["payload"],
    }
    existing_values[field] = different_value
    existing = SimpleNamespace(**existing_values)
    session = SimpleNamespace(
        execute=AsyncMock(side_effect=[_result(None), _result(existing)])
    )

    with pytest.raises(
        OutboxIdentityConflict,
        match="^outbox identity conflict$",
    ) as error:
        await OutboxWriter().append(
            session,
            organization_id=organization_id,
            values=values,
        )

    assert "sensitive-secret-ref" not in str(error.value)


@pytest.mark.asyncio
async def test_reconciliation_handler_enforces_tenant_identity() -> None:
    organization_id = uuid4()
    request_id = f"req_{uuid4().hex}"
    event = OutboxMessage(
        id=uuid4(),
        organization_id=organization_id,
        event_type="gateway.reconciliation",
        aggregate_type="request",
        aggregate_id=request_id,
        idempotency_key=f"request:{request_id}:outbox:gateway.reconciliation",
        payload={
            "organization_id": str(organization_id),
            "request_id": request_id,
            "lifecycle_status": "completed",
            "urgent": False,
        },
        attempt_count=1,
        created_at=datetime.now(timezone.utc),
    )

    await report_reconciliation(event)

    with pytest.raises(ValueError, match="tenant identity mismatch"):
        await report_reconciliation(
            replace(
                event,
                payload={
                    **event.payload,
                    "organization_id": str(uuid4()),
                },
            )
        )


@pytest.mark.asyncio
async def test_forward_post_pins_the_vetted_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = "https://hooks.example:8443/events?source=budget"
    resolver = AsyncMock(return_value=[(0, 0, 0, "", ("8.8.8.8", 8443))])
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolver)
    client = AsyncMock()
    client.__aenter__.return_value = client
    response_context = AsyncMock()
    response_context.__aenter__.return_value = Mock()
    client.stream = Mock(return_value=response_context)
    client_factory = Mock(return_value=client)
    monkeypatch.setattr(handlers.httpx, "AsyncClient", client_factory)
    await handlers._post_forward_url(
        endpoint,
        content=b"{}",
        headers={"content-type": "application/json"},
    )

    resolver.assert_awaited_once_with(
        "hooks.example",
        8443,
        type=socket.SOCK_STREAM,
    )
    client_factory.assert_called_once_with(
        timeout=10.0,
        follow_redirects=False,
        trust_env=False,
    )
    client.stream.assert_called_once()
    posted_method, posted_url = client.stream.call_args.args
    posted_options = client.stream.call_args.kwargs
    assert posted_method == "POST"
    assert posted_url == "https://8.8.8.8:8443/events?source=budget"
    assert posted_options["headers"]["host"] == "hooks.example:8443"
    assert posted_options["extensions"] == {"sni_hostname": "hooks.example"}


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [200, 503])
async def test_forward_post_uses_status_without_buffering_the_response_body(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
) -> None:
    class BodyMustNotBeRead(httpx.AsyncByteStream):
        def __init__(self) -> None:
            self.closed = False

        async def __aiter__(self):
            raise AssertionError("forward response body was buffered")
            yield b""  # pragma: no cover

        async def aclose(self) -> None:
            self.closed = True

    body = BodyMustNotBeRead()
    transport = httpx.MockTransport(
        lambda request: httpx.Response(status_code, request=request, stream=body)
    )
    async_client = httpx.AsyncClient
    monkeypatch.setattr(
        handlers.httpx,
        "AsyncClient",
        lambda **options: async_client(transport=transport, **options),
    )
    monkeypatch.setattr(
        handlers,
        "assert_safe_forward_url",
        AsyncMock(return_value="8.8.8.8"),
    )

    delivery = handlers._post_forward_url(
        "https://hooks.example/events",
        content=b"{}",
        headers={"content-type": "application/json"},
    )
    if status_code == 200:
        await delivery
    else:
        with pytest.raises(httpx.HTTPStatusError):
            await delivery

    assert body.closed is True


@pytest.mark.asyncio
async def test_compliance_slack_delivery_uses_safe_summary_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = uuid4()
    connector_id = uuid4()
    event = OutboxMessage(
        id=uuid4(),
        organization_id=organization_id,
        event_type=handlers.COMPLIANCE_DELIVERY,
        aggregate_type="compliance_connector",
        aggregate_id=str(connector_id),
        idempotency_key="compliance:slack:summary",
        payload={
            "organization_id": str(organization_id),
            "connector_id": str(connector_id),
            "target_id": str(uuid4()),
            "target_kind": "slack",
            "secret_ref": "fernet:v2:slack",
            "body": {
                "event_type": "pii_finding_summary",
                "provider": "openai",
                "finding_count": 2,
                "by_severity": {"high": 2},
            },
        },
        attempt_count=1,
        created_at=datetime.now(timezone.utc),
    )
    store = SimpleNamespace(
        get_secret=AsyncMock(
            return_value=(
                '{"kind":"slack","endpoint":"https://hooks.slack.com/services/test",'
                '"signing_secret":null}'
            )
        )
    )
    posted = AsyncMock()
    monkeypatch.setattr(handlers, "get_secret_store", lambda: store)
    monkeypatch.setattr(handlers, "_post_forward_url", posted)

    await handlers.deliver_compliance_event(event)

    body = json.loads(posted.await_args.kwargs["content"])
    assert set(body) == {"text"}
    assert "2 compliance finding" in body["text"]
    assert "raw" not in body["text"]


@pytest.mark.asyncio
async def test_compliance_email_uses_fixed_resend_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.post.return_value = Mock()
    client_factory = Mock(return_value=client)
    monkeypatch.setattr(handlers.httpx, "AsyncClient", client_factory)
    monkeypatch.setattr(handlers.settings, "RESEND_API_KEY", "re_secret")
    monkeypatch.setattr(
        handlers.settings, "COMPLIANCE_EMAIL_FROM", "compliance@example.com"
    )

    await handlers._send_compliance_email(
        "alerts@example.com",
        text="SHIM summary",
        idempotency_key="compliance:email:1",
    )

    client.post.assert_awaited_once()
    assert client.post.await_args.args[0] == "https://api.resend.com/emails"
    assert client.post.await_args.kwargs["json"]["to"] == ["alerts@example.com"]
    assert client.post.await_args.kwargs["headers"]["authorization"] == (
        "Bearer re_secret"
    )
