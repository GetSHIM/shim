"""Single-attempt handlers for post-commit outbox side effects."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import ssl

import httpx

from shim_enterprise.compliance.url_guard import (
    UnsafeForwardURL,
    assert_safe_forward_url,
)
from shim_enterprise.compliance.services.forwarder import ComplianceForwarderService
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import AsyncSessionLocal
from shim.gateway.contracts.ids import SecretRef, TenantId
from shim_enterprise.outbox.publisher import OutboxMessage, OutboxPublisher
from shim_enterprise.secrets.store import get_secret_store


logger = logging.getLogger(__name__)
AUDIT_CHAIN_APPEND = "audit.chain_append_requested"
GATEWAY_RECONCILIATION = "gateway.reconciliation"
BUDGET_THRESHOLD = "budget.threshold_crossed"
COMPLIANCE_DELIVERY = "compliance.connector_delivery_requested"
BULK_DISCLOSURE = "privacy.bulk_disclosure"
_DELIVERY_TIMEOUT_SECONDS = 10.0
_COMPLIANCE_DELIVERY_PURPOSE = "compliance-forward-target-delivery"


async def _post_forward_url(
    url: str,
    *,
    content: bytes,
    headers: dict[str, str],
) -> None:
    address = await assert_safe_forward_url(url)
    original = httpx.URL(url)
    async with httpx.AsyncClient(
        timeout=_DELIVERY_TIMEOUT_SECONDS,
        follow_redirects=False,
        trust_env=False,
        verify=ssl.create_default_context(cafile=settings.OUTBOUND_CA_BUNDLE),
    ) as client:
        async with client.stream(
            "POST",
            original.copy_with(host=str(address)),
            content=content,
            headers={**headers, "host": original.netloc.decode("ascii")},
            extensions={"sni_hostname": original.raw_host.decode("ascii")},
        ) as response:
            response.raise_for_status()


def build_publisher() -> OutboxPublisher:
    from shim_enterprise.observability.analytics_projection import (
        register_analytics_handlers,
    )

    publisher = OutboxPublisher()
    publisher.register(AUDIT_CHAIN_APPEND, append_audit_chain)
    publisher.register(GATEWAY_RECONCILIATION, report_reconciliation)
    publisher.register(BUDGET_THRESHOLD, deliver_budget_alert)
    publisher.register(COMPLIANCE_DELIVERY, deliver_compliance_event)
    publisher.register(BULK_DISCLOSURE, fan_out_bulk_disclosure)
    register_analytics_handlers(publisher)
    return publisher


async def append_audit_chain(message: OutboxMessage) -> None:
    from shim_enterprise.ai_act.audit_writer import append_audit_row_deduplicated

    await append_audit_row_deduplicated(_audit_payload(message))


async def report_reconciliation(message: OutboxMessage) -> None:
    payload = _request_payload(message)
    log = logger.warning if payload.get("urgent") is True else logger.info
    log(
        "Gateway reconciliation lifecycle_status=%s urgent=%s",
        payload.get("lifecycle_status"),
        payload.get("urgent") is True,
    )


async def deliver_budget_alert(message: OutboxMessage) -> None:
    payload = _tenant_payload(message, aggregate_type="budget")
    target = payload.get("target")
    if not isinstance(target, dict) or target.get("kind") not in {
        "slack",
        "webhook",
    }:
        raise ValueError("budget alert requires one webhook delivery target")
    secret_ref = target.get("secret_ref")
    if not isinstance(secret_ref, str):
        raise ValueError("budget alert target requires a secret reference")
    store = get_secret_store()
    url = await store.get_secret(
        TenantId(message.organization_id),
        SecretRef(secret_ref),
        expected_purpose="budget-alert-endpoint",
    )
    # The delivery target, with its secret-store reference, stays inside shim.
    alert = {key: value for key, value in payload.items() if key != "target"}
    body = (
        {"text": _budget_text(alert)}
        if target["kind"] == "slack"
        else {"event": BUDGET_THRESHOLD, "payload": alert}
    )
    content = json.dumps(body).encode()
    headers = {
        "content-type": "application/json",
        "idempotency-key": message.idempotency_key,
    }
    signing_ref = target.get("signing_secret_ref")
    if isinstance(signing_ref, str):
        headers["x-shim-signature"] = _signature(
            await store.get_secret(
                TenantId(message.organization_id),
                SecretRef(signing_ref),
                expected_purpose="budget-alert-signing",
            ),
            content,
        )
    try:
        await _post_forward_url(url, content=content, headers=headers)
    except UnsafeForwardURL as exc:
        raise ValueError("budget alert endpoint is unsafe") from exc


async def fan_out_bulk_disclosure(message: OutboxMessage) -> None:
    payload = _request_payload(message)
    body = {
        "source": "shim",
        "event_type": "privacy_alert",
        "kind": "bulk_disclosure",
        **{key: value for key, value in payload.items() if key != "organization_id"},
    }
    async with AsyncSessionLocal() as session:
        await ComplianceForwarderService().send_tenant_alert(
            session,
            TenantId(message.organization_id),
            body=body,
            delivery_key=f"bulk_disclosure:{payload['request_id']}",
        )
        await session.commit()


async def deliver_compliance_event(message: OutboxMessage) -> None:
    tenant_level = message.aggregate_type == "organization"
    payload = _tenant_payload(
        message,
        aggregate_type="organization" if tenant_level else "compliance_connector",
    )
    owner = payload["organization_id"] if tenant_level else payload.get("connector_id")
    if owner != message.aggregate_id:
        raise ValueError("compliance delivery identity mismatch")
    body = payload.get("body")
    if not isinstance(body, dict):
        raise ValueError("compliance delivery body must be an object")
    target_kind = payload.get("target_kind")
    if target_kind not in {"siem_webhook", "slack", "email"}:
        raise ValueError("compliance delivery target kind is invalid")
    secret_ref = payload.get("secret_ref")
    if not isinstance(secret_ref, str):
        raise ValueError("compliance delivery requires a secret reference")
    raw_bundle = await get_secret_store().get_secret(
        TenantId(message.organization_id),
        SecretRef(secret_ref),
        expected_purpose=_COMPLIANCE_DELIVERY_PURPOSE,
    )
    bundle_kind, endpoint, signing_secret = _delivery_bundle(raw_bundle)
    if bundle_kind != target_kind:
        raise ValueError("compliance delivery target kind mismatch")
    if target_kind == "email":
        await _send_compliance_email(
            endpoint,
            subject={
                "privacy_protection_relaxed": "shim privacy protection turned off",
                "bulk_disclosure": "shim bulk disclosure in one request",
            }.get(str(body.get("kind")), "shim compliance finding summary"),
            text=_compliance_text(body),
            idempotency_key=message.idempotency_key,
        )
        return
    delivered_body = (
        {"text": _compliance_text(body)} if target_kind == "slack" else body
    )
    encoded = json.dumps(delivered_body, separators=(",", ":"), default=str).encode(
        "utf-8"
    )
    headers = {
        "content-type": "application/json",
        "idempotency-key": message.idempotency_key,
    }
    if signing_secret:
        headers["x-shim-signature"] = _signature(signing_secret, encoded)
    await _post_forward_url(endpoint, content=encoded, headers=headers)


def _signature(secret: str, content: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), content, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


async def _send_compliance_email(
    recipient: str,
    *,
    subject: str,
    text: str,
    idempotency_key: str,
) -> None:
    if not settings.RESEND_API_KEY or not settings.COMPLIANCE_EMAIL_FROM:
        raise ValueError("compliance email forwarding is not configured")
    async with httpx.AsyncClient(
        timeout=_DELIVERY_TIMEOUT_SECONDS,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        response = await client.post(
            "https://api.resend.com/emails",
            headers={
                "authorization": f"Bearer {settings.RESEND_API_KEY}",
                "idempotency-key": idempotency_key,
            },
            json={
                "from": str(settings.COMPLIANCE_EMAIL_FROM),
                "to": [recipient],
                "subject": subject,
                "text": text,
            },
        )
        response.raise_for_status()


def _compliance_text(body: dict) -> str:
    if body.get("event_type") == "pii_finding_summary":
        return (
            f"shim detected {body.get('finding_count', 0)} compliance finding(s) "
            f"for {body.get('provider', 'provider')}. "
            f"Severity: {json.dumps(body.get('by_severity', {}), sort_keys=True)}"
        )
    if body.get("event_type") == "pii_finding":
        return (
            f"shim compliance finding: {body.get('severity', 'unknown')} "
            f"{body.get('entity_type', 'entity')}"
        )
    if body.get("kind") == "privacy_protection_relaxed":
        fields = ", ".join(map(str, body.get("fields", [])))
        actor = body.get("actor_email") or f"user {body.get('actor', 'unknown')}"
        return f"shim privacy protection turned off: {fields} (by {actor})"
    if body.get("kind") == "bulk_disclosure":
        counts = ", ".join(
            f"{entity_type} {count}"
            for entity_type, count in (body.get("entity_counts") or {}).items()
        )
        return (
            f"shim bulk disclosure: {body.get('distinct_values')} distinct values "
            f"({counts}) in one request with API key {body.get('api_key_id')} "
            f"at {body.get('occurred_at')}, threshold {body.get('threshold')}"
        )
    return f"shim compliance alert: {body.get('message', body.get('kind', 'event'))}"


def _request_payload(message: OutboxMessage) -> dict:
    payload = _tenant_payload(message, aggregate_type="request")
    request_id = payload.get("request_id")
    if not isinstance(request_id, str) or request_id != message.aggregate_id:
        raise ValueError("outbox request identity mismatch")
    return payload


def _audit_payload(message: OutboxMessage) -> dict:
    payload = _tenant_payload(message, aggregate_type=message.aggregate_type)
    request_id = payload.get("request_id")
    if not isinstance(request_id, str) or request_id != message.aggregate_id:
        raise ValueError("audit identity mismatch")
    return payload


def _tenant_payload(
    message: OutboxMessage,
    *,
    aggregate_type: str,
) -> dict:
    payload = dict(message.payload)
    if str(payload.get("organization_id")) != str(message.organization_id):
        raise ValueError("outbox tenant identity mismatch")
    if message.aggregate_type != aggregate_type:
        raise ValueError("outbox aggregate type mismatch")
    return payload


def _budget_text(payload: dict) -> str:
    scope = payload.get("scope_value") or payload.get("scope_type")
    return (
        f"shim budget {scope}: {payload.get('percent_used', 0):.0f}% used in "
        f"{payload.get('period')}"
        + (
            f" (known spend only; {payload.get('unpriced_requests')} unpriced requests)"
            if payload.get("cost_complete") is False
            else ""
        )
    )


def _delivery_bundle(value: str) -> tuple[str, str, str | None]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid compliance delivery secret") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("kind") not in {"siem_webhook", "slack", "email"}
        or not isinstance(payload.get("endpoint"), str)
    ):
        raise ValueError("compliance delivery secret has no endpoint")
    signing_secret = payload.get("signing_secret")
    if signing_secret is not None and not isinstance(signing_secret, str):
        raise ValueError("invalid compliance delivery signing secret")
    return payload["kind"], payload["endpoint"], signing_secret
