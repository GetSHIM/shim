"""Single-attempt handlers for post-commit outbox side effects."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import httpx

from shim_enterprise.compliance.url_guard import (
    UnsafeForwardURL,
    assert_safe_forward_url,
)
from shim_enterprise.core.config import settings
from shim.gateway.contracts.ids import SecretRef, TenantId
from shim_enterprise.outbox.publisher import OutboxMessage, OutboxPublisher
from shim_enterprise.secrets.store import get_secret_store


logger = logging.getLogger(__name__)
AUDIT_CHAIN_APPEND = "audit.chain_append_requested"
GATEWAY_RECONCILIATION = "gateway.reconciliation"
BUDGET_THRESHOLD = "budget.threshold_crossed"
COMPLIANCE_DELIVERY = "compliance.connector_delivery_requested"
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
    url = await get_secret_store().get_secret(
        TenantId(message.organization_id),
        SecretRef(secret_ref),
        expected_purpose="budget-alert-endpoint",
    )
    body = (
        {"text": _budget_text(payload)}
        if target["kind"] == "slack"
        else {"event": BUDGET_THRESHOLD, "payload": payload}
    )
    try:
        await _post_forward_url(
            url,
            content=json.dumps(body).encode(),
            headers={
                "content-type": "application/json",
                "idempotency-key": message.idempotency_key,
            },
        )
    except UnsafeForwardURL as exc:
        raise ValueError("budget alert endpoint is unsafe") from exc


async def deliver_compliance_event(message: OutboxMessage) -> None:
    payload = _tenant_payload(message, aggregate_type="compliance_connector")
    if payload.get("connector_id") != message.aggregate_id:
        raise ValueError("compliance connector identity mismatch")
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
        digest = hmac.new(
            signing_secret.encode("utf-8"),
            encoded,
            hashlib.sha256,
        ).hexdigest()
        headers["x-shim-signature"] = f"sha256={digest}"
    await _post_forward_url(endpoint, content=encoded, headers=headers)


async def _send_compliance_email(
    recipient: str,
    *,
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
                "subject": "SHIM compliance finding summary",
                "text": text,
            },
        )
        response.raise_for_status()


def _compliance_text(body: dict) -> str:
    if body.get("event_type") == "pii_finding_summary":
        return (
            f"SHIM detected {body.get('finding_count', 0)} compliance finding(s) "
            f"for {body.get('provider', 'provider')}. "
            f"Severity: {json.dumps(body.get('by_severity', {}), sort_keys=True)}"
        )
    if body.get("event_type") == "pii_finding":
        return (
            f"SHIM compliance finding: {body.get('severity', 'unknown')} "
            f"{body.get('entity_type', 'entity')}"
        )
    return f"SHIM compliance alert: {body.get('message', body.get('kind', 'event'))}"


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
        f"SHIM budget {scope}: {payload.get('percent_used')}% used in "
        f"{payload.get('period')}"
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
