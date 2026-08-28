from __future__ import annotations

from collections.abc import Callable
from functools import partial
from types import SimpleNamespace
from typing import NoReturn
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from shim_enterprise.gateway.api.enterprise_errors import (
    raise_accounting_limit,
    raise_audit_intent_error,
    raise_persistence_error,
    raise_tenant_policy_error,
)
from shim_enterprise.billing.ledger import QuotaLimitExceeded, SpendLimitExceeded
from shim_enterprise.gateway.pipeline.audit_intent import AuditIntentPersistenceError
from shim.gateway.pipeline.authenticate import GatewayRequestMetadata
from shim_enterprise.gateway.pipeline.quota_reservation import (
    AccountingPersistenceError,
)
from shim_enterprise.services.gateway.enterprise import EnterpriseGatewayService
from shim_enterprise.tenants.policy import TenantPolicyConfigurationError


@pytest.mark.parametrize(
    ("raise_error", "status_code", "detail"),
    [
        (
            raise_persistence_error,
            503,
            {
                "code": "INTERNAL_ERROR",
                "message": "Gateway state could not be persisted.",
            },
        ),
        (
            raise_audit_intent_error,
            503,
            {
                "code": "AUDIT_INTENT_FAILED",
                "message": "The required audit intent could not be persisted.",
                "retryable": True,
                "provider": None,
            },
        ),
        (
            partial(raise_accounting_limit, "MONTHLY_QUOTA_EXCEEDED"),
            429,
            {
                "code": "MONTHLY_QUOTA_EXCEEDED",
                "message": "The request exceeds the current account limit.",
            },
        ),
        (
            raise_tenant_policy_error,
            503,
            {
                "code": "INTERNAL_ERROR",
                "message": "Gateway policy configuration is unavailable.",
            },
        ),
    ],
)
def test_enterprise_errors_keep_fixed_safe_envelopes(
    raise_error: Callable[[], NoReturn],
    status_code: int,
    detail: dict[str, object],
) -> None:
    with pytest.raises(HTTPException) as raised:
        raise_error()

    assert raised.value.status_code == status_code
    assert raised.value.detail == detail


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "status_code", "code"),
    [
        (AccountingPersistenceError(), 503, "INTERNAL_ERROR"),
        (AuditIntentPersistenceError(), 503, "AUDIT_INTENT_FAILED"),
        (QuotaLimitExceeded(), 429, "MONTHLY_QUOTA_EXCEEDED"),
        (SpendLimitExceeded(), 429, "SPEND_LIMIT_EXCEEDED"),
        (TenantPolicyConfigurationError(), 503, "INTERNAL_ERROR"),
    ],
)
async def test_enterprise_service_maps_enterprise_failures(
    error: Exception,
    status_code: int,
    code: str,
) -> None:
    service = EnterpriseGatewayService(
        SimpleNamespace(execute=AsyncMock(side_effect=error)),  # type: ignore[arg-type]
        SimpleNamespace(),  # type: ignore[arg-type]
    )

    with pytest.raises(HTTPException) as raised:
        await service.dispatch_inference(
            payload={},
            provider="openai",
            protocol="chat",
            model="gpt-test",
            stream=False,
            headers={},
            provider_credential=None,
            principal=SimpleNamespace(),  # type: ignore[arg-type]
            request_metadata=GatewayRequestMetadata(endpoint="/v1/chat/completions"),
        )

    assert raised.value.status_code == status_code
    assert raised.value.detail["code"] == code
