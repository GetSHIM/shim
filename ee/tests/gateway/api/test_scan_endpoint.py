from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, call
from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException, Request, Response
from httpx import ASGITransport, AsyncClient

import shim_enterprise.api.enterprise_deps as deps
from shim_enterprise.api.v1.scan import router as scan_router
from shim_enterprise.api.v1.scan import scan_text, scan_usage
from shim_enterprise.gateway.contracts.enterprise_errors import (
    ScanLimitExceeded,
    ScanPersistenceError,
)
from shim_enterprise.gateway.contracts.enterprise_scan import ScanUsageStatus
from shim.gateway.contracts.errors import ScanAnalysisError
from shim.gateway.contracts.ids import ApiKeyId
from shim.gateway.contracts.inference import ScanInput
from shim.gateway.contracts.principal import AuthenticatedPrincipal


def principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        actor_type="api_key",
        api_key_id=ApiKeyId(uuid4()),
        authenticated_at=datetime.now(timezone.utc),
    )


def request(*headers: tuple[bytes, bytes]) -> Request:
    return Request({"type": "http", "headers": list(headers)})


@pytest.mark.asyncio
async def test_scan_boundary_rejects_caller_supplied_identity() -> None:
    gateway = SimpleNamespace(dispatch_scan=AsyncMock())
    application = FastAPI()
    application.include_router(scan_router, prefix="/v1")
    application.dependency_overrides[deps.get_enterprise_gateway_service] = lambda: (
        gateway
    )
    application.dependency_overrides[deps.get_scan_principal] = principal
    application.dependency_overrides[deps.get_db] = lambda: AsyncMock()

    async with AsyncClient(
        transport=ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/scan",
            json={"text": "safe", "tenant_id": str(uuid4())},
        )

    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "extra_forbidden"
    gateway.dispatch_scan.assert_not_awaited()


@pytest.mark.asyncio
async def test_scan_api_key_auth_accepts_header_and_bearer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_key = SimpleNamespace(id=uuid4())
    authenticate = AsyncMock(return_value=api_key)
    session = AsyncMock()
    monkeypatch.setattr(deps, "authenticate_api_key", authenticate)

    header = await deps.get_scan_principal(
        request((b"x-shim-key", b"sk-shim-auth-test")),
        None,
        None,
        session,
    )
    bearer = await deps.get_scan_principal(
        request((b"authorization", b"Bearer sk-shim-auth-test")),
        None,
        None,
        session,
    )

    assert header.api_key_id == bearer.api_key_id == api_key.id
    assert authenticate.await_args_list == [
        call(session, "sk-shim-auth-test"),
        call(session, "sk-shim-auth-test"),
    ]


@pytest.mark.asyncio
async def test_scan_auth_does_not_fall_through_an_empty_shim_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authenticate = AsyncMock()
    load_jwt = AsyncMock()
    monkeypatch.setattr(deps, "authenticate_api_key", authenticate)
    monkeypatch.setattr(deps, "_load_jwt_user", load_jwt)

    with pytest.raises(HTTPException) as captured:
        await deps.get_scan_principal(
            request(
                (b"x-shim-key", b""),
                (b"authorization", b"Bearer valid-lower-priority-token"),
            ),
            None,
            None,
            AsyncMock(),
        )

    assert captured.value.status_code == 401
    authenticate.assert_not_awaited()
    load_jwt.assert_not_awaited()


@pytest.mark.asyncio
async def test_scan_endpoint_renders_canonical_result() -> None:
    gateway = SimpleNamespace(
        dispatch_scan=AsyncMock(
            return_value=SimpleNamespace(
                request_id="scan_test_correlation",
                verdict="warn",
                entities_found=[
                    SimpleNamespace(type="EMAIL_ADDRESS", score=0.99, start=0, end=18)
                ],
                entity_types=["EMAIL_ADDRESS"],
                scan_count=4,
                scan_limit=200,
                scans_remaining=196,
                policy="warn",
            )
        )
    )
    wire_response = Response()

    response = await scan_text(
        ScanInput(text="person@example.com", source="chatgpt"),
        wire_response,
        gateway,
        principal(),
        AsyncMock(),
    )

    assert response.model_dump() == {
        "verdict": "warn",
        "entities_found": [
            {"type": "EMAIL_ADDRESS", "score": 0.99, "start": 0, "end": 18}
        ],
        "entity_types": ["EMAIL_ADDRESS"],
        "scan_count": 4,
        "scan_limit": 200,
        "scans_remaining": 196,
        "policy": "warn",
    }
    assert wire_response.headers["X-Shim-Request-Id"] == "scan_test_correlation"


@pytest.mark.asyncio
async def test_scan_endpoint_maps_limit_to_429() -> None:
    gateway = SimpleNamespace(
        dispatch_scan=AsyncMock(
            side_effect=ScanLimitExceeded(
                ScanUsageStatus(
                    scan_count=200,
                    scan_limit=200,
                    scans_remaining=0,
                    resets_at="2026-08-01T00:00:00+00:00",
                )
            )
        )
    )

    with pytest.raises(HTTPException) as captured:
        await scan_text(
            ScanInput(text="scan", source="unknown"),
            Response(),
            gateway,
            principal(),
            AsyncMock(),
        )

    assert captured.value.status_code == 429
    assert captured.value.detail == {
        "code": "SCAN_LIMIT_EXCEEDED",
        "scan_limit": 200,
        "resets_at": "2026-08-01T00:00:00+00:00",
    }


@pytest.mark.parametrize("error", [ScanAnalysisError(), ScanPersistenceError()])
@pytest.mark.asyncio
async def test_scan_endpoint_maps_internal_failure(error: RuntimeError) -> None:
    gateway = SimpleNamespace(dispatch_scan=AsyncMock(side_effect=error))

    with pytest.raises(HTTPException) as captured:
        await scan_text(
            ScanInput(text="private", source="unknown"),
            Response(),
            gateway,
            principal(),
            AsyncMock(),
        )

    assert captured.value.status_code == 503
    assert captured.value.detail["code"] == "INTERNAL_ERROR"


@pytest.mark.asyncio
async def test_scan_usage_maps_persistence_failure() -> None:
    gateway = SimpleNamespace(scan_usage=AsyncMock(side_effect=ScanPersistenceError()))

    with pytest.raises(HTTPException) as captured:
        await scan_usage(gateway, principal(), AsyncMock())

    assert captured.value.status_code == 503
    assert captured.value.detail["code"] == "INTERNAL_ERROR"
