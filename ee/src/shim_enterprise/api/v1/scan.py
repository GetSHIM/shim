"""Provider-free privacy scan HTTP boundary."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import (
    get_enterprise_gateway_service,
    get_scan_principal,
)
from shim_enterprise.core.database import get_db
from shim_enterprise.gateway.contracts.enterprise_errors import (
    ScanLimitExceeded,
    ScanPersistenceError,
)
from shim.gateway.contracts.errors import ScanAnalysisError
from shim.gateway.contracts.inference import ScanInput
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim_enterprise.services.gateway.enterprise import EnterpriseGatewayService


router = APIRouter(tags=["scan"])


class EntityFound(BaseModel):
    type: str
    score: float
    start: int
    end: int


class ScanResponse(BaseModel):
    verdict: str
    entities_found: list[EntityFound]
    entity_types: list[str]
    scan_count: int
    scan_limit: int
    scans_remaining: int
    policy: str


class ScanUsageResponse(BaseModel):
    scan_count: int
    scan_limit: int
    scans_remaining: int
    resets_at: str | None


@router.post("/scan", response_model=ScanResponse)
async def scan_text(
    payload: ScanInput,
    response: Response,
    gateway: EnterpriseGatewayService = Depends(get_enterprise_gateway_service),
    principal: AuthenticatedPrincipal = Depends(get_scan_principal),
    session: AsyncSession = Depends(get_db),
) -> ScanResponse:
    try:
        result = await gateway.dispatch_scan(
            payload=payload,
            principal=principal,
            db=session,
        )
    except ScanLimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": exc.code,
                "scan_limit": exc.usage.scan_limit,
                "resets_at": exc.usage.resets_at,
            },
        ) from None
    except (ScanAnalysisError, ScanPersistenceError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": exc.code, "message": str(exc)},
        ) from None
    response.headers["X-Shim-Request-Id"] = str(result.request_id)
    return ScanResponse(
        verdict=result.verdict,
        entities_found=[
            EntityFound(
                type=entity.type,
                score=entity.score,
                start=entity.start,
                end=entity.end,
            )
            for entity in result.entities_found
        ],
        entity_types=list(result.entity_types),
        scan_count=result.scan_count,
        scan_limit=result.scan_limit,
        scans_remaining=result.scans_remaining,
        policy=result.policy,
    )


@router.get("/scan/usage", response_model=ScanUsageResponse)
async def scan_usage(
    gateway: EnterpriseGatewayService = Depends(get_enterprise_gateway_service),
    principal: AuthenticatedPrincipal = Depends(get_scan_principal),
    session: AsyncSession = Depends(get_db),
) -> ScanUsageResponse:
    try:
        usage = await gateway.scan_usage(principal=principal, db=session)
    except ScanPersistenceError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": exc.code, "message": str(exc)},
        ) from None
    return ScanUsageResponse(**usage.model_dump())
