"""Local provider-free privacy scan boundary."""

from __future__ import annotations

import asyncio
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel

from shim.api.deps import get_authenticated_principal
from shim.gateway.contracts.errors import ScanAnalysisError
from shim.gateway.contracts.inference import (
    ScanEntity,
    ScanInput,
    ScanPolicy,
    ScanVerdict,
)
from shim.gateway.contracts.principal import AuthenticatedPrincipal


router = APIRouter(tags=["scan"])


class CommunityScanResponse(BaseModel):
    request_id: str
    verdict: ScanVerdict
    entities: list[ScanEntity]
    entity_types: list[str]
    policy: ScanPolicy


@router.post("/scan", response_model=CommunityScanResponse)
async def scan_text(
    request: Request,
    payload: ScanInput,
    response: Response,
    _principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
) -> CommunityScanResponse:
    policy: ScanPolicy = "block"
    try:
        result = await asyncio.to_thread(
            request.app.state.scan_privacy.analyze,
            payload.text,
            config={},
            policy=policy,
        )
    except ScanAnalysisError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": exc.code, "message": str(exc)},
        ) from None

    request_id = f"scan_{uuid4().hex}"
    response.headers["X-Shim-Request-Id"] = request_id
    return CommunityScanResponse(
        request_id=request_id,
        verdict=result.verdict,
        entities=list(result.entities),
        entity_types=list(result.entity_types),
        policy=policy,
    )
