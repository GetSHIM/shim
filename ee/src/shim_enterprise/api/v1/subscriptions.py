"""Public payment-provider webhooks."""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim_enterprise.tenants.subscriptions import (
    process_lemonsqueezy_webhook,
    verify_lemonsqueezy_signature,
)

router = APIRouter(tags=["webhooks"])


@router.post("/webhooks/lemonsqueezy")
async def lemonsqueezy_webhook(
    request: Request,
    session: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    secret = settings.LEMON_SQUEEZY_SIGNING_SECRET
    if not secret:
        raise HTTPException(status_code=503, detail="Billing webhook is not configured")
    raw_body = await request.body()
    if not verify_lemonsqueezy_signature(
        raw_body,
        request.headers.get("x-signature", ""),
        secret,
    ):
        raise HTTPException(status_code=403, detail="Invalid webhook signature")
    try:
        result = await process_lemonsqueezy_webhook(session, raw_body)
    except ValueError as exc:
        await session.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        await session.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception:
        await session.rollback()
        raise
    return {"status": result}
