"""Versioned HTTP route composition with no gateway policy."""

from fastapi import APIRouter

from shim.api.v1.chat import router as chat_router
from shim.api.v1.messages import router as messages_router
from shim.api.v1.responses import router as responses_router
from shim_enterprise.ai_act.api import router as ai_act_router
from shim_enterprise.api.v1 import management, scan, subscriptions
from shim_enterprise.compliance.api import router as compliance_router
from shim_enterprise.shared_results.api import authenticated_router, public_router

gateway_router = APIRouter()
gateway_router.include_router(chat_router)
gateway_router.include_router(responses_router)
gateway_router.include_router(messages_router)
gateway_router.include_router(scan.router)
gateway_router.include_router(authenticated_router)

management_router = APIRouter()
management_router.include_router(subscriptions.router)
management_router.include_router(
    management.router,
    prefix="/management",
    tags=["management"],
)
management_router.include_router(compliance_router)
management_router.include_router(ai_act_router)
management_router.include_router(public_router)
