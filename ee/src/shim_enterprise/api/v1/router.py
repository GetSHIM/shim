"""Versioned HTTP route composition with no gateway policy."""

from fastapi import APIRouter

from shim.api.v1.chat import router as chat_router
from shim.api.v1.messages import router as messages_router
from shim.api.v1.responses import router as responses_router
from shim_enterprise.ai_act.api import router as ai_act_router
from shim_enterprise.api.v1 import management, scan
from shim_enterprise.approvals.api import router as approvals_router
from shim_enterprise.aws.attribution import router as aws_router
from shim_enterprise.compliance.api import router as compliance_router
from shim_enterprise.compliance.model_evidence_api import (
    router as model_evidence_router,
)
from shim_enterprise.findings.api import router as findings_router
from shim_enterprise.incidents.api import router as incidents_router
from shim_enterprise.config_file.api import router as config_router
from shim_enterprise.mcp.api import router as mcp_router
from shim_enterprise.policy.api import router as policy_router
from shim_enterprise.policy.remediation import router as remediations_router
from shim_enterprise.rules.proposals import router as proposals_router
from shim_enterprise.rules.api import router as rules_router
from shim_enterprise.rules.canaries import router as canaries_router
from shim_enterprise.rules.change_tests import router as change_tests_router
from shim_enterprise.semantic.api import check_router as semantic_check_router
from shim_enterprise.semantic.api import router as semantic_router
from shim_enterprise.semantic.questions import router as semantic_questions_router
from shim_enterprise.shared_results.api import authenticated_router, public_router

from shim_enterprise.tenants.oidc import router as identity_router

gateway_router = APIRouter()
gateway_router.include_router(chat_router)
gateway_router.include_router(responses_router)
gateway_router.include_router(messages_router)
gateway_router.include_router(scan.router)
gateway_router.include_router(authenticated_router)

management_router = APIRouter()
management_router.include_router(identity_router)
management_router.include_router(
    management.router,
    prefix="/management",
    tags=["management"],
)
management_router.include_router(compliance_router)
management_router.include_router(aws_router, prefix="/management", tags=["aws"])
management_router.include_router(incidents_router)
management_router.include_router(ai_act_router)
management_router.include_router(policy_router)
management_router.include_router(config_router)
management_router.include_router(mcp_router)
management_router.include_router(rules_router)
management_router.include_router(canaries_router)
management_router.include_router(change_tests_router)
management_router.include_router(model_evidence_router)
management_router.include_router(semantic_questions_router)
management_router.include_router(semantic_router)
management_router.include_router(semantic_check_router)
management_router.include_router(proposals_router)
management_router.include_router(approvals_router)
management_router.include_router(findings_router)
management_router.include_router(remediations_router)
management_router.include_router(public_router)
