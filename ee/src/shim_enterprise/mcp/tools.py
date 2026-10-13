"""Every MCP tool is one management route, called with the caller's own key."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from shim_enterprise.policy.api import PlanInput, RestoreInput
from shim_enterprise.policy.resources import REGISTRY
from shim_enterprise.tenants.permissions import Permission

MANAGEMENT = "/api/v1/management"


class _Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NoArguments(_Arguments):
    pass


class FindingArguments(_Arguments):
    finding_id: UUID


class ListFindings(_Arguments):
    status: str | None = Field(
        default=None, description="open, new, in_progress or resolved."
    )
    rule_id: str | None = Field(default=None, max_length=64)
    severity_id: int | None = Field(default=None, ge=1, le=5)
    limit: int = Field(default=20, ge=1, le=50)
    offset: int = Field(default=0, ge=0)


class ListRequests(_Arguments):
    start: AwareDatetime | None = None
    end: AwareDatetime | None = None
    status: str | None = Field(default=None, max_length=32)
    model: str | None = Field(default=None, max_length=255)
    request_id: str | None = Field(default=None, max_length=255)
    tag: str | None = Field(default=None, max_length=64)
    limit: int = Field(default=20, ge=1, le=50)
    offset: int = Field(default=0, ge=0)


class CreatePlan(_Arguments):
    body: PlanInput
    window_days: int = Field(default=7, ge=1, le=31)


class ProposeRules(_Arguments):
    body: dict[str, Any] = Field(
        description="{sentence, language, rules}: each rule a term, pattern or "
        "destination rule (no state) with examples {match, no_match} the user gave. "
        "Read the write_rules prompt first."
    )


class ListPlans(_Arguments):
    status: str | None = Field(default=None, max_length=20)
    limit: int = Field(default=20, ge=1, le=50)


class ListRemediations(_Arguments):
    status: str | None = Field(
        default=None,
        description="watching, kept, restored, restore_skipped, skipped or undone.",
    )
    limit: int = Field(default=20, ge=1, le=50)
    before: AwareDatetime | None = None


class PlanArguments(_Arguments):
    plan_id: UUID


class ListVersions(_Arguments):
    limit: int = Field(default=20, ge=1, le=50)
    before: int | None = Field(default=None, ge=1)


class RestoreVersion(_Arguments):
    version: int = Field(ge=0)
    body: RestoreInput = RestoreInput()


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    arguments: type[_Arguments]
    method: str
    path: str
    # Listed for a caller holding any of these; the route itself still decides.
    permissions_any: tuple[Permission, ...]
    read_only: bool

    def listing(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.arguments.model_json_schema(),
            "annotations": {
                "readOnlyHint": self.read_only,
                "destructiveHint": self.name in {"apply_plan", "restore_version"},
            },
        }


TOOLS: tuple[Tool, ...] = (
    Tool(
        "list_findings",
        "List shim's findings, newest first, with their evidence and suggested action.",
        ListFindings,
        "GET",
        f"{MANAGEMENT}/findings",
        ("findings.read",),
        True,
    ),
    Tool(
        "get_finding",
        "Read one finding.",
        FindingArguments,
        "GET",
        f"{MANAGEMENT}/findings/{{finding_id}}",
        ("findings.read",),
        True,
    ),
    Tool(
        "explain_finding",
        "A finding with its rule's facts and documentation, to explain it from.",
        FindingArguments,
        "GET",
        f"{MANAGEMENT}/findings/{{finding_id}}/explain",
        ("findings.read",),
        True,
    ),
    Tool(
        "list_finding_rules",
        "Every finding rule, its mode and how many findings are open.",
        NoArguments,
        "GET",
        f"{MANAGEMENT}/findings/rules",
        ("findings.read",),
        True,
    ),
    Tool(
        "list_remediations",
        "Changes shim or an agent applied without a person, newest first: what "
        "changed, the measurement window and whether it was kept or undone.",
        ListRemediations,
        "GET",
        f"{MANAGEMENT}/remediations",
        ("findings.read", "audit.read"),
        True,
    ),
    Tool(
        "plan_from_finding",
        "Turn a finding's suggested action into a draft policy plan. A finding "
        "suggests one only when its rule is in suggest mode; otherwise use create_plan.",
        FindingArguments,
        "POST",
        f"{MANAGEMENT}/findings/{{finding_id}}/plan",
        ("plans.create",),
        False,
    ),
    Tool(
        "list_requests",
        "Request metadata (never prompt or answer text), filtered and paged.",
        ListRequests,
        "GET",
        f"{MANAGEMENT}/requests",
        ("usage.read",),
        True,
    ),
    Tool(
        "get_rules",
        "The tenant's rule set.",
        NoArguments,
        "GET",
        f"{MANAGEMENT}/rules",
        ("rules.read",),
        True,
    ),
    Tool(
        "get_privacy_settings",
        "The privacy settings and the action every entity type gets.",
        NoArguments,
        "GET",
        f"{MANAGEMENT}/settings/pii",
        ("settings.read",),
        True,
    ),
    Tool(
        "get_gateway_settings",
        "The tenant's gateway switches.",
        NoArguments,
        "GET",
        f"{MANAGEMENT}/gateway-settings",
        ("settings.read",),
        True,
    ),
    Tool(
        "list_deployments",
        "The model deployment registry.",
        NoArguments,
        "GET",
        f"{MANAGEMENT}/model-deployments",
        ("deployments.read",),
        True,
    ),
    Tool(
        "create_plan",
        "Propose a change as a draft policy plan. body.changes is a list of "
        "{resource, item, set: {field: value}} or {resource, item, delete: true}; "
        f"resource is one of {', '.join(sorted(REGISTRY))}; item is the id the read "
        'tools show ("_" for privacy and gateway_settings). Example: '
        '{"resource": "deployments", "item": "<id>", "set": {"enabled": false}}.',
        CreatePlan,
        "POST",
        f"{MANAGEMENT}/policy/plans",
        ("plans.create",),
        False,
    ),
    Tool(
        "propose_rules",
        "Turn the user's own sentence into concrete rules. Send the sentence and the "
        "rules you derived, each with examples the user gave. shim stores nothing "
        "until an administrator applies the plan. When the answer has questions, ask "
        "the user, do not guess.",
        ProposeRules,
        "POST",
        f"{MANAGEMENT}/rules/proposals",
        ("plans.create",),
        False,
    ),
    Tool(
        "list_plans",
        "Policy plans, newest first.",
        ListPlans,
        "GET",
        f"{MANAGEMENT}/policy/plans",
        ("plans.create", "audit.read"),
        True,
    ),
    Tool(
        "get_plan",
        "One plan: each change's before, after, risk and impact.",
        PlanArguments,
        "GET",
        f"{MANAGEMENT}/policy/plans/{{plan_id}}",
        ("plans.create", "audit.read"),
        True,
    ),
    Tool(
        "apply_plan",
        "Apply a plan. PLAN_NOT_ALLOWLISTED means it needs a person.",
        PlanArguments,
        "POST",
        f"{MANAGEMENT}/policy/plans/{{plan_id}}/apply",
        ("plans.apply", "plans.apply_allowlisted"),
        False,
    ),
    Tool(
        "list_versions",
        "The policy history, newest first.",
        ListVersions,
        "GET",
        f"{MANAGEMENT}/policy/versions",
        ("audit.read", "plans.create"),
        True,
    ),
    Tool(
        "restore_version",
        "Put the policy back as it was at a version, through a plan.",
        RestoreVersion,
        "POST",
        f"{MANAGEMENT}/policy/versions/{{version}}/restore",
        ("plans.apply", "plans.apply_allowlisted"),
        False,
    ),
)
BY_NAME = {tool.name: tool for tool in TOOLS}
