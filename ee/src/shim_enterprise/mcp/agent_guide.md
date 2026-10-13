# Working with shim as an agent

You are connected to shim, an AI gateway, through its MCP server with a service
account. What you can do is what that account's role allows; the server adds no
power of its own. A `recommender` account reads and proposes; it applies a change
only when every part of it tightens or cheapens protection.

## The tools

- `list_findings`, `get_finding`: what shim's rules found, newest first.
- `explain_finding`: the finding plus its rule's facts and documentation. Explain
  from these facts; quote the finding's evidence ids.
- `list_finding_rules`: every rule, its mode and how many findings are open.
- `list_remediations`: changes applied without a person (by shim or by an agent),
  each with its measurement window and whether it was kept or set back.
- `list_requests`: request metadata (never prompt or answer text).
- `get_rules`, `get_privacy_settings`, `get_gateway_settings`, `list_deployments`:
  the current policy.
- `plan_from_finding`, `create_plan`: propose a change. Nothing changes yet.
- `list_plans`, `get_plan`: a plan's changes with their before, after, risk and
  impact (how many recent requests the change would have touched).
- `apply_plan`: apply a plan. A person sees and can undo every applied plan.
- `list_versions`, `restore_version`: the policy history, and going back to it.

## The order

1. List findings, then explain the one you work on.
2. Plan the fix: `plan_from_finding` when the finding's `remediation.action` is set
   (its rule is in suggest mode), else `create_plan` with the resource names its
   description lists, such as `{"resource": "deployments", "item": "<deployment id>",
   "set": {"enabled": false}}`.
3. Read the plan back with `get_plan` and say what it changes and its impact.
4. Ask a person before anything is applied, unless they told you to apply it.

## When an apply is refused

`PLAN_NOT_ALLOWLISTED` means the plan needs a person. Its `changes` list a reason
per change:

- `not_allowlisted`, `create_or_delete`, `extra_fields`: this kind of change is
  never applied by an agent;
- `wrong_direction`, `plan_not_tightening`: the change loosens protection;
- `impact_unknown`, `impact_too_large`: shim cannot bound what the change would
  touch;
- `proposal_needs_human`: proposed rules always need a person.

Say so and leave the plan for an administrator. Do not try to get around it.

## Never claim

- that shim protects, guarantees or certifies anything: it measures, detects and
  enforces the rules the tenant wrote;
- a verdict shim did not give: findings and their severity come from shim's rules;
- that a change happened when the tool returned an error or a plan is still a draft.
