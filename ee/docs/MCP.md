# MCP server

Claude Code, Codex, Cursor or any MCP client can manage shim through one endpoint,
`POST /api/v1/mcp`, with a [service account](team-access.md#service-accounts) key.
shim has no agent of its own: the agent reads findings, explains them in its own
words, proposes plans and applies what its role allows. The server is a thin
adapter: every tool is one management route, called in-process with the caller's
own key, so the route's permission, validation, plans, four eyes, audit and the
[recommender's apply limit](POLICY_DECISIONS.md#the-recommender-and-its-apply-limit)
apply unchanged. There is no second authorization path.

## Connecting

Create a service account (owner), usually with the role `recommender`:

```console
curl -X POST https://shim.example/api/v1/management/service-accounts \
  -H "Authorization: Bearer $OWNER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "claude-code", "role": "recommender", "expires_in_days": 30}'
```

Give the `sk-shim-svc-` key to the agent. Claude Code:

```console
claude mcp add --transport http shim https://shim.example/api/v1/mcp \
  --header "Authorization: Bearer ${SHIM_MANAGEMENT_KEY}"
```

or a `--mcp-config` file:

```json
{"mcpServers": {"shim": {"type": "http", "url": "https://shim.example/api/v1/mcp",
  "headers": {"Authorization": "Bearer ${SHIM_MANAGEMENT_KEY}"}}}}
```

Allow the tools with `mcp__shim__*` (or name them one by one). Codex and Cursor
take the same URL and header in their settings for a remote HTTP MCP server.

## Transport and revisions

JSON only, stateless: no sessions (`Mcp-Session-Id` is ignored and never set), no
SSE, no subscriptions. Both protocol eras are served:

- modern `2026-07-28`: `server/discover`, the version in
  `params._meta["io.modelcontextprotocol/protocolVersion"]` mirrored in
  `MCP-Protocol-Version`, `Mcp-Method` and, for `tools/call`, `resources/read` and
  `prompts/get`, `Mcp-Name` (plain or `=?base64?...?=`). A mismatch or a missing
  header is 400 `-32020`; another version is 400 `-32022` with `data.supported`;
  an unknown method is 404 `-32601`. Results carry `resultType: "complete"`, and
  list and read results `ttlMs: 0` and `cacheScope: "private"`.
- legacy `2025-11-25`, `2025-06-18` and `2025-03-26`: `initialize` (answering the
  client's version when it is one of these, else `2025-11-25`), then requests
  without the modern headers; a request with no `MCP-Protocol-Version` is
  `2025-03-26`. Notifications answer 202 with no body; an unknown method is 200
  `-32601`.

Invalid JSON is 400 `-32700`; a batch, or a message without `jsonrpc: "2.0"`, is
400 `-32600`; an unknown tool, prompt or resource is `-32602`. GET and DELETE are
405, a request with an `Origin` header is 403 (browsers send it, agents do not), a
body over 1,000,000 bytes is 413 and a content type other than JSON is 415.

## Authentication

Only `Authorization: Bearer sk-shim-svc-...`. No key, or a revoked, expired or
unknown service key, is 401 `INVALID_API_KEY` with `WWW-Authenticate: Bearer`. Any
other bearer value (a person's token, a gateway `sk-shim-` key) is 403
`MCP_SERVICE_ACCOUNT_REQUIRED` and is never looked up. Any service account role may
connect; what it can do is decided by the routes.

## Tools

| Tool | Route | Listed for |
| --- | --- | --- |
| `list_findings` | `GET /findings` (`status`, `rule_id`, `severity_id`, `limit` at most 50, `offset`) | `findings.read` |
| `get_finding` | `GET /findings/{finding_id}` | `findings.read` |
| `explain_finding` | `GET /findings/{finding_id}/explain` | `findings.read` |
| `list_finding_rules` | `GET /findings/rules` | `findings.read` |
| `list_remediations` | `GET /remediations` (`status`, `limit` at most 50, `before`) | `findings.read`, `audit.read` |
| `plan_from_finding` | `POST /findings/{finding_id}/plan` | `plans.create` |
| `list_requests` | `GET /requests` (`start`, `end`, `status`, `model`, `request_id`, `tag`, `limit` at most 50, `offset`) | `usage.read` |
| `get_rules` | `GET /rules` | `rules.read` |
| `get_privacy_settings` | `GET /settings/pii` | `settings.read` |
| `get_gateway_settings` | `GET /gateway-settings` | `settings.read` |
| `list_deployments` | `GET /model-deployments` | `deployments.read` |
| `create_plan` | `POST /policy/plans` (`body`: `changes`, `reason`; `window_days`) | `plans.create` |
| `list_plans` | `GET /policy/plans` (`status`, `limit` at most 50) | `plans.create`, `audit.read` |
| `get_plan` | `GET /policy/plans/{plan_id}`: each change's before, after, risk and impact | `plans.create`, `audit.read` |
| `apply_plan` | `POST /policy/plans/{plan_id}/apply` | `plans.apply`, `plans.apply_allowlisted` |
| `list_versions` | `GET /policy/versions` (`limit` at most 50, `before`) | `audit.read`, `plans.create` |
| `restore_version` | `POST /policy/versions/{version}/restore` (`body`: `reason`) | `plans.apply`, `plans.apply_allowlisted` |
| `propose_rules` | `POST /rules/proposals` (`body`: `sentence`, `language`, `rules` with `examples`) | `plans.create` |

Routes are under `/api/v1/management`. `tools/list` shows a tool when the caller
holds one of its permissions (an auditor key sees the thirteen read tools); listing
is a convenience, the route decides. `apply_plan` and `restore_version` carry
`destructiveHint`. A plan created through MCP by a service account has `source:
"mcp"`: the server sends `X-Shim-Channel: mcp`, a label that grants nothing and is
ignored for people.

A tool result carries the route's JSON as `structuredContent` (a list as
`{"items": [...]}`) and the same JSON as one text block. A route error (status 400
or above) is a result with `isError: true` and `structuredContent` `{"status",
...}` holding every field of the route's `detail` (`code`, `message`, `hint`, and
for `PLAN_NOT_ALLOWLISTED` the `changes` with their reasons), so the agent reads
the same code and hint a script would. Invalid arguments are `INVALID_TOOL_ARGUMENTS`
with `errors`; a call that takes longer than 30 seconds is `TOOL_TIMEOUT`; a result
over 256 KB is `RESULT_TOO_LARGE` (ask with narrower filters).

Never a tool: stored request content, provider secrets, gateway keys, members,
invitations, roles, service accounts, configuration-file mode and signing keys,
exports, and finding status changes.

## What a recommender can apply

A `recommender` account applies a plan only when every change is on the
allowlist: disabling a deployment, narrowing a key's model list, lowering a
team's limits or a budget, and moving a detection type from `off` to `monitor`
([automatic fixes](FINDINGS.md#automatic-fixes)). Anything else is
`PLAN_NOT_ALLOWLISTED` with a reason per change. Its applied changes are watched
like shim's own: `list_remediations` shows them with `actor_type: "service"`, a
rise in refusals inside the window sets them back, and only a person undoes one.
A paused tenant answers 409 `AUTO_REMEDIATION_PAUSED`, 20 unattended changes in
24 hours 429 `REMEDIATION_LIMIT`.

## Resources and prompts

- `shim://guide/agent` (markdown): what each tool is for, the order "list findings,
  explain, plan, show the impact, ask a person", how to read `PLAN_NOT_ALLOWLISTED`
  reasons and what an agent must never claim.
- `shim://guide/rules/tr` and `shim://guide/rules/en`: how to turn the user's sentence
  into concrete rules with `propose_rules`, and what to ask for each question it
  returns ([rule proposals](POLICY_DECISIONS.md#rule-proposals)).
- Prompt `write_rules` (argument `language`, `tr` by default or `en`): one `user`
  message with the rule guide in that language; another value is `-32602`.
The `initialize` and `server/discover` answers carry the same rules as
`instructions`.

## Records

`shim_mcp_requests_total{method, outcome}` (an MCP method or `other`; `ok`,
`tool_error`, `protocol_error`) and `shim_mcp_tool_calls_total{tool, outcome}` (a
tool name or `unknown`; `ok`, `error`). Logs carry the method, the HTTP status and
the duration, never arguments, results, keys or `Mcp-Name` values. Reads are not
audited, as through the API; every write is audited by its route, with
`actor_type: service` and the account's `actor_role`.
