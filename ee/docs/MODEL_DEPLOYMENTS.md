# Model deployments

Workspace owners and admins register models at **Gateway → Model deployments**
or `/api/v1/management/model-deployments`. Create a stored provider credential
first. The registry stores its tenant-scoped identifier, never credential text.
A deployment has a stable UUID, gateway alias, upstream model, protocol, base
URL, timeout, internal/external classification, owner and declared version.
Updates and health checks produce management audit events.

Set `MODEL_DEPLOYMENT_REQUIRED=true` for registry-only inference. With `false`,
registered aliases override public-catalog routing. Disabled aliases remain
denied. Gateway-key model allowlists use tenant aliases; unknown aliases cannot
be assigned. Registry-routed Responses requests must include the gateway alias,
including continuations with `previous_response_id`; the continuation identifier
does not select a deployment. Restrict each key to the models its workload needs. Registry
checks cover requests passing through shim, not direct access to other servers.

The platform operator sets `MODEL_DEPLOYMENT_ALLOWED_ORIGINS` to a JSON list of
exact scheme/host/port origins, for example `["https://models.internal:8443"]`.
API users cannot expand this policy. URL credentials, queries, fragments,
metadata addresses and redirects are rejected. Internal HTTP origins require
explicit approval; use HTTPS in production. Add private certificate authorities
with `OUTBOUND_CA_BUNDLE` (the earlier name `MODEL_DEPLOYMENT_CA_BUNDLE` is still
read); certificate verification stays enabled.
Enforce DNS and outbound network policy at the deployment boundary as well.

For OpenAI-compatible deployments, use the API base including `/v1`; for
Anthropic use the server root. shim uses its existing native transports, masks
configured sensitive content before forwarding, and makes one provider attempt.
There is no retry or failover. A five-second model-list health probe records
only HTTP success/failure and never reads an unbounded response body. A
deployment marked `unhealthy` receives no traffic for 300 seconds from that
check: requests for its alias get 503 `DEPLOYMENT_UNHEALTHY` with `Retry-After`
set to the seconds left and `x-should-retry: false`, and it leaves `/v1/models`.
The mark ends sooner when a health check marks it healthy or an update resets it
to `unknown`. After 300 seconds the deployment serves again and the per-tenant
provider circuit breaker protects callers if it is still failing; a mark without
a check time never refuses traffic. To keep traffic away for longer, disable the
deployment (`enabled: false`). Nothing is routed to another deployment or to the
public catalog instead, and no probe runs automatically.
Health is not a version-verification guarantee.

The declared version/hash/digest is operator supplied and included in the
registry policy evidence. Pin the actual serving image and model revision at
the model server; shim does not independently attest which weights it serves.

A deployment may state its own price, `input_price_per_million` and
`output_price_per_million` (both or neither), and its `context_window`. A
stated price wins over a catalog match for the upstream model name, because the
operator knows what the deployment costs; settlements and spend reservations use
it with `pricing_resolution=deployment`, with no tier and no cache prices. A
stated window is checked before the call: a request whose prompt certainly does
not fit is refused with 400 `MODEL_CONTEXT_EXCEEDED`, which matters most where a
server would truncate it silently. Without a window a deployment is not checked,
even when its upstream name is in the catalog, and deployments get no capability
check.

Without a stated price, public catalog prices apply to recognized upstream model
names. Other custom models are explicitly unpriced: ledger arithmetic uses a zero
placeholder with `pricing_resolution=unknown`, and usage reports carry
completeness counters. A monetary provider limit rejects unpriced inference
instead of treating it as free. Token and request quotas still apply.

## The inventory

`GET /api/v1/management/model-inventory?start=…&end=…` (owners, admins and
auditors; default the last 30 days, at most 31) puts the registry and the
traffic side by side. It is built from the gateway's own request records, not
kept by hand:

- one `registry` item per registered deployment, enabled or not, with its
  requests in the window (by the deployment id each request recorded, or for
  older rows by the alias), first and last request, distinct API keys and teams,
  and `byok_requests` (requests that carried their own provider key);
- one `catalog` item per provider and model that requests reached through the
  provider's public endpoint (`deployment_kind: unknown`) after spend
  reservation, with the same counts and `registered: false`.

Registry items come first, then catalog items, each by requests; at most 500
items, `truncated: true` beyond, plus totals. What the inventory cannot show:
the names of unknown models that were refused (caller-controlled text is never
recorded), and servers that receive no traffic through shim. Two findings act
on it: [`gateway.unregistered_model`](FINDINGS.md#gatewayunregistered_model) and
[`gateway.byok_usage`](FINDINGS.md#gatewaybyok_usage). The ISO/IEC 42001
readiness report lists the inventory's catalog models as "Models in traffic
outside the registry", so the two never disagree.

## Idle deployments

An internal deployment that served between 1 and 299 requests in 30 days raises
the low-severity finding `gateway.idle_internal_deployment`; one with no
requests raises `gateway.unused_deployment`. Traffic is attributed by the
deployment id each request records, so renaming an alias keeps its history. See
[findings](FINDINGS.md#gatewayidle_internal_deployment).

## Verified compatibility

`uv run --locked python -m pytest -q ee/tests/tenants/test_deployments.py`
uses the actual provider SDK over a mock HTTP transport, two distinct endpoint
origins and PostgreSQL accounting. It verifies OpenAI Chat Completions and
Responses JSON/SSE, upstream model selection, tenant-scoped credentials,
privacy, one-attempt errors, isolated endpoint circuits, model restrictions and
unpriced spending limits. A deployment's circuit is per tenant: two tenants that
register the same base URL do not share failures. Health tests exercise the bounded model-list probe.

These checks establish shim's wire behavior. They do not certify every vLLM,
NIM, TGI or Ollama version. Run the same request families against each selected
serving version before enabling it; unsupported protocol capabilities return
native errors rather than an emulated result.

## Anthropic token counting

`POST /v1/messages/count_tokens` preserves Anthropic's native request/response
and beta forms. It uses the same gateway authentication, model permissions,
RPM/TPM limits and privacy transformation as Messages. Counts describe the
transformed payload that would be sent upstream, not the original sensitive
text. Counting has a separate repeat identity from inference. Streaming is not
supported by this endpoint.

Token counting makes one nonbillable provider request. It persists audit preflight before forwarding and an audit
completion/outbox intent with `operation_type=token_count` and
`billable_execution=false`; it never reserves billable quota or provider spend,
starts an inference lifecycle, or creates a settlement. Community mode leaves
its billable JSONL usage stream unchanged. Strict enterprise audit mode fails
closed before forwarding if preflight cannot be persisted, and returns an error if
completion persistence fails after the response.

Run `uv run --locked python -m pytest -q tests/gateway/test_token_count.py
 ee/tests/tenants/test_deployments.py` to check native SDK routing, privacy,
errors and durable nonbillable accounting. Registry tests also exercise
Anthropic Messages JSON and SSE.
