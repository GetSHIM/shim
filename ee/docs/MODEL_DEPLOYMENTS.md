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
A hosted gateway that cannot list every tenant's host sets
`MODEL_DEPLOYMENT_ALLOWED_ORIGIN_SUFFIXES`, a JSON list of host suffixes such as
`[".openai.azure.com", ".services.ai.azure.com", ".cognitiveservices.azure.com"]`
(each lowercase, starting with a dot, with at least two labels; startup fails
otherwise). A URL is then also approved when it is `https` on port 443 and its host
ends with a suffix and is longer than it; every other check above still applies.

`deployment_kind` (`internal` or `external`) is what the tenant admin declares;
shim does not derive it. [Destination rules](POLICY_DECISIONS.md#destination-rules)
let an `internal` target see a data type an `external` one may not, so changing an
existing deployment from `external` to `internal` is a relaxation: it records
`tenant.privacy_protection_relaxed` with `relaxed: ["deployment_kind.<deployment id>"]`
and alerts the tenant's forward targets, beside the update's own before and after.
Moving an `internal` deployment to another `base_url` relaxes the same way, as
`base_url.<deployment id>`, whether or not the operator lists internal origins.
The reverse, and creating an `internal` deployment, write no relaxation. The
operator can also set `MODEL_DEPLOYMENT_INTERNAL_ORIGINS`, a JSON list of origins in
the same format as `MODEL_DEPLOYMENT_ALLOWED_ORIGINS` (empty by default, which keeps
`internal` the tenant's word). When it is set, a create or update with
`deployment_kind: internal` and a base URL outside it answers 422 "Deployment origin
is not an operator-approved internal origin", and a row stored as `internal` before
the list existed is treated as `external` for each request, recorded with the verdict
`deployment.classification` (`INTERNAL_ORIGIN_NOT_APPROVED`).

For OpenAI-compatible deployments, use the API base including `/v1`; for
Anthropic use the server root. shim uses its existing native transports, masks
configured sensitive content before forwarding, and makes one provider attempt.
There is no retry or failover unless a tenant rule asks for one; each extra attempt
is its own request with its own cost. A five-second model-list health probe records
only HTTP success/failure and never reads an unbounded response body; it uses the
credential the gateway would use, so an Entra credential sends a fresh token. For an
`azure_openai` deployment a 200 or a 404 from `/openai/v1/models` is healthy (the
resource answered and accepted the credential; Microsoft documents no v1 model
listing); anything else is unhealthy. A
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
`output_price_per_million` (both or neither), its cache prices
`cache_read_price_per_million` and `cache_write_price_per_million` (each needs the
input price; an unset cache read is priced as input), and its `context_window`. A
stated price wins over a catalog match for the upstream model name, because the
operator knows what the deployment costs; settlements and spend reservations use
it with `pricing_resolution=deployment`, with no tier. An `anthropic` deployment's
stated price writes the cache at 1.25 times the input price unless a cache write
price is set, and a one-hour write at twice the input price. A stated window is
checked before the call: a request whose prompt certainly does not fit is refused
with 400 `MODEL_CONTEXT_EXCEEDED`, which matters most where a server would truncate
it silently. Deployments get no capability check.

`price_model` names the catalog model a deployment stands for, when its upstream
name is not one: an Azure deployment `kurum-mini` serving `gpt-5.6-luna`. It must be
an exact catalog chat model of the deployment's provider (422 "price_model is not a
catalog model for this provider"). Prices come first from the deployment's own
prices, then from `price_model`'s catalog entry (with its cache prices), then from
the upstream name's entry, else the request is unpriced. `price_model` also lends
its context window, input limit and output limit when the deployment states no
window. Without a window or a `price_model`, a deployment is not checked, even
when its upstream name is in the catalog.

`upstream` is `generic` (default) or `azure_openai`. An `azure_openai` deployment
uses provider `openai`, is `external`, has a base URL whose path is exactly
`/openai/v1` (Azure's v1 API, with no `api-version`), and its `upstream_model` is the
Azure deployment name (letters, digits, `.`, `_` and `-`, at most 64 characters,
starting with a letter or digit); each rule refuses with its own 422. Its credential
is an Azure key (a provider `openai` secret) or a Microsoft Entra ID client
credential (provider `azure_entra`), which can back only an `azure_openai`
deployment, is never used for catalog routes or their spend cap, and is never
selected by a build that predates it. shim
asks Entra for a token at `SHIM_AZURE_AUTHORITY_HOST` with the credential's scope
(default `SHIM_AZURE_TOKEN_SCOPE`) and keeps it until 300 seconds before it expires;
rotating the credential starts a new token. A `PUT` that leaves out `upstream`,
`price_model` or a cache price keeps the stored value, so a client that predates
them never erases them; every other field still follows the body.

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
  reservation, with the same counts and `registered: false`. The model is the
  price-book entry the requested name matched (a dated snapshot counts under its
  family entry), `model not specified` for a Responses request that named no
  model, and `other` for a name the current price book no longer matches: the
  requested name is caller text of any length and is never an item's key.

Registry items come first, then catalog items, each by requests; at most 500
items, `truncated: true` beyond, plus totals. What the inventory cannot show:
the names of unknown models that were refused (caller-controlled text is never
recorded), and servers that receive no traffic through shim. Two findings act
on it: [`gateway.unregistered_model`](FINDINGS.md#gatewayunregistered_model) and
[`gateway.byok_usage`](FINDINGS.md#gatewaybyok_usage). The ISO/IEC 42001
readiness report lists the same catalog model names (from a names-only read)
as "Models in traffic outside the registry", so the two never disagree.

## Retiring models

`GET /api/v1/management/model-retirements?days=90` (owners, admins and auditors;
`days` 1 to 730) lists every model with a retirement date at most `days` away, or
already past, that the organization used in the last 30 days or has registered:
`provider`, `model`, `retires_on`, `deprecated_on`, `replacement`, `source`,
`checked_on`, and `affected` with the API keys (id, name, requests, last used), the
teams (id, requests) and tags, at most 100 of each with the busiest first, and
the registry aliases whose `upstream_model` it is. A request counts under the date
entry its model matched, never under the caller's own text. It reads one aggregate
over `request_lifecycle` by `started_at`, only for the model names that can match
an entry retiring within `days`, plus the registry.

Catalog dates ship with shim. An on-prem or self-hosted model has no provider date,
so the operator adds one in `SHIM_MODEL_LIFECYCLE_FILE` under the `registry` key,
with the alias as the model name:

```json
{"format": "shim.model.lifecycle", "version": 1,
 "models": {"registry": {"internal-llm": {"retires_on": "2027-03-31",
   "replacement": "internal-llm-v2", "source": "https://wiki.example.com/llm",
   "checked_on": "2026-10-11"}}}}
```

A request to that alias then carries `MODEL_RETIRING` within 90 days of the date. An
alias without its own entry inherits its upstream model's date.
## Cold starts and timeouts

A model server that unloads an idle model loads it again on the next request,
which then waits: sometimes seconds, sometimes past the deployment's
`timeout_seconds` (1 to 300), when it ends as a timeout. The finding
[`gateway.cold_start`](FINDINGS.md#gatewaycold_start) names a deployment where
requests after a quiet spell of at least 10 minutes come back late or time out;
[`gateway.queueing`](FINDINGS.md#gatewayqueueing) names one whose streams wait at
busy hours. `GET /api/v1/management/latency?group_by=deployment` shows the first
byte, queue time, output speed and peak concurrency per hour. shim does not change
a server's keep-alive or a deployment's timeout by itself.

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
