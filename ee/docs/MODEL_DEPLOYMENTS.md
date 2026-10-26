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

The egress guard (`SHIM_EGRESS_GUARD`) lets the gateway and its workers resolve the
hosts of these origin lists and suffixes, and of the AWS URL templates. Every
deployment's base URL has to match them, so a deployment needs no entry in
`SHIM_EGRESS_ALLOW_HOSTS`. See [supply chain](../../docs/SUPPLY_CHAIN.md#process-guards).

For OpenAI-compatible deployments, use the API base including `/v1`; for
Anthropic use the server root. shim uses its existing native transports, masks
configured sensitive content before forwarding, and makes one provider attempt.
There is no retry or failover unless a tenant rule asks for one; each extra attempt
is its own request with its own cost. A five-second model-list health probe records
only HTTP success/failure and never reads an unbounded response body. A transport
error or a timeout is tried once more (a first call can spend its five seconds on a
cold connection); an HTTP status is not. A failed check logs a WARNING with the
deployment id and the reason (the status, or the error type). The probe uses the
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
public catalog instead unless the tenant wrote a [fallback rule](#fallback-rule), and
no probe runs automatically.
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

`aws_bedrock` reaches Amazon Bedrock in `aws_region` (such as `eu-central-1`)
through its own Anthropic-native and OpenAI-compatible routes, executed exactly as
the other deployments: a client speaks Anthropic Messages or OpenAI Chat to shim and
Bedrock answers in the same format, streams and errors included. There is no
Converse or InvokeModel translation and no `bedrock-mantle`. Rules, each its own 422:

- provider `anthropic` (Bedrock's `/anthropic` route) or `openai` (its
  `/openai/v1` route, for OpenAI's open models, Mistral, Qwen and others);
  `deployment_kind` `external`;
- `base_url` is derived: `AWS_BEDROCK_RUNTIME_URL_TEMPLATE` for the region plus
  `/anthropic` or `/openai/v1`, checked against `MODEL_DEPLOYMENT_ALLOWED_ORIGINS` or
  the suffix list (`.amazonaws.com`); a client-sent `base_url` that differs is
  refused, and changing the region or provider moves it;
- `upstream_model` is a model id (`anthropic.claude-...`, `openai.gpt-oss-120b-1:0`),
  a system inference profile id (`eu.anthropic.claude-sonnet-4-5-20250929-v1:0`), or
  their ARN; an application inference profile serves the anthropic format only;
- the credential's `provider` is an AWS one, which serves only the Bedrock
  deployments that name it, of either format (a build that predates Bedrock never
  selects it): `aws_access_key` (a long-term `AKIA` key pair; shim mints a
  short-term Bedrock API key from it locally, for the deployment's region, valid one
  hour and replaced 300 seconds early, so no AWS call happens on the request path) or
  `aws_bedrock_api_key` (a long-term Bedrock API key, used as it is), or
  `aws_role` (a role in the tenant's AWS account: shim stores its ARN and nothing
  secret, assumes it with the tenant's external id for at most an hour, and mints
  the Bedrock key from that session; see [connect Bedrock with an AWS
  role](COOKBOOK.md#connect-bedrock-with-an-aws-role)).

Token counting is not available for Bedrock deployments: `count_tokens` answers 400
`MODEL_CAPABILITY_UNSUPPORTED` before any call. The health check reads the model
(`GET /foundation-models/{id}`) or the inference profile (`GET
/inference-profiles/{id}`, for an id with two dots before any `:` or a profile ARN)
on `AWS_BEDROCK_CONTROL_URL_TEMPLATE` with the Bedrock key; 200 is `healthy`.
Bedrock prices follow the calling region and the profile type (global profiles cost
about 10 percent less than geographic ones), so enter the deployment's prices,
including the cache read and write prices Bedrock bills separately; `price_model`
gives only an approximation. The three AWS URL templates
(`AWS_BEDROCK_RUNTIME_URL_TEMPLATE`, `AWS_BEDROCK_CONTROL_URL_TEMPLATE`,
`AWS_STS_URL_TEMPLATE`) are operator settings for VPC interface endpoints and tests:
an absolute http(s) URL with no path, query or credentials and at most one
`{region}`; startup fails otherwise. Their hosts are never tenant input. A `PUT`
that leaves out `upstream` and `aws_region` keeps both.

**Where a Bedrock deployment can route.** An inference profile routes to several
regions, and its prefix alone does not say which (AWS: "Don't rely on the
geographic prefix"). shim stores the deployment's destinations
(`aws_destination_regions`): its own region for a model id, otherwise the regions
of `GetInferenceProfile`'s model ARNs, read on create, when the region or model
changes, and on every health check; `null` while Bedrock does not say. It is read
with no transaction open and without the tenant lock that every request of the
tenant waits on; a policy write that lands during an update's read answers 409
`POLICY_VERSION_CHANGED` (send the update again). The view
also shows `aws_profile_scope`: `in_region` for a model, else the profile prefix
(`eu`, `us`, `apac`, `global`).

**The region lock** is the gateway setting `bedrock_region_lock`: `mode` (`off`,
`monitor`, `enforce`), `scopes` (allowed profile prefixes or `in_region`; empty
allows any) and `regions` (region codes or geography prefixes such as `eu`;
every destination must equal one or start with one followed by `-`; empty allows
any, and unknown destinations fail a non-empty list). It is checked before any AWS
call: `monitor` records `aws.region_lock` `BEDROCK_REGION_OUTSIDE_LOCK` and lets
the request through, `enforce` answers 403 `BEDROCK_REGION_NOT_ALLOWED`, and
creating or moving a deployment the enforced lock refuses answers 422 with that
code. `GET /api/v1/management/aws/region-lock/preview` (`settings.read`, optional
`mode`, `scopes`, `regions`) shows, per Bedrock deployment, what a lock would do
and how many requests it served in the last 7 days. A tier's
`features.provider_policy.allowed_regions` is the operator's ceiling for Bedrock:
always enforced, unknown destinations refused; no shipped tier sets it. Under four
eyes, a change of `mode` alone decides its direction (`off` < `monitor` <
`enforce`), whatever the lists do in the same change; with the mode kept and on, a
narrower list tightens and a wider or emptied one relaxes.

Without a stated price, public catalog prices apply to recognized upstream model
names. Other custom models are explicitly unpriced: ledger arithmetic uses a zero
placeholder with `pricing_resolution=unknown`, and usage reports carry
completeness counters. A monetary provider limit rejects unpriced inference
instead of treating it as free. Token and request quotas still apply.

## Routing rules

A tenant [route rule](POLICY_DECISIONS.md#route-rules) can serve a conversation from
another registered alias of the same provider than the one the client names, chosen
from the conversation's first turn: its length, tools, media, structured output or
keywords. The resolver applies it after the client's alias passed its own checks
(key allowlist, enabled, provider, health, origin) and checks the target the same way;
a target the key may not use or that cannot serve leaves the request on the client's
alias. The client's model name stays the requested model in records; the answer's
`model` is the target's upstream model. What is never routed: token counting,
embeddings, and Responses requests the provider stores (`store` not `false`, or a
`previous_response_id` or `conversation`), since that conversation's state lives where
it started. New route rules start in `monitor`, which only records where a request
would have gone. Recipe: [Send simple requests to a cheaper model](COOKBOOK.md#send-simple-requests-to-a-cheaper-model).

## Fallback rule

A route rule with `match.on: "unavailable"` names what serves an alias when its
deployment cannot: `from` is one registered alias, `to` one or two others of the same
provider, tried in order (never `from`, never a catalog model), and `triggers` says
when:

| Trigger | When | Decided |
|---|---|---|
| `health_flag` | `from` is marked `unhealthy` | before the call, one attempt |
| `circuit_open` | the tenant's circuit for `from` is open | before the call, one attempt |
| `provider_error` | the attempt failed with 500, 502, 503 or 504, a timeout or a connection error | after the call, a new attempt |
| `rate_limited` | the provider answered 429 | after the call, a new attempt |

No other 4xx triggers, a disabled `from` is still refused with 403, and a token count
(`/v1/messages/count_tokens`) for an unhealthy `from` is refused with 503 as before: it
never reaches the step that moves a request. The rule's scope is read at `from`, so a
rule scoped by `models` or `deployment_kinds` tries its second `to` too. A tenant
holds at most one `unavailable` rule per alias; the rules PUT refuses an unknown or
cross-provider alias, a third `to` and an empty `triggers` with 422 and the field path.

Before the call, an enforced rule takes the request to the first `to` the key may use
and that can serve (enabled, not unhealthy, approved origin, never Bedrock): one
provider call, one row, `X-Shim-Request-Id` its id, and `route_decision` with
`reason: "fallback"`. After a failed call, the next `to` not yet tried runs as its
own attempt (`X-Shim-Attempts`, rows linked by `attempt_group_id`, one request
unit). The failed one is refunded when the provider refused it, and settled at its
reservation when the provider started it and gave no usage. Streams fall back only
before their first byte and never as a Responses continuation. A request leaves an
`internal` deployment for an `external` `to` only when nothing was detected in it
and no privacy rule matched; otherwise that `to` is skipped with
`ATTEMPT_WOULD_LEAVE_INTERNAL`.

When no `to` is usable, an unhealthy alias still answers 503 `DEPLOYMENT_UNHEALTHY`
with the same body and headers, but after admission: the request used its share of
the rate window and has a refunded row. An open circuit answers 503
`PROVIDER_UNAVAILABLE` as before. The answer comes from the deployment the tenant
named; when that is another model, the tenant chose it. A client's Anthropic beta
`fallbacks` field is a different thing, left untouched and still priced at the
requested model, so a provider-side fallback to a dearer model is under-priced.

A `monitor` rule never changes the target or adds an attempt. It records where the
request would have gone, verdict `RULE_WOULD_ROUTE`, from what the request actually
met: on the refusal's audit event for an unhealthy alias, on the failing row for an
open circuit or a provider error. The 7-day preview cannot replay health or circuit
state, so it answers "start in monitor". The circuit is read only for an alias an
enforced rule covers with `circuit_open`; without a rule nothing is read. Evidence:
[the record](POLICY_DECISIONS.md#fallback-rules). Recipe:
[Add a fallback rule](COOKBOOK.md#add-a-fallback-rule).

## Roll out a new model gradually

A route rule with `match.on: "split"` sends a share of one alias's conversations to
another alias of the same provider: `from` the stable alias, `to` the candidate,
`share_percent` 0 to 100 (one decimal), `fallback_to_stable` false by default. An
`internal` alias never splits to an `external` one, since a split moves every kind of
request; an alias has at most one split, and a split's `to` is never another split's
`from`. While an alias is under an enforced split, its long-request lane and
request-start route rules do not run; a `monitor` split never changes the target, so
they decide as without it.

Each request's bucket is `sha256("<tenant id>|<rule id>|<identity>")`, its first eight
hex digits as a number, modulo 10,000; the request goes to `to` when the bucket is below
`share_percent × 100`. The identity is the `X-Shim-Conversation-Id` header (at most 128
characters), else `key:<gateway key id>`, so without the header every conversation of
one key lands on one side; send the header, on every turn, for a finer split. Nothing
is stored: the same conversation always lands on the same side, raising the share keeps
every conversation already on `to` there, and lowering it moves only the top buckets
back. A Responses chain stays on its side only while its turns carry the same identity
and the share stays: raising the share moves the conversations of the new buckets to
`to` mid-chain, so their next `previous_response_id` turn gets the provider's "not
found", as a rollback does for chains that started on `to`.

Enforced, the candidate is checked as a direct request to it would be (enabled, not
unhealthy, approved origin, in the key's allowlist) and, for an internal `from`, still
internal at run time; one that cannot serve leaves the request on `from` with the reason
in `held`. A candidate call that fails is the split's to answer: a fallback rule on
`from` does not take it. Still one provider call; with
`fallback_to_stable`, a candidate call that fails before its first byte with 500, 502,
503, 504, a timeout or a connection error gets one more attempt on `from`
(`attempt_reason: "canary_fallback"`, `X-Shim-Attempts: 2`). In `monitor` every request
is served by `from` and the row says which side it would have had.

`POST /api/v1/management/canaries/{rule_id}/rollback` (`rules.write`) sets the share to
0 in one applied policy plan, reason "canary rollback", and returns the new policy
version; changing only a split's share is neutral, so [four eyes](POLICY_DECISIONS.md#four-eyes)
never holds it. 404 for an unknown rule, 409 for a rule that is not a split. Undo it by
restoring the version before it. A Responses chain that started on `to` gets the
provider's "not found" for its next turn after a rollback. `GET
/api/v1/management/canaries?hours=24` (`usage.read`, 1 to 744 hours) shows each split
rule (at most 50) with, per side, the requests of the window, their completion
outcomes, failed rows (`provider_error`, `timeout`, `failed`), p50 and p95 of
`shim_latency_ms` and `ttft_ms`, the settled cost and cost per request (null when a row
of that side is unpriced), and in `monitor` the would-move count. Rows are attributed by
the side that served them. Recipe: [Roll out a new model to a share of conversations](COOKBOOK.md#roll-out-a-new-model-to-a-share-of-conversations).

## Long-request lane

A route rule with `match.on: "size"` sends an alias's long requests to a replica of the
same model: `from` the alias, `to` the lane, `min_input_tokens` 256 to 10,000,000. The
lane must have the provider, the upstream model and the kind (`internal` or `external`)
of `from`: it is the same model on its own server, not another model or another
residency (sending long requests to another model is a [route rule](#routing-rules)).
One lane per alias.

The measure is admission's TPM unit for text: the UTF-8 bytes of the compact JSON
request, divided by four and rounded up, computed only for an alias that has a lane.
Inline images and files count as their encoded bytes here (the lane is chosen before
admission sizes media by parts), so a request carrying them reaches the threshold sooner. At or above
the threshold an enforced rule sends the request to the lane, checked as a direct
request to it (enabled, not unhealthy, approved origin, in the key's allowlist, still
of the kind of `from` at run time); a lane that cannot serve leaves it on `from` with
the reason in `held`. One provider call, one
row, `route_decision` with `reason: "long_request"` and `input_tokens_approx`; a
request below the threshold gets nothing, and a long request is served by its lane
alone (request-start route rules do not run for it), and a fallback rule on `from`
does not move it again. In `monitor` every request is served by `from`, a long one
records the lane it would have used, and route rules decide as without the lane. A conversation
whose history grows past the threshold moves to the lane once and stays there while it
keeps growing; a model server's prefix cache is per replica, so that one turn misses
it. The 7-day preview cannot count past sizes, so it answers "start in monitor".
Recipe: [Give long requests their own replica](COOKBOOK.md#give-long-requests-their-own-replica).

## Test a model change on live traffic

A route rule with `match.on: "shadow"` copies a share of an alias's requests to a
candidate alias after the caller's answer is complete, and compares the two answers
in memory. The caller always gets the answer of the model it asked for; nothing is
moved (that is a [split](#roll-out-a-new-model-gradually)) and nothing is replayed:
shim keeps no prompts to replay, and live copies need none.

```json
{"id": "llama4_degisiklik", "name": "Llama 4 change test", "kind": "route", "action": "route",
 "state": "monitor", "scope": {"tags": ["mobil"]},
 "match": {"on": "shadow", "from": "kurum-llama", "to": "kurum-llama-4", "share_percent": 10,
           "starts_at": "2026-11-02T00:00:00Z", "ends_at": "2026-11-09T00:00:00Z",
           "max_requests": 1000, "max_cost_usd": "50"}}
```

`from` and `to` are registered aliases of one provider (an `internal` alias is never
copied to an `external` one), `share_percent` 0.1 to 100 with one decimal, a window of
at most 31 days that ends in the future when the test is new or changed, `max_requests`
1 to 100,000 and `max_cost_usd` 0.01 to 100,000. One test per alias, ten per set. A
test is its rule id and `starts_at`: a new `starts_at` starts a new test with fresh
counters. In `monitor` nothing is copied and `GET /api/v1/management/change-tests` shows
a 7-day estimate of the copies and their extra cost at the candidate's price (the
rule's preview counts the same); enforcing is relaxing for four eyes, since masked
request data goes to one more deployment and the tenant pays for it.

Enforced, a request to `from` in scope and in the window is copied when the hash of the
rule id and request id falls in the share (one copy per request at most). The copy
follows the core shadow guards: never a token count, a Responses continuation or a
stored Responses request, only after a completed answer, the masked payload with the
bands re-run for the candidate, the key's model allowlist applied, no copy when an
enforced privacy rule would act at the candidate and not at `from` (it never saw the
payload). The copy is its own row (`shadow_of`), with its own cost, which is the
tenant's; it uses no request unit. Caps count the copies sent, after those guards, in
Redis seeded from the ledger, so a test may overshoot
`max_requests` or `max_cost_usd` by the copies already in flight
(`SHADOW_MAX_IN_FLIGHT` per gateway process); without Redis no copy is made. Each
skipped copy counts in `shim_change_test_skips_total{reason}`.

The comparison writes `shadow_comparison` on the copy's row: per side the outcome,
schema validity (always checked), language and soft refusal (when the tenant's
analyzers are on), answer length, tokens, latency and cost; never text, and after a
request with personal data no answer is analysed. `GET
/api/v1/management/change-tests/{rule_id}` (`usage.read`, a window of at most 31 days,
the test's by default) reads the outcome mix, schema rates, length ratios, latency and
cost per side with fixed caveats; `POST /api/v1/management/change-tests/{rule_id}/stop`
(`rules.write`) moves the rule to `monitor` in one tightening policy version, undone by
restoring the version before it. Recipe:
[Test a model change before switching](COOKBOOK.md#test-a-model-change-before-switching).

Change tests, canaries and route rules can be written up as a
[model evidence document](POLICY_DECISIONS.md#model-evidence-documents).

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

## Hardware cost and capacity

An internal deployment's hardware costs money every month whether it is called or
not. Enter that cost per month in its own currency: `PUT
/api/v1/management/model-deployments/{id}/hardware-costs/{YYYY-MM}` with `amount`
(above 0, 2 decimals), `currency` (three capital letters, such as `TRY` or `USD`)
and an optional `note` (`deployments.manage`; internal deployments only, else 422).
`DELETE` the same path removes it, `GET .../hardware-costs` lists them
(`deployments.read`); each write is audited as `tenant.deployment_hardware_cost_set`
or `_deleted` with the amount and currency before and after.

`GET /api/v1/management/cost/hardware?period=YYYY-MM` (`usage.read`; the current
month or one of the last 24) shares each cost out by tokens (input plus output) of
the requests the deployment served that month, per API key and per team.
Amounts are rounded to cents so they add up exactly to the entered amount (the
leftover cents go to the largest remainders, ties to the smaller key id). A month
with no entry uses the latest entry of the 12 months before (`carried_from`); a
deployment with a cost and no tokens shows the whole amount as `unattributed`.
Totals are given per currency and never added across currencies; no exchange rate
is applied. Requests are matched by the `deployment_id` recorded at reservation, so
renaming an alias keeps its history; `attributed_since` says from when the month is
covered. It is a report: no settlement, budget, quota or spend limit changes.

`capacity_concurrent_requests` (1 to 100,000) is how many requests the hardware
holds at once, as you state it; a `PUT` that leaves it out keeps it.
`GET /api/v1/management/capacity/forecast` (`usage.read`) takes, per internal
deployment over the last 56 days, each hour's average number of requests in flight
(request durations from the provider's start to completion or failure, counted in
the hour they started), each day's busiest hour, and the straight-line trend of
those days. A day without traffic since the deployment was created counts as 0; days
before it existed are left out. It answers `days_with_traffic`, `current_peak` (the busiest hour of the
last 7 days), `slope_per_day`, `capacity` and, when the trend reaches the capacity
within 365 days, `projected_date`, with a `status`: `not_enough_data` (fewer than 14
days with traffic), `no_capacity`, `at_capacity`, `not_growing`, `projected` or
`beyond_horizon`. It measures busy-hour average concurrency from gateway records;
instantaneous peaks are higher.

## Server metrics

The model server knows what the gateway cannot: how many requests it runs now,
how many wait in its queue, and how full its cache is. List internal deployments in
the gateway setting `inference_metrics` (each `deployment_id`, `server` `vllm`,
`tgi` or `ollama`, `send_credential`; at most 64, one per deployment; a PATCH
replaces the list) and the reconciliation worker reads them every
`INFERENCE_METRICS_INTERVAL_SECONDS` (default 60, 15 to 3,600).

- **Where.** The deployment's own approved origin plus a fixed path: `/metrics`
  for vLLM and TGI, `/api/ps` for Ollama. Never a tenant-given URL; an origin that
  is no longer approved is not read (`origin_not_approved`). One GET, no redirects,
  no proxy from the environment, the operator's CA bundle, 5 seconds, at most 1 MiB,
  at most 8 servers at once, and a pass deadline of `min(50 s, interval - 5 s)`. With
  no deployment listed the worker sends no request at all.
- **Credential.** Only with `send_credential`: the deployment's stored key as
  `Authorization: Bearer`. vLLM's `/metrics` is outside its `--api-key` prefixes and
  needs none. A 401 or 403 records `unauthorized`; a key the secret store cannot
  return records `credential_unavailable`, and the server is not read without it.
- **What is kept.** vLLM: `vllm:num_requests_running`, `vllm:num_requests_waiting`
  (summed over models) and `vllm:kv_cache_usage_perc` (or the older
  `vllm:gpu_cache_usage_perc`; the highest, at most 1). TGI: `tgi_batch_current_size`
  and `tgi_queue_size`. Ollama: whether the deployment's `upstream_model` is loaded,
  and its VRAM; Ollama reports neither running nor waiting requests. Every other
  line of a page, model names and label values included, is never stored or logged.
- **How.** Hourly aggregates per deployment (samples, busy and queued samples, sums
  and maxima, errors and the last error), kept 90 days; no raw series.

`GET /api/v1/management/inference-metrics?hours=24` (`deployments.read`, 1 to 744
hours) shows, per listed deployment, the last read and its error, the busy and
queued shares, running and waiting averages and peaks, cache use, Ollama's loaded
share and VRAM, and `utilisation` (average running over the entered capacity).
The [capacity forecast](#hardware-cost-and-capacity) gains `measured_peak` and
`measured_capacity` (the concurrency of the busiest hour in which the server
queued); without an entered capacity it uses the measured one
(`capacity_source: "measured"`). Two findings read the same rows:
[`gateway.idle_inference_capacity`](FINDINGS.md#gatewayidle_inference_capacity)
and [`gateway.inference_queue_saturated`](FINDINGS.md#gatewayinference_queue_saturated).

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
