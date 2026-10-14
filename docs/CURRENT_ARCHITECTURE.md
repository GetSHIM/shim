# shim current architecture

Status: current implementation contract

Last verified: 2026-10-07

This document describes the code in this branch. When it disagrees with prose,
use this order of authority:

1. tests and the three checked-in OpenAPI documents;
2. `architecture/module_ownership.toml` and `architecture/route_profiles.toml`;
3. runtime code under `src/shim`, `ee/src/shim_enterprise`, and `ee/cloud/src/shim_cloud`;
4. this document and the developer guide.

## Product and dependency shape

shim is a package-modular monolith with three application compositions and one
lockfile.

```text
public/community region                    enterprise region

shim-gateway                               shim-enterprise
src/shim                                   ee/src/shim_enterprise
    ^                                              |
    +----------------------------------------------+
                 exact, allowlisted imports

shim-cloud (ee/cloud/src/shim_cloud) -> shim-enterprise -> shim
Forbidden: reverse imports; community/on-prem -> cloud/Polar
```

| Product | Runtime | State |
| --- | --- | --- |
| Community | `shim.application:create_community_app` | Bounded in-process state and local JSONL usage events |
| Enterprise | `shim_enterprise.application:create_enterprise_app` | PostgreSQL truth, Redis acceleration, managed secrets, outbox, and workers |
| Hosted cloud | `shim_cloud.application:create_cloud_app` | Shared enterprise state plus isolated cloud commerce operations |

The community package has no ORM, Alembic, Redis, Supabase, or managed-secret
dependency. Enterprise imports community contracts and implementations; it does
not fork the provider gateway.

## Request flow

All products share the same inference hot path:

```text
provider-native HTTP request
        |
        v
route validation + gateway authentication
        |
        v
GatewayService
  credential lifetime and safe error mapping
        |
        v
GatewayKernel
  policy -> admission -> privacy -> rules -> settings band -> transform band
         -> provider start
         -> one SDK attempt -> restore -> finalize
        |
        v
provider-native JSON or SSE response
```

Provider-owned JSON remains open-ended. shim validates the routing, privacy,
and accounting fields it consumes, then uses the official provider SDK or
native Gemini transport. It does not introduce a canonical cross-provider
request model.

Outbound SDK retries are disabled. One admitted shim request makes at most one
billable provider attempt, unless a tenant-written rule adds attempts. The kernel
takes an optional `AttemptPolicy` (`src/shim/gateway/kernel/attempts.py`); community
passes none. The policy may choose the request's target after privacy, before the
bands (same row and request id, recorded as `route_decision`), and, after a
`ProviderCallError` or an answered JSON attempt, name a target for one more attempt.
Each extra attempt is its own request: a new request id and start, the same privacy
outcome and admission, the bands run again for its target from the masked payload
before the bands, a usage reservation (rate limits and the repeat detector never see
it) that takes the client request's one request unit only when no earlier attempt was
answered (`AttemptInfo.counted`), its own spend reservation and settlement, and the
`attempt_group_id`, `attempt_number`, `attempt_reason` and `attempt_rule_id` of its
row. Core guards skip a target with a `gateway.attempt` verdict: at most
`MAX_ATTEMPTS` (3), never from an internal deployment to another kind when the
request carried personal data or a privacy rule match (term, pattern, record set,
destination), never to a target for which an enforced mask, block or approval rule
of a privacy kind is in scope that was not in scope for the target privacy ran for
(`ATTEMPT_DESTINATION_CHANGED`: privacy ran once, for the first target), never off
the deployment a Responses continuation is pinned to, never without a stored
credential after a BYOK key was consumed. An extra attempt starts without the pin
matches and answer warnings of the one before it, since its bands and answer run
again; a cancelled start gives back its row and its lease. A stream is never offered once it has started. The client sees the serving
attempt's `X-Shim-Request-Id` and, when more than one ran, `X-Shim-Attempts`; an
answered attempt a later one supersedes is settled and never returned.

The kernel also takes an optional `ShadowSender` (`src/shim/gateway/kernel/shadow.py`;
none in community, none in enterprise until a tenant feature supplies one). Right
before the provider call it may select the request for a copy: never a token count,
a Responses continuation or a Responses request whose `store` is not `false`. Only
after the serving attempt settled `completed`, and only after the caller's answer is
complete (after the JSON body is sent, after a stream's finalization), a background
task registered with the postprocessor asks for a candidate target, checks that it is
internal or of the primary's kind, has a stored credential and brings no privacy rule
into scope that the primary's privacy did not apply (the same check as
`ATTEMPT_DESTINATION_CHANGED`), and sends the same masked payload, bands re-run for
the candidate, without the caller's provider key. The copy is its own request
(`shadow_of`), reserves no request unit, never passes the admission stage, never adds
to the caller's task cost, and is settled with its own cost; then the sender compares
both answers in memory. At most `shadow_max_in_flight` copies run per process
(enterprise `SHADOW_MAX_IN_FLIGHT`, 1 to 64, default 4); more are dropped. Each copy
runs under `SHADOW_RUN_SECONDS` (600) from the candidate lookup to the comparison. A
copy's failure or timeout is logged by type and counted in `shim_shadow_copies_total`
(`failed`), never raised; `drain()` at shutdown cancels a copy still running and
fails it.

Admission may also hold or refuse work for capacity through the
`ConcurrencyLimiter` port (`src/shim/gateway/concurrency.py`), the only place that
does: after the rate, repeat and task checks and before the usage reservation it
acquires a lease for the request's target (tenant, provider, base URL) sized
`ceil(input bytes / 4)` plus the resolved output, waiting at most the configured
time. A refusal is 429 `CONCURRENCY_LIMITED` with `Retry-After` (or
`x-should-retry: false` when the work can never fit) and the request is rejected
without a reservation. The lease is released exactly once on every terminal: after a
JSON postprocess, in a stream's finalizer (heartbeats renew it), on every error after
admission; an S57 move takes room on the new target first, without waiting, and a
refusal skips the move (`ATTEMPT_TARGET_SATURATED`); a move to the same target keeps
the room it holds; a shadow copy asks with priority
`low` and is dropped when full. Community offers a one-process adapter
(`SHIM_CONCURRENCY_TOKEN_LIMIT`), off by default; enterprise passes none yet.

## Community composition

`src/shim/application.py` constructs the community application explicitly:

```text
create_community_app
|-- LocalAuthenticator
|-- LocalRequestPolicyResolver
|-- InMemoryRateLimiter and InMemoryLoopDetector
|-- InMemoryCircuitBreaker
|-- InMemoryPrivacyContinuationStore
|-- LocalUsageLifecycle -> redacted JSONL
|-- OpenAI, Anthropic, and Google executions
`-- community routes, /health, and /metrics
```

Community mode requires no external state service. Process loss can discard
rate, circuit, continuation, and local-event state. Missing referenced privacy
state fails closed. Unknown catalog prices remain nullable rather than guessed.

`SHIM_API_KEY` is optional on loopback and required for a non-loopback bind.
Browser CORS is disabled in keyless mode. Provider credentials resolve from an
invocation header first and the matching environment variable second.

## Enterprise composition

`ee/src/shim_enterprise/application.py` constructs the enterprise application
from the same public kernel and provider executions:

```text
create_enterprise_app
|-- DatabaseGatewayAuthenticator and tenant policy
|-- Redis admission, loop, circuit (per tenant and target), and continuation adapters
|-- ManagedProviderCredentialResolver
|-- DurableUsageLifecycle and accounting coordinator
|-- enterprise scan pipeline and error composition
|-- management, shared-result, compliance, and AI Act routes
`-- database, Redis, tracing, metrics, and lifecycle hooks
```

PostgreSQL is authoritative for request lifecycle, quota and spend
reservations, audit intent, reconciliation, and outbox delivery. Redis is an
accelerator for burst control, loop detection, circuit state, tenant-policy
caching, and encrypted privacy-continuation mappings. Redis is never a second
accounting truth store. Each provider circuit is keyed by tenant and target (the
deployment base URL, or the catalog route), so one tenant's failing traffic does
not open another tenant's circuit; community keeps one circuit per provider.

No database transaction spans the provider call. Provider-start, heartbeat,
finalization, and reconciliation use their established short transaction
boundaries. External effects are dispatched from committed outbox intent.

## API profiles

The exact method/path inventories live in `architecture/route_profiles.toml`.

`/metrics` is intentionally excluded from OpenAPI. Enterprise provider routes
must preserve the community provider request, response, selector, error, and
stream contracts while adding enterprise authentication and lifecycle policy.

### Authentication and provider credentials

Enterprise OIDC and Vault deployment contracts are documented in
[`ee/docs/ON_PREM_IDENTITY.md`](../ee/docs/ON_PREM_IDENTITY.md). The on-prem
control plane uses configured issuer/subject identities and server-side Redis
sessions; hosted Supabase remains a separate selected authentication mode.

- OpenAI SDKs carry the shim key in `Authorization: Bearer ...`.
- Anthropic SDKs carry the shim key in `x-api-key` on Anthropic routes.
- Gemini SDKs carry the shim key in `x-goog-api-key` on Gemini routes; it is
  never inferred to be a provider credential.
- `x-shim-key` is the explicit provider-independent gateway-key header.
- `x-provider-key` is an invocation-scoped provider credential. In enterprise it
  wins over the tenant's stored key on catalog routes, is ignored on registered
  deployments, and is refused with 403 `PROVIDER_KEY_NOT_ALLOWED` when the tenant
  turns `allow_customer_provider_keys` off.
- Anthropic `x-api-key` is never inferred to be a provider credential.

Credential-bearing headers are removed before request metadata is recorded.
Admission reads three gateway headers besides the credentials: `X-Shim-Tag`,
`X-Shim-Task-Id` and `traceparent` (the task and trace ids of the request);
with `SHIM_TRACE_PARENT=honor` the kernel also starts the request span as a
child of the incoming `traceparent`/`tracestate`. None of them is forwarded.
Inbound authorization, cookies, host headers, shim tags, and credentials are
never forwarded wholesale.

### Native responses, streams, and errors

| Provider | Current route family | Native stream terminal |
| --- | --- | --- |
| OpenAI | `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`, `/v1/models` | Chat ends with `[DONE]`; Responses uses named `response.*` events; embeddings never stream |
| Anthropic | `/v1/messages`, `/v1/messages/count_tokens`, `/v1/models` | Messages use native named events ending in `message_stop`; token counting returns JSON |
| Gemini | `/v1beta/models/{model}:generateContent` and stream, `:embedContent`, `:batchEmbedContents` | Data-only Gemini SSE, without `[DONE]`; embeddings return JSON |

Embeddings run the same stages as chat. Catalog entries carry a `kind`: an
`embedding` model answers only the embeddings routes and never appears in
`/v1/models`, and every other route refuses it with `MODEL_NOT_PRICED`. Admission
reserves no output and skips the context and capability checks; the privacy stage
applies the tenant's actions (and its embeddings-only `monitor` list) and refuses
token-id input while any type is masked or blocked; OpenAI runs through the SDK
with `encoding_format: "float"` when the client omitted it, Gemini through a native
HTTP call (the SDK would turn `:embedContent` into a batch); nothing is restored in
vectors; settlement takes the prompt tokens the provider reports, no completion
tokens and no outcome.

Images and files have one definition, `classify_media` in `src/shim/gateway/media.py`:
the parts the privacy walk reaches in content (image, file, document, audio and
Gemini inline or file data parts) with their kind, source, declared type, the path
of their inline data and its decoded size. Admission walks the payload for them only
when its compact JSON carries a media word, and the model capability check reads
them. Privacy refuses them (400 `PRIVACY_POLICY_BLOCKED`) while it protects anything
and the tenant's `media_inputs` is `block`; otherwise it forwards them byte for byte
and never gives their data string to the detector. When they will be forwarded,
admission sizes the request by its text bytes plus a published token estimate per
part instead of the base64 bytes. With `documents` at `scan` or `scan_and_convert`,
inline PDF, Word and text parts are not media: the privacy stage reads their text in
its worker thread (`src/shim/privacy/documents.py`, bounded in size, pages and time;
pypdf is the optional `documents` extra), scans it with the same actions and rules, and
forwards the part, stops the request, or replaces the part with its (masked) text,
recorded as a `document_text` entry of `transforms_applied`.

OpenAI errors use `{error: {message, type, param, code, hint}}`. Anthropic
errors use `{type: "error", error: {type, message, code, hint}, request_id}`,
where `request_id` keeps its native meaning, the provider's request id, and is
present only when the provider sent one. Gemini errors use the google.rpc.Status
`{error: {code, message, status, details}}` shape. Upstream details that could
contain credentials or PII are discarded, with one exception: for a provider
400, 404, 413 or 422 the provider's own message is the error message, trimmed to
500 characters and never restored, so masked values stay placeholders. A stream
failure after headers is emitted as a sanitized terminal event. A provider 429
keeps its status and `retry-after` and carries the code `PROVIDER_RATE_LIMITED`;
it is the caller's quota, so it neither opens nor closes the provider circuit.
A provider 400, 403, 404, 413 or 422 keeps its status with the code
`PROVIDER_REJECTED_REQUEST`, and a provider 401 keeps its status with
`INVALID_PROVIDER_CREDENTIAL`, so it is never mistaken for a bad shim key. An
OpenAI-protocol 400 whose body code is `content_filter` (Azure's content filter) is
`PROVIDER_CONTENT_FILTERED`, with a fixed message naming only the allowlisted
filter categories. A request the provider SDK refuses before sending it is 400
`INVALID_REQUEST` with a fixed message; a provider answer the SDK cannot parse
stays 502 `PROVIDER_UNAVAILABLE`. A credential resolver may raise a
`ProviderCallError`, which reaches the caller with its own status and code (an
Entra ID refusal is 401 `INVALID_PROVIDER_CREDENTIAL`); any other resolver
exception is 503 `PROVIDER_UNAVAILABLE`.

Every gateway error response whose code shim knows carries it in
`X-Shim-Error-Code`, in all three shapes, and browsers may read that header.
OpenAI and Anthropic bodies repeat the code in `error.code`; Gemini bodies, JSON
and stream, carry it as a google.rpc `ErrorInfo` detail (`reason`, domain
`getshim.tech`) beside a google.rpc `status`. The same bodies carry a `hint`, one
sentence on what to do next: `error.hint` in OpenAI and Anthropic bodies and
stream error events, `ErrorInfo.metadata.hint` in Gemini. Hints come from one
table keyed by code, `ERROR_HINTS` in `src/shim/gateway/pipeline/provider_execution.py`;
a raise site may override it with `detail["hint"]`, and a new code adds one entry
there. An error raised after authentication also carries `X-Shim-Request-Id`.
The codes raised are `MISSING_API_KEY`, `INVALID_API_KEY`,
`INVALID_PROVIDER_CREDENTIAL`, `INVALID_REQUEST`, `REQUEST_TOO_LARGE`,
`MODEL_NOT_FOUND`, `MODEL_NOT_PRICED`, `MODEL_CONTEXT_EXCEEDED`,
`MODEL_CAPABILITY_UNSUPPORTED`, `PROVIDER_NOT_ALLOWED`, `TASK_LIMIT_EXCEEDED`,
`CONCURRENCY_LIMITED`,
`AGENT_LOOP_DETECTED`,
`ZERO_RETENTION_REQUIRED`, `RATE_LIMIT_EXCEEDED`, `PRIVACY_POLICY_BLOCKED`,
`SECRET_BLOCKED`, `PII_BLOCKED`, `DOCUMENT_UNSCANNABLE`, `RULE_BLOCKED`, `APPROVAL_REQUIRED`,
`APPROVAL_REJECTED`, `APPROVAL_QUEUE_FULL`, `APPROVAL_UNAVAILABLE`,
`PRIVACY_STATE_UNAVAILABLE`, `PROVIDER_NOT_CONFIGURED`, `PROVIDER_RATE_LIMITED`,
`PROVIDER_REJECTED_REQUEST`, `PROVIDER_CONTENT_FILTERED`, `PROVIDER_UNAVAILABLE`,
`PROVIDER_TIMEOUT` and `INTERNAL_ERROR`; enterprise adds
`MODEL_NOT_ALLOWED`, `MODEL_NOT_REGISTERED`, `DEPLOYMENT_NOT_APPROVED`,
`MODEL_PRICE_UNKNOWN`, `MONTHLY_QUOTA_EXCEEDED`, `SPEND_LIMIT_EXCEEDED`,
`PROVIDER_KEY_NOT_ALLOWED`,
`SCAN_LIMIT_EXCEEDED`, `TENANT_NOT_FOUND`, `DEPLOYMENT_UNHEALTHY`,
`BEDROCK_REGION_NOT_ALLOWED` and `AUDIT_INTENT_FAILED`. A request
that fails schema validation carries the validator's error type instead.

`background=true` Responses requests remain unsupported because shim has no
retrieval lifecycle with which to settle them safely. Community model IDs must exist in the checked-in model and price catalog.
Enterprise can resolve tenant aliases through its approved deployment registry;
`MODEL_DEPLOYMENT_REQUIRED=true` disables catalog fallback. Registry targets
reuse the native executions with operator-approved destinations and stored
credential references. Unpriced deployments remain explicit in accounting, and
monetary caps reject them. See [`MODEL_DEPLOYMENTS.md`](../ee/docs/MODEL_DEPLOYMENTS.md).

After a completed answer has been delivered (after the last body byte of a JSON
answer, after a stream's finalization), one background task per request runs the
opt-in response scan and the opt-in response analyzers
(`src/shim/gateway/pipeline/analysis.py`, registry in
`src/shim/gateway/analyzers/`), each on a single worker thread of its own, so a
slow analyzer never holds the scan, then writes each record: community JSONL
lines, enterprise lifecycle metadata in a short transaction of its own. Each
thread takes at most 64 pending requests; work beyond that is dropped and
counted, never queued, so a stuck run cannot grow memory. The task is registered
with the postprocessor and drained at shutdown. With both off nothing is kept
and no task is created. An analyzer declares `reads_answer`; one that does never
runs after a request that carried personal data, and the answer is extracted (or
kept by the stream meter) only while one that does runs.
Enterprise tenant switches live in `organization_gateway_settings`, one validated
`GatewaySettings` model read next to the privacy settings and cached for 300
seconds; core sees it only as `tenant_gateway_settings` on the request.

Tenant rules (`src/shim/rules/`) are one validated `Rule` object with a fixed
table of kinds; each kind names the point where it is evaluated: `resolver`,
`admission`, `privacy` or `settings`. Matchers record `RuleMatch` facts on the
request; after the base privacy decision, which wins, the kernel's decision
point turns them into `rule.<id>` verdicts, refuses an enforced block with
`RULE_BLOCKED` (400, `X-Shim-Rule-Id`), adds the `RULE_WARN` warning, and asks
the optional `ApprovalGate` port (`src/shim/rules/approval.py`) about an
enforced `require_approval` match, passing the payload as it entered privacy.
Without a gate such a match is a block. Community has no rule store: the set
arrives as `rules` on the resolved policy, which enterprise reads from
`organization_rule_sets`, keyed by a revision kept in the privacy cache entry,
with the rules themselves only in process memory. A stored rule this build
cannot run is kept aside as unusable (`load_rule_set`): enforced, it blocks the
requests in its scope. The `term` and `pattern` kinds (`src/shim/rules/content.py`)
are searched by `PIIScrubberService` on its normalized text (percent-decoded,
invisible characters dropped, NFKC, every script's decimal digits as 0-9, each
character mapped back to its source offsets for masking): terms through a
word index and pattern regexes, both built once per `RuleSet` object
(`RuleSet.matchers`), the Turkish endings from a grammar
(`src/shim/rules/tr_suffixes.py`). The `destination` kind (`src/shim/rules/destination.py`)
names entity types: for a request in its scope the privacy stage detects them,
masks them under an enforced `mask` rule, and records the matches for the decision
point. The `request_limit` kind (`src/shim/rules/request_limit.py`) is evaluated in
admission before the rate limits, where an enforced block refuses; token counting is
exempt. The `route` kind (`src/shim/rules/route.py`) is evaluated at the resolver
point, which only enterprise has: the `prepare_inference` hook, called with the
request headers, reads the conversation's first turn (`start_view`) and may give the
request another registry target before admission. The `parameter_pin` kind (`src/shim/rules/parameter_pin.py`) is evaluated in
the settings band (`src/shim/gateway/pipeline/settings_band.py`), a kernel stage
after the token-count branch and before `record_privacy`: it runs only when a pin
is in scope for the request's protocol or a band setting is on, sets
provider parameters on the masked payload, copying only the objects it changes,
and never a content string. Its verdicts carry stage `settings`; an enforced block
records the privacy facts and then refuses with `RULE_BLOCKED`. Applied steps are
recorded as `settings_applied`. After the pins the band runs its fixed `STEPS`,
each off by default: `anthropic_auto_cache` (a top-level Anthropic breakpoint) and
`openai_prompt_cache_key` (an OpenAI routing key derived from the prompt prefix),
`tool_search` (`defer_loading` and the provider's search tool),
`anthropic_clear_thinking` (`context_management`, with its beta flag in
`provider_betas`, which moves the Anthropic execution to the beta client),
`openai_reasoning_context` and `image_detail` (a cheaper `detail` or Gemini 3
`mediaResolution` on image parts the client left unset, where the version-pinned
table in `src/shim/gateway/image_rules.py` says it lowers the budget), for catalog routes and the registry aliases the tenant
lists. A step that declines a request it was on for records a `settings.<step>`
`skip` verdict. The transform band (`src/shim/gateway/pipeline/transform_band.py`)
follows it, only when a transform is on, and changes content under four conditions:
nothing changes below a published threshold, each step is deterministic and
version-pinned, before and after sizes are recorded (`transforms_applied`), and the
tenant can turn it off. Its one step, `json_compaction`, removes whitespace between
JSON tokens in tool results and keeps a string only when it parses to the same value;
it skips Anthropic requests bound to thinking with a `transforms.json_compaction`
verdict, and runs in a worker thread above 65,536 candidate characters. The `route` kind
ships no matcher yet.
`ResponseWarning` also defines `SEMANTIC_WARN`, which no stage raises yet.
Admission adds `MODEL_RETIRING` (retirement within 90 days) or `MODEL_RETIRED`
(after the date) from `src/shim/billing/lifecycle.py`, which reads the reviewed
`model_lifecycle.json` and an operator's `SHIM_MODEL_LIFECYCLE_FILE`; both codes stay
out of `X-Shim-Warnings` unless the tenant's mode is `header`. Nothing is refused
for a date.
With `SHIM_INJECTION_MARKERS` (enterprise: the `injection_markers` gateway
setting) at `count` or `warn`, the privacy stage also counts instruction markers
in tool results and documents of the raw request (`src/shim/privacy/injection.py`,
shim-cli's patterns), on the same worker thread as the privacy scan; `warn` adds
the `INJECTION_MARKERS` warning. It never blocks or changes the request.

Anthropic token counting shares authentication, registry authorization and
privacy transformation. It persists nonbillable enterprise audit preflight and
completion without quota/spend reservations or inference lifecycle settlement.

## Physical ownership

```text
src/shim/                         community package
tests/                            community and boundary tests
openapi/community.json            community schema
Dockerfile                        community image

ee/src/shim_enterprise/           enterprise package
ee/tests/                         enterprise tests
ee/alembic/                       enterprise schema history
ee/scripts/                       enterprise operations
ee/openapi/enterprise.json        enterprise schema
ee/Dockerfile                     enterprise image
```

The ownership manifest enumerates every governed Python file and the exact leaf
community modules and symbols consumed by enterprise runtime code. Architecture
tests reject reverse dependencies, forbidden public dependencies, broad or
unresolved imports, stale allowlist entries, undeclared files, and route-profile
drift. Broad eager facades are not the cross-licence API.

`ee/tests` may white-box community internals for atomic monorepo regression
coverage. Those test-only imports do not expand the supported runtime API;
runtime code, Alembic, and enterprise scripts remain exact-manifest-only.

## Entrypoints

| Process | Canonical command |
| --- | --- |
| Community API | `shim serve` |
| Enterprise API | `uvicorn shim_enterprise.application:create_enterprise_app --factory` |
| Cloud API | `uvicorn shim_cloud.application:create_cloud_app --factory` |
| Cloud migrations | `python -m shim_cloud.migrate` |
| Cloud outbox | `python -m shim_cloud.worker` |
| Migrations | `alembic -c ee/alembic.ini upgrade head` |
| Outbox | `python -m shim_enterprise.workers.outbox` |
| Reconciliation | `python -m shim_enterprise.workers.reconciliation` |
| Compliance | `python -m shim_enterprise.workers.compliance` |
| AI Act | `python -m shim_enterprise.workers.ai_act` |

The root Dockerfile contains only the community runtime. `ee/Dockerfile`
contains both packages plus enterprise migrations and operational scripts.
Customer Compose uses the enterprise image. Cloud Build uses `ee/cloud/Dockerfile`,
which installs `shim-cloud` and selects cloud API, outbox and migration entrypoints.
Its other workers reuse enterprise entrypoints. Cloud commerce is excluded from
customer wheels/images. See the [cloud runbook](../ee/cloud/README.md).

## Change map

| Concern | Primary implementation |
| --- | --- |
| Community composition and CLI | `src/shim/application.py`, `src/shim/cli.py` |
| Provider HTTP boundaries | `src/shim/api/v1/` |
| Kernel and public contracts | `src/shim/gateway/` |
| Provider execution and streams | `src/shim/gateway/pipeline/`, `src/shim/gateway/streaming/` |
| Privacy | `src/shim/privacy/`, enterprise continuation adapter under `ee/src/shim_enterprise/privacy/`; the detection contract is `tests/gateway/privacy/corpus/detection-v1.json` |
| Enterprise composition and authentication | `ee/src/shim_enterprise/application.py`, `ee/src/shim_enterprise/api/` |
| Durable accounting | `ee/src/shim_enterprise/gateway/pipeline/quota_reservation.py` |
| Tenancy and managed secrets | `ee/src/shim_enterprise/tenants/`, `ee/src/shim_enterprise/secrets/` |
| Schema and migrations | `ee/src/shim_enterprise/**/models.py`, `ee/alembic/` |
| Cloud commerce | `ee/cloud/src/shim_cloud/`, `ee/cloud/alembic/` |
| Route and import rules | `architecture/`, `tests/architecture/` |

## SDK update procedure

Before changing an SDK pin:

1. Review the provider's official create, stream, error, retry, and timeout
   contract.
2. Update the exact pin and regenerate the single `uv.lock`.
3. Compare public SDK create signatures and representative nested payloads.
4. Run real SDK clients through the ASGI transport tests.
5. Review new fields through privacy restoration, metering, and error
   sanitization.
6. Regenerate all affected OpenAPI profiles and the enterprise dashboard client.

## Licence boundary

`LICENSE` and `NOTICE` apply Apache-2.0 outside `ee/`. `ee/LICENSE` and
`ee/NOTICE` apply Elastic-2.0 under `ee/` and name the licensor. All package
manifests declare the matching SPDX expression and legal files; CI verifies
those files in wheel and sdist metadata. Production enterprise boots verify an
offline `SHIM_LICENSE_KEY` in `shim_enterprise.core.license`; no other runtime
licence validator exists.

Production deployment is triggered by `v<major>.<minor>.<patch>` tags, not by a
merge to `main`. Cloud Build serializes migration and promotion with a shared
lock, validates staged gateway and worker revisions, and restores the captured
traffic splits on promotion failure. Release publication workflows do not deploy.
See [repository release rules](../AGENTS.md#release-and-deployment) and the
[customer-operated deployment guide](../ee/deploy/README.md).
