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
  policy -> admission -> privacy -> provider start
         -> one SDK attempt -> restore -> finalize
        |
        v
provider-native JSON or SSE response
```

Provider-owned JSON remains open-ended. shim validates the routing, privacy,
and accounting fields it consumes, then uses the official provider SDK or
native Gemini transport. It does not introduce a canonical cross-provider
request model.

Outbound SDK retries are disabled. One admitted shim request may make at most
one billable provider attempt.

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
- `x-provider-key` is an invocation-scoped provider credential.
- Anthropic `x-api-key` is never inferred to be a provider credential.

Credential-bearing headers are removed before request metadata is recorded.
Inbound authorization, cookies, host headers, shim tags, and credentials are
never forwarded wholesale.

### Native responses, streams, and errors

| Provider | Current route family | Native stream terminal |
| --- | --- | --- |
| OpenAI | `/v1/chat/completions`, `/v1/responses`, `/v1/models` | Chat ends with `[DONE]`; Responses uses named `response.*` events |
| Anthropic | `/v1/messages`, `/v1/messages/count_tokens`, `/v1/models` | Messages use native named events ending in `message_stop`; token counting returns JSON |
| Gemini | `/v1beta/models/{model}:generateContent` and stream | Data-only Gemini SSE, without `[DONE]` |

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
`INVALID_PROVIDER_CREDENTIAL`, so it is never mistaken for a bad shim key. A
request the provider SDK refuses before sending it is 400 `INVALID_REQUEST` with
a fixed message; a provider answer the SDK cannot parse stays 502
`PROVIDER_UNAVAILABLE`.

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
`MODEL_NOT_FOUND`, `MODEL_NOT_PRICED`, `PROVIDER_NOT_ALLOWED`,
`ZERO_RETENTION_REQUIRED`, `RATE_LIMIT_EXCEEDED`, `PRIVACY_POLICY_BLOCKED`,
`PRIVACY_STATE_UNAVAILABLE`, `PROVIDER_NOT_CONFIGURED`, `PROVIDER_RATE_LIMITED`,
`PROVIDER_REJECTED_REQUEST`, `PROVIDER_UNAVAILABLE`, `PROVIDER_TIMEOUT` and
`INTERNAL_ERROR`; enterprise adds
`MODEL_NOT_ALLOWED`, `MODEL_NOT_REGISTERED`, `DEPLOYMENT_NOT_APPROVED`,
`MODEL_PRICE_UNKNOWN`, `MONTHLY_QUOTA_EXCEEDED`, `SPEND_LIMIT_EXCEEDED`,
`SCAN_LIMIT_EXCEEDED`, `TENANT_NOT_FOUND`, `DEPLOYMENT_UNHEALTHY` and
`AUDIT_INTENT_FAILED`. A request
that fails schema validation carries the validator's error type instead.

`background=true` Responses requests remain unsupported because shim has no
retrieval lifecycle with which to settle them safely. Community model IDs must exist in the checked-in model and price catalog.
Enterprise can resolve tenant aliases through its approved deployment registry;
`MODEL_DEPLOYMENT_REQUIRED=true` disables catalog fallback. Registry targets
reuse the native executions with operator-approved destinations and stored
credential references. Unpriced deployments remain explicit in accounting, and
monetary caps reject them. See [`MODEL_DEPLOYMENTS.md`](../ee/docs/MODEL_DEPLOYMENTS.md).

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
