# shim current architecture

Status: current implementation contract

Last verified: 2026-08-28

This document describes the code in this branch. When it disagrees with prose,
use this order of authority:

1. tests and the two checked-in OpenAPI documents;
2. `architecture/module_ownership.toml` and `architecture/route_profiles.toml`;
3. runtime code under `src/shim` and `ee/src/shim_enterprise`;
4. this document and the developer guide.

## Product and dependency shape

shim is a package-modular monolith with two application compositions and one
lockfile.

```text
public/community region                    enterprise region

shim-gateway                               shim-enterprise
src/shim                                   ee/src/shim_enterprise
    ^                                              |
    +----------------------------------------------+
                 exact, allowlisted imports

Forbidden: shim -> shim_enterprise
```

| Product | Runtime | State |
| --- | --- | --- |
| Community | `shim.application:create_community_app` | Bounded in-process state and local JSONL usage events |
| Enterprise | `shim_enterprise.application:create_enterprise_app` | PostgreSQL truth, Redis acceleration, managed secrets, outbox, and workers |

The community package has no ORM, Alembic, Redis, Supabase, or managed-secret
dependency. Enterprise imports community contracts and implementations; it does
not fork the provider gateway.

## Request flow

Both products share the same inference hot path:

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
|-- Redis admission, loop, circuit, and continuation adapters
|-- ManagedProviderCredentialResolver
|-- DurableUsageLifecycle and accounting coordinator
|-- enterprise scan pipeline and error composition
|-- management, subscription, shared-result, compliance, and AI Act routes
`-- database, Redis, tracing, metrics, and lifecycle hooks
```

PostgreSQL is authoritative for request lifecycle, quota and spend
reservations, audit intent, reconciliation, and outbox delivery. Redis is an
accelerator for burst control, loop detection, circuit state, tenant-policy
caching, and encrypted privacy-continuation mappings. Redis is never a second
accounting truth store.

No database transaction spans the provider call. Provider-start, heartbeat,
finalization, and reconciliation use their established short transaction
boundaries. External effects are dispatched from committed outbox intent.

## API profiles

The exact method/path inventories live in `architecture/route_profiles.toml`.

| Profile | Surface | Contract |
| --- | --- | --- |
| Community | OpenAI Chat and Responses; Anthropic Messages; Gemini generate and stream; model discovery; local scan; health | `openapi/community.json` |
| Enterprise | Community provider routes plus durable scan usage, management, subscriptions, shared results, compliance, and AI Act | `ee/openapi/enterprise.json` |

`/metrics` is intentionally excluded from OpenAPI. Enterprise provider routes
must preserve the community provider request, response, selector, error, and
stream contracts while adding enterprise authentication and lifecycle policy.

### Authentication and provider credentials

- OpenAI SDKs carry the shim key in `Authorization: Bearer ...`.
- Anthropic SDKs carry the shim key in `x-api-key` on Anthropic routes.
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
| Anthropic | `/v1/messages`, `/v1/models` | Native named events ending in `message_stop` |
| Gemini | `/v1beta/models/{model}:generateContent` and stream | Data-only Gemini SSE, without `[DONE]` |

OpenAI errors retain the safe `{error: {message, type, param, code}}` shape.
Anthropic errors retain `{type: "error", error: {type, message}}`. Gemini errors
retain the google.rpc.Status `{error: {code, message, status}}` shape. Upstream
details that could contain credentials or PII are discarded. A stream failure
after headers is emitted as a sanitized terminal event.

`background=true` Responses requests remain unsupported because shim has no
retrieval lifecycle with which to settle them safely. Explicit model IDs must
exist in the checked-in model and price catalog.

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
| Migrations | `alembic -c ee/alembic.ini upgrade head` |
| Outbox | `python -m shim_enterprise.workers.outbox` |
| Reconciliation | `python -m shim_enterprise.workers.reconciliation` |
| Compliance | `python -m shim_enterprise.workers.compliance` |
| AI Act | `python -m shim_enterprise.workers.ai_act` |

The root Dockerfile contains only the community runtime. `ee/Dockerfile`
contains both packages plus enterprise migrations and operational scripts.
Compose and Cloud Build use the enterprise image and canonical enterprise
entrypoints.

## Change map

| Concern | Primary implementation |
| --- | --- |
| Community composition and CLI | `src/shim/application.py`, `src/shim/cli.py` |
| Provider HTTP boundaries | `src/shim/api/v1/` |
| Kernel and public contracts | `src/shim/gateway/` |
| Provider execution and streams | `src/shim/gateway/pipeline/`, `src/shim/gateway/streaming/` |
| Privacy | `src/shim/privacy/`, enterprise continuation adapter under `ee/src/shim_enterprise/privacy/` |
| Enterprise composition and authentication | `ee/src/shim_enterprise/application.py`, `ee/src/shim_enterprise/api/` |
| Durable accounting | `ee/src/shim_enterprise/gateway/pipeline/quota_reservation.py` |
| Tenancy and managed secrets | `ee/src/shim_enterprise/tenants/`, `ee/src/shim_enterprise/secrets/` |
| Schema and migrations | `ee/src/shim_enterprise/**/models.py`, `ee/alembic/` |
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
6. Regenerate both OpenAPI profiles and the enterprise dashboard client.

## Required verification

```bash
uv lock --check
uv sync --locked --all-packages
uv run --locked ruff format --check src ee/src tests ee/tests scripts ee/scripts ee/alembic
uv run --locked ruff check src ee/src tests ee/tests scripts ee/scripts ee/alembic
uv run --locked ty check
uv run --locked python -m pytest -q
uv run --locked --package shim-gateway python scripts/export_openapi.py --profile community --check
uv run --locked --package shim-enterprise python scripts/export_openapi.py --profile enterprise --check
git diff --check
```

Persistence tests require PostgreSQL and Redis. The canonical Alembic config is
`ee/alembic.ini`.

## Licence boundary

`LICENSE` and `NOTICE` apply Apache-2.0 outside `ee/`. `ee/LICENSE` and
`ee/NOTICE` apply Elastic-2.0 under `ee/` and name the licensor. Both package
manifests declare the matching SPDX expression and legal files; CI verifies
those files in wheel and sdist metadata. No runtime licence validator exists.

The public repository uses this mixed-licence package split. It is live in
production; deployment and verification evidence is recorded in
`MIGRATION_PROGRESS.md`. Production releases are automated from `main` through
the staged, serialized, exact-revision Cloud Build flow documented in
`TARGET_ARCHITECTURE.md`.
