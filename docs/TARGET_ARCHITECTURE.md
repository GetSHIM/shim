# SHIM target architecture

Status: approved and implemented architecture

Last reviewed: 2026-08-28

This is the architectural contract for the SHIM backend. Implementation and
release evidence are tracked in
[`MIGRATION_PROGRESS.md`](./MIGRATION_PROGRESS.md).

## Decision

Use one public, mixed-licence monorepo containing two Python packages:

| Product | Distribution | Import package | Intended licence region |
| --- | --- | --- | --- |
| Community | `shim-gateway` | `shim` | Apache-2.0 |
| Enterprise | `shim-enterprise` | `shim_enterprise` | Elastic-2.0, source-available |

The architecture is a package-modular monolith. It takes Polylith's useful
ideas—small capabilities, explicit composition, and testable boundaries—but
does not adopt Polylith tooling, a component taxonomy, or a package per feature.

```text
one repository / one lock / one release pair

  community package                         enterprise package
  +---------------------------+             +---------------------------+
  | src/shim                  |<------------| ee/src/shim_enterprise    |
  | native provider gateway   |  allowlist  | tenant/durable adapters   |
  | privacy and local policy  |             | billing/audit/compliance  |
  +---------------------------+             +---------------------------+

  allowed:   shim_enterprise -> shim
  forbidden: shim -> shim_enterprise
```

This keeps cross-product changes atomic and makes the licence boundary visible
in the filesystem. It is not a rewrite, microservice split, plugin platform, or
attempt to hide enterprise source.

## Goals

- Make community useful, installable, and runnable without enterprise code or
  infrastructure.
- Preserve existing enterprise behavior, schema, accounting, privacy, tenant
  isolation, streaming, and workers.
- Keep one implementation of provider transport, privacy, and the inference
  kernel.
- Make every cross-region dependency explicit and machine-enforced.
- Produce separate packages, schemas, images, settings, and tests from one
  commit and one lockfile.
- Give humans and coding agents an obvious owner and verification path for each
  change.

## Repository layout

```text
shim/
|-- src/shim/
|   |-- application.py               # community composition root
|   |-- api/v1/                      # provider-native and local scan routes
|   |-- gateway/                     # contracts, kernel, stages, streaming
|   |-- privacy/                     # classification, masking, restoration
|   |-- billing/                     # public catalog and cost attribution
|   |-- secrets/                     # invocation/local credential contract
|   `-- observability/               # public logging, tracing, metrics
|-- tests/                           # community and boundary tests
|-- openapi/community.json
|-- Dockerfile                       # community image
|
|-- ee/
|   |-- src/shim_enterprise/
|   |   |-- application.py           # enterprise composition root
|   |   |-- tenants/                 # identity and policy
|   |   |-- billing/                 # ledger, quota, budgets, spend
|   |   |-- gateway/                 # durable adapters and enterprise scan
|   |   |-- secrets/                 # managed secret stores
|   |   |-- outbox/                  # durable external effects
|   |   |-- compliance/ and ai_act/
|   |   `-- workers/
|   |-- tests/
|   |-- alembic.ini and alembic/
|   |-- scripts/
|   |-- openapi/enterprise.json
|   |-- pyproject.toml
|   |-- Dockerfile
|   `-- AGENTS.md
|
|-- architecture/                    # executable ownership and route rules
|-- scripts/                         # cross-profile export and public catalog
|-- pyproject.toml                   # community package + workspace
|-- uv.lock                          # one authoritative lock
`-- AGENTS.md
```

The tree is the primary ownership signal. Do not add another layer merely to
mirror this diagram.

## Runtime architecture

Both products compose the same public request path:

```text
native request
    |
    v
provider route + authentication
    |
    v
GatewayService
    |
    v
GatewayKernel
    |
    +-- policy and principal
    +-- admission and loop control
    +-- privacy transform
    +-- provider-start lifecycle marker
    +-- exactly one provider attempt
    `-- restore, meter, and finalize
    |
    v
native JSON or provider-specific SSE
```

Provider payloads remain native dictionaries or SDK objects at the boundary.
Public contracts contain plain values, not ORM records, database sessions,
enterprise settings, or provider credentials.

### Community composition

```text
create_community_app
  = public routes and kernel
  + local authentication and policy
  + invocation/environment credentials
  + bounded in-memory admission, circuits, and continuation state
  + redacted local usage events and public cost catalog
```

Community is intentionally single-process and ephemeral. It requires no
PostgreSQL, Redis, Supabase, enterprise variable, migration, or worker. Add
distributed community state only for a demonstrated use case.

### Enterprise composition

```text
create_enterprise_app
  = community kernel and provider transports
  + database authentication and tenant policy
  + durable quota, spend, audit, outbox, and reconciliation
  + Redis acceleration and encrypted continuation state
  + managed secrets
  + management, compliance, AI Act, and workers
```

Enterprise adds behavior through explicit construction. Public code must not
contain commercial feature flags, licence checks, optional enterprise imports,
or plugin discovery.

## Capability ownership

| Capability | `shim` | `shim_enterprise` |
| --- | --- | --- |
| Provider-native HTTP and SDK transport | Owns | Reuses |
| Gateway kernel, streaming, safe errors | Owns | Reuses |
| PII classification, masking, restoration | Owns | Configures durable state/policy |
| Local authentication, scan, usage events | Owns | Replaces with tenant/durable adapters |
| Model catalog and cost attribution | Owns | Reuses for settlement inputs |
| Tenant identity, RBAC, organizations | Does not contain | Owns |
| Ledger, quota, budgets, reconciliation | Does not contain | Owns |
| Audit, outbox, compliance, AI Act | Does not contain | Owns |
| SQLAlchemy models and Alembic history | Does not require | Owns |
| Enterprise management and workers | Does not contain | Owns |

For an ambiguous capability, choose community only when a local developer can
use it without enterprise infrastructure. Otherwise keep it under `ee/`.

## Dependency rules

1. `shim` never imports `shim_enterprise` or enterprise-only dependencies,
   including lazy, optional, and type-checking imports.
2. Enterprise runtime imports only the exact leaf `shim` modules and symbols
   listed in `architecture/module_ownership.toml`; broad eager facades are not
   the cross-licence API.
3. A new cross-region symbol is an architectural API change: add it only with
   its consumer and boundary test.
4. Provider SDK objects stay in execution adapters. Provider JSON is not
   normalized into a shared request model.
5. Infrastructure differences use the existing narrow contracts for policy,
   credentials, continuation state, usage lifecycle, admission, and circuits.
6. Do not create `common`, `utils`, re-export facades, or compatibility packages
   to bypass ownership.

Standard-library AST tests compare the enterprise runtime import graph exactly
with the manifest. They reject undeclared imports, stale entries, star or bare
module imports, and unresolved recognized dynamic imports. The ownership
manifest also rejects unclassified Python files.

## Data and transaction rules

Community has no required database. Enterprise owns the current SQLAlchemy
models and complete Alembic history under `ee/`.

Moving package ownership must not change table names, columns, identifiers,
revision IDs, `down_revision` links, `alembic_version`, indexes, constraints,
triggers, functions, grants, or production data.

PostgreSQL remains the enterprise accounting truth. Redis may accelerate burst
limits, loop detection, circuit state, policy reads, and privacy continuation;
failure must not make it an alternate ledger. No database transaction spans a
provider call. Production rollback uses a previous schema-compatible image,
not an Alembic downgrade.

## API and artifact profiles

| Profile | OpenAPI | Artifact boundary |
| --- | --- | --- |
| Community | `openapi/community.json` | `shim` wheel/sdist and community image; no `ee/`, enterprise package, migrations, settings, or direct dependencies |
| Enterprise | `ee/openapi/enterprise.json` | Exact-version `shim` + `shim-enterprise`, enterprise image, migrations, scripts, and required assets |

Enterprise provider routes keep the same native wire and stream contracts as
community while adding tenant policy and durable lifecycle behavior. Enterprise
may add routes; community must never expose them.

The distributions share a release version. `shim-enterprise X.Y.Z` requires
`shim-gateway X.Y.Z`. One `uv.lock` is authoritative for repository development
and CI.

## Build and deployment

| Process | Canonical entrypoint |
| --- | --- |
| Community API | `shim serve` |
| Enterprise API | `uvicorn shim_enterprise.application:create_enterprise_app --factory` |
| Enterprise migration | `alembic -c ee/alembic.ini upgrade head` |
| Workers | `python -m shim_enterprise.workers.{outbox,reconciliation,compliance,ai_act}` |

The root Dockerfile is community-only. `ee/Dockerfile` contains both installed
packages and enterprise runtime assets. Root Compose and Cloud Build remain
enterprise deployment definitions and use only canonical enterprise paths.

The `main` Cloud Build trigger is the production release path. It builds one
commit-tagged enterprise image, then acquires a generation-guarded Cloud Storage
lock before Alembic or any Cloud Run mutation. It stages commit-named gateway
and worker revisions without traffic and verifies the temporarily tagged
gateway. Each exact worker revision must become active, emit its runtime signal,
and remain error-free before the exact gateway revision receives traffic. A
failed promotion restores only the active splits captured by that build;
successful releases verify the default gateway URL and remove the temporary
release tag.

## Mixed-licence boundary

The repository is public, so enterprise is source-available rather than secret.
No committed region may contain credentials, customer data, or confidential
customer integrations.

The checked-in boundary is authoritative:

- `LICENSE` contains Apache-2.0 and `NOTICE` applies it outside `ee/`;
- `ee/LICENSE` contains Elastic-2.0 and `ee/NOTICE` identifies Shim as the
  licensor for files under `ee/`;
- each `pyproject.toml` declares its own SPDX expression and legal files; and
- CI compares the legal files and metadata embedded in wheels and sdists with
  their source files.

A repository archive necessarily contains both licence regions. Community
binary/source artifacts exclude `ee/` and carry only the community terms. The
enterprise distribution carries its own terms and depends on the separately
licensed community distribution. The enterprise image contains both installed
packages and both packages' metadata.

No CLA, runtime licence check, or bootstrap validator is part of this
architecture. Add one only after the owner adopts a contribution or commercial
policy that requires it.

## Agent-friendly enforcement

- `AGENTS.md` states repository-wide invariants; `ee/AGENTS.md` adds persistence
  and commercial-boundary rules.
- Ownership and supported imports are data in `architecture/`, not prose-only
  conventions.
- Tests live with their licence region and each OpenAPI profile has one
  deterministic exporter.
- Composition roots reveal concrete adapters; there is no hidden service
  locator or runtime plugin graph.
- One focused change should normally touch one owner. A public contract change
  updates both compositions and boundary tests atomically.

## Non-goals

- Microservices or independently deployed capability packages.
- Canonical Polylith layout or tooling.
- A generic plugin/factory framework.
- A provider-neutral request schema.
- Compatibility modules for superseded package paths.
- Database redesign during package movement.
- Hiding enterprise source in a separate repository.

## Definition of done

Technical completion requires:

- both packages build and install from one locked commit;
- community starts with `ee/` and enterprise infrastructure absent;
- enterprise API, migrations, and four workers use canonical entrypoints;
- reverse imports, unsupported public imports, route leakage, dependency
  leakage, and artifact leakage fail CI;
- both OpenAPI profiles and all public/enterprise behavior tests pass;
- schema identifiers and enterprise accounting invariants remain unchanged; and
- independent architecture, persistence, artifact, and security review has no
  blocking finding.

Licence completion additionally requires exact package metadata and legal-file
checks in built artifacts. The licensor name and contributor/security channels
remain owner-controlled publication details.
