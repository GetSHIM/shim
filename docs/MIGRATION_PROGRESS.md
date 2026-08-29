# Community and enterprise migration progress

Status: migration implementation and initial production rollout complete

Release branch: `main`

Initial migrated production commit: `e0c7901`

Architecture contract: [`TARGET_ARCHITECTURE.md`](./TARGET_ARCHITECTURE.md)

## Goal

Deliver one mixed-licence monorepo with:

- a standalone `shim-gateway` distribution importing `shim`; and
- a `shim-enterprise` distribution under `ee/` importing `shim_enterprise` and
  composing the exact matching community package.

Both products must build and run from one commit and one lockfile. CI must reject
dependency, route, schema, and artifact leakage in either direction.

## Non-negotiable invariants

- `shim` never imports `shim_enterprise` or enterprise-only dependencies.
- Enterprise runtime imports only the public `shim` symbols declared in the
  ownership manifest.
- Provider-native request, response, error, and stream contracts do not change
  accidentally.
- One admitted request makes at most one provider attempt.
- Provider credentials remain invocation-scoped and absent from durable state
  and telemetry.
- Enterprise stage order and transaction boundaries remain unchanged.
- PostgreSQL remains enterprise lifecycle and accounting truth; Redis remains
  an accelerator and continuation store.
- Table names, Alembic revisions, constraints, functions, triggers, and
  production data remain unchanged during package movement.
- Community runtime, artifacts, image, settings, behavior tests, direct
  dependency metadata, and OpenAPI contain no enterprise code or assets.
- No compatibility package, generic plugin layer, provider-neutral wire model,
  retry layer, microservice split, or duplicated gateway implementation.

## Status

| Phase | State | Remaining gate |
| --- | --- | --- |
| 0. Baseline and inventory | Complete | Historical DB-baseline limitation recorded |
| 1. Boundary guardrails | Complete | None |
| 2. Public contracts and enterprise adapters | Complete | None |
| 3. Community vertical slice | Complete | None |
| 4. Complete community API | Complete | None |
| 5. Physical package split | Complete | None |
| 6. Packages and deployment | Complete | None |
| 7. Final verification and handoff | Complete | None |
| Mixed licensing | Complete | None |
| Publication policy | Owner decision | Confirm final holder name and contribution/security channels |

## Detailed checklist

### Phase 0: baseline and ownership

- [x] Create an isolated worktree and `migration/community-enterprise` branch
  from `00f3ed7`.
- [x] Record the current and target architecture before movement.
- [x] Map routes, kernel stages, provider execution, streaming, accounting,
  tenancy, secrets, migrations, workers, OpenAPI, packaging, and deployment.
- [x] Classify governed Python files as community, enterprise, or intentionally
  shared tooling.
- [x] Record baseline Ruff and type results.
- [x] Record that a database-backed test baseline could not be captured before
  semantic work because the original Docker environment lacked storage. Current
  disposable-database results are tracked below; this historical result cannot
  be recreated honestly.

### Phase 1: executable guardrails

- [x] Add `architecture/module_ownership.toml` as the file-ownership source of
  truth.
- [x] Add exact community and enterprise route profiles.
- [x] Reject public imports of enterprise packages and infrastructure clients.
- [x] Detect absolute, relative, lazy, optional, type-checking, and recognized
  dynamic imports with standard-library AST checks.
- [x] Fail closed on unclassified governed files and unresolved dynamic import
  targets.
- [x] Separate community and enterprise OpenAPI route inventories.

### Phase 2: public contracts and explicit composition

- [x] Split community settings from enterprise settings.
- [x] Remove ORM records, sessions, global enterprise settings, and billing
  objects from public request contracts.
- [x] Resolve authentication and tenant policy in short sessions before the
  provider hot path.
- [x] Separate public provider/privacy errors from enterprise quota, audit,
  tenancy, and reconciliation errors.
- [x] Extract only the contracts required by both products: request policy,
  credentials, privacy continuation, usage lifecycle, admission, circuits, and
  health.
- [x] Add bounded community adapters and preserve current enterprise adapters.
- [x] Preserve credential precedence, consume-once cleanup, stream
  finalization, stage order, and transaction boundaries.
- [x] Break the managed-secret import cycle without adding a service locator or
  plugin framework.
- [x] Obtain independent architecture review and close blocking findings.

### Phase 3: community vertical slice

- [x] Compose OpenAI Chat JSON and streaming without enterprise imports or
  infrastructure.
- [x] Implement optional local shim key authentication and refuse keyless
  non-loopback binds.
- [x] Implement invocation-first provider credentials.
- [x] Add bounded local admission, circuit, and privacy-continuation state.
- [x] Add redacted terminal JSONL usage events and nullable cost attribution.
- [x] Add community health and metrics.
- [x] Verify clean community startup with `ee/` absent.

### Phase 4: complete community API

- [x] Add OpenAI Responses.
- [x] Add Anthropic Messages and beta selection.
- [x] Add Gemini generate and stream routes.
- [x] Add provider-specific model discovery and exact catalog admission.
- [x] Add provider-free local privacy scan without quota, audit, or persistence
  fields.
- [x] Preserve privacy restoration and provider-native streaming across all
  protocols.
- [x] Generate `openapi/community.json` and reject enterprise route leakage.
- [x] Run SDK client, credential, error, privacy, stream, scan, catalog, and cost
  tests without enterprise fixtures.

### Phase 5: physical package split

- [x] Move community runtime to `src/shim` and retain public tests under
  `tests/`.
- [x] Move enterprise runtime to `ee/src/shim_enterprise` and enterprise tests
  to `ee/tests/`.
- [x] Move enterprise Alembic history, operational script, workers, OpenAPI,
  and AI Act assets under `ee/`.
- [x] Rename the application and worker entrypoints to their canonical package
  modules.
- [x] Remove the legacy package rather than leave aliases or forwarding modules.
- [x] Preserve the two Alembic revision files, IDs, order, and content apart
  from package imports.
- [x] Import every enterprise runtime module and run the moved enterprise suite.
- [x] Confirm all 177 runtime modules are free of import-time cycles.
- [x] Enforce the exact enterprise-to-community leaf module-and-symbol allowlist
  in both directions: undeclared imports and stale manifest entries fail.
- [x] Obtain independent approval for the cross-package architecture boundary.
- [x] Obtain independent physical/package and persistence approval. No P0-P2
  finding remains; the accepted P3 enterprise test-only white-box imports do
  not expand the runtime API.
- [x] Integrate the coordinated source, test, migration, guard, packaging, and
  documentation changes in a runnable Git commit.

### Phase 6: packages, schemas, images, and deployment

- [x] Configure `shim-gateway` and workspace member `shim-enterprise` with one
  authoritative `uv.lock` and exact matching versions.
- [x] Split direct dependencies and keep managed AWS/Azure secret clients as
  enterprise extras.
- [x] Build and inspect both wheels and sdists.
- [x] Install the community wheel alone and both wheels together in clean
  environments.
- [x] Generate and check community and enterprise OpenAPI from their own
  composition roots.
- [x] Split `.env.example` and `ee/.env.example` by product.
- [x] Add a community-only root Dockerfile and an enterprise `ee/Dockerfile`.
- [x] Point Compose and Cloud Build at the canonical enterprise API, migration,
  and worker entrypoints.
- [x] Split CI into isolated community and full enterprise jobs with package,
  dependency, image, and OpenAPI boundary checks.
- [x] Build, inspect, and start both final images after all deployment edits are
  integrated.
- [x] Validate development and production Compose configurations and all
  deployment manifest entrypoints.
- [x] Confirm the enterprise OpenAPI has no schema diff; dashboard client
  regeneration is therefore not required for this physical move.

### Phase 7: final verification and handoff

- [x] Run the locked full Ruff, formatting, type, architecture, public, and
  enterprise test matrix on the integrated diff.
- [x] Rehearse fresh upgrade, current-head check, disposable downgrade, and
  re-upgrade with `ee/alembic.ini`.
- [x] Verify the migrated production schema identity, grants, role search path,
  Alembic head, gateway health, worker readiness, and background queues after
  release.
- [x] Rebuild and inspect both wheels, sdists, images, and OpenAPI documents.
- [x] Start community with `ee/` and enterprise variables absent.
- [x] Start the enterprise API with PostgreSQL and Redis connected.
- [x] Import-smoke all four canonical worker module bootstraps with validated
  enterprise settings; do not start their long-running loops in CI.
- [x] Recheck one-attempt, credential redaction, continuation fail-closed,
  streaming finalization, and accounting recovery invariants.
- [x] Run `git diff --check`, review the full patch, and remove caches and
  generated build artifacts.
- [x] Review the final commits and confirm a clean worktree.
- [x] Obtain final independent architecture, code-quality, artifact, and
  security review; close all blocking findings.
- [x] Rewrite repository, developer, current-architecture, target-architecture,
  migration, and agent guidance for the implemented layout.
- [x] Commit final integration and mark the technical goal complete.
- [x] Obtain owner authorization before public publication.

### Mixed-licence completion

- [x] Add canonical Apache-2.0 terms and scope them outside `ee/`.
- [x] Add canonical Elastic-2.0 terms under `ee/` with the licensor named in `ee/NOTICE`.
- [x] Add matching PEP 639 package metadata and legal-file declarations.
- [x] Include and compare legal files in both wheel and sdist profiles.
- [x] Keep the community image free of enterprise source and install both
  separately licensed packages in the enterprise image.
- [x] Omit CLA and runtime licence validation until an approved policy requires
  either.

The holder name may be replaced later by the owner without changing the
architecture. Contribution and security-reporting policy remain publication
decisions, not package-boundary dependencies.

## Verification evidence

These results were recorded on the integrated worktree. They must be rerun if
review changes runtime, packaging, or deployment files.

| Check | Latest evidence |
| --- | --- |
| Full suite | 778 tests passed from the locked all-packages environment against disposable PostgreSQL and Redis |
| Isolated community suite | 403 root tests passed from a community-only locked environment with no enterprise package or infrastructure dependencies |
| Enterprise-free public behavior suite | 356 tests passed in a scrubbed environment without database, Redis, tenant fixtures, or enterprise variables |
| Moved enterprise suite | 375 tests passed; all 105 enterprise runtime modules imported |
| Combined non-architecture suite | 733 tests passed after source and test movement |
| Integrated architecture suites | 45 tests passed across root and enterprise architecture tests |
| Critical runtime invariants | 150 credential, one-attempt, provider, privacy-continuation, streaming, and accounting-recovery tests passed |
| Independent architecture-boundary review | Approved with no blocking finding |
| Independent physical/package and persistence review | Approved with no P0-P2 finding; Alembic blobs byte-identical and history preserved; accepted test-only P3 documented |
| Final principal architecture review | Approved with no remaining P0-P3 finding |
| Final code-quality and security review | Approved with no remaining P0-P3 finding |
| Ruff, format, type, OpenAPI, lock, diff checks | Passed at completed implementation milestones |
| Community artifacts | Wheel and sdist contained `shim`, model data, Apache-2.0 metadata, `LICENSE`, and `NOTICE` with no enterprise paths |
| Workspace artifacts | Both wheel/sdist pairs built; enterprise carried Elastic-2.0 metadata and its exact legal files; enterprise YAML assets remained present |
| Alembic | `head -> base -> head`, history, current, and model import passed on disposable PostgreSQL; revision hashes preserved |
| Community image | Import, filesystem, direct-dependency, Apache-2.0 metadata, and live `/health` checks passed |
| Enterprise image | Both packages and licence regions, migrations, control assets, worker modules, dependency boundary, and live database/Redis `/health` checks passed |
| Enterprise worker bootstraps | All four canonical modules imported from the clean enterprise wheel; image module specs present |
| Compose and deployment manifests | Development and production Compose rendered; candidate staging, serialized exact-revision promotion, runtime health, and guarded restoration assertions passed |
| Initial production rollout | Gateway and four worker pools run commit `e0c7901`; PostgreSQL and Redis health passed and all background queues were clear |
| Split CI profiles | Isolated community and full enterprise jobs include exact licence metadata/file assertions and were locally mirrored |
| Exact cross-package import guard | Passed for 37 leaf modules and 62 symbols; undeclared imports, stale entries, broad imports, and unresolved dynamic imports fail |
| Import-time cycle audit | All 177 community and enterprise runtime modules passed |

The unchanged baseline migration cannot render offline SQL because its existing
JSONB default renderer requires a live dialect. Online migration checks are the
authoritative gate; fixing that unrelated baseline behavior is outside this
migration.

## Git milestones

| Commit | Milestone |
| --- | --- |
| `e582fe5` | Runnable community gateway |
| `aedb485` | Community Responses API |
| `ee11460` | Community Anthropic Messages |
| `ea14fac` | Community Gemini API |
| `59e56ad` | Community privacy scan |
| `a1f829c` | Separate community and enterprise OpenAPI |
| `a004c96` | Separate public and enterprise scan contracts |
| `f8d4e25` | Separate public and enterprise metrics |
| `cddb4d3` | Move community package to `src/shim` |
| `8d00cce` | Move enterprise package, tests, migrations, packaging, and deployment under `ee/` |
| `1a618d0` | Finalize the mixed-licence boundary |
| `55bcefe` | Merge the migration into `main` |
