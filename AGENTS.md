# shim repository rules

Read `docs/CURRENT_ARCHITECTURE.md`, `docs/TARGET_ARCHITECTURE.md`, and
`DEVELOPER_GUIDE.md` before changing runtime boundaries.

## Ownership

- `src/shim` and root `tests` are community-owned.
- `ee/src/shim_enterprise` and `ee/tests` are enterprise-owned.
- `architecture/module_ownership.toml` is the executable file and public-import
  contract.
- `architecture/route_profiles.toml` is the executable HTTP surface contract.

Community code must run without `ee/`, PostgreSQL, Redis, Supabase, Alembic, or
managed-secret clients. It must never import `shim_enterprise`, including from
optional, lazy, or type-checking paths. Enterprise runtime may import only the
exact public `shim` symbols in the ownership manifest.

## Preserve

- provider-native payload, error, and streaming contracts;
- one provider attempt per admitted request;
- invocation-scoped credential lifetime and redaction;
- privacy fail-closed behavior;
- enterprise transaction order, accounting truth, tenant isolation, and outbox
  semantics; and
- existing database and Alembic identifiers during code movement.

Trace a request through the route, service, kernel, provider execution, and
finalization before changing it. Update both compositions, boundary tests, and
OpenAPI artifacts in the same change when a public contract moves.

Do not add compatibility packages, provider-neutral request models, retry
layers, plugin discovery, generic factories, or duplicate gateway paths without
a demonstrated consumer. Reuse the existing contract or adapter first.

## Required gate

```bash
uv lock --check
uv run --locked ruff format --check src ee/src tests ee/tests scripts ee/scripts ee/alembic
uv run --locked ruff check src ee/src tests ee/tests scripts ee/scripts ee/alembic
uv run --locked ty check
uv run --locked python -m pytest -q
uv run --locked --package shim-gateway python scripts/export_openapi.py --profile community --check
uv run --locked --package shim-enterprise python scripts/export_openapi.py --profile enterprise --check
git diff --check
```

Use `trash` for deletions. Do not commit caches, local environments, secrets, or
build artifacts.

Preserve the mixed-licence boundary: Apache-2.0 applies outside `ee/`, and
Elastic-2.0 applies under `ee/`. Keep both packages' `license`, `license-files`,
`LICENSE`, and `NOTICE` declarations aligned. Do not add a CLA, runtime licence
check, or new commercial terms without an approved policy.
