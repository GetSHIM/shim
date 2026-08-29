# shim repository rules

Read `docs/CURRENT_ARCHITECTURE.md`, `docs/TARGET_ARCHITECTURE.md`, and
`DEVELOPER_GUIDE.md` before changing runtime boundaries.

## Ownership

- `src/shim` and root `tests` are community-owned.
- `ee/src/shim_enterprise` and `ee/tests` are enterprise-owned.
- `architecture/module_ownership.toml` is the executable file and public-import
  contract. Every Python file appears in it exactly once. A new file is added
  there, in sorted order, in the change that creates it, or the ownership tests
  fail as a group with an error that does not name your file.
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

Continuous integration runs on pull requests and on pushes to `main`. Pushing a
branch verifies nothing, so run the gate locally and open a pull request rather
than reading a green tick that is not there.

Use `trash` for deletions. Do not commit caches, local environments, secrets, or
build artifacts.

## The name

The name is `shim`, lowercase, in every position including the start of a
sentence. Four things keep their own casing and are never rewritten: environment
variables such as `SHIM_API_KEY`, HTTP headers such as `X-Shim-Tag`, the
`GetSHIM` organisation handle, and `LICENSE` and `NOTICE`. Renaming a header
breaks callers; renaming an environment variable breaks deployments.

`PROJECT_NAME` in `src/shim/core/community_config.py` carries the name into the
OpenAPI title, so changing it means regenerating both checked-in contracts in
the same change.

## Release and deployment

A merge to `main` deploys nothing. Production is reached only by pushing a tag
of the form `v<major>.<minor>.<patch>`, which is what the Cloud Build trigger
watches. A tag carrying a suffix, such as `v0.1.0-rc.1`, publishes the image,
the SBOM and the provenance attestation without touching production; use it to
exercise a release for real.

`cloudbuild.yaml` declares its deployment substitutions empty on purpose. The
project, the service accounts, the secret prefix, the lock bucket and the
network names live on the Cloud Build trigger, because this repository is
public. Do not fill them in. Two architecture tests fail if you do, and the
failure is the point.

The release workflow publishes artifacts and must never grow a deployment step.
Every `uses:` in every workflow stays pinned to a full commit SHA.

Rolling back production is a traffic change on Cloud Run, not a new tag.

The model catalog workflow opens a pull request and does not merge it. Pricing
feeds cost accounting, so it reaches `main` through review.

Preserve the mixed-licence boundary: Apache-2.0 applies outside `ee/`, and
Elastic-2.0 applies under `ee/`. Keep both packages' `license`, `license-files`,
`LICENSE`, and `NOTICE` declarations aligned. Do not add a CLA, runtime licence
check, or new commercial terms without an approved policy.
