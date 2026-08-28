# SHIM developer guide

Read `docs/CURRENT_ARCHITECTURE.md` before changing provider routes, privacy,
streaming, authentication, accounting, or package boundaries.

## Place code by product

```text
src/shim/                    community runtime and public contracts
tests/                       community and architecture tests
openapi/community.json       community HTTP contract

ee/src/shim_enterprise/      enterprise runtime and adapters
ee/tests/                    enterprise tests
ee/alembic/                  enterprise schema history
ee/openapi/enterprise.json   enterprise HTTP contract
```

Community code must run without `ee/`, PostgreSQL, Redis, Supabase, or managed
secret clients. Enterprise may import only the exact `shim` modules and symbols
declared in `architecture/module_ownership.toml`. Do not bypass the boundary
with lazy imports, `TYPE_CHECKING`, re-export bags, or compatibility packages.

When ownership is unclear, use this rule: code belongs in `shim` only when it
is useful to a local developer and can build, start, and test without enterprise
infrastructure.

## Runtime invariants

- Provider request and response bodies stay provider-native.
- Each admitted request makes at most one provider attempt; SDK retries remain
  disabled.
- Provider credentials are invocation-scoped, consumed once, and absent from
  logs, events, responses, and persistence.
- Missing privacy-continuation state fails closed in community mode.
- PostgreSQL is the enterprise lifecycle and accounting truth. Redis is an
  accelerator and continuation store, never a second ledger.
- No database transaction spans a provider call. Reservation, provider-start,
  heartbeat, finalization, and reconciliation keep their existing commit
  boundaries.
- External side effects are emitted through the transactional outbox.
- Existing table names, constraints, functions, revision IDs, and migration
  order are not changed as a side effect of moving code.

## Local environments

Community:

```bash
cp .env.example .env
uv sync --locked --package shim-gateway
uv run --locked --package shim-gateway shim serve
```

Enterprise with local services:

```bash
cp ee/.env.example ee/.env
docker compose up --build
```

Enterprise from the source environment:

```bash
uv sync --locked --all-packages
uv run --locked --package shim-enterprise alembic -c ee/alembic.ini upgrade head
uv run --locked --package shim-enterprise uvicorn \
  shim_enterprise.application:create_enterprise_app --factory
```

The optional manual dashboard is installed only by the enterprise application.
Set `MANUAL_TEST_DASHBOARD_ENABLED=true` in `ee/.env`, start the enterprise API,
and open `http://localhost:8000/_dev/manual-test`. Never enable it in a shared
or production environment.

## Database workflow

SHIM has one independent enterprise baseline and one linear Alembic history
under `ee/alembic/`. Validate schema changes against disposable data:

```bash
uv run --locked --package shim-enterprise alembic -c ee/alembic.ini heads
uv run --locked --package shim-enterprise alembic -c ee/alembic.ini upgrade head
uv run --locked --package shim-enterprise alembic -c ee/alembic.ini check
uv run --locked --package shim-enterprise alembic -c ee/alembic.ini downgrade base
uv run --locked --package shim-enterprise alembic -c ee/alembic.ini upgrade head
```

Never downgrade a production database. Roll production back to the previous
schema-compatible application image.

Contact-only plan activation is an enterprise operation:

```bash
uv run --locked --package shim-enterprise python ee/scripts/activate_plan.py --help
```

## Required gates

Run the locked full gate before merging a cross-package or enterprise change:

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

Build both distributions when package metadata or package data changes:

```bash
uv build --package shim-gateway --wheel --sdist
uv build --package shim-enterprise --wheel --sdist
```

Inspect the artifacts and install them in clean environments. The community
artifacts must contain no `ee`, `shim_enterprise`, enterprise migrations, or
enterprise direct dependencies. The enterprise wheel must include its runtime
assets and require the exact matching `shim-gateway` version.

## Changing an API or dependency

1. Trace the route through authentication, `GatewayService`, `GatewayKernel`,
   provider execution, streaming, and usage finalization.
2. Change the owning product; keep the other product unchanged unless a public
   contract truly moves.
3. If a public Python symbol changes, update the exact enterprise allowlist and
   both compositions in the same change.
4. If an HTTP contract changes, regenerate both affected OpenAPI documents and
   the enterprise dashboard client.
5. Run the smallest focused test first, then the required gates.

Do not add generic factories, plugin discovery, provider-neutral payload
models, compatibility aliases, branch-bridge migrations, or a second gateway
implementation. Reuse the existing stage and adapter before adding another
abstraction.

## Legal boundary

Apache-2.0 applies outside `ee/`; Elastic-2.0 applies under `ee/`. Preserve both
regions' `LICENSE`, `NOTICE`, and matching package metadata. Do not add a CLA,
runtime licence check, or commercial-validation policy without owner approval.
Never move enterprise source or assets outside `ee/` merely to simplify
packaging.
