# Enterprise region rules

This file adds to the repository-root `AGENTS.md`.

All runtime source, tests, migrations, operational scripts, generated schema,
and package assets for enterprise capabilities stay under `ee/`. This region is
source-available under Elastic-2.0, not open source. Preserve `ee/LICENSE`,
`ee/NOTICE`, and the matching package metadata; do not add or change commercial
terms without an approved policy.

Enterprise code composes `shim`; it does not copy or patch it. Add a community
import only when its exact module and symbol are deliberately added to
`architecture/module_ownership.toml` with a boundary test.

Enterprise tests may white-box community internals for regression coverage in
this atomic monorepo. Those test imports do not expand the supported runtime
API. Runtime code under `ee/src`, `ee/alembic`, and `ee/scripts` remains
exact-manifest-only.

Preserve these enterprise invariants:

- PostgreSQL is lifecycle, quota, spend, audit, reconciliation, and outbox
  truth; Redis is only an accelerator and continuation store.
- No database transaction spans a provider call.
- Reservation, provider-start, heartbeat, finalization, and reconciliation keep
  their established transaction boundaries.
- External effects originate from committed outbox intent.
- Tenant ownership remains non-null and hot-path references remain
  tenant-scoped.
- Provider credentials never enter relational data or telemetry.
- Schema moves do not rename tables, columns, revisions, constraints, indexes,
  functions, triggers, grants, or production data.

Canonical checks and processes use:

```bash
uv run --locked --package shim-enterprise alembic -c ee/alembic.ini check
uv run --locked python -m pytest -q ee/tests
uvicorn shim_enterprise.application:create_enterprise_app --factory
python -m shim_enterprise.workers.outbox
python -m shim_enterprise.workers.reconciliation
python -m shim_enterprise.workers.compliance
python -m shim_enterprise.workers.ai_act
```

Never downgrade production. Test downgrade only against disposable data and
roll production back with a previous schema-compatible image.
