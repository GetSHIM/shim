# Cloud subscriptions execution plan

Status: final verification in progress. Owner: Codex. Approved scope: [proposal](CLOUD_SUBSCRIPTIONS_PROPOSAL.md).
Fixed monthly/yearly subscriptions, monthly included organization quotas, fresh
launch without legacy subscriber migration. Preserve on-prem operator provisioning.

## Checklist and ownership

- [x] Inspect current backend/dashboard, roadmap, release boundaries, and Polar SDK.
- [x] Record the approved design and create an active execution goal.
- [x] Shared entitlements and quotas — backend worker + root integration.
  - [x] Add optional organization monthly request/token caps and a billing revision.
  - [x] Extend existing reservation, settlement, refund, and reconciliation scopes.
  - [x] Share locked organization/key tier updates; preserve operator behavior/history.
  - [x] Verify aggregate concurrent use, key rotation/creation, downgrade and refunds.
- [x] Cloud composition and commerce — root.
  - [x] Add the `ee/cloud` uv package, settings, factory, and exact public imports.
  - [x] Implement owner-scoped durable checkout and portal operations.
  - [x] Validate Polar signatures and securely bind webhook customers to tenants.
  - [x] Deduplicate webhook intents and synchronize latest state with revision checks.
  - [x] Add cloud outbox wiring and periodic reconciliation without inference calls.
  - [x] Keep SDK/commerce storage, tests, migrations and scripts out of on-prem assets.
- [ ] Cloud/on-prem dashboard composition — dashboard worker.
  - [x] Add explicit build profiles independent of authentication selection.
  - [ ] Preserve plan/interval through login; add pending checkout and portal flows.
  - [ ] Enforce owner controls and show activation/failure/cancellation/reset information.
  - [x] Exclude cloud commerce imports/routes from on-prem build artifacts.
  - [ ] Add focused browser tests and verify both builds.
- [ ] Distribution and contracts — root, with bounded delegation after contracts settle.
  - [x] Explicit package/image selection for community, on-prem, and cloud.
  - [x] Extend import/route profiles and generated backend/frontend API contracts.
  - [x] Wire cloud deployment factory, worker, secrets and migrations.
  - [x] Verify customer images/wheels/bundles contain no cloud commerce/Polar runtime.
- [ ] Verification and documentation — root.
  - [x] Start isolated local PostgreSQL/Redis and apply migrations.
  - [x] Run focused unit/integration, SDK transport, authorization and concurrency checks.
  - [ ] Run required backend gate, dashboard typecheck/lint/API checks and builds.
  - [x] Review money/security paths and integration independently; resolve findings.
  - [x] Update architecture, provisioning, roadmap and runbook with verified behavior.
  - [x] Record evidence and external Polar sandbox/production prerequisites accurately.

## Agreed HTTP contract

All paths below are relative to `/api/v1`. The existing enterprise
`GET /management/subscription` remains shared and unchanged.

- `GET /management/cloud-billing`: `{plan, status, source, current_period_end,
  cancel_at_period_end, can_manage, can_checkout, can_open_portal, products}`. `products` contains available
  `{plan: "managed"|"agency", interval: "monthly"|"yearly"}` choices.
- `POST /management/cloud-billing/checkout`: body `{request_id: UUID, plan,
  interval}`. Returns `BillingOperationView`.
- `POST /management/cloud-billing/portal`: body `{request_id: UUID}`. Returns
  `BillingOperationView`.
- `GET /management/cloud-billing/operations/{operation_id}`: returns
  `BillingOperationView`: `{id: UUID, status: "pending"|"processing"|"complete"|
  "failed"|"expired", url: string|null, error: string|null}`.
- `POST /webhooks/polar`: signature-authenticated durable intake. No browser
  authority over tenant IDs, product IDs, price amounts or return URLs.

Checkout/portal operation mutations and results require the current workspace
owner. Reuse a `request_id` when retrying an ambiguous operation creation; never
automatically open multiple purchases. Frontend polls pending operations and
redirects only on a completed response; return-from-checkout polls local state.

Backend worker exclusively owns quota models/ledger/admission, tenant model
columns, one additive enterprise migration and quota tests. Root owns
`tenants/plans.py`, cloud runtime, package metadata, shared manifests and
integration. Dashboard worker exclusively owns `SHIM_LP` until handback.
Workers report new Python file paths for root's atomic manifest update and do
not edit root-owned manifests concurrently. Local commits are authorized for verified milestones; no pushing, merging or deployment.

## Evidence

- Shared quota/accounting/plan/deployment focused suite: 108 passed.
- Pinned Polar SDK transport/catalog suite: 18 passed, including interval mismatch.
- Enterprise and cloud migrations applied to disposable PostgreSQL; both Alembic
  models matched after upgrade. Cloud schema revision is `cloud_0001`.
- Cloud runtime Ruff and repository type check passed during integration.
- Initial dashboard typecheck/lint, profile builds, artifact exclusion and browser
  checks passed. Return-flow and generated cloud-contract integration are undergoing
  their final recheck.
- Docker builder-stage checks passed for all three package selections. Complete
  runtime inspection is continuing within local Docker disk limits.
- Real Polar checkout is not run: sandbox/production merchant credentials and
  configured products are external prerequisites documented in `ee/cloud/README.md`.
- Docker ran out of local disk during concurrent artifact verification; only the
  task's community build cache was removed, then the disposable PostgreSQL volume
  recovered successfully. Full integration checks run after recovery.


## Final integration evidence

- Full backend suite on fresh migrated PostgreSQL: 956 passed, 4 historical
  comparison snapshots unavailable/skipped. Follow-up cloud tests cover periodic
  reconciliation dedup/expiry and hidden configuration credential values.
- Real SDK 404 regression caught and fixed: all typed Polar errors derive from
  `PolarError`; first checkout accepts customer-not-found, other failures remain
  sanitized. SDK and webhook contracts use transport/signature checks, not only
  mocked service functions.
- Wheel and sdist checks pass for all three profiles: correct licence, source
  ownership, and cloud-only commerce dependency metadata.
- Community runtime image `8d2900dbd01b` and on-prem runtime `13b322b875c9`
  were inspected: no cloud or Polar packages/code. Task-created images/caches were
  removed after inspection to recover local Docker space.
- Cloud runtime image built; migration module and all three packages plus pinned
  Polar are present. Factory has exactly five commerce paths; HTTP health reports
  connected PostgreSQL/Redis and an unsigned webhook returns 403.
- Organization locking fences first-cap activation against already-started
  uncapped admissions. It serializes short admissions within a tenant; measure
  contention before introducing a more complex shared activation barrier.
- Dashboard initial implementation committed as `8eb9b92`. Final action
  capability alignment and CI backend revision pin follow after backend commit.
