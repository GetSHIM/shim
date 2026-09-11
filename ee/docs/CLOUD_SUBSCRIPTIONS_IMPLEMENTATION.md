# Cloud subscriptions execution plan

Status: complete for local implementation and verification. Live merchant launch prerequisites are listed below. Owner: Codex. Approved scope: [proposal](CLOUD_SUBSCRIPTIONS_PROPOSAL.md).
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
- [x] Cloud/on-prem dashboard composition — dashboard worker.
  - [x] Add explicit build profiles independent of authentication selection.
  - [x] Preserve plan/interval through login; add pending checkout and portal flows.
  - [x] Enforce owner controls and show activation/failure/cancellation/reset information.
  - [x] Exclude cloud commerce imports/routes from on-prem build artifacts.
  - [x] Add focused browser tests and verify both builds.
- [x] Distribution and contracts — root, with bounded delegation after contracts settle.
  - [x] Explicit package/image selection for community, on-prem, and cloud.
  - [x] Extend import/route profiles and generated backend/frontend API contracts.
  - [x] Wire cloud deployment factory, worker, secrets and migrations.
  - [x] Verify customer images/wheels/bundles contain no cloud commerce/Polar runtime.
- [x] Verification and documentation — root.
  - [x] Start isolated local PostgreSQL/Redis and apply migrations.
  - [x] Run focused unit/integration, SDK transport, authorization and concurrency checks.
  - [x] Run required backend gate, dashboard typecheck/lint/API checks and builds.
  - [x] Review money/security paths and integration independently; resolve findings.
  - [x] Update architecture, provisioning, roadmap and runbook with verified behavior.
  - [x] Record evidence and external Polar sandbox/production prerequisites accurately.
  - [x] Complete the user-requested focused code-cleanup pass and its checks.

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

## Verification evidence

- Final full backend gate: **958 passed, 4 skipped**. The skips are historical
  comparison snapshots unavailable in this checkout. The suite used a fresh
  disposable PostgreSQL database with enterprise and cloud migrations applied.
- `uv lock --check`, Ruff format/lint, Ty, all three OpenAPI checks and
  `git diff --check` pass. Both Alembic schemas match their models.
- Cloud tests: **28 passed**, including real SDK customer 404 handling, typed
  vendor error sanitization, configured product validation, webhook signatures,
  replay/identity conflicts, owner/tenant scopes, concurrent checkout requests,
  billing revision races, cancellation/revocation, crash-safe delivery,
  encrypted/expired URLs, reconciliation deduplication and configuration redaction.
- Dashboard typecheck, lint, both generated API checks and both production builds
  pass. Artifact scans prove commerce absent from the on-prem server/browser
  output. Focused Chromium checks: 8 cloud controls/return tests, 1 on-prem
  absence test, plus the cloud pricing sign-in test. Profile-specific skips are
  intentional. The unrelated live Supabase commercial E2E requires working
  external credentials and was not counted as passing.
- Wheels and sdists for all three profiles pass source ownership, licence and
  commerce dependency checks. Community and on-prem runtime images were built
  and inspected: no cloud code, Polar SDK, or Standard Webhooks runtime.
- Final cloud image: `sha256:3e7c36f73430601fa3983fdbdf50c6d3bf29b7cd9ca682ff2d87351b8c8f606b`.
  Container factory/schema/package inspection passes, including action
  capabilities and migration assets. A full cloud container started, reported
  PostgreSQL/Redis healthy, and rejected an unsigned webhook with HTTP 403.
- Independent quota, SDK/commerce and boundary reviews completed. The typed
  Polar error handling and dashboard action capabilities were corrected and
  regression-tested before the final gate.

## Requested cleanup

The focused `code-cleanup` pass removed five lines in two files:
`ee/cloud/src/shim_cloud/billing.py` no longer scans the same product catalog twice;
`ee/src/shim_enterprise/tenants/plans.py` leaves the final flush to its public
transaction-owning callers. This was deletion/performance cleanup with unchanged
public contracts. Cloud + plan regression checks: **37 passed**; Ruff, Ty and
whitespace checks pass. No additional abstraction or compatibility layer was added.

## Commits and delivery

Backend feature commit: `730a870`. Dashboard feature/capability commits:
`8eb9b92` and `3752021`; verification/docs commit `79078e9` pins its CI contract
to the full backend feature SHA.
These are local commits. Push the backend commit before the dashboard branch so
its cross-repository contract checkout can resolve that SHA. Nothing was pushed,
merged, deployed, or configured in a live Polar account.

The workspace-level `ENTERPRISE_ROADMAP.md` was updated outside either Git
repository to distinguish hosted commerce from on-prem operator provisioning.

## Remaining launch prerequisites and limits

- Real Polar sandbox checkout and production merchant setup require account
  credentials and configured products. Follow `ee/cloud/README.md` for product
  amounts, API scopes, single-subscription enforcement, webhook registration,
  portal behavior, delayed delivery and outage-recovery smoke checks. No live
  purchase or vendor account configuration was performed.
- Quotas use UTC calendar months for both monthly and yearly purchases. Operator
  activation changes authority but does not cancel vendor payment obligations.
- Organization locking fences cap activation against uncapped admissions and
  serializes short admissions per tenant. Measure contention before introducing
  a more complex shared activation barrier.
- Docker ran out of local disk during image verification. Only task-created
  images/cache refs were removed; the disposable PostgreSQL volume recovered.
  Final database gates ran on fresh databases after recovery.
