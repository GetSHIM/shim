# Hosted cloud subscriptions

`shim-cloud` composes the licensed enterprise gateway with Polar commerce. Ship
`ee/Dockerfile` to on-prem customers and build hosted services with
`ee/cloud/Dockerfile`. Customer packages/images do not install `shim-cloud`,
`polar-sdk`, or `standardwebhooks`. Authentication selection is independent:
cloud commerce is selected by the application/build profile, not by Supabase.

## Configure and run

Use the enterprise database, Redis, authentication and offline licence settings,
plus the values in [.env.example](.env.example). Keep tokens in the deployment
secret store. `POLAR_ORGANIZATION_ID` is the merchant organization; customer
`external_id` is the authenticated SHIM workspace UUID.

```bash
uv sync --locked --package shim-cloud
uv run --locked --package shim-cloud python -m shim_cloud.migrate
uv run --locked --package shim-cloud uvicorn shim_cloud.application:create_cloud_app --factory
uv run --locked --package shim-cloud python -m shim_cloud.worker
```

The cloud worker **replaces** `shim_enterprise.workers.outbox`; the other
enterprise workers remain unchanged. Do not run a second plain enterprise
outbox worker against the cloud database: it cannot dispatch commerce events.
The migration command applies the existing enterprise history first, then the
independent `shim_cloud` schema/history. Never downgrade production. Quota
history survives application rollback; on-prem images cannot process cloud
commerce intents and are not a cloud rollback target.

The website uses `NEXT_PUBLIC_BUILD_PROFILE=cloud`. Customer dashboard Docker
builds default to `onprem`; both profiles retain their independently configured
authentication mode. Match `CLOUD_DASHBOARD_URL`, CORS, and (for OIDC)
`DASHBOARD_ORIGIN` to the dashboard's origin.

## Polar setup

Create separate sandbox and production products. This launch has no Lemon
Squeezy subscriber migration. Preserve historical billing references in the
shared database.

| Product choice | Recurrence | Existing website price, USD | Included UTC monthly quota |
| --- | --- | --- | --- |
| `managed:monthly` | One month | 29 | 100,000 requests / 10M tokens |
| `managed:yearly` | One year | 269 | 100,000 requests / 10M tokens |
| `agency:monthly` | One month | 149 | 1M requests / 100M tokens |
| `agency:yearly` | One year | 1,429 | 1M requests / 100M tokens |

Use one unarchived recurring product with one fixed USD price per choice; put
its product UUID in `POLAR_PRODUCTS`. Prices must match the website before
launch; changing either side requires reviewing both. Free remains a local
plan (1,000 requests / 1M tokens monthly), and enterprise contracts remain
operator-managed. Tax, discounts and final totals appear in Polar checkout.

Set `subscription_settings.allow_multiple_subscriptions=false`. Keep automatic
trials/discounts and dunning settings consistent with the approved offer; this
integration adds none. The worker validates merchant/catalog configuration and
performs a fresh customer-state check before checkout. Use the Polar customer
portal for plan changes, payment methods, cancellation and invoices.

Subscribe a Standard Webhooks endpoint to `customer.state_changed`:
`https://YOUR_GATEWAY/api/v1/webhooks/polar`. Store its signing secret as
`POLAR_WEBHOOK_SECRET`. Stable `polar-sdk==0.32.0` handles API calls; pinned
`standardwebhooks` verifies the new `whsec_` secret format directly. The older
SDK convenience webhook helper transforms new secrets incorrectly. Sandbox
and production credentials, merchant IDs, products and webhook secrets must
never be mixed.

## Access and consistency

Owners create checkout/portal requests with a UUID `request_id`. The API commits
an operation and an outbox intent together, returning a pending operation.
Retry an ambiguous API response with the same UUID and identical choice. The
worker makes bounded SDK calls outside database transactions and stores an
encrypted result URL for ten minutes. Results are readable only by the creating
owner in that workspace and use `Cache-Control: no-store`.

A worker interrupted after starting checkout does not blindly repeat creation;
it marks the operation failed on redelivery. A definitively failed/expired
operation requires a new request ID. Polar controls the external checkout URL's
own expiration; the local ten-minute expiry does not cancel that checkout.
The merchant's single-subscription setting prevents a second active purchase.
Rotating the enterprise `SECRET_KEY` invalidates stored transient result URLs.

A browser return URL never grants access. Signed webhooks commit deduplicated
sync intents; the worker fetches current customer state from Polar rather than
applying an old event snapshot. Merchant/customer/workspace bindings and a
billing revision protect against tenant confusion, duplicate/out-of-order
updates and concurrent operator changes. Reconciliation enqueues the same sync
work every five minutes by default.

Exactly one configured active/trialing subscription grants its mapped tier.
Scheduled cancellation retains access until its period ends. No active
subscription grants free; an unknown product or multiple active subscriptions
sets free with `review_required` and records a failed synchronization for review.
Vendor/network failure retains the last verified access state and retries via
the existing outbox. No new local dunning/grace policy is introduced: Polar's
customer-state access decision is authoritative. API reads/checkout returns do
not reset usage, and inference makes no Polar calls.

Quotas are pooled across every key/team in an organization, with UTC calendar
month reset dates independent of payment recurrence. A yearly purchase still
has twelve monthly allowances. Enabling caps seeds current key usage and active
reservations; upgrades, downgrades, key creation/rotation, refunds and renewals
never reset accumulated monthly usage. On-prem tenants retain existing key/team
behavior unless their optional organization caps are explicitly configured.

## Operations and launch verification

Monitor existing outbox readiness, retry/dead-letter counts and lag. Inspect
cloud failures with a restricted operator query; payloads contain identifiers
and digests, not vendor customer documents or checkout URLs:

```sql
SELECT event_type, status, count(*), min(created_at)
FROM outbox_event
WHERE event_type LIKE 'cloud.%' AND status <> 'processed'
GROUP BY event_type, status;

SELECT id, billing_status, billing_event_at
FROM organizations
WHERE billing_source = 'polar'
  AND (billing_event_at IS NULL OR billing_event_at < now() - interval '15 minutes');
```

Alert on stale paid snapshots and unresolved `review_required` status. Preserve
last verified entitlements during outages and restore synchronization before
manual plan changes; the operator activation command switches authority to
`operator`, so subsequent Polar sync cannot overwrite it. Checkout attempts for
an operator plan are rejected. Do not automatically switch authority back.
Changing authority does not cancel an existing Polar subscription; settle or
cancel its payment obligations through Polar before completing that transition.

Before production, verify the real Polar sandbox with the configured merchant:
monthly and yearly checkout, verified activation across two keys, portal plan
change/cancel, signed webhook replay and delayed delivery, period expiration,
and outage recovery. Then validate the production product amounts, webhook
health, scopes, merchant single-subscription setting and dashboard return URL.
These checks need account credentials and actual vendor checkout; mocked HTTP
integration tests do not replace them. Existing API token scopes must permit
organization/product reads, customer-state reads, checkouts and customer sessions.

Local verification, in addition to the repository gate:

```bash
uv run --locked --package shim-cloud python -m alembic -c ee/cloud/alembic.ini check
uv run --locked --package shim-cloud python -m pytest -q ee/cloud/tests
uv run --locked --package shim-cloud python scripts/export_openapi.py --profile cloud --check
```

References: [Python SDK](https://polar.sh/docs/integrate/sdk/python),
[customer state](https://polar.sh/docs/integrate/customer-state),
[webhook delivery](https://polar.sh/docs/integrate/webhooks/delivery),
[subscriptions](https://polar.sh/docs/features/subscriptions/introduction).
