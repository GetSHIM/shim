# Operator-managed enterprise plans

## Provisioning and subscription transition

Enterprise plans are provisioned by an authorized operator after the existing
commercial approval process. PostgreSQL `organizations.tier` and the existing
`tier_definitions` remain authoritative for access and quota policy. The
enterprise startup licence check is separate and remains offline.

Lemon Squeezy checkout, portal links, webhooks, and configuration are retired.
No migration changes existing organization tiers, API keys, usage, or billing
history. Historical billing columns and `billing_webhook_receipts` stay in the
schema; do not drop or clear them during this transition.

## Provision a new organization

Configure the enterprise environment, apply migrations, and run from the
backend repository using an operator database account:

```bash
uv run --locked --package shim-enterprise python ee/scripts/activate_plan.py \
  --create-name 'Example organization' enterprise
```

The command prints the new organization UUID. It creates the organization,
privacy defaults, and plan in one transaction without an identity account,
password, email, or subscription-service call. Each `--create-name` invocation
creates a separate tenant, even when the display name matches; retain the UUID.
Configure the identity provider for that tenant using this UUID (for OIDC,
`OIDC_ORGANIZATION_ID`) and the deployment's approved owner-group mapping.

Existing organization activation and subsequent plan changes use its UUID:

```bash
uv run --locked --package shim-enterprise python ee/scripts/activate_plan.py \
  ORGANIZATION_UUID enterprise
```

Allowed tiers remain `free`, `managed`, `agency`, and `enterprise`. The command
locks the organization, updates its current plan/source/status, and applies the
tier to active API keys atomically. Newly issued keys inherit it. Revoked keys
stay revoked; usage counters, reservations, and the immutable ledger are not
reset. Unknown tenants/tiers fail without committing a partial change.

## Transition an existing customer

1. Before retiring the old integration in a deployed environment, record each
   affected customer's tenant UUID, approved tier, last billing status/period,
   external references, and the operator responsible for future plan changes.
2. Reconcile any renewal/cancellation/payment obligations through the existing
   commercial process. Removing the integration does not cancel or settle a
   subscription at the billing service.
3. Run the activation command with the customer's approved **existing tier**.
   Change the tier only when that change has been approved. The command retains
   external customer/subscription/variant identifiers, historical period and
   cancellation fields, portal references, and webhook receipts.
4. Verify an existing key still authenticates, a new key inherits the tier, and
   the dashboard shows the expected entitlements and usage. Operator-managed
   status is `active` for paid tiers and `free` for the free tier.
5. Remove the obsolete `LEMON_SQUEEZY_*` deployment values and the billing-service
   webhook destination after the agreed cutover. Deploy the matching dashboard
   contract with the backend.

Historical period/cancellation fields are no longer a renewal schedule. An
operator must apply future access changes according to the existing agreement;
this release adds no automatic expiration or new commercial terms.

## API and verification

`POST /api/v1/webhooks/lemonsqueezy` is removed.
`GET /api/v1/management/subscription` remains a tenant-scoped read endpoint with
`plan`, `status`, `source`, and `entitlements`. Purchase/portal/renewal fields are
removed from its response. The dashboard displays the configured plan and directs
plan changes to an administrator/contact flow.

```bash
uv run --locked python -m pytest -q ee/tests/tenants/test_plans.py
```

These regression checks cover new provisioning, invalid inputs, transitions
across all existing tiers, active/revoked/new keys, tenant separation, historical
billing records, ledger values, and quota counters. They use disposable
PostgreSQL and make no subscription-service calls.
