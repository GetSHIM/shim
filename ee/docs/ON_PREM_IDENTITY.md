# Customer identity and secrets

The connected on-prem composition uses customer OIDC, PostgreSQL, Redis, and
Vault KV v2. Set `AUTH_MODE=oidc` explicitly. Hosted Supabase authentication
remains available with `AUTH_MODE=supabase`; the OIDC path needs neither
`SUPABASE_URL` nor `SUPABASE_KEY` and never initializes a Supabase client.

## Bootstrap and configuration

1. Apply migrations and provision an organization using
   `python ee/scripts/activate_plan.py --create-name 'Pilot organization' enterprise`.
   Record the printed organization UUID. The operator selects capacity separately;
   this guide does not issue a licence or prescribe customer limits.
2. Create a confidential OIDC client with authorization code flow and PKCE S256.
   Register exactly `https://shim.internal/api/v1/auth/callback` as a redirect and
   `https://shim.internal/login` as a permitted post-logout redirect.
3. Configure the following backend variables through Kubernetes Secrets/config:

| Variable | Example or meaning |
| --- | --- |
| `AUTH_MODE` | `oidc` |
| `OIDC_ISSUER_URL` | Exact discovery issuer, e.g. `https://identity.internal/realms/customer` |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | Confidential client credentials |
| `OIDC_REDIRECT_URI` | `https://shim.internal/api/v1/auth/callback` |
| `DASHBOARD_ORIGIN` | `https://shim.internal` |
| `OIDC_ORGANIZATION_ID` | Operator-provisioned organization UUID |
| `OIDC_GROUPS_CLAIM` | Top-level group array claim; defaults to `groups` |
| `OIDC_GROUP_ROLE_MAP` | JSON, e.g. `{"/shim/owners":"owner","/shim/users":"member"}` |
| `OIDC_TEAM_GROUP_MAP` | Optional JSON group-to-team mapping, e.g. `{"/shim/platform":{"team_id":"<UUID>","role":"team_admin"}}`; teams must already belong to the configured organization |
| `OIDC_SESSION_SECONDS` | Absolute session lifetime; default 28,800, maximum 86,400 |
| `OIDC_REVALIDATE_SECONDS` | Refresh/group revalidation interval; default 60, maximum 300 |
| `OIDC_API_AUDIENCE` | Optional, distinct API audience for direct bearer access; absent disables it |
| `OIDC_API_MAX_TOKEN_SECONDS` | Maximum bearer token lifetime; default 300, maximum 900 |
| `SECRET_KEY` | High-entropy shared server secret; protects login state and encrypts Redis session material |

All application replicas use the same issuer/client/tenant mapping and
`SECRET_KEY`. Changing that secret invalidates current login/session material.
`ENVIRONMENT=production` requires HTTPS for issuer, dashboard/callback, and Vault,
a supported managed secret backend, and the existing offline licence check.
Only local development can use HTTP. Never disable certificate verification.

Use a customer CA bundle through `SSL_CERT_FILE` for Python HTTP clients and
`NODE_EXTRA_CA_CERTS` for the dashboard. Standard HTTP(S) proxy and `NO_PROXY`
variables are honored by HTTPX; direct Node-to-API networking must be permitted.
Do not assume a proxy environment variable changes Node fetch routing.

## Identity and authorization contract

The issuer and subject bind an OIDC identity to its local user. First login
requires a valid email and `email_verified=true`; it never adopts a user based
on a matching email. Email collisions require operator resolution. A token
cannot select an arbitrary organization. Changing the configured tenant does
not migrate existing identities. A locally deactivated user stays deactivated.

Only mapped groups grant access. The strongest configured role wins; owner,
admin, member, then auditor. User-supplied profile metadata does not grant roles.
Group removal/downgrade is applied on session refresh, at most
`OIDC_REVALIDATE_SECONDS` after the identity provider reflects the change.
Providers must return a newly signed ID token with current groups on refresh.
A provider without refresh tokens requires sign-in again at revalidation.
Explicit bearer tokens must have the configured API audience, valid signature,
issuer, subject, issue/expiry times, and a lifetime within
`OIDC_API_MAX_TOKEN_SECONDS`; existing tokens may remain valid for that bound.

The browser receives an opaque HttpOnly, SameSite=Lax session cookie, Secure in
production. Token/refresh material is encrypted in Redis, never returned to
browser JavaScript. State, nonce, and PKCE are handled by Authlib. Cookie-based
mutations require the exact dashboard Origin. Redis/identity outages fail
closed. Logout revokes the local session and uses provider discovery for
end-session navigation without exposing an ID token in the browser URL.

Recovery uses the customer's identity-provider administrator: restore access to
a configured owner group, then sign in again. No local password backdoor,
email invitation, or implicit first-user privilege escalation is added. Human
OIDC session revocation and application API-key revocation are separate
lifecycles: removing a human from IdP groups does not revoke workload keys they
created. Revoke workload keys through the administration API when retiring an
integration; local account deactivation also blocks its keys.

To retire a person, a remaining organization owner calls
`DELETE /api/v1/management/team/members/{user_id}` (with their own authenticated
session and the dashboard Origin). This deactivates the local account and
revokes every active key owned by that account in one transaction. It refuses
to remove the last owner: provision another mapped owner first. Remove the
person's IdP groups as well; later IdP login cannot reactivate the local account.
To retire only an integration, call
`DELETE /api/v1/management/api-keys/{api_key_id}`. Verify the retired key returns
HTTP 401 on an authenticated gateway request before closing the offboarding
record. A group-only change intentionally leaves workload keys usable.

Keycloak: map a group-membership claim to both ID/access tokens and enable
verified email for permitted users. Full group paths avoid colliding leaf names.
For Entra ID, use the tenant-specific issuer and application group claims;
explicitly configure a verified email assertion for provisioning. Group-overage
claims requiring Microsoft Graph are not fetched implicitly: require the group
array in the token. Actual Entra tenant acceptance remains required. LDAP/AD
federation belongs in the chosen IdP. Direct LDAP, SCIM, SAML, and local passwords
are outside this increment.

## Vault KV v2

Set `SECRET_BACKEND=vault`, `VAULT_ADDR=https://vault.internal`,
`VAULT_KV_MOUNT=secret`, and `VAULT_TOKEN_FILE=/run/vault/token`.
`VAULT_NAMESPACE` is optional. Use Vault Agent Kubernetes/AppRole auto-auth and a
read-only token-sink mount. shim rereads the token on every request so Agent
renewal/replacement requires no process restart. Tokens never appear in secret
references or database records.

A minimal KV v2 policy for the configured mount is:

```hcl
path "secret/data/shim/*" {
  capabilities = ["create", "read", "update"]
}
path "secret/destroy/shim/*" {
  capabilities = ["update"]
}
```

References pin mount, opaque tenant namespace, object identifier, and numeric
version. Envelopes also verify tenant and purpose. Rotation creates a new object,
so prior references keep their meaning until the existing committed cleanup
path removes them. Deletion destroys the specified version. Vault owns its own
unseal, storage encryption, HA, backups, and token renewal. Fernet remains
forbidden as a production provider-secret backend.

## Dashboard and network contract

Build the enterprise dashboard with `NEXT_PUBLIC_AUTH_MODE=oidc` and run with
`SHIM_API_URL` set to the internal gateway origin. `/api/v1/*` forwards at runtime
only to that configured origin, preserving safe session cookies and redirects.
Browser login/management calls use same-origin paths; no baked public API URL is
used for those calls. Public origin build variables still drive documentation
examples and metadata. Enterprise `/` opens the dashboard; hosted registration,
password reset, invitations, and public playground paths are unavailable.

Permit dashboard-to-gateway, browser-to-IdP, gateway-to-IdP, database, Redis,
Vault, and explicitly configured internal model endpoints. Leave email/hosted
telemetry credentials unset unless intentionally enabling those destinations.
Run enabled workers with the same internal service configuration. Configure
reverse proxy/ingress access logs to omit authentication query strings; shim
redacts `/api/v1/auth/*` query strings from Uvicorn access logs. Production Next
servers should not run with development request logging.

## Verification

Backend checks: `uv run --locked python -m pytest -q ee/tests/tenants/test_oidc.py
ee/tests/secrets/test_vault.py`. These exercise RSA/JWKS validation, Authlib's
actual code/PKCE exchange, tenant/subject binding, email collisions, role removal,
encrypted Redis sessions, Origin rejection, expiry, and logout.

Browser check: run `npm run test:e2e -- e2e/oidc.spec.ts` with
`PLAYWRIGHT_BASE_URL`, `NEXT_PUBLIC_AUTH_MODE=oidc`, `OIDC_TEST_ISSUER`,
`OIDC_TEST_USERNAME`, and `OIDC_TEST_PASSWORD` against disposable services. Never
use production identities or commit credentials. The test creates/revokes a
key, checks account controls and logout, and rejects unexpected browser hosts.
For local Next development with a numeric loopback URL, bind `next dev` to that
same hostname to avoid Next's dev-origin protection blocking hydration.

Production HTTPS/CA, network-denied Kubernetes, IdP lifecycle, and an actual
Entra tenant require operator acceptance in the deployment record; a local mock
or HTTP development run does not establish those results.
