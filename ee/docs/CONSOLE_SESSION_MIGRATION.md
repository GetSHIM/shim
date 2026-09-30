# Console session migration

The Python control plane owns one opaque `shim_session` cookie for hosted and
customer-operated consoles. Provider tokens are encrypted in the coordination
store and never returned to the browser. `GET /api/v1/auth/session` is the typed
identity/workspace/capability contract in both compositions. Workspace IDs and
local user IDs remain stable when display names change. API permissions remain
server-enforced; capability availability does not grant a role.

`user.is_active` separates a verified identity from active workspace membership.
An inactive hosted account can sign in and accept a valid invitation through the
existing `/management/team/invites/accept` endpoint. Ordinary management APIs
still reject it. Hide/block the dashboard for inactive principals, permit the
invitation page, and reread the safe session after acceptance. The
`hosted_invitations` flag means that the identity composition supports invitation
flows; listing/creating invitations still requires owner/admin authorization.

## Hosted provider bridge

`AUTH_MODE=supabase` temporarily preserves existing Supabase UUID-to-local-user
identity. Set `DASHBOARD_ORIGIN` to the single console origin and keep
`SUPABASE_KEY` server-side. Configure the Supabase redirect allowlist for
`DASHBOARD_ORIGIN/api/v1/auth/callback`. The existing `.ConfirmationURL` email
template works with the server-started PKCE signup, recovery and resend flows.
The initiating browser holds only signed login state containing an opaque flow
ID; the verifier and safe return path are encrypted server-side for five minutes.
If an email is opened in a different browser or after expiration, restart the
flow. No implicit provider-token callback is accepted.

Endpoints under `/api/v1/auth`:

| Method/path | Input or behavior |
| --- | --- |
| POST `/password/login` | `email`, `password`; creates cookie, returns `{ok:true}` |
| POST `/register` | `email`, `password`, optional `full_name`, `organization`, `next` |
| POST `/recovery` | `email`, optional validated `next`; recovery lands at `/reset-password` |
| POST `/resend` | `email`, optional `next`; fresh server PKCE confirmation flow |
| GET `/login` | Hosted `provider=google\|github`; optional safe local `next` |
| GET `/callback` | Provider authorization code exchange; safe stored destination |
| GET `/confirm` | Explicit token-hash email link with `token_hash`, `type`, safe `next`; optional custom email-template path |
| POST `/password/reset` | `password`; requires a verified recovery session |
| POST `/account/password` | `current_password`, `password`; verifies current credential and matching subject |
| GET `/session` | Safe principal/workspace/capabilities/team grants; no provider tokens |
| POST `/logout` | Invalidates local session and attempts provider session revocation |

Credential/account POSTs require the exact configured Origin. Management cookie
mutations apply the same check. Refresh uses one store lock per session; a
competing refresh returns 503 with Retry-After. Provider outage/rate limiting
fails the request while retaining the encrypted session; definitive invalid
credentials revoke it. Refresh keeps the opaque cookie ID and absolute expiry.
Sessions, callbacks, authenticated APIs and downloads use private/no-store.
Ingress must preserve cookies, redirects, download/request-ID headers and these
cache rules, and must never rewrite API/auth routes to SPA HTML.

Supabase validates the signed access token through the existing server-side
`JwtIdentityVerifier` (`auth.get_user`), not unverified JWT decoding. Provider
user metadata supplies display fields only. Legacy Bearer API authentication
remains additive during rollback; migrated browser consumers use cookie
transport. Existing organization invitations are SHIM-owned scoped records;
provider email recovery and credential verification remain Supabase-owned.

Remove `tenants/hosted_auth.py` and its routes only after the independently
reviewed Keycloak provider release has proven existing/new/invited account
mapping, recovery/email delivery, deactivation, passkey/MFA/SSO flows, backup and
availability, provider rollback, and retirement of every browser Supabase
consumer. Do not deploy an old unpatched Next artifact as session rollback.

## Keycloak identity trial and linking

`AUTH_MODE=keycloak` uses the same Authlib PKCE/callback/encrypted-session
lifecycle as customer OIDC, but resolves only an explicitly linked
`(oidc_issuer,oidc_subject)` on an existing active local user. It requires signed
ID tokens and verified email. It neither provisions from email nor imports
provider role/groups into SHIM roles. Customer `AUTH_MODE=oidc` retains its fixed
organization and configured group grants independently.

The local-only trial composition is `ee/deploy/identity-trial/compose.yml`.
Its pinned Keycloak realm has a confidential PKCE-required client and synthetic
member. Its displayed local passwords/secrets are fixtures, never production
credentials. Ports bind only loopback. It is a development provider, not a
production deployment recipe.

```sh
docker compose -f ee/deploy/identity-trial/compose.yml up -d
export KEYCLOAK_TRIAL_URL=http://localhost:58080
# Point DATABASE_URL at a disposable migrated PostgreSQL database and
# REDIS_URL at redis://localhost:56381/0; set ordinary local test config.
uv run --locked python -m pytest -q ee/tests/tenants/test_keycloak_trial.py
uv run --locked python -m pytest -q ee/tests/tenants/test_console_session.py ee/tests/tenants/test_oidc.py
```

The explicit trial checks actual Keycloak password/form login, PKCE code
exchange, signed callback, stable local ID/workspace/role, refreshed ID token,
opaque session and logout. HTTPX needs explicit delivery of Keycloak loopback
login cookies in this local-only browser emulation. Ordinary test runs skip the
provider trial unless its URL is supplied; a skipped trial is not acceptance.

For an operator-reviewed account link, first verify the exact issuer, subject,
existing local user ID and organization ID against trusted records. Then:

```sh
AUTH_MODE=keycloak uv run --locked --package shim-enterprise python ee/scripts/link_identity.py ORGANIZATION_UUID USER_UUID EXTERNAL_SUBJECT --operator OPERATOR_ID
```

Set the issuer/client/redirect configuration for the chosen Keycloak deployment.
The script locks tenant then user, rejects inactive/out-of-tenant users,
collisions and replacement bindings, and writes transactional audit intent. It
preserves local identity, role, tenant, API keys and ledger references. Its
operator identity is an audit fact, not an HTTP authorization grant. Run it only
with approved operator database access. A deliberate unlink/relink needs its own
review; email similarity is never linking evidence.

Hosted Keycloak invitation automation is disabled: the capability reports false
until invitation/account recovery continuity is accepted. Operators own explicit
local membership provisioning/linking; Keycloak owns credentials, verification,
recovery, MFA/passkeys and email delivery. Existing pending Supabase/SHIM invites
must be reconciled deliberately before a provider cutover. Unknown/inactive
subjects fail closed. Provider rollback preserves local records and requires
sign-in again; it never restores browser token storage.

## Intervals and coordination acceptance

Requests list/export and billing usage/breakdown/export accept additive
`end_exclusive=true`. Default false preserves inclusive legacy callers. Overview
already uses an exclusive end. New console windows use exact `[start,end)` UTC
bounds without subtracting an epsilon. Requests uses projected event timestamp,
Overview/breakdown use lifecycle reconciliation time, and daily usage uses ledger
creation time; equal bounds do not promise identical rows across these axes.
Requests projection is asynchronous. `generated_at` is query execution time,
not a measured projection watermark.

Run `ee/tests/cache/test_coordination_compatibility.py` against the actual store.
The verified command inventory is GET/SET (EX/NX/XX), GETDEL, DEL, MGET, TTL,
INCR/INCRBY/EXPIRE through EVAL, and the Redis client lock's token-checked Lua
release. Session keys use `identity:session:*` and refresh locks, login-flow keys
use `identity:flow:*` (300s), policy/tier caches use `config:*` (300s), burst/loop
windows use configured TTLs, circuit/probe keys use recovery windows, compliance
pacing uses 60s and connector locks use 1800s, and encrypted privacy continuation
keys use configured TTLs. Runtime uses no streams, Redis JSON/search modules or
Redis accounting ledger. PostgreSQL remains lifecycle/accounting/outbox truth.

The local Valkey 8.1 trial passed these real commands, Lua atomicity, competing
locks, pacing/connector token fencing, encrypted session create/update/revoke and
tenant-isolated privacy continuation tests. A synthetic AOF key survived a local
container restart. This proves the single-node trial, not production failover.
Before switching production, separately accept backups/restores, failover,
persistence/RPO, maxmemory/eviction policy, monitoring, rolling compatibility and
retention/transfer of active encrypted sessions with the unchanged SECRET_KEY.
The existing deployment Redis configuration remains unchanged.
