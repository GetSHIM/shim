# Customer-operated deployment

This chart runs the enterprise API, dashboard, outbox, reconciliation, compliance,
and audit-maintenance workers. PostgreSQL and Redis remain customer-operated;
optional single-instance services are provided for disposable installations.
The chart has no downloaded chart dependencies. Use the signed release's image
digests and its matching chart, not a mutable `latest` tag.

## Prerequisites

- Kubernetes 1.28 or later, Helm, a default storage class when using test services,
  and an ingress controller when exposing the supplied Ingress.
- A dedicated namespace, customer DNS/TLS, PostgreSQL, Redis Stack (the existing
  cache requires its modules), OIDC, and Vault KV v2.
- The current signed `SHIM_LICENSE_KEY`. Licence validation remains offline and
  runs only at production API startup; this package adds no capacity terms.
- Read [identity setup](../docs/ON_PREM_IDENTITY.md) for OIDC client registration,
  group mapping, owner recovery, workload-key revocation, and Vault policy.
- An independently trusted release-verification public key. Verify the delivered
  artifacts before importing images or running their scripts.

Use one HTTPS origin for the dashboard and gateway. The ingress sends `/v1` and
`/v1beta` to the API, and other paths to the dashboard. The dashboard forwards
`/api/v1` internally at runtime using `SHIM_API_URL`; browser sessions and
management requests stay on the same origin. Build the dashboard with
`NEXT_PUBLIC_AUTH_MODE=oidc`; changing that mode requires a different image.
Configure ingress access logs to omit authentication query strings and cookies.

## Configuration and first installation

Create a namespace and an environment file outside source control with mode 0600.
Create `shim-runtime` from that file using
`kubectl -n shim create secret generic shim-runtime --from-env-file=/secure/shim.env`.
Supply these settings (values shown here are examples, not working credentials):

```dotenv
DATABASE_URL=postgresql+asyncpg://shim:REPLACE@postgres.customer.example/shim
REDIS_URL=redis://redis.customer.example:6379/0
SECRET_KEY=REPLACE_WITH_A_RANDOM_SECRET_OF_AT_LEAST_32_BYTES
SHIM_LICENSE_KEY=REPLACE_WITH_THE_ISSUED_LICENCE
OIDC_ISSUER_URL=https://identity.customer.example/realms/shim
OIDC_CLIENT_ID=shim
OIDC_CLIENT_SECRET=REPLACE
OIDC_REDIRECT_URI=https://shim.customer.example/api/v1/auth/callback
DASHBOARD_ORIGIN=https://shim.customer.example
OIDC_ORGANIZATION_ID=00000000-0000-4000-8000-000000000001
OIDC_GROUP_ROLE_MAP={"/shim/owners":"owner","/shim/members":"member","/shim/auditors":"auditor"}
VAULT_ADDR=https://vault.customer.example
MODEL_DEPLOYMENT_ALLOWED_ORIGINS=["https://model-a.customer.example","https://model-b.customer.example"]
```

The initial organization UUID above is a placeholder until provisioning below.
The chart sets `ENVIRONMENT=production`, `AUTH_MODE=oidc`, `SECRET_BACKEND=vault`,
and `MODEL_DEPLOYMENT_REQUIRED=true`. It disables Sentry and OTLP export by default.
Do not select development mode to bypass production secret or licence validation.

Create a `shim-vault-token` Secret with a `token` key, refreshed by your Vault Agent
or secret controller. Mounting a projected Secret permits token rotation without
rebuilding the image. The Vault adapter reads the current token for each operation.
For private CAs, create a ConfigMap containing `ca.pem`, a PEM bundle including all
required roots; the chart sets `SSL_CERT_FILE` and `NODE_EXTRA_CA_CERTS`. Never
disable certificate verification. PostgreSQL TLS configuration remains part of
the database URL/customer database policy.

Create a private `values.yaml`:

```yaml
existingSecret: shim-runtime
gateway:
  image: registry.customer.example/shim-enterprise@sha256:REPLACE
dashboard:
  image: registry.customer.example/shim-dashboard@sha256:REPLACE
vault:
  tokenSecretName: shim-vault-token
caBundleConfigMap: shim-ca
imagePullSecrets:
  - name: customer-registry
ingress:
  enabled: true
  className: customer-ingress
  host: shim.customer.example
  tlsSecretName: shim-tls
networkPolicy:
  extraEgress: [] # Add customer service/proxy destination rules before installing.
```

The default egress policy permits pods in the same namespace and cluster DNS.
Add only required external namespace/IP and port rules for PostgreSQL, Redis,
OIDC, Vault, model endpoints and any explicitly enabled connector. NetworkPolicy
requires an enforcing CNI; verify actual denied traffic, not just resource creation.
For outbound proxies, add `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` to the runtime
Secret; include internal service names/addresses in `NO_PROXY` and allow the proxy
in the network policy. The browser also needs access to its customer OIDC origin.

```sh
helm upgrade --install shim ./chart --namespace shim --create-namespace \
  --values /secure/values.yaml --wait --wait-for-jobs --timeout 10m
kubectl -n shim exec deployment/shim-gateway -- \
  python ee/scripts/activate_plan.py --create-name 'Customer organization' enterprise
```

The migration Job upgrades the database before the applications' schema checks
allow startup. Kubernetes retries failed schema init checks. The migration Job's
default deadline is five minutes; set `migration.activeDeadlineSeconds` from the
measured migration duration and give Helm a longer timeout for application startup.
Provisioning prints the organization UUID; update
`OIDC_ORGANIZATION_ID` in the runtime Secret to that value. Restart all backend
deployments after changing environment-backed configuration:

```sh
kubectl -n shim rollout restart deployment/shim-gateway deployment/shim-outbox \
  deployment/shim-reconciliation deployment/shim-compliance deployment/shim-ai-act
kubectl -n shim rollout status deployment/shim-gateway --timeout=5m
```

For an existing organization, activate its existing UUID instead of creating a
duplicate. Sign in with a mapped owner group, create teams, register two internal
model deployments using Vault-backed credentials, then issue a scoped gateway key.
Exercise one JSON and one streaming request and verify usage and audit visibility.
See [team access](../docs/team-access.md) and [decision evidence](../docs/POLICY_DECISIONS.md).

## Health and operating limits

API readiness checks `/health`; dashboard readiness checks `/login`. Each worker
is ready only after a successful processing pass. Failed/partial passes do not
refresh its local heartbeat. Adjust `workerReadinessMaxAgeSeconds` when changing
worker intervals or measured pass duration (defaults allow the hourly audit job).
Readiness is not proof that every outbox message was delivered; monitor backlog,
dead letters, reconciliation lag, database capacity and the existing metrics.
Worker readiness failures do not trigger restart loops during a database outage.

All application containers run without root, elevated capabilities, a writable
root filesystem, or a Kubernetes service-account token. Writable temporary and
dashboard cache volumes are bounded. Set `gateway.resources`, `dashboard.resources`
and replica counts from measured traffic. Workers remain independent processes.
Compliance ingestion only contacts configured active connectors; leave none active
in an isolated installation. Email, exporters and external model endpoints are
explicit operator choices, not prerequisites for login or inference.

For disposable local databases, enable `postgres.enabled` and `redis.enabled`;
set `POSTGRES_PASSWORD` in `shim-runtime`, point `DATABASE_URL` at `shim-postgres`
with database/user `shim`, and `REDIS_URL` at `shim-redis:6379`. Their image digests
and persistent storage sizes are configurable. These single instances are not an
HA or database backup solution.

## Upgrade, backup and recovery

Before upgrading, record the chart version, both image digests, current Alembic
revision, runtime configuration version and a tested PostgreSQL backup. Preserve
Vault data/keys and the application `SECRET_KEY` using customer backup controls.
Back up Redis when active sessions and encrypted continuation state must survive
recovery; losing it invalidates sessions/continuations and does not erase ledger truth.

Run the same Helm command with the new verified chart/images. It creates a new
migration Job for the release revision. Check the Job and each rollout, perform
login/inference/audit checks, and record results. Never run an Alembic downgrade
against production.

For application rollback, select previously verified images compatible with the
current schema and upgrade with `--set migration.enabled=false`. This disables
both the migration Job and the exact-head init check; compatibility must be
established beforehand. Do not use blind Helm rollback to an incompatible schema.
For disaster recovery, restore the backup into a separate database, confirm its
revision and integrity, restore the corresponding secrets, then test a compatible
application before switching customer traffic. Rehearse this on disposable data.

### PostgreSQL restore rehearsal

Use a separate database and recovery application, leaving the source database and
customer traffic untouched. These commands use PostgreSQL client tools matching
the source server's major version. Configure private libpq service profiles
(`~/.pg_service.conf`, mode 0600): `shim-source` for the source database,
`shim-restore-admin` for a maintenance database with database-creation permission,
and `shim-restored` for the new `shim_restore` database as the application owner
`shim`. Put passwords in a private `~/.pgpass` or your credential helper; do not
put them in command arguments. Use the customer's TLS verification settings in
all three profiles. The application SQLAlchemy URL (`postgresql+asyncpg://...`)
is not a libpq connection string.

```sh
umask 077
PGSERVICE=shim-source pg_dump --format=custom --no-owner --no-acl \
  --file=/secure/shim-before-upgrade.dump
PGSERVICE=shim-source psql --no-psqlrc --tuples-only \
  --command='SELECT version_num FROM alembic_version;'
PGSERVICE=shim-restore-admin createdb --owner=shim shim_restore
pg_restore --exit-on-error --no-owner --no-acl \
  --dbname='service=shim-restored' /secure/shim-before-upgrade.dump
PGSERVICE=shim-restored psql --no-psqlrc --tuples-only \
  --command='SELECT version_num FROM alembic_version;'
```

The destination must be new and empty; do not add `--clean` against a live
database. `pg_dump` takes a consistent logical snapshot while the source remains
online. Record its time and archive checksum with the image digests and Alembic
revision. This archive omits cluster-level roles, grants and tablespaces: restore
those through customer database administration. Compare critical record counts
and audit-chain verification with the captured source evidence; merely listing
an archive or seeing `pg_restore` exit successfully is insufficient.

Create recovery configuration pointing `DATABASE_URL` to `shim_restore`, with an
isolated Redis instance or database index. Preserve the backed-up organization
UUID, `SECRET_KEY`, any existing encryption key, and the corresponding Vault
secret versions. Register a separate recovery dashboard/callback origin with
the customer IdP, and provision its DNS, TLS, namespace secrets and permitted
network destinations. Use the exact chart and application images recorded with
the backup before testing an upgrade:

```sh
helm upgrade --install shim-restore ./chart --namespace shim-recovery \
  --create-namespace --values /secure/restore-values.yaml \
  --set migration.enabled=false --wait --timeout 10m
kubectl -n shim-recovery exec deployment/shim-restore-gateway -- \
  alembic -c ee/alembic.ini current --check-heads
```

The private restore values must name the recovery runtime Secret and recovery
services; they must not reuse source database endpoints. Verify login, existing
request/ledger/audit visibility, audit-chain verification, Vault-backed model
access, and a new disposable workload key. Revoke that key after the test.
Only then rehearse the new chart/images with migrations enabled and repeat the
checks. An application rollback is a separate upgrade to previously verified,
current-schema-compatible images with `migration.enabled=false`; it does not
restore database contents. A successful same-schema restart does not establish
compatibility across a future schema change.

Keep the source installation available until recovery evidence is reviewed and
traffic cutover is explicitly scheduled. Backups contain sensitive tenant data:
retain or dispose of the private archive and recovery resources under customer
policy. This logical database rehearsal does not test Vault disaster recovery,
IdP recovery, point-in-time recovery, or a different PostgreSQL major version.

Troubleshooting starts with `kubectl -n shim get pods,jobs`, the migration Job
logs, and the affected process logs. Schema init failures mean the expected
migration has not completed. Login failures usually indicate issuer/client/redirect,
group mapping, CA, time, or Redis problems. Missing usage/audit projections require
checking outbox readiness and pending/dead-letter events. Never paste credentials,
session cookies, provider payloads or login callback queries into incident records.
