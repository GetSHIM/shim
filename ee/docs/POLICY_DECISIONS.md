# Gateway decision evidence

Gateway audit events include `policy_verdicts` for the checks actually evaluated.
Each verdict contains `schema_version`, `rule_id`, `rule_version`,
`policy_version`, `stage`, `outcome`, `reason_code`, and `effective_at` (UTC).
`effective_at` is the evaluation time, not a claim about when a configuration
first became effective. Configuration digests or the locked accounting policy
version identify the evaluated snapshot; rule version 1 identifies the shipped
check semantics. No policy document, prompt, response, credential, or raw error
message is included.

The event envelope binds all verdicts to the request, tenant, actor type and
API key or authenticated user. An API key identifies the key, including when
shared: it does not identify its owner as the person making the request.
Unrecognized credentials and policy-resolution failures without a verified
tenant remain sanitized authentication/error telemetry; they are never assigned
to a guessed tenant or user. HTTP/body validation before the gateway invocation
also remains outside tenant decision evidence.

| Rule | Evidence |
| --- | --- |
| `tenant.allowed_providers` | Provider passed or failed the tenant allowlist. |
| `tenant.zero_retention_request` | Required request flags/options passed or failed the gateway's check, or the check was not required. This does not attest to the provider's wider retention practices. |
| `gateway.model_catalog` | Model is supported by the catalog snapshot, or was rejected. Unsupported caller-supplied model text is omitted from rejected enterprise events. |
| `rate.requests`, `rate.tokens`, `rate.repeated_requests` | Configured burst/repeat checks passed, were unlimited, or denied admission. `rate.tokens` counts approximate tokens (serialized request bytes divided by four, rounded up; its policy carries `"unit": "approximate_tokens"`), while quota and spend reservation keep the byte count as their upper bound. A denied amount is not added to its window. Repeated content does not establish an automatic retry. |
| `quota.requests_and_tokens` | Atomic request/token reservation passed or was rejected, using the policy loaded under the accounting lock. The combined limit is not attributed to a particular counter when the atomic check cannot distinguish it. |
| `privacy.input` | Scrubbing masked data (`mask`, `PII_MASKED`), only monitored values (`allow`, `PII_MONITORED`), found no enabled entity (`allow`, `PII_NOT_DETECTED`), was disabled (`skip`, `PII_DISABLED`), found a type whose action is `block` (`deny`, `SECRET_BLOCKED` when a blocked type is `SECRET` or `DB_URI`, otherwise `PII_BLOCKED`), blocked unsupported content (`deny`, `PRIVACY_POLICY_BLOCKED`), or failed closed. Its policy carries the switches and the effective action of every type, so changing an action changes `policy_version`. |
| `spend.provider_monthly` | Provider spending reservation passed, was unlimited, was rejected, or could not be evaluated. Invocation-scoped BYOK remains outside the stored-provider cap; a tenant that turned customer provider keys off rejects it with `PROVIDER_KEY_NOT_ALLOWED`. |
| `gateway.admission` | Other admission validation failed or admission infrastructure was unavailable. |
| `deployment.registry`, `deployment.destination` | A registered deployment alias was allowed or refused: `MODEL_NOT_REGISTERED`, `MODEL_NOT_ALLOWED`, `DEPLOYMENT_UNHEALTHY` (marked unhealthy, 503) or `DEPLOYMENT_NOT_APPROVED`. |

`allow` means that individual check passed; it does not imply that the entire
request completed. `mask`, `deny`, `error`, and `skip` are distinct outcomes.
Later stages are absent when an earlier stage stopped execution. Terminal
lifecycle status remains separate from policy results and provider behavior.

## Durability and failures

Existing short quota, privacy, and spend transactions retain decision snapshots
in lifecycle metadata. Terminal settlement/refund builds the existing audit
completion/outbox event from those snapshots. Failures before a quota lifecycle
exists create an audit completion and committed outbox intent directly, without
usage charges or provider execution. The identity remains
`request:<request_id>:outbox:audit.completion`. Outbox redelivery uses the existing
tenant/request/event deduplication and hash-chain writer.

Admission fences the organization and API-key rows with `FOR NO KEY UPDATE`, so
foreign-key checks from settlement and analytics projection never wait on an admission.

For pre-admission denials, audit mode `off` writes no audit intent. `best_effort`
attempts the transaction and emits a content-free error log if it cannot commit,
preserving the original rejection. `strict` returns `AUDIT_INTENT_FAILED` (503)
when required evidence cannot commit; no provider attempt occurs.

Admitted accounting retains its existing atomic audit behavior: a required
preflight failure prevents provider execution, and an audit completion failure
rolls back settlement for reconciliation. Accounting truth is never discarded to
make evidence delivery appear successful. A strict failure while finalizing a
denial is surfaced instead of swallowed; best-effort failure retains recovery
and a sanitized error log. Database unavailability cannot guarantee new durable
evidence, and best-effort mode must not be described as lossless.

After worker delivery, the tenant-scoped `GET /api/v1/compliance/audit/logs` response
exposes verdicts, caller key/user identity, actor type, and terminal lifecycle
status. Unknown historical fields remain null. The existing chain verifier
continues to verify this evidence.
Decision evidence records existing gateway checks. It is not a configurable
policy engine, content archive, signature or independent trust anchor.

Verification: `uv run --locked python -m pytest -q
 ee/tests/gateway/pipeline/test_decisions.py` covers real quota/spend transactions,
pre-admission denials, masking and privacy rejection, audit failure modes,
redelivery, and chain verification. The repository-wide gate is in [the developer
guide](../../DEVELOPER_GUIDE.md#required-gates).

## Management change details

Management actions append an `audit.chain_append_requested` event in the same
transaction as the change. The audit API returns the stored `extra` object as
written, so these details are readable through `GET /api/v1/compliance/audit/logs`.

| Event | `extra` details |
| --- | --- |
| `tenant.privacy_policy_updated` | `before` and `after` of the privacy switches and of `entity_actions` when they changed |
| `tenant.privacy_protection_relaxed` | `relaxed`: the switches turned from on to off by name, and `entity_actions.<TYPE>` for a type whose override moved its effective action down the order `block`, `mask`, `mask_last4`, `monitor`, `off` |
| `tenant.budget_created` / `tenant.budget_deleted` | `after` / `before`: scope, limits, period, thresholds, enabled flag, and notify targets as `kind` and `endpoint_origin` only |
| `tenant.budget_updated` | `before` and `after` of the fields that changed |
| `tenant.provider_key_policy_updated` | `before` and `after` of `allow_customer_provider_keys` when it changed |
| `tenant.provider_secret_created` / `_verified` / `_rejected` / `_deleted` | `provider`, `name`, `monthly_limit_usd`, `key_rotated` (false) |
| `tenant.provider_secret_updated` | `before` and `after` of `name` and `monthly_limit_usd` when they changed, and `key_rotated` (true when the update replaced the key) |
| `tenant.profile_updated` | `full_name_changed` (the name itself is never written to the immutable chain) and, on a rename, `before` and `after` of `organization_name` |
| `tenant.api_key_updated` | `before` and `after` of the changed fields (`cost_center`, `team`, `team_id`, `allowed_models`) |
| `tenant.model_deployment_updated` | `before` and `after` of the changed configuration fields |
| `tenant.budgets_evaluated` | `budgets_evaluated`: how many enabled budgets the manual run evaluated |
| `tenant.oidc_user_provisioned` | `source: "oidc"` and `after`: `role` and `oidc_teams` (team id to role) of the new user |
| `tenant.oidc_user_synchronized` | `source: "oidc"` and `before` and `after` of `role` or `oidc_teams` when a login changed them |
| `compliance.connector_created` / `_updated` / `_deleted` | `after` / `before` and `after` / `before`: `provider`, `status`, and the redacted `config` |
| `compliance.connector_run_requested` | `provider`; recorded before the manual run starts |
| `compliance.forward_target_created` / `_updated` / `_deleted` | `after` / `before` and `after` / `before`: `kind`, `endpoint_origin`, `signed`, `min_severity`, `enabled`; an update adds `destination_rotated` (true when the endpoint or signing secret was replaced) |
| `compliance.oversight_policy_created` / `_updated` / `_deleted` | `after` / `before` and `after` / `before`: `name`, `enabled`, `mode`, `trigger`, `ttl_seconds`, `default_on_timeout` |
| `compliance.oversight_evaluated` | `evaluated`, `created`, `expired` counts of the manual run |
| `compliance.audit_anchored` | `anchor_date` and `row_count` of the manually written anchor |

No key, secret reference, masked key, endpoint path or fingerprint is recorded.
The actor of every event is the signed-in user. For the two OIDC events the actor
is the user who signed in, and a login that changes nothing records nothing.

Evidence reads are recorded too, once the data is selected, so an export never
contains its own event: `compliance.audit_bundle_exported`,
`compliance.audit_verified` (with `ok`), `compliance.audit_report_generated`,
`compliance.kvkk_report_generated`, `tenant.requests_exported` and
`tenant.billing_exported`. Each carries the window `start` and `end` and, where it
applies, the row count, format, frameworks, connector or grouping. List views
(`/requests`, `/compliance/audit/logs` and the like) are not recorded.

Turning any privacy switch off, or lowering a type's action, also queues, for every enabled forward target of
the tenant, connector-bound or not, one `compliance.connector_delivery_requested`
delivery with aggregate type `organization` and the body `{"source": "shim",
"event_type": "tenant_policy", "kind": "privacy_protection_relaxed", "fields":
[...], "actor": <user id>, "actor_email": <user e-mail>, "occurred_at": ...}`.
Slack and e-mail show the e-mail address. Its key is derived from the audit
event id, so a retry does not duplicate it. A tenant without forward targets
gets the audit event only.
Turning a switch back on, or raising a type's action, records only
`tenant.privacy_policy_updated`.

## Audit evidence bundle

`GET /api/v1/compliance/audit/bundle?start=…&end=…` exports the tenant's audit
chain as a `shim.audit.bundle` v1 file for the independent verifier
(`shim-audit-verify`, whose repository holds the format document `FORMAT.md`; the
document wins where it and this export disagree). Owners, admins and auditors can
call it with a signed-in user session; a gateway API key gets 401. `start` and
`end` are optional: without them the whole chain is exported, from sequence 1
anchored to the genesis hash; a window that starts later carries the first row's
stored link instead. Rows are written exactly as they were hashed, together with
the daily anchors of the days in the window. The genesis salt never leaves the
deployment.

The window is resolved to a sequence range first: from the lowest `seq` written
at or after `start` to the highest written at or before `end`. Rows carry each
instance's own clock, so a row from a slightly skewed instance stays inside the
range instead of showing up as a gap at the window's edge.

Synchronous limits: at most 10,000 rows and 366 anchors (422 beyond), 404 for a
window without rows, and 422 when `start` is after `end`. A tenant that writes
more than 10,000 rows a day exports hour-sized windows; the verifier skips the
anchors of days a window only partly covers, so such windows verify.

The server-side check, `POST /api/v1/compliance/audit/verify`, names its window
`from` and `to`. With `from`, it starts after the latest daily anchor dated
before `from`: it checks that the stored row at the anchor's `to_seq` still has
the anchor's `tip_hash` (`anchor_link_mismatch` otherwise) and verifies every row
from there through `to`, read in pages. Without such an anchor, or without
`from`, it starts at genesis, as before. The 10,000-row budget counts only the
rows read, so a window after a recent anchor stays within it however long the
chain is. The response's `chain_start` (`from_seq`, `anchor_date`) says where the
check started. `POST /api/v1/compliance/reports/audit` runs the same check over
its window.

The trade-off: the anchors live in the same database as the rows. A check seeded
from an anchor proves that the window links to that stored anchor, not that the
rows before it are intact; someone able to rewrite both rows and anchors is not
detected (see "Anchors are local only" in the verifier's `FORMAT.md`). The
anchor check of the same call recomputes the anchors of the days in the window
only. To check a whole chain from genesis, call without `from` (up to 10,000
rows), or export bundles and verify them offline. A float that jsonb
would store in another form (non-finite, or `abs(value) >= 1e16`) is written to
the chain as its string, so every stored row re-hashes as written.

## KVKK exposure report

`POST /api/v1/compliance/reports/kvkk` counts two sources. Compliance connector
findings (provider compliance APIs) appear as before, one CSV row per finding.
A tenant-wide PDF also has a "Gateway detections" section: per entity type, its
KVKK category and the sum of the distinct values per request that the gateway
detected and masked, taken from `request_lifecycle` records started in the
window. The scope line then reads "all tenant connectors and the gateway". The
section holds entity names, categories and counts only, and the header names the
organization by its id. A connector-scoped report and the CSV keep their
connector-only content.
