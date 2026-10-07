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
| `rate.requests`, `rate.tokens`, `rate.repeated_requests` | Configured burst/repeat checks passed, were unlimited, or denied admission. Repeated content does not establish an automatic retry. |
| `quota.requests_and_tokens` | Atomic request/token reservation passed or was rejected, using the policy loaded under the accounting lock. The combined limit is not attributed to a particular counter when the atomic check cannot distinguish it. |
| `privacy.input` | Scrubbing masked data, found no enabled entity, was disabled, blocked unsupported content, or failed closed. |
| `spend.provider_monthly` | Provider spending reservation passed, was unlimited, was rejected, or could not be evaluated. Invocation-scoped BYOK remains outside the stored-provider cap. |
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

After worker delivery, the tenant-scoped `GET /v1/compliance/audit/logs` response
exposes verdicts, caller key/user identity, actor type, and terminal lifecycle
status. Unknown historical fields remain null. The existing chain verifier
continues to verify this evidence.
Decision evidence records existing gateway checks. It is not a configurable
policy engine, content archive, signature or independent trust anchor.

Verification: `uv run --locked python -m pytest -q
 ee/tests/gateway/pipeline/test_decisions.py` covers real quota/spend transactions,
pre-admission denials, masking and privacy rejection, audit failure modes,
redelivery, and chain verification. The repository-wide gate is in `AGENTS.md`.

## Management change details

Management actions append an `audit.chain_append_requested` event in the same
transaction as the change. The audit API returns the stored `extra` object as
written, so these details are readable through `GET /v1/compliance/audit/logs`.

| Event | `extra` details |
| --- | --- |
| `tenant.privacy_policy_updated` | `before` and `after` of the privacy switches that changed |
| `tenant.privacy_protection_relaxed` | `relaxed`: the switches turned from on to off |
| `tenant.budget_created` / `tenant.budget_deleted` | `after` / `before`: scope, limits, period, thresholds, enabled flag, and notify targets as `kind` and `endpoint_origin` only |
| `tenant.budget_updated` | `before` and `after` of the fields that changed |
| `tenant.provider_secret_created` / `_updated` / `_verified` / `_rejected` / `_deleted` | `provider`, `name`, `monthly_limit_usd`, `key_rotated` (true only when an update replaced the key) |

No key, secret reference, masked key or fingerprint is recorded.

Turning any privacy switch off also queues, for every enabled compliance forward
target of the tenant's connectors, one `compliance.connector_delivery_requested`
delivery with the body `{"source": "shim", "event_type": "tenant_policy",
"kind": "privacy_protection_relaxed", "fields": [...], "actor": <user id>,
"occurred_at": ...}`. Its key is derived from the audit event id, so a retry does
not duplicate it. A tenant without forward targets gets the audit event only.
Turning a switch back on records only `tenant.privacy_policy_updated`.

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

Synchronous limits: at most 10,000 rows and 366 anchors (422 beyond), 404 for a
window without rows, 422 when `start` is after `end`, and 422 naming the row when
a stored row holds a float that would not survive the round trip (non-finite or
`abs(value) >= 1e16`).

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
