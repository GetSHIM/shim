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
| `admission.context` | The request certainly exceeds the model's catalog context window or input limit (`deny`, `MODEL_CONTEXT_EXCEEDED`), before any rate or token capacity is used. The count is the number of whitespace-separated words of the prompt text, a lower bound for the public tokenizers (OpenAI's, and the Llama, Qwen, Mistral and Gemma families), which split on whitespace before merging. Claude's and Gemini's tokenizers are not published; the same bound is assumed for them, not proven. Earlier turns' thinking and reasoning blocks are not counted. The output limit counts against the window for OpenAI models and registry deployments only: Gemini's is separate, and Claude 4.5 and later accept input plus `max_tokens` above the window and stop at it. A request the provider truncates or compacts itself (Responses `truncation: "auto"`, `context_management`, `compaction`, a compaction block) is not checked; `count_tokens` is never checked. Only a model's own catalog entry is used, never a prefix match. Recorded only on a refusal. |
| `admission.capability` | The catalog says the model lacks tools, structured output or an input modality the request uses (`deny`, `MODEL_CAPABILITY_UNSUPPORTED`). An absent catalog flag is unknown and never refuses; only a model's own catalog entry is used, never a prefix match; OpenAI file parts are not checked (they need not be PDFs, and the catalog's OpenAI `pdf` flag is unreliable); registry deployments are not checked. Recorded only on a refusal. |
| `privacy.input` | Scrubbing masked data (`mask`, `PII_MASKED`), only monitored values (`allow`, `PII_MONITORED`), found no enabled entity (`allow`, `PII_NOT_DETECTED`), was disabled (`skip`, `PII_DISABLED`), found a type whose action is `block`, in content or in a protocol identifier (`deny`, `SECRET_BLOCKED` when a blocked type is `SECRET` or `DB_URI`, otherwise `PII_BLOCKED`), blocked unsupported content (`deny`, `PRIVACY_POLICY_BLOCKED`), or failed closed. Its policy carries the switches and the effective action of every type, so changing an action changes `policy_version`. |
| `privacy.bulk` | The request carried at least the tenant's `bulk_threshold` of distinct detected values (`allow`, `BULK_DISCLOSURE`); recorded beside `privacy.input`, also when that one denies. Its policy carries the threshold. Absent below the threshold or with the alarm off. |
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
| `tenant.privacy_protection_relaxed` | `relaxed`: the switches turned from on to off by name, and `entity_actions.<TYPE>` for a type whose override moved its effective action down the order `block`, `mask`, `mask_last4`, `monitor`, `off`, `placeholder_mode` when it moved from `random` to `stable`, `bulk_threshold` when it was raised or cleared, and `response_scan` when it moved from `count` to `off` |
| `tenant.budget_created` / `tenant.budget_deleted` | `after` / `before`: scope, limits, period, thresholds, enabled flag, and notify targets as `kind` and `endpoint_origin` only |
| `tenant.budget_updated` | `before` and `after` of the fields that changed |
| `tenant.provider_key_policy_updated` | `before` and `after` of `allow_customer_provider_keys` when it changed |
| `tenant.provider_secret_created` / `_verified` / `_rejected` / `_deleted` | `provider`, `name`, `monthly_limit_usd`, `key_rotated` (false) |
| `tenant.provider_secret_updated` | `before` and `after` of `name` and `monthly_limit_usd` when they changed, and `key_rotated` (true when the update replaced the key) |
| `tenant.profile_updated` | `full_name_changed` (the name itself is never written to the immutable chain) and, on a rename, `before` and `after` of `organization_name` |
| `tenant.api_key_updated` | `before` and `after` of the changed fields (`cost_center`, `team`, `team_id`, `allowed_models`) |
| `tenant.model_deployment_updated` | `before` and `after` of the changed configuration fields |
| `tenant.personal_workspace_archived` | `removed`: rows deleted per table when the workspace's only user joined another organization; recorded in the archived workspace's chain |
| `tenant.service_account_created` | `after`: `name`, `role` and `expires_at` of the new service account |
| `tenant.service_account_rotated` / `_deleted` | none beyond the account id in `subject_id` |
| `tenant.budgets_evaluated` | `budgets_evaluated`: how many enabled budgets the manual run evaluated |
| `tenant.oidc_user_provisioned` | `source: "oidc"` and `after`: `role` and `oidc_teams` (team id to role) of the new user |
| `tenant.oidc_user_synchronized` | `source: "oidc"` and `before` and `after` of `role` or `oidc_teams` when a login changed them |
| `compliance.connector_created` / `_updated` / `_deleted` | `after` / `before` and `after` / `before`: `provider`, `status`, and the redacted `config` |
| `compliance.connector_run_requested` | `provider`; recorded before the manual run starts |
| `compliance.forward_target_created` / `_updated` / `_deleted` | `after` / `before` and `after` / `before`: `kind`, `endpoint_origin`, `signed`, `min_severity`, `enabled`; an update adds `destination_rotated` (true when the endpoint or signing secret was replaced) |
| `compliance.oversight_policy_created` / `_updated` / `_deleted` | `after` / `before` and `after` / `before`: `name`, `enabled`, `mode`, `trigger`, `ttl_seconds`, `default_on_timeout` |
| `compliance.oversight_evaluated` | `evaluated`, `created`, `expired` counts of the manual run |
| `compliance.audit_anchored` | `anchor_date` and `row_count` of the manually written anchor |
| `tenant.readiness_declared` | `framework`, `control_id`, `before` and `after` of `status`, and `note_changed` (the note itself is never written to the chain) |

No key, secret reference, masked key, endpoint path or fingerprint is recorded.
The actor of every event is the signed-in user or service account, and `extra.actor_type`
says which: `user_jwt` or `service`. For the two OIDC events the actor
is the user who signed in, and a login that changes nothing records nothing.

Evidence reads are recorded too, once the data is selected, so an export never
contains its own event: `compliance.audit_bundle_exported`,
`compliance.audit_verified` (with `ok`), `compliance.audit_report_generated`,
`compliance.kvkk_report_generated`, `compliance.readiness_report_generated`, `tenant.requests_exported`,
`tenant.billing_exported` and `tenant.evidence_downloaded` (with `kind`,
`period` and `sha256` of the file). Each carries the window `start` and `end` and, where it
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

## Monthly evidence file

On each pass the ai_act worker writes the previous calendar month's evidence
file (UTC) for every organization that is not archived, had at least one request
started in that month, and has no file for it yet. The file is a PDF stored in
`evidence_reports` (`kind` `monthly`) with its SHA-256, size, generation time and
generator version. A row is written once and never changed; a second worker
racing for the same month inserts nothing. Rendering runs off the event loop.
An organization whose file fails counts as an error of the pass, so the worker
writes no heartbeat and the next pass tries again.

The PDF says on its cover that it is a measurement of gateway traffic, not an
audit, an assessment or a certification. Each section names its source table
and window:

1. Traffic: requests and cost per provider and per model, from the spend and
   quota settlements, with unknown prices shown as unknown, never as zero.
2. What left: per provider and entity type, the values masked, monitored and
   blocked, the count of bulk disclosures and the entity types found in
   answers, from `request_lifecycle` metadata. A field the gateway version did
   not record reads "not recorded in this version".
3. What was stopped: policy verdicts with outcome `deny`, by rule and reason code.
4. Who changed what: management actions by action and actor type.
5. Audit chain: the [server-side check](#audit-evidence-bundle) for the month,
   from the latest daily anchor before it, or the reason it could not run.
6. Findings: per rule, the [findings](FINDINGS.md) opened, open at the end and
   resolved in the month.

The file holds counts and names only: no prompt, answer, detected value or key.

The same transaction queues one `evidence.monthly_ready` intent (idempotency key
`evidence:<kind>:<period>`). The outbox worker turns it into one
`compliance.connector_delivery_requested` delivery per enabled
[forward target](COOKBOOK.md#send-tenant-alerts) of the tenant, with the body
`{"source": "shim", "event_type": "tenant_evidence", "kind":
"evidence_monthly_ready", "report_kind": ..., "period": ..., "sha256": ...,
"download": "/api/v1/compliance/evidence/monthly/<period>?kind=<kind>",
"occurred_at": ...}`; Slack and e-mail get one sentence with the period and
the download route. The file itself is never sent.

An operator can write one file with `ee/scripts/generate_monthly_evidence.py
--organization <uuid> --period YYYY-MM`: a closed month is written as `monthly`,
the current month as `monthly_partial` (so a test never takes the closed
month's place), a future month is refused, and so is a period that already has
a file of that kind.

## ISO/IEC 42001 readiness report

`POST /api/v1/compliance/reports/readiness` with `{"framework": "iso42001",
"start", "end", "format": "pdf" | "csv"}` lists the 38 Annex A controls, one row
each, for a window of at most 366 days (default the last 30 days). Owners, admins
and auditors can produce it. It is a paid report behind the tier feature
`readiness_report`; a plan without it gets 403 `PLAN_UPGRADE_REQUIRED` with the
eligible plans. The feature ships switched off on every tier, see
[Turning the report on](#turning-the-readiness-report-on).

Each row has a source:

- `measured` (A.4.2, A.4.4, A.6.2.6, A.6.2.8, A.9.2, A.10.3): numbers from
  `request_lifecycle`, the audit chain, the settlements and the model registry
  over the window, and whether evidence is present by the rule printed beside
  it, for example "present when the window has audit rows, the chain verifies
  and retention is at least 180 days".
- `input` (A.2.2, A.4.3, A.5.4, A.9.4): numbers for the organization's own
  statement, never proof of the control. A.9.4 shows the share of requests
  with a tag or cost center, which says nothing about whether the use was the
  intended one.
- `declared` (the other 28): the organization's statement only, or "not
  declared".

Two rows differ from the 3 September coverage matrix on purpose: A.8.3 is
declared, because stored evidence files do not show a way for interested parties
to report adverse impacts, and A.9.4 is input, as above. A.6.2.4 and A.8.4 stay
declared until continuous evaluation and an incident record exist.

Declarations are kept per organization and control:
`GET /api/v1/compliance/readiness/iso42001/declarations` (readers) and
`PUT /api/v1/compliance/readiness/iso42001/declarations/{control_id}` (owners
and admins) with `status` (`implemented`, `partial`, `not_implemented`,
`not_applicable`) and an optional `note` of up to 2,000 characters; an unknown
control is 404.

The cover says: "This report shows which ISO/IEC 42001 Annex A controls shim can
evidence from gateway traffic, and records the organization's own statements for
the rest. It is not an audit, a certification or a statement of conformity."
The control numbers and titles come from secondary sources; until they are
checked against the purchased standard, `verified_against_standard` in
`shim_enterprise/ai_act/readiness/iso42001.yaml` stays false and the cover adds
"Control numbers and titles have not yet been checked against the published
standard." The five-control framework report (`/reports/audit`) is unchanged.

The CSV starts with the same sentences, one per row, then a blank row, then the
header and the 38 rows. In the PDF a table row cannot span two pages, so an
evidence summary or a note longer than 900 characters is cut there and marked
"(truncated, see CSV)"; the CSV always holds the whole text.

### Turning the readiness report on

The migration that adds the declarations does not grant `readiness_report` to
any tier, so a customer never sees control numbers nobody has checked. The order
is:

1. Every id and title in `shim_enterprise/ai_act/readiness/iso42001.yaml` is
   checked against the purchased standard, and a release sets
   `verified_against_standard: true`.
2. On an installation running that release, an operator grants the feature to
   the enterprise tier:

   ```sql
   UPDATE tier_definitions
   SET features = features || '{"readiness_report": true}'::jsonb
   WHERE slug = 'enterprise';
   ```

   The next request reads it; nothing restarts. To take it away again:
   `UPDATE tier_definitions SET features = features - 'readiness_report' WHERE slug = 'enterprise';`

Declarations can be recorded before the feature is on.
