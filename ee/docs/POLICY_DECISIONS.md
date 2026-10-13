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
| `task.agent_loop` | The latest assistant turn's tool calls (names and canonical arguments) were seen at least `agent_loop.repeats` times within `LOOP_WINDOW_SECONDS` for the request's task (else its key): `allow`, `AGENT_LOOP_SUSPECTED` while the action is `count`, and once above the threshold with `block`, `deny`, `AGENT_LOOP_DETECTED` (429). Its policy carries the action and threshold. Absent below the threshold or with the action `off`. |
| `task.limit` | Only for a request with a task id while a task cap is set: `allow`, `TASK_LIMIT_PASSED`; `deny`, `TASK_LIMIT_EXCEEDED` (429) when the task reached `max_calls` or its recorded cost reached `max_cost_usd`; `error`, `TASK_COUNTER_UNAVAILABLE` when the counter could not be reached (the call goes on). Its policy carries the caps. |
| `inflight.share` | The request received the answer of an identical request of the same key that was in flight on the same replica: `skip`, `INFLIGHT_RESPONSE_SHARED` (stage `provider_spend`). No spend was reserved and no provider call was made for it. Absent otherwise. |
| `quota.requests_and_tokens` | Atomic request/token reservation passed or was rejected, using the policy loaded under the accounting lock. The combined limit is not attributed to a particular counter when the atomic check cannot distinguish it. |
| `admission.context` | The request certainly exceeds the model's catalog context window or input limit (`deny`, `MODEL_CONTEXT_EXCEEDED`), before any rate or token capacity is used. The count is the number of whitespace-separated words of the prompt text, a lower bound for the public tokenizers (OpenAI's, and the Llama, Qwen, Mistral and Gemma families), which split on whitespace before merging. Claude's and Gemini's tokenizers are not published; the same bound is assumed for them, not proven. Earlier turns' thinking and reasoning blocks are not counted. The output limit counts against the window for OpenAI models and registry deployments only: Gemini's is separate, and Claude 4.5 and later accept input plus `max_tokens` above the window and stop at it. A request the provider truncates or compacts itself (Responses `truncation: "auto"`, `context_management`, `compaction`, a compaction block) is not checked; `count_tokens` is never checked. Only a model's own catalog entry is used, never a prefix match. Recorded only on a refusal. |
| `admission.capability` | The catalog says the model lacks tools, structured output or an input modality the request uses (`deny`, `MODEL_CAPABILITY_UNSUPPORTED`). An absent catalog flag is unknown and never refuses; only a model's own catalog entry is used, never a prefix match; OpenAI file parts are not checked (they need not be PDFs, and the catalog's OpenAI `pdf` flag is unreliable); registry deployments are not checked. Recorded only on a refusal. |
| `privacy.input` | Scrubbing masked data (`mask`, `PII_MASKED`), only monitored values (`allow`, `PII_MONITORED`), found no enabled entity (`allow`, `PII_NOT_DETECTED`), was disabled (`skip`, `PII_DISABLED`), found a type whose action is `block`, in content or in a protocol identifier (`deny`, `SECRET_BLOCKED` when a blocked type is `SECRET` or `DB_URI`, otherwise `PII_BLOCKED`), blocked unsupported content (`deny`, `PRIVACY_POLICY_BLOCKED`), or failed closed. Its policy carries the switches and the effective action of every type, so changing an action changes `policy_version`. |
| `privacy.restore` | Only when the caller's key and team are outside a [restore grant](COOKBOOK.md#show-masked-values-only-to-some-teams): at least one placeholder of a withheld type stays in the answer (`mask`, `RESTORE_WITHHELD`) or none was in the request (`allow`, `RESTORE_NOT_NEEDED`). Its policy carries the sorted withheld types. Absent for every caller a grant does not concern. |
| `privacy.bulk` | The request carried at least the tenant's `bulk_threshold` of distinct detected values (`allow`, `BULK_DISCLOSURE`); recorded beside `privacy.input`, also when that one denies. Its policy carries the threshold. Absent below the threshold or with the alarm off. |
| `spend.provider_monthly` | Provider spending reservation passed, was unlimited, was rejected, or could not be evaluated. Invocation-scoped BYOK remains outside the stored-provider cap; a tenant that turned customer provider keys off rejects it with `PROVIDER_KEY_NOT_ALLOWED`. |
| `gateway.admission` | Other admission validation failed or admission infrastructure was unavailable. |
| `rule.<id>` | A tenant rule matched (see [Tenant rules](#tenant-rules)); at most 32 per request, blocks first. Its `policy_version` is a digest of the rule and the set's revision. |
| `rules.evaluated` | A rule matcher ran for the request (`allow`, `RULES_EVALUATED`); its `policy_version` is a digest of the revision. Absent when none ran: no rules, none in scope, or only rules this release cannot run. |
| `deployment.registry`, `deployment.destination` | A registered deployment alias was allowed or refused: `MODEL_NOT_REGISTERED`, `MODEL_NOT_ALLOWED`, `DEPLOYMENT_UNHEALTHY` (marked unhealthy, 503) or `DEPLOYMENT_NOT_APPROVED`. |
| `aws.region_lock` | A Bedrock deployment met the tenant's region lock and the operator's ceiling: `BEDROCK_REGION_ALLOWED`, `BEDROCK_REGION_OUTSIDE_LOCK` (monitor mode, allowed) or `BEDROCK_REGION_NOT_ALLOWED` (403, before any AWS call). Not recorded when the lock is off and no ceiling is set. |

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
Decision evidence records the gateway's checks and the tenant's own rules. It is
not a content archive (unless the self-hosted [request archive](#request-archive)
is turned on), signature or independent trust anchor.

Verification: `uv run --locked python -m pytest -q
 ee/tests/gateway/pipeline/test_decisions.py` covers real quota/spend transactions,
pre-admission denials, masking and privacy rejection, audit failure modes,
redelivery, and chain verification. The repository-wide gate is in [the developer
guide](../../DEVELOPER_GUIDE.md#required-gates).

## Tenant rules

A tenant keeps one rule set: `GET` and `PUT /api/v1/management/rules`, replaced
whole, with the revision it was read at (a stale one answers 409
`RULE_SET_REVISION_CONFLICT`). Each rule has an `id`, a `kind`, an `action`, a
`state` (`monitor` or `enforced`), a `scope` (API keys, teams, tags, models,
deployment kinds, endpoints; an empty list means every one) and a kind-specific
`match`. A `models` entry is compared with the model the request reaches, never
the registry alias the caller named, case-insensitively, and covers that model's
dated snapshots (`gpt-5-mini` covers `gpt-5-mini-2025-08-07`, not `gpt-5`). A new rule starts in `monitor`. The `term`, `pattern`, `record_set`,
`destination` and `request_limit` kinds are available; `GET /rules` lists the others with
`available: false` and the reason.

A `record_set` rule matches a hashed customer list or confidential documents' fingerprints
in the same pass; see [record sets](RECORD_SETS.md).

Content rules (`term`, `pattern`) are searched inside the privacy stage, on the
same normalized text as the built-in detectors (percent-decoded, invisible
characters and the combining dot of a lower-cased `İ` removed, NFKC), and only
for the rules in scope for the request.
Every term of a rule in scope is found, a shorter one inside a longer one too;
a rule out of scope or in state `monitor` never hides one that is enforced. Where
matches overlap, each other and built-in detections, the strongest enforced
action wins (`block` > `require_approval` > `mask` > `warn` > `monitor`, where a
`monitor`-state rule counts as `monitor` and a built-in type as its own action),
then a built-in type, then the longer span, then the earlier. Masking never
yields: every built-in mask stays, and a rule match with any enforced `mask` rule
is masked even when another rule on it holds or blocks, joining any mask it
overlaps into one placeholder (typed by the built-in value, else by the longer
match). So a `block` term inside a masked value still refuses, a held term
inside an e-mail address is held and the address still masked, and a term
inside a value a built-in type only monitors is masked. An enforced `mask` match
is replaced by a `<LABEL_…>` placeholder and counted in `pii_entities` under its
label; `block` and `require_approval` matches keep the text for the decision
point. Rule matches never enter `monitored_entities` or `blocked_entities`.
Protocol identifiers are not searched, and a term in one never refuses a request.

### Destination rules

A `destination` rule names 1 to 32 built-in entity types (`match.entity_types`) and
needs at least one scope list (422 `RULE_SCOPE_REQUIRED` without one), typically
`deployment_kinds: ["external"]`. A `block` rule also needs a list the server
decides (keys, teams, models or deployment kinds): tags and the endpoint are the
caller's choice, so a block scoped by them alone is refused with the same code. A target is `internal` or `external` as its
[deployment](MODEL_DEPLOYMENTS.md) says; a catalog route and every Gemini request
are `unknown`, which a scope listing `external` matches. For a request in the rule's
scope, the privacy stage looks for every type the rule names, also when the base
action is `off`. The action applied to the text is the stronger of the base action
and every enforced `mask` rule naming the type (`block` > `mask` > `mask_last4` >
`monitor` > `off`); a rule never weakens the base action, and a rule in state
`monitor` only counts. Each rule whose types were found records a `rule_matches`
entry counting the distinct values; an enforced `block` refuses at the decision
point with `RULE_BLOCKED`, and `warn` adds `RULE_WARN`. A type the base itself
blocks keeps `PII_BLOCKED` or `SECRET_BLOCKED`, decided first. A value found only
because a rule named its type is sent unchanged unless an enforced `mask` applies,
and counts in `monitored_entities`. Like an enforced content rule, an enforced
`block` destination rule refuses images and files it cannot search. To keep a type
inside, set its base action to the weakest action wanted everywhere and add a rule
that tightens it for external targets.

### Request limits

A `request_limit` rule caps what a request may carry: `max_tools`, `max_documents`,
`max_history`, `max_input_bytes`, measured on the request as the client sent it, and
`below_price_tier`. It is evaluated in admission, after the output bounds and the
context checks and before the rate limits, so a refused request consumes no
requests-per-minute or tokens-per-minute window, repeat count or quota; an enforced
`block` refuses there with `RULE_BLOCKED`, its `rule.<id>` verdict, `rules.evaluated`
and the match in `rule_matches`. Token
counting is exempt: no request-limit rule is evaluated or recorded for it, since it
reaches no model and is how a client decides what to trim. `below_price_tier`
applies only to catalog models with a large-context price tier: when the request's
whitespace-separated words already exceed the tier, the crossing is certain and the
rule's action applies; when only its approximate size (bytes / 4) exceeds it, the
crossing is possible and the rule records a `warn` match whatever its action, so it
never refuses a request that may be under the tier.

Rules are evaluated in the `rules` stage, after the base privacy decision, which
wins when both refuse. The verdict of each matched rule:

| Match | Outcome | `reason_code` |
| --- | --- | --- |
| action `monitor` | `allow` | `RULE_MONITORED` |
| state `monitor`, any other action | `allow` | `RULE_WOULD_<ACTION>` (`RULE_WOULD_BLOCK`, `RULE_WOULD_ROUTE`, ...) |
| enforced `block` | `deny` | `RULE_BLOCKED`: 400, `X-Shim-Rule-Id`, no provider call |
| enforced `mask` | `mask` | `RULE_MASKED` |
| enforced `warn` | `allow` | `RULE_WARN`, and the `RULE_WARN` response warning |
| enforced `require_approval` | `allow` / `deny` / `error` | `RULE_APPROVED`, `APPROVAL_REQUIRED`, `APPROVAL_REJECTED`, `APPROVAL_QUEUE_FULL`, `APPROVAL_UNAVAILABLE` |
| evaluation timed out, enforced `mask`, `block` or `require_approval` | `deny` | `RULE_BLOCKED` |
| evaluation timed out, any other rule | `error` | `RULE_EVALUATION_TIMEOUT` |
| stored rule this release cannot run, enforced, in scope | `deny` | `RULE_BLOCKED` |

Fail closed: an enforced `mask`, `block` or `require_approval` rule whose
evaluation fails blocks the request with `RULE_BLOCKED`, recorded `rejected`
like any rule block (its `rule_matches` entry carries `error: true`); an
enforced `require_approval` rule without an approval gate is a block too, and a
gate that cannot be reached answers 503 `APPROVAL_UNAVAILABLE` with no provider
call. Any other evaluation error is recorded and the request continues. Token
counting never asks for approval: it answers 403 `APPROVAL_REQUIRED`.

A release older than the one that wrote a rule set may find a rule it cannot
run: a kind it has no matcher for, or an action, field or scope list it does not
know. Such a rule is kept, never dropped, and never makes the tenant
unavailable. In state `enforced` with an action other than `monitor` or `warn`
it refuses every request in its scope with `RULE_BLOCKED` (a scope the release
cannot read is every request); otherwise it is skipped. The gateway logs each
one once per revision, by id. `GET /rules` lists them as stored under
`unavailable_rules`, and a `PUT` keeps them as they are.

The request record carries `rule_matches` (rule id, kind, action, state, count;
at most 32, blocks first) and `rule_matches_truncated`; see
[diagnostic metadata](DIAGNOSTIC_METADATA.md). Terms and patterns stay in the
database row and in process memory, never in Redis, a log, a metric or an audit
event.

### Request approval

An enforced `require_approval` rule holds a request before it is sent; the
existing oversight queue (`ai_act` oversight policies) reviews requests after
they were sent and is unchanged. The enterprise gateway decides in one short
database transaction, never open across the provider call:

- "The same request" is a keyed digest: HMAC-SHA256, under a key derived for
  this purpose from `COMPLIANCE_HASH_SALT` (else `SECRET_KEY`), of the tenant,
  key, protocol, model, `stream` and the canonical JSON of the request as it
  entered the privacy stage. Unmasked, because random placeholders would make
  every masked request unique. Only the digest is stored, and only while the row
  can still be used: a row that becomes `used`, `expired` or `rejected` clears
  it, because the digest is derived from a request that may carry personal data.
  `request_approvals` holds ids, counts, sizes and times, never content, a term
  or a pattern, and the audit maintenance worker deletes a row 30 days after it
  was held (in batches, like the request archive).
- One approval allows one send, within 60 minutes of the approval; it is
  consumed before the provider call, so a failed attempt needs a new approval.
  A pending approval lives 24 hours; at most 200 wait per tenant and 50 per key,
  so one key cannot fill the queue. These are constants, not settings. The
  gateway and every read of the approvals API store `expired` as they meet an
  overdue row, and each audit maintenance pass (hourly by default) expires every
  tenant's overdue rows in batches of 1,000, each statement bounded to 10
  seconds, so an untouched row keeps its request digest at most one interval
  past its expiry (`request_approvals_expired` in the pass summary).
- A presented `X-Shim-Approval-Id` that does not fit (unknown, another tenant
  or key, another request, used, expired, malformed) is ignored rather than
  refused, so ids cannot be probed and a changed request gets its own approval.
  A rejected id is refused for its key whatever is sent with it, since the
  rejected row kept no digest.
- The approver is always a second person: never a service account, nor the key's
  owner, nor the recorded requester, nor whoever created or rotated the key of a
  service account that owns the key, whatever the tenant's
  [four eyes](#four-eyes) setting (that governs settings changes). With nobody on
  record to exclude, nobody decides. `POST /approvals/reject` with an
  `api_key_id` rejects every pending request of that key as one decision, under
  the same rule (audited as `tenant.request_approvals_rejected` with the count).
- Decisions are audited as `tenant.request_approval_approved` and
  `tenant.request_approval_rejected` (approval id, rule ids, key id, model,
  request id). The creation and the use are on the requests themselves, as
  `approval_id`. `shim_request_approvals_total{outcome}` counts gate outcomes,
  `shim_request_approval_decisions_total{decision}` decisions.

## Request archive

Self-hosted only, off by default, and only for requests a rule or a detector
matched. It needs two switches: the installation's `REQUEST_ARCHIVE_ENABLED`
(with an `ENCRYPTION_KEY`, or the gateway does not start; the hosted cloud
refuses to start with it) and the tenant's `request_archive.enabled` in the
gateway settings. `GET /gateway-settings` shows `request_archive_state` and, when
the installation does not allow it, the reason under `unavailable`.

- **What is kept.** A request whose privacy step masked, monitored or blocked a
  value, or that any tenant rule matched (monitor state included: during a
  "watch before masking" rollout this is what the admin needs). A clean request
  and a token count are never kept, and neither is the answer. Kept: the masked
  payload as the provider received it and the edit (placeholder to original),
  each Fernet-encrypted with `ENCRYPTION_KEY`, plus `matched` (entity types and
  rule ids with action and count, never a value). Nothing else is in the clear.
- **The write never fails the request.** It runs after the privacy facts commit,
  encrypts in a worker thread and inserts in one short transaction; any failure
  is logged by type, counted as `shim_request_archive_writes_total{result="failed"}`
  and the request goes on unchanged. A payload above 2,000,000 bytes is skipped
  (`skipped_size`). The request record says `stored` only when the row committed.
  A request sent again under a held [request approval](#request-approval) (while
  it waits, or once approved) has the same digest, so the same content: when the
  first held request is kept, the resend is not (`result="duplicate"`, no record
  marker); open the held request's row instead.
- **90 days at most.** A tenant may shorten `retention_days` (1 to 90), never
  lengthen it; shortening moves existing rows' expiry forward in the same
  change. The ai_act worker deletes expired rows in batches of 1,000, at most 50
  per pass, whatever the switches say. The owner can delete the whole archive at
  once (`DELETE /request-archive`, audited as `tenant.request_archive_purged`).
  A deleted row stays in database backups until they rotate and in PostgreSQL's
  storage until vacuum: keep backup retention in line with the 90 days.
- **Only an admin opens content, and every opening is visible.** Owners and
  admins (`content.read`, never a service account) open one request; the opening
  is audited as `tenant.request_content_opened` and committed before anything is
  decrypted. Auditors see every opening, a member the openings of requests made
  with their own keys; nobody else reads the text. Content never appears in a
  list, an export, a log or a finding.
- Turning the archive on or keeping content longer is a loosening change for
  [four eyes](#four-eyes); turning it off or shortening is tightening.

## Imported gateway logs

A tenant can [import a LiteLLM spend log](COOKBOOK.md#import-litellm-spend-logs)
to see findings before routing traffic through shim. The import is an operator
script, not a connector: no API caller ever names an internal address for shim
to fetch. Its rows live in `external_usage_records` and nowhere else; they are
the source's claim (its status, timings, tokens and `spend`) and never touch
`request_lifecycle`, `usage_ledger`, budgets, quotas or evidence built from
gateway records. The findings they raise carry `source: litellm`, use the
source's cost labelled `cost_source: litellm`, and say when a signal is weaker
than its gateway counterpart (`litellm.retry_burst` compares token counts, not
content). Prompts and answers in an export are ignored: only their presence is
counted. Nothing free-form is stored either: no user, team, tag or endpoint, a
model only under a price-book or registry name (else `other`), a key only as a
SHA-256 digest, and a cost only when it is a finite amount from 0 up. The worker
never evaluates `litellm.*` rules; an import does, with windows ending at the
latest imported row.

## Management change details

Management actions append an `audit.chain_append_requested` event in the same
transaction as the change. The audit API returns the stored `extra` object as
written, so these details are readable through `GET /api/v1/compliance/audit/logs`.

| Event | `extra` details |
| --- | --- |
| `tenant.privacy_policy_updated` | `before` and `after` of the privacy switches and of `entity_actions` when they changed |
| `tenant.privacy_protection_relaxed` | `relaxed`: the switches turned from on to off by name, and `entity_actions.<TYPE>` for a type whose override moved its effective action down the order `block`, `mask`, `mask_last4`, `monitor`, `off`, `placeholder_mode` when it moved from `random` to `stable`, `bulk_threshold` when it was raised or cleared, `response_scan` when it moved from `count` to `off`, `embeddings_monitor_types.<TYPE>` for a type added to the embeddings-only list, and `rules.<id>` for an enforced tenant rule that was removed, moved to `monitor`, given a weaker action, a narrower scope or a match other than added terms or patterns |
| `tenant.rules_updated` | `revision`, and `added`, `changed` and `removed` rules as `id`, `kind`, `action`, `state`, the non-empty `scope` keys, `match_changed` and entry counts (`{"terms": 12}`), and `policy_version`; never a term, pattern, name or match hash |
| `tenant.rule_previewed` | `rule_id`, `kind`, `basis`, `requests`, `window_days`, `enforce_on_create` |
| `tenant.rules_imported` | `plan_id` (null when nothing would change), `mapped` and `not_mapped` counts, `source_revision` |
| `tenant.gateway_settings_updated` | `before` and `after` of the gateway settings fields that changed, and `policy_version` |
| `tenant.gateway_protection_relaxed` | `relaxed`: the gateway settings fields whose change their direction classifies as relaxing; written with the update |
| `tenant.budget_created` / `tenant.budget_deleted` | `after` / `before`: scope, limits, period, thresholds, enabled flag, and notify targets as `kind` and `endpoint_origin` only |
| `tenant.budget_updated` | `before` and `after` of the fields that changed |
| `tenant.provider_key_policy_updated` | `before` and `after` of `allow_customer_provider_keys` when it changed |
| `tenant.provider_secret_created` / `_verified` / `_rejected` / `_deleted` | `provider`, `aws_role_arn` (null unless a role), `name`, `monthly_limit_usd`, `key_rotated` (false); an AWS check's rejection adds `step` and `aws_error` |
| `tenant.provider_secret_updated` | `before` and `after` of `name`, `monthly_limit_usd` and `aws_role_arn` when they changed, and `key_rotated` (true when the update replaced the key) |
| `tenant.aws_identity_created` | none beyond the organization id in `subject_id`; the external id is never written to the chain |
| `tenant.profile_updated` | `full_name_changed` (the name itself is never written to the immutable chain) and, on a rename, `before` and `after` of `organization_name` |
| `tenant.api_key_updated` | `before` and `after` of the changed fields (`cost_center`, `team`, `team_id`, `allowed_models`) |
| `tenant.model_deployment_updated` | `before` and `after` of the changed configuration fields |
| `tenant.personal_workspace_archived` | `removed`: rows deleted per table when the workspace's only user joined another organization; recorded in the archived workspace's chain |
| `tenant.service_account_created` | `after`: `name`, `role` and `expires_at` of the new service account |
| `tenant.service_account_rotated` / `_deleted` | none beyond the account id in `subject_id` |
| `tenant.custom_role_created` / `tenant.custom_role_deleted` | `after` / `before`: `slug`, `name` and `permissions` of the role (`slug` and `permissions` on delete) |
| `tenant.custom_role_updated` | `before` and `after` of the changed `slug`, `name` and `permissions` |
| `tenant.member_custom_role_changed` | `before` and `after`: the member's custom role slug, `null` for none |
| `tenant.budgets_evaluated` | `budgets_evaluated`: how many enabled budgets the manual run evaluated |
| `tenant.oidc_user_provisioned` | `source: "oidc"` and `after`: `role`, `custom_role` (slug or null) and `oidc_teams` (team id to role) of the new user |
| `tenant.oidc_user_synchronized` | `source: "oidc"` and `before` and `after` of `role`, `custom_role` or `oidc_teams` when a login changed them; `api_keys_revoked` when the login revoked the user's keys |
| `compliance.connector_created` / `_updated` / `_deleted` | `after` / `before` and `after` / `before`: `provider`, `status`, and the redacted `config` |
| `compliance.connector_run_requested` | `provider`; recorded before the manual run starts |
| `compliance.forward_target_created` / `_updated` / `_deleted` | `after` / `before` and `after` / `before`: `kind`, `endpoint_origin`, `signed`, `min_severity`, `enabled`; an update adds `destination_rotated` (true when the endpoint or signing secret was replaced) |
| `compliance.forward_target_change_announced` | `subject_id` only: the target whose endpoint moved while four eyes was on; recorded with the notice to the old endpoint, never an endpoint |
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

Turning any privacy switch off, lowering a type's action, or relaxing an enforced tenant rule also queues, for every enabled forward target of
the tenant, connector-bound or not, one `compliance.connector_delivery_requested`
delivery with aggregate type `organization` and the body `{"source": "shim",
"event_type": "tenant_policy", "kind": "privacy_protection_relaxed", "fields":
[...], "actor": <user id>, "actor_email": <user e-mail>, "occurred_at": ...}`.
Slack and e-mail show the e-mail address. Its key is derived from the audit
event id, so a retry does not duplicate it. A tenant without forward targets
gets the audit event only.
Turning a switch back on, or raising a type's action, records only
`tenant.privacy_policy_updated`.

## Policy versions and plans

Eleven resources are managed: every write to them records a version, a plan can
change them, and a restore can put them back.

| Resource | Item | Fields | Write paths | Relaxing when |
| --- | --- | --- | --- | --- |
| `privacy` | `_` | the five switches, `entity_actions`, `placeholder_mode`, `bulk_threshold`, `response_scan`, `embeddings_monitor_types` | `PUT /settings/pii` | the change records `tenant.privacy_protection_relaxed` |
| `gateway_settings` | `_` | every gateway settings field | `PATCH /gateway-settings` | a field's direction says so (`four_eyes` turned off, a finding rule moved to `auto`); a field without a direction always; `restore_withheld` records `tenant.privacy_protection_relaxed` |
| `rules` | rule id | the rule without its id | `PUT /rules` | an enforced rule is removed, moved to `monitor`, given a weaker action, a narrower scope, another kind, or a match other than added terms or patterns; the opposite move (a wider scope, a stronger action, enforcing) tightens |
| `teams` | team id | `name` and the three limits | `POST /teams`, `PUT /teams/{id}` | a limit is raised or removed |
| `api_keys` | key id | `allowed_models`, `team_id` | `PATCH /api-keys/{id}` | a model is added or the list removed; the key leaves its team or moves to another |
| `deployments` | deployment id | every registration field and `enabled` | `POST`, `PUT /model-deployments` | created; enabled; `external` to `internal`; any change but `owner`, `declared_version`, `timeout_seconds` |
| `budgets` | budget id | scope, limits, thresholds, `enabled`, notification targets (kind, origin and a digest of the stored reference, never the URL) | `POST`, `PATCH`, `DELETE /cost/budgets` | deleted; a limit raised or removed; disabled; a threshold removed; the targets replaced |
| `oversight_policies` | policy id | `name`, `enabled`, `mode`, `trigger`, `ttl_seconds`, `default_on_timeout` | `POST`, `PATCH`, `DELETE /compliance/oversight/policies` | deleted or disabled; `default_on_timeout` to `allow`; any change to `mode`, `trigger`, `ttl_seconds` |
| `provider_keys` | `_` | `allow_customer_provider_keys` | `PUT /settings/provider-keys` | turned on |
| `forward_targets` | target id | `enabled`, `min_severity` | `PATCH`, `DELETE /compliance/forward-targets/{id}` | deleted; disabled; `min_severity` raised |
| `record_sets` | set id | `active_revision`, and `enforced` (read only: an enforced rule uses the set) | `POST /record-sets/{id}/revisions/{n}/activate` | another revision of a set an enforced rule uses (any revision can drop records); a revision that lacks a record or document of the active one also records `tenant.privacy_protection_relaxed` |

Each resource lists, per field, the direction of a change (one shared rule,
`classify_fields`); a field it does not list is `relaxing` whatever the change,
so a field added later fails closed until its direction is written down. A field
moved the other way is `tightening`, a listed label `neutral`; a change with both
a relaxing and a tightening field is `relaxing`, and so is a plan with one
relaxing change. Lowering cost (a lower budget, a disabled deployment) counts
as tightening. A forward target's destination is a secret, so a plan never
creates one or moves it; its own route does. Provider credentials, connectors,
members, invitations, service accounts, key issue, rotation and revocation,
memberships, finding status and readiness declarations are not managed. A
restore never brings back a budget's notification targets (their secrets are
deleted when replaced): they stay as they are and the budget is listed in
`not_restored` with `notify_targets_not_restored`.

Each managed write takes the organization row lock and, when its items changed,
inserts one `policy_versions` row in the same transaction: the next `version`
number, `previous` and `snapshot` (the before and after state of only the items
it changed, `null` for an item that did not exist), `source` (`api` for a direct
write, `plan`, `restore`, and later `mcp`, `file`, `auto`, `import`,
`proposal`), `risk`, the actor and its type. A write that changes nothing records
no version. The audit details of these writes gain `policy_version`, the version
they belong to; a write without a version carries none.

A plan (`policy_plans`) is a change set with each change's before and after
state, risk and estimated impact, created as `draft` and expiring after 7 days.
Each change also needs what its own route asks for: `settings.write` for
privacy and provider keys, `rules.write` for rules, `teams.manage` for teams,
`deployments.manage`, `budgets.manage`, and `compliance.manage` for oversight
policies and forward targets; a key change follows the key
route's rules (`keys.manage` for a key without a team, team administration for
a team's key). This is checked when the plan is created, again for the one who
applies it, and for every item a restore puts back (403
"Permission required: <permission>"). Creating a plan also runs the checks the
routes run before writing, so a change naming a team, model alias or provider
secret the organization lacks, or a secret of another provider, answers 422,
and so does a change that sets nothing new.
Applying it checks that every item still has the stored before-state
(`PLAN_STALE` otherwise), writes every change through the same code as the
direct routes, records one version and marks the plan `applied`. Impact counts
`request_lifecycle` rows of the window (`started_at`) that the change would
have affected: requests carrying an entity type whose action changes (`null`
for a type that was `off`, since it was never detected), a key's requests for
models it would no longer allow, a deployment's requests, and requests above a
lowered team limit. A budget reports its month-to-date use against the new
limit, and an oversight policy has no estimate.

A rule change is tightening when it adds an enforced rule, enforces a rule,
raises its action or only adds terms or patterns to an enforced rule. A plan
creates a rule with `{"resource": "rules", "item": null, "set": {"id": ...}}`;
its impact is the [rule preview](#rule-previews).

Restoring a version applies a plan with source `restore` that puts every item a
version touched back to its state at that version. A revoked key
(`key_revoked`), a deleted record set (`record_set_deleted`) or forward target
(`forward_target_deleted`), a team created after it (teams cannot be deleted)
and a re-created budget's notification targets are listed in `not_restored`,
and so is an item whose own
route would refuse that state now (a deleted provider secret, a disabled model
alias, a deployment origin no longer allowed, a team name another team took),
with the route's message as the reason; the rest is restored. A deployment
created after the version is disabled and listed in `approximated`. A restore
sent with `expected_version` answers 409
`{"code": "POLICY_VERSION_CHANGED", "version": <current>}` when the current
version is no longer that one, and changes nothing. A restore, like a plan,
holds at most 100 changes (422 beyond; restore a later version first), and a
privacy field added after the restored version takes its default. Reading the
current state (`/policy/state`) or one version's states needs, besides
`audit.read`, the reads of what they show: `settings.read`, `usage.read`,
`rules.read` and `deployments.read` (403 naming the missing ones). Plans applied
after the version and before the restore was planned become `rolled_back`; a
plan applied while a restore waited for approval keeps `applied`. Audit actions: `tenant.policy_plan_created`,
`tenant.policy_plan_applied` (`plan_id`, `risk`, `resources`, `policy_version`)
and `tenant.policy_version_restored` (`target_version`, `plan_id`,
`policy_version`).

### Four eyes

With the gateway setting `four_eyes` at `relaxing`, a change that loosens
protection needs a second administrator. Turning it on needs at least two
active human users whose permissions hold `plans.approve` (409
`FOUR_EYES_UNAVAILABLE` otherwise, also when a plan turning it on is applied).
While it is on, demoting or removing one of them below two answers the same 409
(`PATCH`, `DELETE /team/members/{id}`); an identity-provider role change at
sign-in is applied, since the provider is the source of roles, and leaves the
owner override below.

- A direct write to a managed resource that classifies as relaxing is refused
  before anything is written: 409 `{"code": "CHANGE_REQUIRES_APPROVAL",
  "relaxed": [...]}`, each entry `resource.item.field` (or `resource.item` for a
  created or deleted item), a field listed when changing it alone would relax.
  `PUT /rules`, `PUT /settings/provider-keys` and `PATCH`, `DELETE
  /compliance/forward-targets/{id}` are such writes, and so is activating
  another revision of a record set an enforced rule uses. `POST /api-keys` without
  `allowed_models` answers the same 409 with `api_keys.new.allowed_models`:
  create the key with a model list and widen it through a plan.
- Applying a relaxing plan, or a restore whose plan relaxes, does not apply it:
  the plan becomes `pending_approval` with `submitted_by` and `submitted_at`,
  expires 72 hours later, and the call answers 202. The same transaction queues
  one `policy.approval_requested` intent (idempotency key
  `policy_approval:<plan_id>`: organization, plan id, risk, resources and
  submitter, never a value), which the outbox worker sends to every enabled
  forward target as `kind: "policy_approval_requested"`.
- `POST /policy/plans/{id}/approve` (`plans.approve`) applies it with the stale
  check, `approved_by` and `approved_at`; `POST .../reject` makes it `rejected`.
  Either needs a `pending_approval` plan (409 `PLAN_STATE_CONFLICT`) and a human
  who neither created, submitted nor (for a configuration file) signed it, nor
  created or rotated a key of the
  service account that did (403 `APPROVER_NOT_ELIGIBLE`). An
  optional `note` is kept on the plan as `context.decision_note`.
- Turning `four_eyes` off is relaxing. While fewer than two users can approve,
  an owner may still turn it off directly: the write gets a version, the audit
  event `tenant.four_eyes_single_admin_override` and a
  `gateway_protection_relaxed` alert naming `four_eyes`.
- A forward target's destination is a secret, so a plan cannot move it, and
  `PATCH /compliance/forward-targets/{id}` with a new `endpoint` is not refused:
  one administrator could otherwise redirect alerts, and with them these
  announcements. Instead, while four eyes is on, the same transaction first
  queues one delivery to the target's old endpoint (same delivery path and
  address checks as every forward delivery): `kind: "forward_target_changed"`
  with the target id and kind, who changed it and when, never the new endpoint
  or a secret. It also records `compliance.forward_target_change_announced`
  (target id only). If the delivery cannot be queued the move is refused (503)
  and the endpoint stays; once queued, a failed send follows the outbox retry.
  Delivery keeps the old secret until the notice is sent, then deletes it.
  Disabling or deleting a target is already a relaxing change, so it already
  asks for a plan.

Tightening and neutral writes and plans are unchanged, and with `four_eyes`
`off` none of this applies. Audit actions: `tenant.policy_plan_submitted`,
`tenant.policy_plan_approved` and `tenant.policy_plan_rejected` (`plan_id`,
`risk`, `resources`).

### The recommender and its apply limit

A service account with the role `recommender` (an agent, through the MCP server)
creates plans for any resource, since what it may change is decided when the plan
is applied, not when it is proposed. `POST /policy/plans/{id}/apply` and `POST
/policy/versions/{version}/restore` take `plans.apply` or `plans.apply_allowlisted`.
A caller with only the second is checked by `policy/allowlist.py` after the stale
check and before anything is written:

- the plan must be `tightening` (`plan_not_tightening`) and not a rule proposal
  (`proposal_needs_human`);
- each change must change an existing item (`create_or_delete`) through an
  allowlist entry for its resource (`not_allowlisted`), only in the entry's fields
  (`extra_fields`) and in the allowed direction (`wrong_direction`);
- an entry with an impact bound recomputes the change's impact now, over its
  window, and refuses when it is unknown (`impact_unknown`) or above the bound
  (`impact_too_large`);
- an entry with a proof needs refusal rows to measure: audit mode `off` refuses
  it (`proof_unavailable`);
- a plan holds at most 5 changes (`too_many_changes`).

Any refusal answers 403 `{"code": "PLAN_NOT_ALLOWLISTED", "changes": [{"index",
"resource", "item", "reason"}], "message", "hint"}`. The plan stays `draft` (a
refused restore creates none), and `tenant.policy_plan_apply_refused` (plan id,
risk, reason codes; never a before or after value) is committed before the 403.
An allowlisted plan tightens by construction, so four eyes never holds it.
Approving and rejecting stay with `plans.approve`, which no service account holds.
Before the check, a paused tenant (`auto_remediation_paused`) answers 409
`AUTO_REMEDIATION_PAUSED` and a tenant with 20 agent applies in 24 hours 429
`REMEDIATION_LIMIT` (shim's own fixes count apart). The check recomputes impact,
so it runs before the tenant lock; the pause and the limit are checked again under it. The five entries and what happens after an applied change
(the measurement window, the automatic undo, the undo route) are in
[automatic fixes](FINDINGS.md#automatic-fixes); the worker's own fixes for `auto`
findings pass the same check.

Two decisions there:

- **The automatic undo skips four eyes.** It is relaxing by classification, but it
  returns each item to the exact state a person had in place, and the stale check
  stops it when anything else changed since. Holding it for a second approver
  would keep a change that measurably broke traffic in place while it waits. The
  condition is narrow: source `auto` and a reason starting `remediation:`. An undo
  a person asks for is an ordinary restore and four eyes holds it.
- **One remediation per finding, ever.** A unique index on (tenant, finding) stops
  the worker from retrying a fix that was skipped, set back or undone; that
  finding only suggests from then on, and a person decides. A refusal that
  passes (the day's limit, a pause, `proof_unavailable`) writes no row, so it is
  retried on the next pass.

### Rule proposals

An agent turns the user's own sentence into rules and sends them to `POST
/rules/proposals` (`plans.create`). shim calls no model and parses no sentence: it
judges whether each rule is concrete from the examples the user gave, with the
same matcher the gateway uses (`count_rule_matches`).

- **A vague sentence gives no rule.** A `term` or `pattern` rule needs at least one
  example it must catch. It is refused with a question when it has none
  (`missing_examples`), when a term is a generic word for a kind of information
  (`too_generic`, against a packaged stoplist of Turkish and English words, compared
  after Turkish folding), when it fires on a packaged 3,000-word neutral office text
  (`too_broad`), when it misses its own example (`example_not_matched`) or catches a
  counter-example (`no_match_example_matched`). A search that times out counts as a
  miss on an example and as a hit on the neutral text. No rule at all is `no_rules`.
  `destination` rules name entity types and a scope and need no text examples. Any
  question answers 422 `RULE_PROPOSAL_NEEDS_EXAMPLES` with every question of every
  rule; a shape or set error answers 422 `RULE_PROPOSAL_INVALID` with field paths at
  the request's own indices. The stoplist, the text and the checks carry
  `PROPOSAL_CHECKS_VERSION` (now 1), recorded on every proposal.
- **Proposals only add rules**, of the kinds `term`, `pattern` and `destination`, all
  in `monitor`; an id already in the set is `RULE_ID_EXISTS`. At most 20 proposals
  wait per tenant (409 `RULE_PROPOSAL_LIMIT`). In file mode nothing is stored: the
  409 `CONFIG_FILE_MANAGED` carries `validated_rules` for the signed file.
- **The sentence is never stored.** The plan (source `proposal`) holds the rules and
  `context.proposal`: the checks version, an HMAC of the sentence with whitespace
  collapsed (`sentence_digest`, keyed per purpose from the installation's base key),
  its length, its language, the channel (`mcp` or `api`) and how many examples each
  rule had. The examples are never stored, logged, audited or returned. Audit
  `tenant.rule_proposal_created`: plan id, rule count, count per kind, term count,
  channel.
- **Only a person turns a proposal on.** A plan with source `proposal` is applied only
  by a human holding `plans.apply`; any service account, of any role, gets 403
  `PROPOSAL_NEEDS_HUMAN` (a recommender is already refused by the allowlist with
  `proposal_needs_human`). Adding monitor rules loosens nothing, so four eyes does not
  hold it. Enforcing a rule afterwards is a separate change by a person.

### Configuration file

A tenant can manage `privacy`, `gateway_settings` and `rules`, or any non-empty
subset of them, from a signed YAML file instead of the panel ([keep the policy in
Git](COOKBOOK.md#keep-the-policy-in-git)). The mode is its own managed resource,
`config_mode` (item `_`, fields `mode` and `resources`), stored in
`organization_config_modes`; no row means `api`. It is never file-managed and every
change to it is neutral, since it decides where changes come from, not what they
allow. `PUT /config/mode` is owner-only (`config.manage`) and turning file mode on
needs an active signing key (409 `CONFIG_NO_SIGNING_KEY`).

- **What a signature covers.** Ed25519 over `shim-config-v1\n`, the pushing
  tenant's lowercase id, `\n` and the file's exact bytes. The prefix stops a config
  signature from verifying as anything else, the tenant id stops a file signed for
  one tenant from applying to another, and the file's `serial`, which must be
  above the last applied one (409 `CONFIG_SERIAL_STALE`), stops an older signed
  file from being replayed. The signature string is `<key_id>.<signature>`, both
  base64url without padding as licence keys are; `key_id` is the first 32 hex
  characters of the SHA-256 of the raw public key. Only an unrevoked key of the
  tenant whose holder is active and may still create plans verifies; anything else is 403
  `CONFIG_SIGNATURE_INVALID`, without saying which check failed. Keys belong to
  human users who may create plans, at most ten active per tenant; adding one
  records `tenant.config_signing_key_added` and sends the tenant alert
  `config_signing_key_added`, because a new key can change policy. Revoking the
  last key while the mode is `file` is 409 `CONFIG_LAST_SIGNING_KEY`; revoking a key
  expires its file plans still waiting.
- **The 409.** While a resource is file-managed, every write to it from another
  source is refused before the route body runs: 409 `CONFIG_FILE_MANAGED` with the
  resource and a hint. This covers direct API writes (`PUT /settings/pii`, `PATCH
  /gateway-settings`, `PUT /rules`), plans from any other source at creation
  (`api`, `import`, and later `mcp`, `proposal`, `auto`), a plan created before the
  switch when it is applied, and restores, which skip file-managed items and list
  them in `not_restored` with reason `file_managed`. The check runs before the
  four-eyes check. Reads are unchanged.
- **Applying a file.** `POST /config/apply` (`plans.apply`) verifies the signature,
  parses and validates the file, checks the serial, expires older waiting file
  plans, and turns the differences into one plan with source `file` and `context`
  `serial`, `key_id`, `signer_user_id`, `registered_by` (who registered the key)
  and `file_sha256`. Parsing, validating and previewing run without the tenant
  lock, which every request of the tenant waits on; a policy write in between
  answers 409 `POLICY_VERSION_CHANGED` (push again). A file holds at most 50,000
  YAML nodes, and one file is parsed at a time: privacy and gateway
  settings one change each, rules deleted first, then updated, then created, so
  the 100-rule limit holds at every step; a file plan holds up to 250 changes. The
  plan applies through the same code as any plan, so a new `enforced` rule still
  needs its preview. Anything refused rolls back the whole push, serial included.
  A file with no difference only moves the serial (`status: unchanged`). Audit
  `tenant.config_file_applied` (serial, key id, plan id, status, file SHA-256).
  `POST /config/plan` (`plans.create`) computes the same plan, says whether a given
  signature is valid, and stores nothing.
- **Four eyes with files.** Under `four_eyes: "relaxing"` a relaxing file waits in
  `pending_approval` (202) like any relaxing plan. Besides the plan's creator and
  submitter, the person who signed the file (`context.signer_user_id`) and the
  person who registered its key (`context.registered_by`) cannot approve it, so a loosening change needs a second person even when CI pushed it
  with a service account. Tightening and neutral files apply at once.

Audit actions: `tenant.config_mode_changed` (before and after `mode` and
`resources`), `tenant.config_signing_key_added` (key id, holder),
`tenant.config_signing_key_revoked` (key id), `tenant.config_exported` (version,
resources) and `tenant.config_file_applied`.

## Rule previews

The gateway keeps no prompt, so it cannot replay last week's traffic against a
new term list. A preview counts only what is honest:

- `monitor_history`: a rule in the set whose kind, scope and match are unchanged
  has one `rule_matches` entry per request it matched. The count runs from the
  later of the window start and the moment its definition last changed
  (`rule_definitions`, a keyed digest of kind, scope and match, never the terms;
  a rule stored before that table existed is bounded by the set's last write).
  Requests whose matches were cut at 32 make it a lower bound.
- `metadata`: a kind whose condition can be checked on stored request metadata
  registers an estimator under its kind or `<kind>:<match.on>`
  (`rules/estimators.py`). The scope is the gateway's: the model the request
  reached (date suffix stripped, case folded), never the alias, and `unknown`
  targets count as `external`.
  - `destination` counts requests whose record shows a named type in
    `pii_entities` or `monitored_entities`. A type whose base action is `off`
    was not detected, so it is not counted and the note names it; a type the
    base action blocked is not counted, because the rule would not change that
    request.
  - `request_limit` counts each request that crossed any cap once: the byte cap
    on the quota reservation (requests with media parts left out and counted in
    the note), the price tier on the settled `LARGE_CONTEXT_PRICE` warning (an
    upper bound of what an enforced block refuses before the call), and the
    tool, document and history caps on the `shape` analyzer's counts, which only
    some rows carry (the note says how many). With a shape cap and no shape row
    in the window, it gives no estimate.
  - `term`, `pattern`, `record_set`, `parameter_pin` and most `route` variants
    need content or have no estimator.
- `none`: anything else, or a query over 10 seconds.

So content rules start in `monitor`, and their preview becomes real after they
have run. A new rule may be stored enforced only with an unexpired preview row of
the same kind, action, scope and match that covered a whole window of at least 7
days; a restore may re-create an enforced rule without one, because it brings
back exactly what was there. A new rule has no monitor history, so only a
`metadata` estimator can give it such a preview: `destination` and
`request_limit` rules can start enforced after one, other kinds start in
`monitor`, and so does a `request_limit` rule with a tool, document or history
cap for a tenant without the `shape` analyzer. Every write to the rule set goes through
one path, which also keeps the definition rows.

AIUC rule files are imported one way. Rule ids become `aiuc_<slug>` (Turkish
fold, ASCII, at most 48 characters, `_2`, `_3` for collisions, the first 8 hex
of the id's SHA-256 when nothing is left); every imported rule starts in
`monitor` with Turkish endings on. `email` and `secret` map to the per-type
actions of `EMAIL_ADDRESS` and `SECRET`, raised from `off` to `monitor` only:
AIUC rules have no scope, a separate rule kind for built-in types would duplicate
the detector, and an import never raises a type to `mask` or `block` (the AIUC
action is reported as a hint). The import produces a draft plan and applies
nothing. It plans without holding the tenant lock (each planned change reads
history), then takes the lock and answers 409 `POLICY_VERSION_CHANGED` if a
policy write landed in between. The body is counted as it arrives: past 256 KB it
is a 413 `REQUEST_TOO_LARGE` before anything is parsed.

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

### Write-once archive

Optional and off: with `WORM_ARCHIVE_ENABLED` and an S3 bucket created with
Object Lock and a default retention, the ai_act worker copies, under
`<WORM_ARCHIVE_PREFIX>/<organization_id>/`, the audit chain in `shim.audit.bundle`
v1 chunks of at most 10,000 rows (`audit/rows/<from>-<to>.json`, each verifiable
on its own from its `chain_start`), each daily anchor (`audit/anchors/<date>.json`)
and each closed monthly evidence file (`evidence/monthly/<YYYY-MM>.pdf`, never a
partial month). Never the request archive, findings or anything with content.

- **What it adds.** Copies the bucket's lock protects: in compliance mode no one,
  root included, can delete or overwrite a locked version before its retention
  ends. The bundle chunks verify with `shim-audit-verify` without the database.
- **What it does not.** PostgreSQL rows stay as they are: the append-only triggers
  keep the application from changing them, but a database superuser can still
  drop them; the bucket copy is what survives that. shim never sets a retention
  mode, date or legal hold: the bucket's default retention decides, and choosing
  governance or compliance and the period is the operator's decision. shim
  refuses to upload unless the bucket reports Object Lock with a default
  retention (`BUCKET_NOT_LOCKED`) and records a `NOT_LOCKED` failure when an
  uploaded object reports no lock.
- Each upload carries its SHA-256 checksum; after a crash, an object already in
  the bucket with the same checksum is recorded without a second upload. At most
  50 objects a pass; a failure is recorded per object and retried with the same
  range. Uploads run outside any database transaction. Each S3 call gives up
  after 5 seconds to connect or 30 to read, with one retry, and a whole pass
  after 5 minutes (a worker error), so a slow endpoint never holds up the rest of
  the audit maintenance. `worm_archive_objects`
  holds the references (`ai_act_audit_anchor.external_ref` stays null: the anchor
  row cannot be updated after insert).
- Not offered in the hosted cloud. `GET /api/v1/compliance/archive` shows the
  state to readers, never a credential or the installation's bucket name.

## KVKK exposure report

`POST /api/v1/compliance/reports/kvkk` counts two sources. Compliance connector
findings (provider compliance APIs) appear as before. The report is read by a
Turkish data protection officer, so the PDF is in Turkish ("KVKK Kişisel Veri
Maruziyet Kanıtı"); entity type ids such as `TR_NATIONAL_ID` stay ids, and
severities print as kritik, yüksek, orta and düşük. The header line is
`Kurum: <name> (<id>)`: the name is mutable, the id keeps the evidence
unambiguous. Every value interpolated into the PDF's text is escaped, so a name
such as `A & <B>` prints as written and cannot inject markup or a link.

A tenant-wide report, one without `connector_id`, also counts the gateway. Its
"Gateway tespitleri" section lists, per entity type and KVKK category, the sum
over requests started in the window of the distinct values the gateway masked
(`pii_entities`), monitored, blocked, and saw in answers (`response_entities`),
from `request_lifecycle` metadata. A column no request in the window recorded
(rows written by an older version) prints "bu sürümde kaydedilmiyor", never 0.
The scope line then reads "tüm bağlayıcılar ve gateway".

The CSV keeps its nine columns in order and adds `source` and `count` at the end,
so a consumer reading by position keeps working. Connector rows have `source`
`connector` and `count` 1. A tenant-wide CSV adds, after them, one row per entity
type and gateway action with a non-zero count: `source` `gateway_masked`,
`gateway_monitored`, `gateway_blocked` or `gateway_response`, severity and
categories from the entity's classification, `count` the sum, and the
per-finding columns empty, ordered by entity type then source. Filter on
`source = connector` for the rows of earlier versions. A connector-scoped report
holds that connector's findings only. The framework evidence report and the
readiness report stay in English.

## Monthly evidence file

On each pass the ai_act worker writes the previous calendar month's evidence
file for every organization that is not archived, had at least one request
started in that month, and has no file for it yet. The file is a PDF stored in
`evidence_reports` (`kind` `monthly`) with its SHA-256, size, generation time and
generator version. A row is written once and never changed; a second worker
racing for the same month inserts nothing. Rendering runs off the event loop.
Months are UTC months: the first three hours of the 1st in Istanbul (UTC+3)
belong to the previous month's file.
An organization whose file fails counts as an error of the pass, so the worker
writes no heartbeat and the next pass tries again.

The PDF follows the [KVKK exposure report](#kvkk-exposure-report): Turkish
text, the header `Kurum: <name> (<id>)`, and every interpolated value escaped.
Its cover says it is a measurement of gateway traffic, not an audit, a
certificate or a declaration of conformity. Each section names its source table
and window ("Kaynak: <table>, dönem: <start> – <end>"):

1. Trafik: requests and cost per provider and per model, from the spend and
   quota settlements, with unknown prices shown as "bilinmiyor", never as zero.
2. Kurumdan ne çıktı: per provider and entity type, the values masked, monitored
   and blocked, the count of bulk disclosures and the entity types found in
   answers, from `request_lifecycle` metadata. A field the gateway version did
   not record reads "bu sürümde kaydedilmiyor".
3. Ne durduruldu: policy verdicts with outcome `deny`, by rule and reason code.
4. Kim neyi değiştirdi: management actions by action and actor type.
5. Denetim zinciri: the [server-side check](#audit-evidence-bundle) for the
   month, from the latest daily anchor before it, or a Turkish sentence saying
   the month is too large to verify at once (the exception goes to the log).
6. Bulgular: per rule, the [findings](FINDINGS.md) opened, open at the end and
   resolved in the month.
7. Kim neye erişti, in two parts:
   - Kanıt ve içerik erişimi: the audited reads and exports listed above
     (`compliance.kvkk_report_generated`, `compliance.audit_report_generated`,
     `compliance.readiness_report_generated`, `compliance.audit_bundle_exported`,
     `compliance.audit_verified`, `tenant.requests_exported`,
     `tenant.billing_exported`, `tenant.evidence_downloaded`, and
     `tenant.request_content_opened` once it exists) by action and actor: the
     user id, the user's current role ("güncel rol"; a custom role by its name,
     marked "özel rol") and "servis hesabı" for a service account, never an
     e-mail. A month without such a row says "Bu ay
     kayıtlı erişim yok." when the organization has an earlier one, and
     "Okuma ve dışa aktarma kayıtları bu kurum için henüz tutulmuyor."
     otherwise. Unaudited list views are not in it.
   - Model erişimi: requests of the month by API key and team, with the
     providers and up to 10 models each called (a model name is cut at 64
     characters); the 50 largest rows, the rest summed as "diğer". Key and team
     names only, never a key id or secret. Text the file writes itself ("diğer",
     "anahtar yok" for requests without a key, "adsız anahtar" for a key without
     a name) is set in italics, so a key named "diğer" never reads as the sum.
     Columns have fixed widths and long names wrap inside them.
8. Dile göre karakter başına token: per model with at least 30 eligible Turkish
   answers in the month, the Turkish and English output tokens per 1,000
   characters with their counts and their quotient, from the
   [language cost read](COOKBOOK.md#how-much-more-do-turkish-answers-cost-on-each-model),
   with the method in one paragraph; "Bu sürümde kaydedilmiyor: dil çözümleyicisi
   kapalı." when the language analyzer labelled no answer of the month.

The file holds counts and names only: no prompt, answer, detected value or key.
Files generated before a change keep their content and generator version.

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

## Incidents

An [incident](INCIDENTS.md) is opened by a person. shim does not open one from
a finding or an alert, because most of them are not incidents and a list full
of them would hide the ones that are. The record holds references (finding ids,
request ids, audit sequences) and the organization's own text; no request or
answer content is copied into it, and the evidence summary is computed on each
read from the linked rows.

shim keeps the notification clock and reminds through forward targets. It never
decides whether something is a breach, never files with the KVKK Board or any
other authority, and never tells data subjects. The deadlines (72 hours from
awareness for the KVKK Board and for a GDPR authority, none for data subjects)
are fixed in code and documented for the organization's counsel to confirm.
Audit rows carry field names, statuses, regimes and references, never `breach`
text, and the OCSF export leaves out the contact person and the free-text
breach fields.

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
"Control numbers and titles, and the gap and next-step texts, have not yet been
checked against the published standard." The five-control framework report
(`/reports/audit`) is unchanged.

Each row has a status, derived when the report is produced and never stored:

| Source | `ready` | `partial` | `gap` |
| --- | --- | --- | --- |
| `measured` | evidence present | | evidence absent |
| `input` | evidence present and declared `implemented` or `not_applicable` | evidence present and declared `partial`, or not declared | evidence absent, or declared `not_implemented` |
| `declared` | declared `implemented` or `not_applicable` | declared `partial` | not declared, or declared `not_implemented` |

After the table, a "Gap list and next steps" section lists the `gap` controls,
then the `partial` ones, each in control order, with one sentence on what is
missing and one to four steps. The sentence of an input or declared control says
what is "not fully recorded", so it holds for a `partial` control as well as for
one with nothing recorded. A step is either "in shim", naming the shim
feature that produces the missing evidence and its documentation, or for the
organization (a policy, a process, an owner, a document). shim never stores or
checks those documents. The texts are static, kept in the mapping beside each
control, and reviewed with the control numbers and titles; one flag covers
both. They are the same for every tenant: no dates, effort, priority, progress
tracking or score, and no percentage of ready controls. The CSV adds `status`
and `next_steps` after its earlier columns.

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
