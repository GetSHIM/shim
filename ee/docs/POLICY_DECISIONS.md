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
not a content archive, signature or independent trust anchor.

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
`match`. A new rule starts in `monitor`. The `term`, `pattern`, `destination`
and `request_limit` kinds are available; `GET /rules` lists the others with
`available: false` and the reason.

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
`deployment_kinds: ["external"]`. A target is `internal` or `external` as its
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
`block` refuses there with `RULE_BLOCKED` and its `rule.<id>` verdict. Token
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

## Management change details

Management actions append an `audit.chain_append_requested` event in the same
transaction as the change. The audit API returns the stored `extra` object as
written, so these details are readable through `GET /api/v1/compliance/audit/logs`.

| Event | `extra` details |
| --- | --- |
| `tenant.privacy_policy_updated` | `before` and `after` of the privacy switches and of `entity_actions` when they changed |
| `tenant.privacy_protection_relaxed` | `relaxed`: the switches turned from on to off by name, and `entity_actions.<TYPE>` for a type whose override moved its effective action down the order `block`, `mask`, `mask_last4`, `monitor`, `off`, `placeholder_mode` when it moved from `random` to `stable`, `bulk_threshold` when it was raised or cleared, `response_scan` when it moved from `count` to `off`, `embeddings_monitor_types.<TYPE>` for a type added to the embeddings-only list, and `rules.<id>` for an enforced tenant rule that was removed, moved to `monitor`, given a weaker action, a narrower scope or a match other than added terms or patterns |
| `tenant.rules_updated` | `revision`, and `added`, `changed` and `removed` rules as `id`, `kind`, `action`, `state`, the non-empty `scope` keys, `match_changed` and entry counts (`{"terms": 12}`); never a term, pattern, name or match hash |
| `tenant.gateway_settings_updated` | `before` and `after` of the gateway settings fields that changed |
| `tenant.gateway_protection_relaxed` | `relaxed`: the gateway settings fields whose change their direction classifies as relaxing; written with the update |
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
| `tenant.custom_role_created` / `tenant.custom_role_deleted` | `after` / `before`: `slug`, `name` and `permissions` of the role (`slug` and `permissions` on delete) |
| `tenant.custom_role_updated` | `before` and `after` of the changed `slug`, `name` and `permissions` |
| `tenant.member_custom_role_changed` | `before` and `after`: the member's custom role slug, `null` for none |
| `tenant.budgets_evaluated` | `budgets_evaluated`: how many enabled budgets the manual run evaluated |
| `tenant.oidc_user_provisioned` | `source: "oidc"` and `after`: `role`, `custom_role` (slug or null) and `oidc_teams` (team id to role) of the new user |
| `tenant.oidc_user_synchronized` | `source: "oidc"` and `before` and `after` of `role`, `custom_role` or `oidc_teams` when a login changed them; `api_keys_revoked` when the login revoked the user's keys |
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

Six resources are managed: every write to them records a version, a plan can
change them, and a restore can put them back.

| Resource | Item | Fields | Write paths | Relaxing when |
| --- | --- | --- | --- | --- |
| `privacy` | `_` | the five switches, `entity_actions`, `placeholder_mode`, `bulk_threshold`, `response_scan`, `embeddings_monitor_types` | `PUT /settings/pii` | the change records `tenant.privacy_protection_relaxed` |
| `teams` | team id | `name` and the three limits | `POST /teams`, `PUT /teams/{id}` | a limit is raised or removed |
| `api_keys` | key id | `allowed_models`, `team_id` | `PATCH /api-keys/{id}` | a model is added or the list removed; the key leaves its team |
| `deployments` | deployment id | every registration field and `enabled` | `POST`, `PUT /model-deployments` | created; enabled; `base_url` changed; `external` to `internal` |
| `budgets` | budget id | scope, limits, thresholds, `enabled` (never notification targets) | `POST`, `PATCH`, `DELETE /cost/budgets` | deleted; a limit raised or removed; disabled |
| `oversight_policies` | policy id | `name`, `enabled`, `mode`, `trigger`, `ttl_seconds`, `default_on_timeout` | `POST`, `PATCH`, `DELETE /compliance/oversight/policies` | deleted or disabled |

A field moved the other way is `tightening`, anything else `neutral`; a change
with both a relaxing and a tightening field is `relaxing`, and so is a plan with
one relaxing change. Lowering cost (a lower budget, a disabled deployment) counts
as tightening. Provider credentials, connectors, forward targets, members,
invitations, service accounts, key issue, rotation and revocation, memberships,
finding status and readiness declarations are not managed.

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
privacy, `teams.manage` for teams, `deployments.manage`, `budgets.manage`, and
`compliance.manage` for oversight policies; a key change follows the key
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

Restoring a version applies a plan with source `restore` that puts every item a
version touched back to its state at that version. A revoked key, a team
created after it (teams cannot be deleted) and a re-created budget's
notification targets are listed in `not_restored`, and so is an item whose own
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
`audit.read`, the reads of what they show: `settings.read`, `usage.read` and
`deployments.read` (403 naming the missing ones). Plans applied after the version become
`rolled_back`. Audit actions: `tenant.policy_plan_created`,
`tenant.policy_plan_applied` (`plan_id`, `risk`, `resources`, `policy_version`)
and `tenant.policy_version_restored` (`target_version`, `plan_id`,
`policy_version`).

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
