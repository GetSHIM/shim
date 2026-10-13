# Gateway findings

A finding is the gateway's conclusion about one subject (an API key, a
deployment or a model): what was checked, how serious it is, the evidence,
the impact and the fix. Findings are derived from request records shim already
keeps (`request_lifecycle` and the spend ledger); no prompt or answer text is read.
The `litellm.*` rules read an [imported LiteLLM spend log](COOKBOOK.md#import-litellm-spend-logs)
instead and carry `source: litellm`; everything else carries `source: gateway`.

This is a different object from `/api/v1/compliance/findings`, which lists the
findings of provider compliance APIs read by compliance connectors. That route
is unchanged.

## Shape

The API returns every finding in the published
[Finding v1 schema](../../docs/FINDINGS_SCHEMA.md)
([JSON Schema](../../docs/schemas/finding-v1.json)): `rule_id` and `rule_version`,
`title`, `summary` in English and Turkish, `severity`, `status` and
`status_detail`, `subject` (`key`, `deployment` or `model` with its id),
`window` (first and last time seen), `occurrences`, `evidence` (up to 40 request
references), `measurements` (the measured numbers), `impact` (`requests`, `usd`,
`risk_class`), `remediation` (`mode`, `max_mode` and `action`, see
[modes](#modes), `reversible`, `blast_radius`, the fix `text`), `playbook` (the rule's section
below), and `resolved_at` and `resolved_by` once resolved. v0.3.0 answered in a
shape of its own; [what changed](../../docs/FINDINGS_SCHEMA.md#what-changes-for-existing-apps).
A row this build cannot render (a rule it does not have, a measurement its
template lacks, a subject of a later kind) is served with its stored English
title and summary, the tenant as its subject and no evidence or measurements,
and logged by id; a list or an export never fails on it.

Stored evidence that is not a plain number reaches the API under fixed names
only. Repeat `classes` become `repeats_after_timeout`, `repeats_after_error`,
`repeats_after_success` and `repeats_pending`. Requests per provider become
`requests_openai`, `requests_anthropic` and `requests_google`; any other
provider counts toward `requests_other`. The first 10 stored `pairs` lead
`evidence`, each as the repeat's request followed by the request it repeats, and
the rule's other request ids follow. `pairs` counts the pairs shown and
`pairs_omitted` the linked repeats left out. A pair's class and gap, the models
of `gateway.byok_usage` and any other word stay in the stored row: a finding
carries no free text beyond its templates.

| Stored `severity_id` | `severity` | | Stored `status_id` | `status` / `status_detail` |
| --- | --- | --- | --- | --- |
| 1 | informational | | 1 | open / new |
| 2 | low | | 2 | open / in_progress |
| 3 | medium | | 3 | dismissed / suppressed |
| 4 | high | | 4 | resolved / resolved |
| 5 | critical | | | |

There is at most one open finding (any status but resolved) per organization,
rule and subject.

## Evaluation

The reconciliation worker evaluates every rule for every organization that is
not archived, once at start and then every `FINDINGS_EVALUATION_INTERVAL_SECONDS`
(default 900, from 60 to 86,400). Each organization is one short transaction; a
failure is logged with its type and the next organization still runs. Inside it
each rule runs in its own savepoint: a rule that fails is rolled back alone and
logged with its rule ids, the other rules still write their findings, and the
failed rule's open findings are not resolved by the 7-day rule on that pass.

Rules that read analyzer output run only while the tenant runs that analyzer
(`response_analysis`): `language_drift` needs `language`, `schema_errors`
`schema`, `soft_refusals` `refusal`, and the three waste rules `shape`. The
cold-start and queueing rules run only when the tenant has a registered
deployment. Every statement of these rules has a 10-second statement timeout; one
that runs out fails its rule for that pass, as above.

- A rule that fires creates a finding, or updates the open one: `last_seen_at`,
  `occurrences`, `summary`, `evidence`, `impact`, `rule_version` and
  `remediation`, so an open finding of an earlier rule version moves to the new
  one in place. A suppressed finding stays suppressed while it keeps firing.
- `occurrences` counts evaluations that fired, not incidents. A rule looks back
  over a window longer than the evaluation interval, so one incident is counted
  once per evaluation that still sees it: at the default interval of 15
  minutes, one retry-storm bucket stays inside the one-hour window for four
  evaluations and adds 4, and a repeat-spend or unused-deployment finding adds
  one on every evaluation while it holds.
- An open finding not seen for 7 days is resolved with `resolved_by: "system"`.
- A rule that fires again after its finding was resolved creates a new finding.

Thresholds are fixed constants in `shim_enterprise.findings.service`; tenants
cannot change them.

## Modes

Per finding type the tenant chooses how far shim may go, in the same words as a
rule's action:

- `observe` (the default): the finding shows the problem and the fix in words;
  `action` is `null`.
- `suggest`: the finding also carries a typed `action` a person can turn into a
  [policy plan](POLICY_DECISIONS.md#policy-versions-and-plans) with
  `POST /api/v1/management/findings/{id}/plan`. Nothing changes until someone
  applies the plan, and a restore undoes it.
- `auto`: shim applies the action itself and watches it
  ([automatic fixes](#automatic-fixes)). Only an action that tightens or
  cheapens and, by the rule's own condition, touches no request that would
  otherwise be served may be `auto`; today that is disabling a deployment that
  served nothing in 30 days. While `auto` cannot run it works as `suggest`: the
  finding says `mode: "suggest"`, and the rules read says `effective_mode:
  "suggest"` with an `unavailable_reason`: `auto_paused` (the tenant paused
  automatic changes), `proof_unavailable` (audit mode `off`, so refusals leave no
  row to measure), `no_allowlist_entry` (no allowlist entry has the rule's action
  kind) or, on one finding, `remediation_restored` (its fix was set back,
  skipped or undone). An effective `auto` finding carries `remediation.proof_after`:
  `{"metric": "refusals", "window_hours": 24, "baseline": null, "threshold":
  null, "comparison": "lte"}`.

Each rule declares its highest mode (`max_mode`) and its action; a rule whose fix
is in the client, the prompt or the provider stays `observe`. The tenant sets
`finding_modes` in its [gateway settings](COOKBOOK.md#change-the-gateway-settings),
per rule id, at or below the rule's `max_mode` (422 otherwise, naming the rule);
a PATCH merges per rule, and `observe` removes the rule's entry. Moving a rule to
`auto` is relaxing (it lets shim act without a person), so
[four eyes](POLICY_DECISIONS.md#four-eyes) applies; any other move is neutral.
The worker writes the mode and action on every finding it raises and, each pass,
on every open finding of the organization. A change of `finding_modes` rewrites
the open findings in the same transaction, so a lowered mode removes the action
at once. Nothing already applied is undone. Planning a finding whose stored
action this build does not know (another kind, no deployment id) answers 409.

| Rule | `max_mode` | Action |
| --- | --- | --- |
| `gateway.retry_storm`, `gateway.repeat_spend` | `observe` | none: the client's timeout and retries |
| `gateway.answer_quality`, `gateway.truncation_rate`, `gateway.refusal_rate` | `observe` | none: the prompt, the model or the client's output limit |
| `gateway.unregistered_model`, `gateway.byok_usage` | `observe` | none: registering needs a secret and an origin; BYOK has no tenant switch |
| `gateway.language_drift`, `gateway.schema_errors`, `gateway.soft_refusals` | `observe` | none: the prompt, the model choice or the client |
| `gateway.oversized_parts`, `gateway.dead_tools`, `gateway.cache_order_churn` | `observe` | none: the fix is in the client's code |
| `gateway.cold_start`, `gateway.queueing` | `observe` | none: the model server's settings or capacity |
| `gateway.idle_inference_capacity`, `gateway.inference_queue_saturated` | `observe` | none: replicas, capacity or the server's idle settings |
| `gateway.idle_internal_deployment` | `suggest` | `deployment.disable`: it still serves some requests |
| `gateway.unused_deployment` | `auto` | `deployment.disable`: no request in 30 days |

`deployment.disable` is `{"kind": "deployment.disable", "params":
{"deployment_id": ...}}`, built from the finding's subject; it is reversible and
its blast radius is the deployment.

## Automatic fixes

shim applies a change by itself only when the change tightens or cheapens,
touches one item, changes nothing in a request's content, and is undone by
setting the item back. The allowlist (`shim_enterprise.policy.allowlist`) holds
exactly these entries:

| Entry | Resource and fields | Accepted direction | Impact bound | Proof |
| --- | --- | --- | --- | --- |
| `deployment.disable` | `deployments.enabled` | true to false | 0 requests in 7 days | refusals of `deployment.registry`, tenant-wide, 24 h |
| `api_key.narrow_models` | `api_keys.allowed_models` | null to a list, or a list to a strict non-empty subset | 0 | refusals of `access.key_models` and `api_key.access` for that key, 24 h |
| `team.lower_limit` | `teams.daily_request_limit`, `monthly_request_limit`, `monthly_token_limit` | each changed limit lowered, or null to a number | 0 | refusals of `quota.requests_and_tokens` for the team's keys, 24 h |
| `budget.lower` | `budgets.limit_usd`, `limit_tokens`, `enabled` | each changed limit lowered (never to or from null), `enabled` false to true | none: budgets only notify | none |
| `privacy.start_counting` | `privacy.entity_actions` | every changed type from `off` to `monitor` | none: counting leaves content untouched | none |

Never automatic: anything that masks or blocks content, any rule change (route
rules included, whatever their `match.on`), any gateway setting, creates,
deletes and loosening moves. An unattended plan holds at most 5 changes, and a
tenant at most 20 unattended changes in 24 hours (skipped ones not counted;
above it 429 `REMEDIATION_LIMIT`).

**Who applies.** The reconciliation worker, right after each findings pass, as
the system actor (`actor: "system"`, versions with source `auto` and actor type
`system`): per organization, at most 5 open findings whose rule's stored mode is
`auto`, oldest first, that have no remediation yet. And an agent holding
`plans.apply_allowlisted` without `plans.apply` (the
[recommender](MCP.md#what-a-recommender-can-apply)) when it applies a plan: its
change is watched the same way, with `actor_type: "service"`. Every refusal
(not on the list, wrong direction, impact above the bound, `proof_unavailable`
when the tenant's audit mode is `off`, a stale item, a file-managed resource)
writes a `skipped` row with the reasons and changes nothing. A finding gets one
remediation, ever: after a skip or an undo shim only suggests it.

**The window.** An applied change with a proof is `watching` for the largest
proof window (24 hours). The window is closed on the first pass after
`window_end + REMEDIATION_WINDOW_GRACE_SECONDS` (operator setting, default 900,
0 to 3,600: the allowance for outbox lag before refusals reach the audit log).
For each item it counts audit-log requests refused with one of the proof's
verdicts in the window (`measured`) and in the window before it (`baseline`);
a key or team proof counts only that key's or team's keys. Every
`measured <= baseline`: `kept`, and the finding is resolved by `system`. Any
rise: one plan sets every item back to its `before` in the fields the change
moved, applied as the system actor even under four eyes (it returns each item to
a state a person set, and the stale check stops it when anything else changed);
the row is `restored` and the finding goes back to `new`. When someone changed an
item since, nothing is written: `restore_skipped` with reason `item_changed`, and
a notification so a person decides. A measurement that runs out of its 10-second
statement timeout leaves the row `watching` for the next pass. A change with no
proof is `kept` at once.

**Seeing and undoing.** `GET /api/v1/management/remediations` (`status`,
`limit` 1 to 100, `before`, newest first) and `GET .../remediations/{id}`
(`findings.read` or `audit.read`) show each row's items (resource, item, entry,
before, after, proof), status, window, result, plans, versions and actor.
`POST .../remediations/{id}/undo` (`plans.apply`, people only: a service account
gets 403 `UNDO_NEEDS_HUMAN`), body `{"reason"}`, sets a `watching` or `kept`
row's items back through a plan with source `restore`, applied as the caller,
and marks the row `undone`. Under four eyes the undo answers 202 with the plan
waiting for a second approver and the row unchanged. Any other status is 409
`REMEDIATION_STATE_CONFLICT`; an item changed since is 409 `PLAN_STALE`.

**The kill switch.** `PATCH /gateway-settings {"auto_remediation_paused": true}`
stops new automatic and agent applies (409 `AUTO_REMEDIATION_PAUSED`); windows
keep closing and automatic undo keeps running. Pausing is tightening, resuming is
relaxing.

**Notifications.** Every phase (`applied`, `kept`, `restored`,
`restore_skipped`, `undone`) is one outbox event `remediation.changed` that
reaches every enabled forward target (`kind: "remediation_changed"`, ids, entry
ids, resources, policy version and actor type, never a before or after value),
and one audit action `tenant.remediation_<phase>` (`skipped` included). The
counter `shim_remediations_total{entry, phase}` counts them; a skipped finding
counts under entry `none`.

## API

| Route | Who | What |
| --- | --- | --- |
| `GET /api/v1/management/findings` | Owner, admin, auditor | Newest `last_seen_at` first; filters `status` (`open`, `dismissed`, `resolved`, or the workflow states `new`, `in_progress`, `suppressed`), `rule_id`, `severity_id`; `limit` (default 50, at most 200) and `offset` |
| `GET /api/v1/management/findings/rules` | Owner, admin, auditor | Per rule: `rule_id`, `rule_version`, `max_mode`, `action_kind`, `mode` (stored, or `observe`), `effective_mode`, `unavailable_reason` and `open_findings`, by rule id |
| `GET /api/v1/management/findings/{id}` | Owner, admin, auditor | One finding (Finding v1) |
| `GET /api/v1/management/findings/{id}/explain` | Owner, admin, auditor | The finding and its rule's facts (`rule_id`, `rule_version`, `title`, `max_mode`, `action_kind`, `blast_radius`, `playbook`) with `doc`: this file's section for the rule, at most 16 KB (cut at a line end with `...`), `null` without one. No model is called; an agent writes the explanation from these facts ([MCP](MCP.md)). The section comes from the packaged copy `ee/src/shim_enterprise/findings/FINDINGS.md`: copy this file there after editing it, or a test fails |
| `PATCH /api/v1/management/findings/{id}` | Owner, admin | `{"status": ...}` with the same values as the filter (`open` keeps an open finding's state and reopens a closed one as `new`, `dismissed` is `suppressed`); recorded as `tenant.finding_status_changed`; 409 when reopening a resolved finding while another open finding exists for the same subject |
| `GET /api/v1/management/findings/export` | Owner, admin, auditor | NDJSON, one OCSF Detection Finding per line, with the same filters; at most 10,000 (422 beyond) |
| `POST /api/v1/management/findings/{id}/plan` | `plans.create` and `deployments.manage` (a recommender needs only `plans.create`) | A draft plan (reason `finding:<id>`) that makes the finding's action: 201; 409 when the finding is not open (`new`, `in_progress`) or has no action; 404 for another organization's finding |

Each export line is an OCSF 1.3.0 Detection Finding: `class_uid` 2004,
`category_uid` 2, `activity_id` 1 (created, seen once), 2 (updated: seen again
or its status changed) or 3 (closed: resolved), `type_uid` 200401, 200402 or
200403, `time` (milliseconds; the resolution time for a resolved finding,
otherwise the last time it was seen), `severity_id`, `status_id`,
`metadata.version` `1.3.0`, `metadata.product` `{"name": "shim", "vendor_name":
"shim"}`, and `finding_info` with `uid`, `title`, `desc` (the summary),
`first_seen_time` and `last_seen_time`. `unmapped` holds `schema_version` (`"1"`),
`summary_tr`, `rule_id`, `rule_version`, `occurrences`, and `subject`,
`evidence`, `measurements`, `impact` and `remediation` in their Finding v1
shapes. The list and detail routes return `{"items": [Finding], "total",
"limit", "offset"}` and a Finding; the PATCH answer is the updated Finding.

## Linked repeats

A repeat is linked to the request it repeats when both came from the same API
key with the same `repeat_digest` ([diagnostic metadata](DIAGNOSTIC_METADATA.md))
and it started at most 900 seconds after the previous one. The link window covers
the pinned OpenAI and Anthropic SDKs' 600-second timeout plus backoff, so a retry
after a client timeout is linked even though it falls outside the 300-second
loop window; a client whose timeout is longer than 900 seconds is not linked.
The loop window, its counting and its 429 are unchanged. Nothing is written to
request records: links are computed when the rules run.

Each linked repeat has a class from how the previous request ended:

| Previous request | Class |
| --- | --- |
| `client_disconnected`, `timeout` | `after_timeout` |
| `provider_error`, `failed`, `rejected`, `internal_error`, `cancelled` | `after_error` |
| `completed` | `after_success` |
| still running | `pending` (left out of impact, classed again on a later pass) |

Requests without a digest (written before the digest existed, without prompt
material, or with personal data, whose digest is cleared) are never linked; the
rules count them through `repeat_chain_length` as before. For repeat spend, such
a request is not counted when the key's previous digest-less request carries a
`repeat_chain_length` one lower, started within 900 seconds and was refunded:
an SDK retry after a 503 is not waste with personal data either. Repeated identical requests sent on purpose, such as an evaluation
batch, look the same: suppress the finding when the pattern is intended.

## gateway.retry_storm

**Checks.** For each API key, the four fixed 15-minute buckets of the last hour,
aligned to the quarter hour in UTC (the current one included). A request counts
when it is a [linked repeat](#linked-repeats), or, when it has no repeat digest,
when its `repeat_chain_length` is 2 or more. It fires when one bucket holds at
least 20 of them. Severity medium. Rule version 2. Max mode `observe`,
blast radius `key`, risk class `cost`.

**Why.** A client that resends the same request quickly is usually retrying
without backoff. Every repeat is a billable provider call, and a storm can
trip provider rate limits for the whole tenant.

**Evidence and impact.** The bucket start, the repeated request count, the
threshold, how many of the key's requests in that bucket ended
`client_disconnected` or `timeout` (`abandoned_requests`), up to 20 request
ids, `classes` (linked repeats per class) and up to 20 `pairs`
(`{"repeat", "previous", "class", "gap_seconds"}`), served as `repeats_<class>`,
`pairs`, `pairs_omitted` and pair references ([shape](#shape)). Impact is the known cost and
the count of the repeated requests. `repeat_chain_length` counts identical
content in the loop window; it is not proof that a client retried
([diagnostic metadata](DIAGNOSTIC_METADATA.md)).

**Fix.** Follows the class most of the bucket's linked repeats belong to:
`after_timeout`, raise the client's timeout or ask for fewer output tokens;
`after_error`, honour `Retry-After`, lower `max_retries` and back off;
`after_success`, deduplicate the request in the app. Without linked repeats:
make the client back off (`Retry-After`, jittered exponential backoff, capped
retries), and raise its timeout when abandoned requests co-occur.

**Resolves** after 7 days without a firing bucket.

## gateway.repeat_spend

**Checks.** For each API key, month to date (UTC), the known cost of
[linked repeats](#linked-repeats) whose previous request was billed (it has a
spend settlement), plus, for requests without a repeat digest, the cost of
those with `repeat_chain_length` of 2 or more that did not follow a refunded
request (see [linked repeats](#linked-repeats)). It fires when that cost is at
least 1 USD and at least 10 percent of the key's known spend. Unpriced requests
count toward neither. Severity medium. Rule version 2. Max mode `observe`,
blast radius `key`, risk class `cost`.

**Why.** Repeated identical requests that cost a tenth of a key's spend are
money spent twice for the same answer. A repeat of a request that failed and
was refunded did not double the bill, so it is not counted as waste.

**Evidence and impact.** The period start, the repeated cost, the known spend,
their share, the repeated request count, up to 20 request ids, `classes`,
`billed_repeats`, `unbilled_repeats` (repeats of refunded or unbilled requests,
never in the impact) and up to 20 `pairs`, served as for
[`gateway.retry_storm`](#gatewayretry_storm). Impact is the repeated cost and count.

**Fix.** Retry only on retryable errors, deduplicate in the client, or cache
answers the client asks for again.

**Resolves** after 7 days without firing, for example once a new month starts
with fewer repeats.

## gateway.unused_deployment

**Checks.** Enabled [registered deployments](MODEL_DEPLOYMENTS.md) created at
least 30 days ago that served no request in the last 30 days. A request belongs
to a deployment by the `deployment_id` it recorded, so a renamed alias keeps its
traffic; requests written before deployment ids were recorded count by their
model name equal to the alias. Severity low. Rule version 2. Max mode `auto`,
blast radius `deployment`, risk class `cost`.

**Why.** An unused deployment keeps a stored credential and an approved
destination alive for nobody.

**Evidence.** The deployment's creation time and the 30-day window. No impact.

**Fix.** Disable or delete the deployment, or point callers at its alias.

**Resolves** 7 days after the deployment receives a request again or is
disabled or deleted.

## gateway.idle_internal_deployment

**Checks.** Enabled deployments of kind `internal` created at least 30 days ago
that served between 1 and 299 requests in the last 30 days (about ten a day),
attributed as for `gateway.unused_deployment`. Zero requests is
`gateway.unused_deployment`, so the two never fire together. External
deployments are never subjects: they hold no hardware of the tenant. Severity
low. Subject: the deployment id and alias. Max mode `suggest`, blast radius
`deployment`, risk class `cost`.

**Why.** An internal model that serves a trickle of requests still holds its
servers and accelerators.

**Evidence and impact.** The requests in the window, the threshold, active days
(distinct UTC dates with traffic), the last request time, distinct API keys, up
to 20 request ids and `hardware_cost: "not recorded"`. Impact is the request
count; its cost stays `null` until a hardware cost is recorded for the
deployment.

**Fix.** Disable the deployment or move its few callers to another deployment;
it can be enabled again in one write.

**Resolves** 7 days after it stops firing: the deployment is disabled, gets
busier, or has no traffic at all.

## gateway.unregistered_model

**Checks.** Only for organizations with at least one enabled
[registered deployment](MODEL_DEPLOYMENTS.md): a tenant without a registry
routes by catalog on purpose. For each provider and model, the requests of the
last 7 days that reached the provider's public endpoint (`deployment_kind:
unknown`, after spend reservation). It fires at 5 or more. Severity medium.
Subject: `{"provider", "model"}`. Max mode `observe`, blast radius `model`, risk
class `privacy`. The model is the price-book entry the requested
name matched, as the gateway matched it (a dated snapshot counts under its
family entry), `model not specified` for a Responses request that named none,
and `other` for a name the current price book no longer matches. The requested
name itself is caller text and never becomes a key.

**Why.** Once a tenant keeps a registry, model use outside it is use nobody
listed: the answer to "is your model list complete" is no.

**Evidence and impact.** The requests, the threshold, distinct API keys and up
to 10 key ids, distinct teams, first and last request, up to 20 request ids and
how many requests carried their own provider key. Impact is the requests and
their settled cost.

**Fix.** Register the model as a deployment, or limit the keys that use it with
`allowed_models`; an operator can make the registry mandatory with
`MODEL_DEPLOYMENT_REQUIRED=true`. A tenant that uses the catalog on purpose
suppresses the finding.

**Resolves** after 7 days without firing.

## gateway.byok_usage

**Checks.** For each API key, the requests of the last 7 days that carried their
own provider key (`x-provider-key`), counted only for providers the tenant
stores a key for: a tenant that never stored one uses its own keys as its only
mode. The request's spend verdict says so (`spend.provider_monthly` with policy
version `spend:ephemeral-byok:unlimited:v1`). It fires at 5 or more. Severity
medium. Subject: the API key. Max mode `observe`, blast radius `key`, risk class
`cost`.

**Why.** Such a request skips the stored key's monthly spend limit and the
managed secret.

**Evidence and impact.** Requests per provider, up to 10 models (named as in
[`gateway.unregistered_model`](#gatewayunregistered_model)), up to 20
request ids, the settled cost and a note that these requests skipped the spend
limit and the stored key. Nothing derived from the caller's provider key is
recorded. The API serves the requests as `requests_<provider>` and leaves the
model names in the stored row ([shape](#shape)). Impact is the requests and
their settled cost.

**Fix.** Give the app the managed key path (no `x-provider-key`), or route it
through a registry deployment, whose stored secret always wins. To refuse such
keys outright, turn `allow_customer_provider_keys` off
([cookbook](COOKBOOK.md#refuse-provider-keys-sent-in-requests)).

**Resolves** after 7 days without firing.

## gateway.answer_quality

**Checks.** For each model (the provider model, or the requested model when the
provider did not name one), requests started in the last 24 hours. It fires
when at least 50 of them have a `completion_outcome` and either `truncated` is
at least 5 percent of those, or `empty` plus `refused` is. Severity low. Max
mode `observe`, blast radius `model`, risk class `quality`.

**Why.** A model that truncates or refuses one answer in twenty is costing
retries and user trust; the cause is usually an output limit or a prompt.

**Evidence.** The answered request count, the `truncated`, `empty` and
`refused` counts and rates, the threshold, and up to 20 request ids of the
affected answers. No impact.

**Fix.** For truncation, raise the output token limit or ask for shorter
answers; for empty or refused answers, review the prompt and the model choice.
[Prompt versions](COOKBOOK.md#see-what-changed-after-a-prompt-change) show
whether the rate changed with a prompt.

**Resolves** after 7 days below the threshold.

## gateway.truncation_rate

**Checks.** For each API key, the requests started in the last 24 hours that
have a `completion_outcome`. It fires when there are at least 50 of them and
`truncated` is at least 5 percent. Severity low. Subject: the API key. Max mode
`observe`, blast radius `key`, risk class `quality`.

**Why.** An app whose answers stop at the output limit usually sends too low a
max output tokens value, or uses a model whose output limit is shorter than the
answers it asks for.

**Evidence and impact.** The answered and truncated counts, the rate and the
threshold, up to five models with their own counts, and up to 20 truncated
request ids. Impact is the truncated request count; no money.

**Fix.** Raise the max output tokens the app sends, or check the model's output
limit. `GET /api/v1/management/requests?completion_outcome=truncated&api_key_id=…`
lists the requests.

**Resolves** after 7 days below the threshold.

## gateway.refusal_rate

**Checks.** The same window, minimum and subject as `gateway.truncation_rate`.
It fires when `refused` plus `filtered` plus `empty` is at least 5 percent of
the answered requests. Severity low. Max mode `observe`, blast radius `key`,
risk class `quality`. Text refusals found by the refusal
analyzer are not counted: `completion_outcome` records the provider's own
signal only.

**Why.** Each of the three has a different cause and fix:

- `filtered`: the provider's content filter stopped the prompt or the answer;
  read the request and the provider's filter settings.
- `refused`: the model returned a refusal field; the prompt asks for something
  the model declines, so rephrase it or choose another model.
- `empty`: the answer had no text; often a tool-only turn the app does not
  expect, or an output limit spent on reasoning tokens.

**Evidence and impact.** The `refused`, `filtered` and `empty` counts, the
rate and the threshold, up to five models with their counts, and up to 20
request ids. Impact is the count of those requests; no money.

**Fix.** Read the requests with `completion_outcome=refused`, `filtered` or
`empty` and this `api_key_id` and apply the fix for their class.

**Resolves** after 7 days below the threshold.

### Model rates and key rates

`gateway.answer_quality` asks whether a model is bad: it groups by model across
every key. The two rules above ask whether one app is configured badly: they
group by API key across models. The same traffic can raise both; they are
separate findings with separate subjects. `GET /api/v1/management/outcomes`
reads the same counts for any window, per model, key or team
([diagnostic metadata](DIAGNOSTIC_METADATA.md#outcome-filters-counts-and-rates)).

## gateway.language_drift

**Checks.** For each API key, the requests started in the last 24 hours whose
`response_analysis.language` (the `language` analyzer, which the tenant turns on
in its [gateway settings](COOKBOOK.md#turn-on-answer-checks-and-read-the-findings))
labels the question `tr` and the answer `tr` or `en`. An answer in English is a
drift. It fires when at least 20 such requests have a drift share of at least 10
percent. An English question answered in Turkish is not a drift, and `other` or
`unknown` answers are not counted. Severity low. Subject: the API key. Max mode
`observe`, blast radius `key`, risk class `quality`.

**Why.** An app whose users write in Turkish and read English answers is failing
them, and nothing in the response says so.

**Evidence and impact.** The analysed and drifted counts, the share and the
threshold, up to five models with their own counts, up to five system prompt
versions (`system_prompt_hash`) among the drifted requests, so the
[prompt version](COOKBOOK.md#see-what-changed-after-a-prompt-change) that causes it
shows, and up to 20 request ids. Impact is the drifted request count.

**Fix.** If the app expects English answers, suppress the finding for the key.
Otherwise state the answer language in the system prompt, or compare the models
the evidence lists.

**Resolves** after 7 days below the threshold.

## gateway.schema_errors

**Checks.** For each API key, the requests started in the last 24 hours whose
`response_analysis.schema` (the `schema` analyzer) checked the answer or a tool
call against the schema the request asked for: `expected` is `json_schema`,
`json_object` or `tool_args`, `valid` is decided, the schema used nothing outside
the [checked subset](../../docs/COOKBOOK.md#check-structured-output) and the
answer ended `complete` (a truncated answer is cut JSON and belongs to
`gateway.truncation_rate`). It fires when at least 20 were checked and at least 5
percent were invalid. Severity medium: the app cannot parse the answer. Subject:
the API key. Max mode `observe`, blast radius `key`, risk class `quality`.

**Why.** An answer that breaks the requested format reaches the app with a 200
and fails there.

**Evidence and impact.** The checked and invalid counts, the share and the
threshold, the checked and invalid counts per kind (`checked_json_schema`,
`invalid_tool_args`, ...), up to five models and up to 20 invalid request ids.
Each request's own record holds where its answer failed; the finding holds no
schema property name. Impact is the invalid request count.

**Fix.** Use the provider's strict structured output where it exists, keep the
schema inside the subset the gateway checks, and compare models.

**Resolves** after 7 days below the threshold.

## gateway.soft_refusals

**Checks.** For each API key, the answers of the last 24 hours that ended
`complete` and that the `refusal` analyzer read. An answer that refuses in words
("Üzgünüm, bu konuda yardımcı olamam") is a soft refusal. It fires when at least 50
were read and at least 5 percent refused. Severity low. Subject: the API key. Max
mode `observe`, blast radius `key`, risk class `quality`.

**Why.** A polite refusal is a `complete` answer with a 200; only its words say
the user got nothing.

**Evidence and impact.** The analysed and refused counts, the share and the
threshold, the counts of the five most frequent phrase markers as
`marker_<language>_<id>` (the analyzer's own ids, never the phrase), up to five
models and up to 20 request ids. Impact is the refused request count.

**Fix.** Read the requests: a polite refusal often means the system prompt
forbids the topic, or the model's own policy differs from the app's. Refusals the
provider marks itself are [`gateway.refusal_rate`](#gatewayrefusal_rate).

**Resolves** after 7 days below the threshold.

A tenant that has not turned an analyzer on gets no finding from its rule: the
rule does not run.

## gateway.oversized_parts

**Checks.** For each API key with at least 20 requests in the last 24 hours that
the `shape` analyzer recorded, the median and p95 of the tool definitions'
characters, the message count, the history's characters and the largest part's
characters. It fires when a median reaches its limit: tool definitions 40,000
characters, history 100 messages or 200,000 characters, the largest part 100,000
characters. Severity low. Subject: the API key. Max mode `observe`, blast radius
`key`, risk class `cost`.

**Why.** Every request pays for its whole input. Tools the task does not need, a
history nobody trims and a whole document where a page would do are paid again on
every call.

**Evidence and impact.** The analysed request count, how many part kinds crossed,
per crossed kind its median and p95 (`tool_definitions_*`, `history_messages_*`,
`history_chars_*`, `large_part_*`) and up to 20 request ids, largest first. Impact
is the requests over a crossed kind's limit and an estimate of their tokens: the
characters of the crossed kinds divided by four (`tokens_estimated: true`). Money
is not shown: tool definitions and early history are usually the provider-cached
prefix, billed at a fraction of the input price. Images are not judged here.

**Fix.** Send only the tools the task needs, or load them when needed; trim or
summarise the history in the app; send the relevant part of a document.

**Resolves** after 7 days below the limits.

## gateway.dead_tools

**Checks.** Once a day per organization (a worker restart evaluates again), over
the last 30 days, for each API key with at least 50 requests that offered tools
and at least one answer that called a tool: a tool offered in at least half of
those requests that no answer of the key called, neither as its name nor, for a
Responses built-in tool offered as `builtin:<type>`, as `<type>_call` (a
`_preview` type as its base name). Severity low. Subject: the API key. Max
mode `observe`, blast radius `key`, risk class `cost`.

**Why.** A tool definition is paid on every request that offers it, whether or not
the model ever uses it.

**Evidence and impact.** The requests that offered tools, how many tools are dead
and how many distinct tools were called. The dead tools' names (at most 20, each
cut to 64 characters, most offered first) with their offer counts stay in the
stored row: Finding v1 has no field for them. Impact is the requests that offered
a dead tool; tokens are not estimated, as the record has no per-tool size.

**Fix.** Remove the tools the app never calls, or load them only when needed. If
the app's tool calls go through a path shim does not see, suppress the finding.

**Resolves** 7 days after the last daily evaluation that found dead tools.

## gateway.cache_order_churn

**Checks.** For each API key, the requests of the last 24 hours with at least two
tools and at least 1,024 settled prompt tokens, grouped by the set of tools they
offered (the `shape` analyzer's set digest). A set with at least 20 requests, two
or more tool orders, a most frequent order under 80 percent of them and a cache
read (`cached_input_tokens` above zero) on under 50 percent fires; a request whose
log has no `cached_input_tokens` counts as no read. Severity low. Subject: the API
key. Max mode `observe`, blast radius `key`, risk class `cost`.

**Why.** Providers discount a prompt prefix they have cached, and the tools are
part of that prefix: sending the same tools in another order is a new prefix every
time.

**Evidence and impact.** The firing sets, the requests in them, the number of
orders and the cache-read share of the largest set, and per set (at most three)
the requests of its ten most used orders, the cache-read share and the providers;
up to 20 request ids. A set is one row of the query however many orders it has. Tool names are not repeated. Impact is the requests; no tokens or money.

**Fix.** Send the tools in a fixed order, for example sorted by name, and keep the
system prompt free of per-request values.

**Resolves** after 7 days without firing.

## gateway.cold_start

**Checks.** For each [registered deployment](MODEL_DEPLOYMENTS.md#cold-starts-and-timeouts),
the requests of the last 24 hours. A request's idle gap is the time since the
deployment's previous request (requests from the day before count; none at all is
a gap of a day; JSON requests count toward the gap). A stream is a cold start when
its gap is at least 600 seconds and it ended `timeout`, or its TTFT is at least
10,000 ms and at least five times the median TTFT of the deployment's warm streams
(gap under 600 seconds). JSON answers are never cold starts: their first byte
includes the generation, so a slow answer after a quiet half hour is not a load.
It fires at 3 cold starts.
Catalog routes are never subjects. Severity low. Subject: the deployment. Max mode
`observe`, blast radius `deployment`, risk class `reliability`.

**Why.** A model server that unloads an idle model makes the next caller wait
for it to load again, sometimes past the deployment's timeout.

**Evidence and impact.** Cold starts, timeouts among them, the median gap, the
median TTFT of cold and warm streams, and up to 20 request ids. Impact is
the cold requests.

**Fix.** Keep the model loaded between requests (the model server's keep-alive or
idle-unload setting), or raise the deployment's timeout when cold starts end in
timeouts.

**Resolves** after 7 days without firing.

## gateway.queueing

**Checks.** For each registered deployment with at least 50 streams in the 7 days
before the last 24 hours, their median TTFT is the baseline. An hour of the last
24 is congested when it has at least 10 streams with a TTFT that are not cold
starts, their p95 TTFT is at least three times the baseline, and at least 4 requests, streams or
JSON, were in flight at once (the
[latency read](COOKBOOK.md#read-latency-per-team-and-app)'s peak concurrency). It
fires at 2 congested hours. JSON answers' latency is not in the p95: it includes
generation. Severity low. Subject: the deployment. Max mode
`observe`, blast radius `deployment`, risk class `reliability`.

**Why.** When more requests arrive than a deployment serves at once, they wait in
the server's queue, and the wait shows as a late first byte at busy hours.

**Evidence and impact.** The congested hours, each with its p95, stream count and
peak concurrency; the baseline; the worst p95 and peak; up to 20 request ids.
Impact is the streams in congested hours.

**Fix.** More capacity for the deployment, a concurrency budget for the target,
or a separate lane for long requests; the latency read grouped by deployment shows
the hours.

**Resolves** after 7 days without firing.

## gateway.idle_inference_capacity

**Checks.** For each internal deployment whose model server shim reads
([server metrics](MODEL_DEPLOYMENTS.md#server-metrics); vLLM and TGI only, since
Ollama reports no running requests), the readings of the last 7 days: with at
least 1,000 of them, it fires when fewer than 10 percent had a request running.
Severity low. Subject: the deployment. Max mode `observe`, blast radius
`deployment`, risk class `cost`.

**Why.** Hardware is paid for whether it runs requests or not. The gateway's own
count can miss load that bypasses shim; the server's count does not.

**Evidence and impact.** The readings, the busy share, the running peak, the
average cache use and the requests shim sent to the deployment in the window; with
a [hardware cost](MODEL_DEPLOYMENTS.md#hardware-cost-and-capacity) entered for the
month, that amount and its currency (never converted). Impact is the requests.
When `gateway.idle_internal_deployment` is open for the same deployment both stay:
one counts gateway traffic, this one the server's load.

**Fix.** Move the deployment's callers to a shared deployment, lower its replica
count, or let the server unload the model when idle; the fix is outside the
gateway.

**Resolves** after 7 days without firing.

## gateway.inference_queue_saturated

**Checks.** For the same servers, the hours of the last 24 with at least 30
readings in which requests waited in at least half of them. It fires at 2 such
hours. Severity medium. Subject: the deployment. Max mode `observe`, blast radius
`deployment`, risk class `reliability`.

**Why.** A queue that stays full means callers wait for the server, not for the
model; `gateway.queueing` infers the same from first-byte times, this rule reads
the server's own queue, and both can fire.

**Evidence and impact.** The saturated hours, the worst hour's queued share, the
waiting and running peaks and the peak cache use. Impact is the requests shim sent
to the deployment in those hours.

**Fix.** Add capacity, set a concurrency budget for the deployment, or send long
requests to their own lane.

**Resolves** after 7 days without firing.

## litellm.unregistered_model

**Checks.** An [imported LiteLLM log](COOKBOOK.md#import-litellm-spend-logs), for a
tenant with at least one enabled registry deployment: a model (LiteLLM's `model`,
else its `model_group`) with at least 10 requests in the last 7 days of the log
whose `model` and `model_group` match no deployment `alias` or `upstream_model`.
Severity low. Subject: the model, or `other` for every model the price book and
the registry do not know (the import stores those as `other`, never their text). Max mode `observe`, blast radius `model`, risk
class `privacy`. Silent for a tenant without deployments.

**Why.** The same question as
[`gateway.unregistered_model`](#gatewayunregistered_model), asked of a gateway
shim does not sit in front of yet.

**Evidence and impact.** The request count, the window and threshold, the import
id and up to 20 LiteLLM request ids. Impact is those requests, their tokens and
LiteLLM's own cost (`cost_source: litellm`), never added to shim's spend.

**Fix.** Register the model as a deployment, or remove it from the LiteLLM
configuration.

**Resolves** after 7 days without an import that fires it.

## litellm.error_rate

**Checks.** The last 24 hours of an imported LiteLLM log: a model with at least
50 requests of which at least 5 % have a `status` other than `success` (rows
without a status are not counted as failed). Severity low. Subject: the model.
Max mode `observe`, blast radius `model`, risk class `reliability`.

**Why.** A wrong key, a retired model or a provider limit fails every call the
same way, and LiteLLM's retries hide it from the client.

**Evidence and impact.** Requests, failed requests, the failure share and
threshold, the import id and up to 20 ids of failed requests. Impact is the
failed requests, their tokens and LiteLLM's cost.

**Fix.** Read the failed requests in LiteLLM by their ids.

**Resolves** after 7 days without an import that fires it.

## litellm.slow_first_token

**Checks.** The last 24 hours of an imported LiteLLM log: a model with at least
50 rows that have a time to first token (LiteLLM's `completionStartTime` minus
`startTime`; it records one only for streams) and a 95th percentile of at least
10,000 ms. Severity low. Subject: the model. Max mode `observe`, blast radius
`model`, risk class `reliability`.

**Why.** Users wait for the first word; behind shim the same wait shows as
[`gateway.queueing`](#gatewayqueueing) and [`gateway.cold_start`](#gatewaycold_start).

**Evidence and impact.** The measured rows, their p95 and the threshold, the
import id and up to 20 request ids. Impact is the measured rows.

**Fix.** Check the deployment's capacity and queue at busy hours, or move
latency-sensitive traffic to a faster model.

**Resolves** after 7 days without an import that fires it.

## litellm.retry_burst

**Checks.** The last hour of an imported LiteLLM log: one LiteLLM key (its
`api_key`, already a hash) sending at least 20 requests with the same model and
the same `prompt_tokens` in one 15-minute bucket. Severity low. Subject: the key,
as `litellm:` and the first 16 characters of the hash. Max mode `observe`, blast
radius `key`, risk class `cost`.

**Why.** It mirrors [`gateway.retry_storm`](#gatewayretry_storm) with a weaker
signal: LiteLLM keeps no content digest, so equal token counts stand in for
equal requests. Two different prompts of the same length count as a repeat; the
summary says so.

**Evidence and impact.** The bucket, the count and threshold, the prompt size,
the import id and up to 20 request ids. Impact is the burst's requests, tokens
and LiteLLM's cost.

**Fix.** Make the client behind the key back off: honour Retry-After, add jittered
exponential backoff and cap retries.

**Resolves** after 7 days without an import that fires it.
