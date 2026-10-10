# Gateway findings

A finding is the gateway's conclusion about one subject (an API key, a
deployment or a model): what was checked, how serious it is, the evidence,
the impact and the fix. Findings are derived from request records shim already
keeps (`request_lifecycle` and the spend ledger); no prompt or answer text is read.

This is a different object from `/api/v1/compliance/findings`, which lists the
findings of provider compliance APIs read by compliance connectors. That route
is unchanged.

## Shape

Each finding has `rule_id` and `rule_version`, a `subject` (for example
`{"api_key_id": "…"}`), `title`, a one-sentence `summary`, `severity_id` and
`status_id` with OCSF values, `first_seen_at`, `last_seen_at`, `occurrences`
(how many evaluations found it), `evidence` (the measured numbers and up to 20
request ids), `impact` (`cost_usd` and `requests`, or `null`) and `remediation`
(`text`, `reversible`, `doc`).

| `severity_id` | Meaning | | `status_id` | Meaning |
| --- | --- | --- | --- | --- |
| 1 | informational | | 1 | new |
| 2 | low | | 2 | in progress |
| 3 | medium | | 3 | suppressed |
| 4 | high | | 4 | resolved |
| 5 | critical | | | |

There is at most one open finding (any status but resolved) per organization,
rule and subject.

## Evaluation

The reconciliation worker evaluates every rule for every organization that is
not archived, once at start and then every `FINDINGS_EVALUATION_INTERVAL_SECONDS`
(default 900, from 60 to 86,400). Each organization is one short transaction; a
failure is logged with its type and the next organization still runs.

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

## API

| Route | Who | What |
| --- | --- | --- |
| `GET /api/v1/management/findings` | Owner, admin, auditor | Newest `last_seen_at` first; filters `status` (`new`, `in_progress`, `suppressed`, `resolved`), `rule_id`, `severity_id`; `limit` (default 50, at most 200) and `offset` |
| `GET /api/v1/management/findings/{id}` | Owner, admin, auditor | One finding |
| `PATCH /api/v1/management/findings/{id}` | Owner, admin | `{"status": "in_progress" \| "suppressed" \| "resolved" \| "new"}`; recorded as `tenant.finding_status_changed`; 409 when reopening a resolved finding while another open finding exists for the same subject |
| `GET /api/v1/management/findings/export` | Owner, admin, auditor | NDJSON, one OCSF Detection Finding per line, with the same filters; at most 10,000 (422 beyond) |

Each export line is an OCSF 1.3.0 Detection Finding: `class_uid` 2004,
`category_uid` 2, `activity_id` 1 (created, seen once), 2 (updated: seen again
or its status changed) or 3 (closed: resolved), `type_uid` 200401, 200402 or
200403, `time` (milliseconds; the resolution time for a resolved finding,
otherwise the last time it was seen), `severity_id`, `status_id`,
`metadata.version` `1.3.0`, `metadata.product` `{"name": "shim", "vendor_name":
"shim"}`, and `finding_info` with `uid`, `title`, `desc` (the summary),
`first_seen_time` and `last_seen_time`. The rule, subject, occurrences,
evidence, impact and remediation are under `unmapped`.

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

Requests without a digest (written before the digest existed, or without prompt
material) are never linked; the rules count them through `repeat_chain_length`
as before. Repeated identical requests sent on purpose, such as an evaluation
batch, look the same: suppress the finding when the pattern is intended.

## gateway.retry_storm

**Checks.** For each API key, the four fixed 15-minute buckets of the last hour,
aligned to the quarter hour in UTC (the current one included). A request counts
when it is a [linked repeat](#linked-repeats), or, when it has no repeat digest,
when its `repeat_chain_length` is 2 or more. It fires when one bucket holds at
least 20 of them. Severity medium. Rule version 2.

**Why.** A client that resends the same request quickly is usually retrying
without backoff. Every repeat is a billable provider call, and a storm can
trip provider rate limits for the whole tenant.

**Evidence and impact.** The bucket start, the repeated request count, the
threshold, how many of the key's requests in that bucket ended
`client_disconnected` or `timeout` (`abandoned_requests`), up to 20 request
ids, `classes` (linked repeats per class) and up to 20 `pairs`
(`{"repeat", "previous", "class", "gap_seconds"}`). Impact is the known cost and
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
those with `repeat_chain_length` of 2 or more. It fires when that cost is at
least 1 USD and at least 10 percent of the key's known spend. Unpriced requests
count toward neither. Severity medium. Rule version 2.

**Why.** Repeated identical requests that cost a tenth of a key's spend are
money spent twice for the same answer. A repeat of a request that failed and
was refunded did not double the bill, so it is not counted as waste.

**Evidence and impact.** The period start, the repeated cost, the known spend,
their share, the repeated request count, up to 20 request ids, `classes`,
`billed_repeats`, `unbilled_repeats` (repeats of refunded or unbilled requests,
never in the impact) and up to 20 `pairs`. Impact is the repeated cost and count.

**Fix.** Retry only on retryable errors, deduplicate in the client, or cache
answers the client asks for again.

**Resolves** after 7 days without firing, for example once a new month starts
with fewer repeats.

## gateway.unused_deployment

**Checks.** Enabled [registered deployments](MODEL_DEPLOYMENTS.md) created at
least 30 days ago that served no request in the last 30 days. A request belongs
to a deployment by the `deployment_id` it recorded, so a renamed alias keeps its
traffic; requests written before deployment ids were recorded count by their
model name equal to the alias. Severity low. Rule version 2.

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
low. Subject: the deployment id and alias.

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
Subject: `{"provider", "model"}`.

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
medium. Subject: the API key.

**Why.** Such a request skips the stored key's monthly spend limit and the
managed secret.

**Evidence and impact.** Requests per provider, up to 10 models, up to 20
request ids, the settled cost and a note that these requests skipped the spend
limit and the stored key. Nothing derived from the caller's provider key is
recorded. Impact is the requests and their settled cost.

**Fix.** Give the app the managed key path (no `x-provider-key`), or route it
through a registry deployment, whose stored secret always wins. To refuse such
keys outright, turn `allow_customer_provider_keys` off
([cookbook](COOKBOOK.md#refuse-provider-keys-sent-in-requests)).

**Resolves** after 7 days without firing.

## gateway.answer_quality

**Checks.** For each model (the provider model, or the requested model when the
provider did not name one), requests started in the last 24 hours. It fires
when at least 50 of them have a `completion_outcome` and either `truncated` is
at least 5 percent of those, or `empty` plus `refused` is. Severity low.

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
