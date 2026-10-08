# Gateway findings

A finding is the gateway's conclusion about one subject (an API key, a
deployment alias or a model): what was checked, how serious it is, the evidence,
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
  `occurrences`, `summary`, `evidence` and `impact`. A suppressed finding stays
  suppressed while it keeps firing.
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

## gateway.retry_storm

**Checks.** For each API key, the four fixed 15-minute buckets of the last hour,
aligned to the quarter hour in UTC (the current one included). It fires when
one bucket holds at least 20 requests with `repeat_chain_length` of 2 or more.
Severity medium.

**Why.** A client that resends the same request quickly is usually retrying
without backoff. Every repeat is a billable provider call, and a storm can
trip provider rate limits for the whole tenant.

**Evidence and impact.** The bucket start, the repeated request count, the
threshold, how many of the key's requests in that bucket ended
`client_disconnected` or `timeout` (`abandoned_requests`), and up to 20 request
ids. Impact is the known cost and the count of the repeated requests.
`repeat_chain_length` counts identical content in the loop window; it is not
proof that a client retried ([diagnostic metadata](DIAGNOSTIC_METADATA.md)).

**Fix.** Make the client back off: honour `Retry-After`, add jittered
exponential backoff and cap retries. When abandoned requests co-occur, the
client's timeout is shorter than the model's answer time; raise it instead of
retrying.

**Resolves** after 7 days without a firing bucket.

## gateway.repeat_spend

**Checks.** For each API key, month to date (UTC), the known cost of requests
with `repeat_chain_length` of 2 or more. It fires when that cost is at least
1 USD and at least 10 percent of the key's known spend. Unpriced requests count
toward neither. Severity medium.

**Why.** Repeated identical requests that cost a tenth of a key's spend are
money spent twice for the same answer.

**Evidence and impact.** The period start, the repeated cost, the known spend,
their share, the repeated request count and up to 20 request ids. Impact is
the repeated cost and count.

**Fix.** Retry only on retryable errors, deduplicate in the client, or cache
answers the client asks for again.

**Resolves** after 7 days without firing, for example once a new month starts
with fewer repeats.

## gateway.unused_deployment

**Checks.** Enabled [registered deployments](MODEL_DEPLOYMENTS.md) created at
least 30 days ago that had no request with their alias as the model in the last
30 days. Severity low.

**Why.** An unused deployment keeps a stored credential and an approved
destination alive for nobody.

**Evidence.** The deployment's creation time and the 30-day window. No impact.

**Fix.** Disable or delete the deployment, or point callers at its alias.

**Resolves** 7 days after the deployment receives a request again or is
disabled or deleted.

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
