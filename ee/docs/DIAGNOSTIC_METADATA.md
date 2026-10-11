# Diagnostic metadata

The gateway records the following observations without archiving prompts,
responses, provider error prose, or credentials. Native responses and the one
provider attempt rule are unchanged.

| Field | Meaning | Unknown/unavailable value |
| --- | --- | --- |
| `provider_finish_reasons` | Map of native completion facts, preserving candidate indices and provider spelling. See the protocol table below. | `null` when no recognized native completion fact was observed; absent map entries remain unknown. |
| `completion_outcome` | One classification per settled request: `complete`, `truncated`, `empty`, `refused` or `filtered`, derived from `provider_finish_reasons`, the emitted answer text and whether a refusal or tool call was seen. See the mapping below. | `null` for rejected and failed requests (a provider block stays `filtered`) and for historical rows. |
| `repeat_chain_length` | Number of matching request-content observations in the configured tenant repeat window, including this request (`1` for the first observation). | `null` when the detector has no observation, including Redis unavailability. |
| `shim_latency_ms` | Integer milliseconds spent processing inside shim, excluding provider waits and generation; measured with a monotonic clock up to the terminal accounting handoff. Includes invocation preprocessing and response transformation; excludes provider SDK awaits, raw stream awaits, client suspension and transport close. Terminal persistence after the snapshot is outside the measurement. Provider-free scans use the same snapshot boundary. | `null` when unmeasured, including historical rows and recovery after process loss; measured zero remains zero. |
| `ttft_ms` | Floating-point milliseconds from the provider-start callback, after its durable marker commits, to the first nonempty text, refusal, thinking, code, tool arguments, or supported media content observed after restoration. Uses a monotonic clock. | `null` for JSON responses, missing start time, or streams without supported content. |
| `provider_latency_ms` | Integer milliseconds of a JSON answer, from the instant the provider call starts (after credential resolution, circuit acquisition and the enterprise provider-start commit, the same instant a stream's clock starts) until the SDK has returned the parsed response. It covers the provider's time to first byte and generation, the transfer and the SDK's parse. It excludes shim's restoring of masked values and the Responses chain-store save, which follow it. | `null` for streams (they carry `ttft_ms`) and for rows written before it existed; not recorded for failed and rejected requests. |
| `answer_characters` | Characters of answer text, the number `completion_outcome` reads. Over JSON: text and refusal fields, without OpenAI reasoning items or Anthropic thinking blocks, and without tool-call arguments for OpenAI chat, Responses and Anthropic. Over SSE: the same, plus the tool-call argument fragments as they arrive (Anthropic thinking and OpenAI reasoning deltas are subtracted). The same tool-calling answer therefore counts fewer characters over JSON than over SSE. Gemini is the same on both paths: every text-bearing part counts, including `thought` parts, function-call `args`, code and code output. A stream that ended early (`client_disconnected`, `timeout`, `provider_error`) records what was emitted before it ended, and so does `tool_call_names`; a ratio over `answer_characters` should keep rows with a non-null `completion_outcome` and `estimated` false. | Not recorded for failed and rejected requests. |
| `tool_call_names` | Sorted, unique tool names the answer called, at most 64 of them. A name is kept only if it is 1 to 64 characters of `A-Za-z0-9_.:-` (what the providers allow); any other, such as a hallucinated name carrying text, is dropped, not truncated. Sources: chat `tool_calls[].function.name` and `function_call.name`; Responses output items whose type ends in `_call` (`name`, else the type, such as `web_search_call`); Anthropic `tool_use` and `server_tool_use`; Gemini `functionCall.name`. | `[]` when the answer called none; not recorded for failed and rejected requests. |
| `reasoning_seen` | `true` when the answer carried reasoning (a Responses `reasoning` item or `response.reasoning*` event, an Anthropic `thinking` or `redacted_thinking` block, a Gemini `thought: true` part, a chat `reasoning_content` field) or reported reasoning tokens above 0 (`reasoning_tokens`, `thoughtsTokenCount`). Token-per-character ratios that include reasoning output are distorted. | `false` when none was seen; not recorded for failed and rejected requests. |
| `system_prompt_hash` | `hmac-sha256:v1:` followed by a 64-character digest of explicitly supplied system/developer instructions. | `null` when instructions are absent or inherited from provider-held state. |
| `deployment_kind` | `internal`, `external`, or `unknown`, supplied by trusted deployment resolution. | New unclassified requests use `unknown`; historical rows use `null`. |
| `deployment_id` | The registry UUID, as a string, of the [deployment](MODEL_DEPLOYMENTS.md) that served the request, written at reservation and never changed. It stays the same when the alias, base URL or upstream model is edited. | `null` for catalog routes; absent on rows written before it existed. |
| `repeat_digest` | 64 lowercase hex characters: a keyed, tenant-bound digest of the same repeat material the loop detector compares. Equal values mean equal repeat material, not the same request, whatever `LOOP_WINDOW_SECONDS` says. | `null` when the request had no prompt material or PII was detected in it; absent on rows written before it existed. |

`completion_outcome` answers whether the caller received a whole answer. The
first class that matches, in this order, wins, including across several choices
or candidates:

| Outcome | Native facts |
| --- | --- |
| `filtered` | OpenAI `content_filter`; Responses `incomplete_details.reason: content_filter`; Gemini `SAFETY`, `RECITATION`, `BLOCKLIST`, `PROHIBITED_CONTENT`, `SPII`, or any `promptFeedback.blockReason` |
| `refused` | Anthropic `refusal`; an OpenAI chat `refusal` field; a Responses `refusal` content part |
| `truncated` | OpenAI `length`; Responses `incomplete_details.reason: max_output_tokens`; Anthropic `max_tokens` or `model_context_window_exceeded`; Gemini `MAX_TOKENS` |
| `empty` | none of the above, no answer text and no tool call |
| `complete` | otherwise |

Only the allowlisted native values above reach the classifier. Anthropic
thinking and OpenAI reasoning text is output but not answer text, so an answer
holding only that is `empty` over JSON and over SSE alike; Gemini thought parts
still count as answer text on both paths. Both editions count the field in
`shim_completion_outcomes_total{provider, outcome}` (a failed request is not
counted, except a provider block, which is `filtered`); community records it in its JSONL usage event, and enterprise carries
it in lifecycle metadata, the analytics projection, the request list and its
CSV export.

A model can also refuse in words and end normally ("Üzgünüm, bu konuda
yardımcı olamam" with `stop`): that answer stays `complete`, because
`completion_outcome` records native signals only and its metric and rate rules
depend on that. The opt-in `refusal` analyzer records such answers separately,
as `response_analysis.refusal`: `soft_refusal` and the `marker` id, never the
text. It reads only `complete` answers, by a versioned Turkish and English
phrase list, and is a heuristic; the
[community cookbook](../../docs/COOKBOOK.md#analyse-answers-after-delivery) says
what it looks for.

The repeat count is a content-match observation, **not evidence of a retry**.
Its existing matching algorithm selects prompt fields plus provider/model,
sorts JSON keys, applies NFKC normalization, and collapses whitespace. The
window and any process/Redis state loss affect comparability. A denied request
that never acquires a durable lifecycle has no diagnostic projection; its
policy-decision event owns denial evidence.

`repeat_digest` links a repeat to the request it repeats even when it arrives
after the loop window, for example a retry after the SDK's 600-second timeout,
which starts a new `repeat_chain_length` at 1. It is
`HMAC-SHA256(key, "<tenant id>:<detector digest>")` with
`key = HMAC-SHA256(COMPLIANCE_HASH_SALT or SECRET_KEY, "shim-repeat-digest-v1")`,
so two tenants sending the same prompt get different values. The key falls back
to `SECRET_KEY` when `COMPLIANCE_HASH_SALT` is unset. It is computed even when
Redis is unavailable.

The repeat material is the prompt-bearing fields plus the provider, protocol and
model alias, normalized. Tools, sampling parameters and `prompt` are not in it,
so two requests that differ only there share a value; renaming a model alias
changes the material and breaks the link.

The value carries no version prefix. After `COMPLIANCE_HASH_SALT` (or the
`SECRET_KEY` fallback) is rotated, old and new values cannot be told apart and
do not link.

The digest is written at reservation, before privacy runs. When privacy detects
PII, whether it is scrubbed, monitored or blocked, the same update that records
`pii_detected` sets `repeat_digest` to `null`: a keyed hash of raw prompt text is
still a pseudonym of the personal data in it. Requests with PII therefore cannot
be linked as repeats. `deployment_id` is unaffected.

The unkeyed detector digest never reaches PostgreSQL, the outbox, logs, spans or
metrics. It lives in Redis, in the `loop:{org}:{sha256(material)}` key, for up to
`LOOP_WINDOW_SECONDS`.

`deployment_id` and `repeat_digest` are lifecycle-only keys: they are in
`request_lifecycle.metadata` and not in the analytics row, the request list, its
CSV or the audit completion. Community JSONL does not carry them.

TTFT is gateway observation time, not the model's internal computation time or
the client's first-byte time. It excludes request admission and input privacy
processing, includes upstream wait and output restoration, and does not count
headers, SSE comments/heartbeats, roles, empty deltas, usage, or terminal events.
Supported media events are OpenAI audio deltas and partial images, and Gemini
inline media. Media contributes to TTFT without being counted as text tokens.
Customer APIs and CSV exports expose `shim_latency_ms`, which measures
shim processing, and `provider_latency_ms`, which measures the provider call of a
JSON answer. Legacy full-cycle `latency_ms` remains internal persisted
evidence, including immutable signed audit records; it is not a product latency
metric and is not exposed in request or audit API views.
Overview and request summaries expose `p95_completed_shim_latency_ms`, computed
only from completed requests with a known shim measurement; periods without
measurements report null.

Successful inference JSON responses expose `X-Shim-Latency-Ms` using the same terminal
measurement snapshot. Streaming responses do not expose this header because
the measurement is available only at stream completion.

## Native completion facts

The JSON and SSE paths use the same extraction rules. Only known native enum
values enter telemetry; malformed, unspecified, or unrecognized future values
remain unknown until support is reviewed. Free-form finish messages and stop
sequence text are never retained.

| Protocol | Map keys | Examples |
| --- | --- | --- |
| OpenAI Chat | `choices.<index>.finish_reason` | `stop`, `length`, `tool_calls`, `content_filter` |
| OpenAI Responses | `status`, `incomplete_details.reason` | `completed`; `incomplete` with `max_output_tokens`; `failed`; `cancelled` |
| Anthropic Messages | `stop_reason` | `end_turn`, `max_tokens`, `tool_use`, `refusal` |
| Gemini | `candidates.<index>.finishReason`, `promptFeedback.blockReason` | `STOP`, `MAX_TOKENS`, `SAFETY` |

Native indices are used when present; otherwise the candidate's array position
is used. Completion facts already observed survive later stream failure or
disconnect. `completed` lifecycle status means the transport completed; a
native truncation/refusal reason can still accompany it. `[DONE]` does not
fabricate a finish reason. Missing provider usage does not erase completion
facts or TTFT; the existing `usage_estimated` field describes accounting fallback.
OpenAI chat streams, on catalog routes and registry targets alike, are metered
from provider usage: when the caller did not set `stream_options.include_usage`,
shim asks for it upstream and keeps the extra usage chunk away from the caller,
so those requests are no longer estimated. An OpenAI-compatible server that
refuses the option answers with its own 400, which reaches the caller as
`PROVIDER_REJECTED_REQUEST`.

## System-instruction hashing

The enterprise quota reservation and, when configured, the community usage
lifecycle compute the digest with one function, `shim.gateway.usage.system_prompt_hash`,
at admission and before input privacy transformation. Hash material is the JSON array
`["shim.system_prompt.v1", tenant_id, protocol, deployment, instructions]`:

- Chat: only `role` and `content` from ordered system/developer messages.
- Responses: explicit `instructions` and ordered system/developer `input` messages.
- Messages: explicit `system` value.
- Gemini: explicit `systemInstruction` value.

Canonical JSON sorts object keys, uses compact separators and ASCII escapes,
and preserves array order, content whitespace, and Unicode without normalization.
The enterprise HMAC key is `COMPLIANCE_HASH_SALT`, falling back to `SECRET_KEY`;
community uses `SYSTEM_PROMPT_HASH_KEY` (at least 32 characters) and writes null
without it. Keep that key secret and unique per installation: two installations
with different keys produce different hashes for the same prompt. Comparisons are scoped to that key,
tenant, protocol, deployment identity/kind, and algorithm version; changing the key ends comparability
with earlier digests. The deployment scope uses its stable registry UUID and internal/external/unknown
kind; unregistered requests use a null UUID. Alias, endpoint, upstream model and
declared-version edits preserve comparability for the same deployment ID/kind.
Model names and user conversation content are excluded.
An explicitly empty instruction differs from an absent instruction. Provider-held
prompts, previous responses, and cached instructions are not reconstructed.

A new digest is a new prompt version. `GET /api/v1/management/prompt-versions`
(owners, admins and auditors) groups the tenant's requests started in a window
(`start` and `end`, default the last 7 days, at most 31; optional `api_key_id`
and `model`, a case-insensitive substring) by digest. Each item has
`system_prompt_hash`, `first_seen` and `last_seen` within the window,
`requests`, up to 10 `api_keys` and `models` (a Responses request that named no
model shows as `model not specified`), `outcomes` (the counts of each
`completion_outcome`), `failed` (requests that ended `provider_error`,
`timeout`, `internal_error` or `failed`) and `p95_shim_latency_ms` over completed
requests. Requests without a digest form one item with
`system_prompt_hash: null`. Items are sorted newest `first_seen` first, at most
200, with `truncated: true` when there were more. `/requests` and
`/requests/export` take `system_prompt_hash=` for an exact match; a value that is
not `hmac-sha256:v1:` and 64 lowercase hex characters answers 422.

## Persistence and reading

Request fields enter `request_lifecycle.metadata` during quota reservation.
Completion facts, TTFT and shim processing time join them in the terminal
accounting transaction, and so do `provider_latency_ms`, `answer_characters`,
`tool_call_names` and `reasoning_seen` when the request settled with an answer
(a refund writes none of the four),
before audit/analytics outbox intent is constructed. Terminal replay preserves
the first committed observations. Analytics delivery copies them into
`request_logs.details` with the existing tenant/request idempotency constraint.
No table or column migration is needed for these existing JSONB fields.

`GET /api/v1/management/requests` exposes the optional fields on each
request; `/requests/export` includes the same fields in CSV (unknown values
are empty cells, and finish-reason maps are JSON). `answer_characters`,
`tool_call_names` and `reasoning_seen` stay in the lifecycle metadata only; the
list and CSV carry `provider_latency_ms` (the column after `ttft_ms`, which shifts every
later CSV column one place right: read the export by header name, not by position). Audit completion `extra`
carries the same fields. Historical rows and
old outbox messages read as null without invented backfills.

`pii_entities`, `monitored_entities` and `blocked_entities` count the values
first seen in a request by entity type: masked, sent unchanged under `monitor`,
and refused under `block`. A Responses continuation does not count again the
placeholders it inherits. New requests always carry all three, `{}` when empty,
so null marks a row written before they existed. They are in the lifecycle
metadata, the request list and its CSV (as JSON) and the audit completion
`extra`; the community JSONL event names the masked map `privacy_counts`.

`bulk_disclosure` is `{"distinct_values": n, "threshold": t}` when the distinct
values first seen in the request, summed over those three maps, reached the
tenant's `bulk_threshold`, and null otherwise or on rows written before it
existed. It is in the lifecycle metadata, the analytics row, the request list
and its CSV (as JSON) and the community JSONL event. A crossing request also
appends one `privacy.bulk_disclosure` outbox intent, idempotency key
`bulk_disclosure:<request_id>`, carrying ids, provider, model, the two numbers
and counts by type; never a value, placeholder or prompt text. Its handler
queues one delivery per enabled forward target (`kind: "bulk_disclosure"`), and
none when the tenant has no target.

`response_entities` holds the distinct values a delivered answer carried that
the request did not, by entity type, when the tenant's `response_scan` is
`count`. The scan runs after the answer is sent, so the field is written to the
lifecycle metadata in its own short transaction, with `response_scan`
(`{"truncated": bool}`, or `{"error": true}` and `response_entities: null` when
the scan failed). The request list and its CSV read it from the lifecycle row;
it is null while the scan is off or still running, and it is not in the
analytics row or the audit completion. The community JSONL writes it as a
second line per request, `event: "response_privacy"`, next to the
`event: "request"` line.

The community JSONL v4 event contains `shim_latency_ms` instead of the ambiguous `latency_ms`,
with `system_prompt_hash` set only when `SYSTEM_PROMPT_HASH_KEY` is configured
(null otherwise, and for a request without system instructions). It also carries `cost_center` (the
first valid `X-Shim-Tag` value, or `untagged`) and `tags` (the valid header
tags); an event written before admission, such as a rejection, has
`cost_center: null` and `tags: []`. Every request line also carries `ts` (the
request's start, UTC ISO 8601 with milliseconds and `Z`), `protocol`
(`openai_chat`, `openai_responses`, `anthropic_messages`,
`anthropic_count_tokens`, which only rejected and failed token counts write, or
`gemini`), `stream`, and the four answer facts above; a rejected or failed line
has `provider_latency_ms: null`, `answer_characters: null`, `tool_call_names: []`
and `reasoning_seen: false`.

`response_analysis` holds the results of the after-answer analyzers the tenant
turned on in its [gateway settings](COOKBOOK.md#change-the-gateway-settings),
by analyzer name, plus `versions` (each analyzer's version), for example
`{"shape": {...}, "versions": {"shape": "1"}}`. An analyzer that raised or
returned anything but a JSON object is `{"error": true}`; one whose result would
exceed 4,096 characters of compact JSON keeps its counts and digests with its
lists as `null`, or, still too large, is `{"error": true, "reason": "too_large"}`;
one the run's one-second budget no longer started is
`{"error": true, "reason": "timeout"}`; one with nothing to record is left out,
and when none recorded anything the key is absent. Results are counts,
labels, ids, protocol field names and JSON pointers, never text from the request
or the answer. An analyzer that reads the answer (`language`, `schema`,
`refusal`) does not run for a request that carried personal data (any detected
value, masked or monitored), so nothing derived from such an answer is stored;
`shape` reads only the masked request and still runs. The pass runs only for
completed requests, after the answer was delivered, in the same task as the response scan, and writes the key into the
lifecycle metadata in its own short transaction; a failed write is logged by
type and dropped. The request list reads it from the lifecycle row and the CSV
writes it as compact JSON with sorted keys. The community JSONL writes one more
line per request, `event: "response_analysis"`, with the same object as
`results`. Analysis has its own worker thread with room for 64 pending
requests; a request beyond that is not analysed and the key stays absent.
`shim_response_analysis_total{analyzer, result}` counts each run as `ok`,
`none`, `error` or `dropped`.

`response_analysis.shape` records what a request was made of: turn, history,
system and tool-result sizes, the tools it offered by name and in order, the
tool calls it replayed, the order and set digests of the offered names, and
image and document counts with the largest inline image's size. Sizes count the
request as the provider saw it: a value of a type that masks counts as its
placeholder, one under `monitor` or `off` as written. Tool names are stored in
clear, which is what the switch is for, and only as 1 to 64 of
`A-Za-z0-9_.:-` (others are counted in `tool_names_dropped`); tool definitions are never
stored or hashed. The keys are listed in the
[community cookbook](../../docs/COOKBOOK.md#analyse-answers-after-delivery).

`response_analysis.language` labels the last user question and the answer
`tr`, `en`, `other` or `unknown`, with `answer_mixed` and the two word counts.
It is a heuristic for Turkish and English only and records no word or score;
how it decides is in the same cookbook section.

`response_analysis.schema` says whether the answer or each tool call matched
the schema the request asked for: `expected`, `valid` (`null` when undecided),
the JSON Pointer and keyword of the first failure, the tool name for a tool
call, the unsupported keywords met, `strict` and a `reason` when it was not
checked. It holds schema property names and indices, never a value. The subset
and the reasons are in the community
[cookbook](../../docs/COOKBOOK.md#check-structured-output).

`rule_matches` lists the [tenant rules](POLICY_DECISIONS.md#tenant-rules) that
matched, as `rule_id`, `kind`, `action`, `state` and `count` (plus `error: true`
when the rule's evaluation failed), blocks first and then by id, at most 32;
`rule_matches_truncated` says whether more matched. Both are written with the
privacy facts, so a refused request has them too. They are `[]` and `false`
when a rule matcher ran and nothing matched, and absent when none ran: no
rules, no rule in scope for the request, or only rules this release cannot
run (those show as a `rule.<id>` verdict). A match is ids and counts, never the matched text. The request list and
its CSV (compact JSON) show it, the community JSONL event carries it, and
`GET /api/v1/management/requests?rule_id=<id>` and the export filter on one
rule. `shim_rule_matches_total{kind, action, state}` counts every match.

`approval_id` is the [request approval](POLICY_DECISIONS.md#request-approval)
the approval gate decided the request with: the one it was held under
(`APPROVAL_REQUIRED`), refused under (`APPROVAL_REJECTED`) or consumed. It is
absent when the queue was full or the gate could not be reached (the error
code says which) and on requests the gate never saw. The request list, its
CSV and `GET /api/v1/management/requests?approval_id=<uuid>` carry it.

`request_archive` says what the self-hosted
[request archive](POLICY_DECISIONS.md#request-archive) did with the request:
`stored` (its row committed) or `skipped_size` (the payload was over 2,000,000
bytes); absent when the archive is off, the request was clean, the write
failed, or it resent a held request whose content is already kept. The request list and its CSV show it as `content_archived` (true only for
`stored`), so a member sees which of their requests an admin could open.

## Outcome filters, counts and rates

`/requests` and `/requests/export` accept two optional filters:

- `completion_outcome`: `complete`, `truncated`, `empty`, `refused`,
  `filtered`, or `none` for a request without a recorded outcome (failed,
  rejected and historical rows). Any other value is 422.
- `soft_refusal`: `true` or `false`, matched against
  `response_analysis.refusal.soft_refusal` on the request's lifecycle row. The
  refusal analyzer writes that field only when the tenant enabled it, so an
  answer it never read matches neither value.

Both combine with every other filter, and a member still sees only their own
keys. The list summary carries `outcome_counts` (`complete`, `truncated`,
`empty`, `refused`, `filtered`, `none`) under the active filters; they sum to
`requests`.

`GET /api/v1/management/outcomes?start&end&group_by=model|api_key|team` (owner,
admin, auditor; window default the last 7 days, at most 31) counts the requests
with a `completion_outcome` per requested model, API key (with its name) or team
(`team_id`, with its name; requests without a team are one group with a null
`group`). Each group has `settled` and the five outcome counts,
`truncation_rate` (truncated / settled) and `refusal_rate` ((refused + filtered
+ empty) / settled), and `analysed`, `soft_refused` and `soft_refusal_rate` for
answers the refusal analyzer read. A rate is null when its denominator is 0.
Groups are sorted by `settled`, at most 200 with `truncated: true` beyond, and
`totals` covers every group. The rates per API key also drive the
[`gateway.truncation_rate` and `gateway.refusal_rate`
findings](FINDINGS.md#gatewaytruncation_rate).

## Latency per group

`GET /api/v1/management/latency` reads the request timestamps on demand over the
indexed `started_at` window; there is no rollup table. Its measures:

- first byte: `ttft_ms` for a stream, `provider_latency_ms` for a JSON answer;
- shim queue: `provider_started_at - started_at`, shim's admission, privacy and
  reservation commits before the provider call;
- output tokens per second: a stream's settled `completion_tokens` over
  `completed_at - stream_started_at`, which includes the terminal commit, so it
  slightly understates the provider's speed; not for estimated usage, answers with
  reasoning, or streams under one second;
- peak concurrency: each request's span from `provider_started_at` to
  `completed_at` (still running: to the window's end), clipped to every bucket it
  overlaps, swept in time order with an end before a start at the same instant;
  a request without `provider_started_at` never reached the provider and is not
  counted;
- head of line: one time-ordered pass per group over long requests' starts and
  ends and short streams' starts counts the long requests in flight when each
  short stream starts (a long request covers its start, not its end).

The findings `gateway.cold_start` and `gateway.queueing` use the same sweep;
`gateway.cold_start` reads only streams' first byte
([findings](FINDINGS.md#gatewaycold_start)).

## Tokens per character by language

`GET /api/v1/management/language-cost` divides the quota settlement's
`completion_tokens` by the answer's `answer_characters`, per model or API key and
per answer language (`response_analysis.language.answer`, `tr` or `en`). No
tokenizer is used: the provider's own count is the measure. Only the output side
is measured, because `prompt_tokens` mixes system prompts, tool definitions,
history and cached prefixes with the question. An answer counts when it ended
`complete`, has at least 200 characters, called no tool, carried no reasoning
(`reasoning_seen`; Gemini thought parts count as answer text, so a Gemini answer
with thoughts is left out too) and its settlement is not estimated; the others
are counted under `excluded` (`estimated_usage`, `tool_calls`, `reasoning`,
`short`, `not_analysed`, `language_unknown`, the first that applies). Money uses
the output price the spend settlement recorded, the large-context one once the
prompt crossed its threshold; unpriced settlements add none. The model is the one
the spend settlement billed, so a registry alias groups under its provider model,
named by the price-book entry it matches (the longest entry it equals or extends
with `-`, as the gateway matches prices) or `other`: a provider model name never
reaches the answer or the evidence PDF as written. One statement reads the
exclusions and the ratios together.

## Responses continuation markers

Enterprise writes an encrypted continuation marker to Redis for every Responses
turn, with the `PRIVACY_CHAIN_TTL_SECONDS` lifetime, so a later
`previous_response_id` can restore that turn's placeholders. The marker of a turn
without personal data is empty and best-effort: if Redis cannot store it, the
turn still succeeds. A missing marker still reads as a turn without personal
data; a later release will make it fail closed.

## Cost basis

Settlement prices input exactly when the provider reported its prompt-cache
split: uncached input at the input price, cache reads at the cache-read price,
cache writes at the cache-write price and Anthropic one-hour writes at twice the
input price. A catalog entry without a cache-read price uses the input price;
without a cache-write price, 1.25 times input for Anthropic and the input price
elsewhere. OpenAI reports no cache-write count, so a token it writes to the cache
arrives as uncached input: an OpenAI model's uncached input is priced at the
higher of its input and cache-write prices, and no write is charged separately.
The reservation, estimated usage, provider usage without cache fields
and failure estimates price every input token at the highest of input, cache
write and, for Anthropic, the one-hour write price. The ledger's pricing
metadata records the three cache prices used and, when reported,
`cache_read_tokens`, `cache_write_tokens` and `cache_write_1h_tokens`.
`cached_input_tokens`, their sum, is in the lifecycle metadata, the analytics
row, the request list and its CSV; it is null when the split was not reported.

The catalog keeps each model's `context_window`, `input_limit`, `tools`,
`structured_output`, `input_modalities` and `status` from models.dev when the
source has them. A deprecated model stays in the catalog with
`status: "deprecated"` and is still priced.

## Warnings

`warnings` lists the `X-Shim-Warnings` codes a request carried
(`MODEL_DEPRECATED`, `CONTEXT_MAY_EXCEED`, `LARGE_CONTEXT_PRICE`,
`CACHE_NOT_APPLIED`, `RULE_WARN`), `[]` when none. It is in the lifecycle metadata at
finalization, the analytics row, the request list and its CSV (comma-separated),
and the community JSONL event. `GET /api/v1/management/requests?warning=<code>`
and the export filter on one code. Rows written before it existed read as null.
A stream's header carries only the codes known before it started; the record
carries all of them. `shim_warnings_total{code}` counts them.

## Unpriced deployment costs

A deployment with a stated price settles at it, with
`pricing_resolution = "deployment"`, and is counted like any priced request. An
unknown deployment price is not a free request. A terminal spend settlement
marked `event_metadata.pricing.pricing_resolution = "unknown"` is exposed by the
request API as `cost_usd: null` and `cost_complete: false`; CSV exports use an
empty cost cell and `cost_complete: False`. The request summary reports
`unpriced_requests`, `cost_complete`, and a `settled_spend_usd` subtotal containing
only priced settlements. These checks read the tenant-scoped ledger directly,
so missing projection metadata cannot turn an unknown settlement into zero.

Overview summary and trend costs are null whenever their period includes an
unpriced settlement, with the same completeness flag and request count. Empty
periods retain known zero costs.

Billing daily and grouped rows expose null costs for groups with an unpriced
settlement. Billing usage totals are also null when incomplete. CSV exports use
empty cost cells plus completeness/count columns; PDF exports label those
groups `Unknown` with the number of unpriced requests.

Budget alerts retain a known-settlement subtotal in `current_usd` and label it
`cost_basis: known_settled_spend`, with `cost_complete` and `unpriced_requests`.
Their contributor rows have the same completeness markers. Threshold evaluation
uses known spend and settled tokens; missing prices cannot imply full coverage.

Analytics `details` and audit completion `extra` also carry `pricing_resolution`.
Their existing numeric cost fields reflect the ledger placeholder when it is
unknown; consumers must inspect that marker. Refunds and requests without a
spend settlement have known settled cost zero. Pricing completeness does not
claim provider-invoice accuracy or actual token measurement; `usage_estimated`
continues to describe token fallback independently.

To verify the contract, run the streaming/community tests and
`ee/tests/gateway/kernel/test_accounting_coordinator.py` plus
`ee/tests/gateway/api/test_management.py` against disposable PostgreSQL/Redis.

The metadata uses existing JSONB storage and adds no database transaction or
network call. Measure overhead with representative payloads and concurrency.
