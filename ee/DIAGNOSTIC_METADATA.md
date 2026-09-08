# Diagnostic metadata

The gateway records the following observations without archiving prompts,
responses, provider error prose, or credentials. Native responses and the one
provider attempt rule are unchanged.

| Field | Meaning | Unknown/unavailable value |
| --- | --- | --- |
| `provider_finish_reasons` | Map of native completion facts, preserving candidate indices and provider spelling. See the protocol table below. | `null` when no recognized native completion fact was observed; absent map entries remain unknown. |
| `repeat_chain_length` | Number of matching request-content observations in the configured tenant repeat window, including this request (`1` for the first observation). | `null` when the detector has no observation, including Redis unavailability. |
| `ttft_ms` | Floating-point milliseconds from the provider-start callback, after its durable marker commits, to the first nonempty text, refusal, thinking, code, tool arguments, or supported media content observed after restoration. Uses a monotonic clock. | `null` for JSON responses, missing start time, or streams without supported content. |
| `system_prompt_hash` | `hmac-sha256:v1:` followed by a 64-character digest of explicitly supplied system/developer instructions. | `null` when instructions are absent or inherited from provider-held state. |
| `deployment_kind` | `internal`, `external`, or `unknown`, supplied by trusted deployment resolution. | New unclassified requests use `unknown`; historical rows use `null`. |

The repeat count is a content-match observation, **not evidence of a retry**.
Its existing matching algorithm selects prompt fields plus provider/model,
sorts JSON keys, applies NFKC normalization, and collapses whitespace. The
window and any process/Redis state loss affect comparability. A denied request
that never acquires a durable lifecycle has no diagnostic projection; its
policy-decision event owns denial evidence.

TTFT is gateway observation time, not the model's internal computation time or
the client's first-byte time. It excludes request admission and input privacy
processing, includes upstream wait and output restoration, and does not count
headers, SSE comments/heartbeats, roles, empty deltas, usage, or terminal events.
Supported media events are OpenAI audio deltas and partial images, and Gemini
inline media. Media contributes to TTFT without being counted as text tokens.
The existing latency and lifecycle status fields remain independent.

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

## System-instruction hashing

The enterprise quota reservation computes the digest before input privacy
transformation. Hash material is the JSON array
`["shim.system_prompt.v1", tenant_id, protocol, instructions]`:

- Chat: only `role` and `content` from ordered system/developer messages.
- Responses: explicit `instructions` and ordered system/developer `input` messages.
- Messages: explicit `system` value.
- Gemini: explicit `systemInstruction` value.

Canonical JSON sorts object keys, uses compact separators and ASCII escapes,
and preserves array order, content whitespace, and Unicode without normalization.
The HMAC key is `COMPLIANCE_HASH_SALT`, falling back to `SECRET_KEY`. Keep that
key secret and unique per installation. Comparisons are scoped to that key,
tenant, protocol, and algorithm version; changing the key ends comparability
with earlier digests. Model names and user conversation content are excluded.
An explicitly empty instruction differs from an absent instruction. Provider-held
prompts, previous responses, and cached instructions are not reconstructed.

## Persistence and reading

Request fields enter `request_lifecycle.metadata` during quota reservation.
Completion facts and TTFT join them in the terminal accounting transaction,
before audit/analytics outbox intent is constructed. Terminal replay preserves
the first committed observations. Analytics delivery copies them into
`request_logs.details` with the existing tenant/request idempotency constraint.
No table or column migration is needed for these existing JSONB fields.

`GET /api/v1/management/requests` exposes the five optional fields on each
request; `/requests/export` includes the same fields in CSV (unknown values
are empty cells, and finish-reason maps are JSON). Audit completion `extra`
carries the same fields. Historical rows and
old outbox messages read as null without invented backfills. The community
JSONL event also contains them, with `system_prompt_hash: null` because community
has no configured installation hashing key.

## Unpriced deployment costs

An unknown deployment price is not a free request. A terminal spend settlement
marked `event_metadata.pricing.pricing_resolution = "unknown"` is exposed by the
request API as `cost_usd: null` and `cost_complete: false`; CSV exports use an
empty cost cell and `cost_complete: False`. The request summary reports
`unpriced_requests`, `cost_complete`, and a `settled_spend_usd` subtotal containing
only priced settlements. These checks read the tenant-scoped ledger directly,
so missing projection metadata cannot turn an unknown settlement into zero.

Analytics `details` and audit completion `extra` also carry `pricing_resolution`.
Their existing numeric cost fields reflect the ledger placeholder when it is
unknown; consumers must inspect that marker. Refunds and requests without a
spend settlement have known settled cost zero. Pricing completeness does not
claim provider-invoice accuracy or actual token measurement; `usage_estimated`
continues to describe token fallback independently.

To verify the contract, run the streaming/community tests and
`ee/tests/gateway/kernel/test_accounting_coordinator.py` plus
`ee/tests/gateway/api/test_management.py` against disposable PostgreSQL/Redis.
