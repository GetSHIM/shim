# Finding schema, version 1

Every finding the enterprise gateway produces has one shape, served by the
findings API and carried by its OCSF export. The shape is a pydantic model,
`shim.findings.Finding`, published as a JSON Schema (Draft 2020-12) in
[`docs/schemas/finding-v1.json`](schemas/finding-v1.json).
`python scripts/export_finding_schema.py` writes the file, and the test suite
fails while it differs from the model. Other producers (`shim doctor --json`,
LiteLLM imports) are planned to emit it; none does yet.

## What changes for existing apps

v0.3.0 served findings in its own shape. From this release the findings API
(`GET /findings`, `GET` and `PATCH /findings/{id}`) answers in v1 instead:

| v0.3.0 | v1 |
| --- | --- |
| `summary` (one English sentence) | `summary.en` and `summary.tr` |
| `severity_id` 1 to 5 | `severity`, `informational` to `critical` |
| `status` and `status_id` | `status` (`open`, `resolved`, `dismissed`) and `status_detail` (`new`, `in_progress`, `suppressed`, `resolved`) |
| `subject` `{"api_key_id"}`, `{"model"}` or `{"deployment_id", "alias"}` | `subject` `{"kind", "id"}`; a deployment is its id, its alias is not repeated |
| `first_seen_at`, `last_seen_at` | `window.start`, `window.end` |
| `evidence` (an object of ids and numbers) | `evidence` (a list of references) and `measurements` (the numbers) |
| `impact.cost_usd` | `impact.usd` |
| `remediation.doc` | `playbook` |
| `resolved_at`, `resolved_by` | the same names |

The `?status=` filter and the `PATCH` body accept the v1 values as well as the
v0.3.0 ones: `open` lists `new` and `in_progress`, `dismissed` means
`suppressed`, and `PATCH` with `open` leaves an open finding as it is and
reopens a closed one as `new`. The OCSF export keeps every field it had; its
`unmapped` object now carries the v1 parts (below).

## Fields

| Field | What it holds |
| --- | --- |
| `schema_version` | `"1"` |
| `id` | The finding's id, 1 to 128 of `A-Za-z0-9_.:-` |
| `source` | `gateway`, `litellm` or `shim-cli` |
| `rule_id`, `rule_version` | The rule that concluded it, such as `gateway.retry_storm`, and its version |
| `title` | The rule's English title |
| `summary` | `{"en", "tr"}`, one sentence each, filled from `measurements` |
| `severity` | `informational`, `low`, `medium`, `high` or `critical` |
| `status`, `status_detail` | `open`, `resolved` or `dismissed`; the workflow state `new`, `in_progress`, `suppressed` or `resolved` when the source has one |
| `subject` | `{"kind", "id"}`, kind `key`, `team`, `deployment`, `model`, `tenant` or `app` |
| `window` | `{"start", "end"}` in UTC: first and last time the rule saw it |
| `occurrences` | How many evaluations found it, or `null` |
| `evidence` | Up to 50 references `{"kind", "id"}`: `request`, `ledger_row`, `audit_row`, `finding`, `policy_version`, `cli_session` |
| `measurements` | Up to 32 finite numbers by name (`^[a-z][a-z0-9_]{0,63}$`) |
| `impact` | `requests`, `tokens`, `usd` (a fixed-point string), `risk_class` (`privacy`, `cost`, `reliability`, `quality`); each may be `null` |
| `remediation` | `mode` and `max_mode` (`observe`, `suggest`, `auto`; `mode` never above `max_mode`), `action` and `proof_after` (objects, `null` until a later release defines and fills them), `reversible`, `blast_radius` (a subject kind) and `text` (`{"en", "tr"}`) |
| `playbook` | A repository-relative doc and anchor, such as `ee/docs/FINDINGS.md#gatewayretry_storm`, readable offline |
| `resolved_at`, `resolved_by` | When and by whom it was resolved (a user id, or `system` when it resolved itself), or `null`; optional |

`measurements` are JSON numbers, for templates and charts: an amount of money
there, such as `repeated_cost_usd`, is rounded like any float. The exact amount
is `impact.usd`, a decimal string.

A measurement name is a fixed word, never a stored value: a count kept per
class, provider or model reaches `measurements` only under a name from the
producer's own vocabulary (such as `requests_openai`, with `requests_other` for
the rest), and a value outside it stays in the producer's store.

The schema checks every field's type, bounds and vocabulary, that `measurements`
holds only names of the pattern above, that `window.start` and `window.end` are
UTC (`Z` or `+00:00`), and that `mode` is not above `max_mode`. One rule it
cannot express: `window.start` is never after `window.end`. shim's producers
check that rule too, and refuse keys this version does not define.

## No values, only references

A finding references what it is about; it never contains it. `evidence` holds
ids, `measurements` holds numbers, and the only free text, `title`, `summary` and
`remediation.text`, comes from the rule's fixed templates filled with
measurements. No prompt, answer, detected value, key or response body enters a
finding. A request reference opens through the request list
(`GET /api/v1/management/requests?request_id=`).

## Versioning

v1 is open for additions:

- An added optional field, or a new value of an existing vocabulary, keeps
  `schema_version: "1"` and updates the file. Every object in the file allows
  keys it does not list, so an older copy still validates a newer finding's
  fields.
- A reader ignores keys it does not know and treats a value it does not know
  (a new `severity`, `subject.kind`, `risk_class`, `evidence.kind` or `rule_id`)
  as "other". A validator that checks vocabularies uses the newest file at the
  schema's `$id`.
- A removed, renamed or retyped field, or one that becomes required, is
  `finding-v2`.
- A rule id never changes meaning; a changed threshold or template bumps
  `rule_version`.

## Example

```json
{
  "schema_version": "1",
  "id": "3f2c9e1a-0b7d-4c5e-9a1f-1234567890ab",
  "source": "gateway",
  "rule_id": "gateway.retry_storm",
  "rule_version": 1,
  "title": "Retry storm from one API key",
  "summary": {
    "en": "One API key sent 20 repeated requests within 15 minutes; the threshold is 20.",
    "tr": "Bir API anahtarı 15 dakika içinde 20 tekrarlanan istek gönderdi; eşik 20."
  },
  "severity": "medium",
  "status": "open",
  "status_detail": "new",
  "subject": {"kind": "key", "id": "11111111-1111-1111-1111-111111111111"},
  "window": {"start": "2026-10-08T12:07:00Z", "end": "2026-10-08T12:22:00Z"},
  "occurrences": 2,
  "evidence": [{"kind": "request", "id": "req_0123456789abcdef0123456789abcdef"}],
  "measurements": {"window_minutes": 15, "repeated_requests": 20, "threshold": 20, "abandoned_requests": 0},
  "impact": {"requests": 20, "tokens": null, "usd": "0.20000000", "risk_class": "cost"},
  "remediation": {
    "mode": "observe",
    "max_mode": "suggest",
    "action": null,
    "reversible": true,
    "blast_radius": "key",
    "proof_after": null,
    "text": {"en": "Find the client behind this key and make it back off: …", "tr": "Bu anahtarın arkasındaki istemciyi bulun …"}
  },
  "playbook": "ee/docs/FINDINGS.md#gatewayretry_storm",
  "resolved_at": null,
  "resolved_by": null
}
```
