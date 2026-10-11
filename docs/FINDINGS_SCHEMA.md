# Finding schema, version 1

Every finding shim produces has one shape: the enterprise findings API and its
export, LiteLLM imports and `shim doctor --json` alike. The shape is a pydantic
model, `shim.findings.Finding`, published as a JSON Schema (Draft 2020-12) in
[`docs/schemas/finding-v1.json`](schemas/finding-v1.json); the package carries the
same file as `shim/findings/finding-v1.schema.json`.
`scripts/export_finding_schema.py` writes both copies and `--check` fails when
either differs from the model.

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
| `remediation` | `mode` and `max_mode` (`observe`, `suggest`, `auto`; `mode` never above `max_mode`), `action` (`{"kind", "params"}` or `null`), `reversible`, `blast_radius` (a subject kind), `proof_after` (`{"metric", "window_hours", "baseline", "threshold", "comparison"}` or `null`) and `text` (`{"en", "tr"}`) |
| `playbook` | A repository-relative doc and anchor, such as `ee/docs/FINDINGS.md#gatewayretry_storm`, readable offline |

Every object is closed (`additionalProperties: false`) except `measurements` and
`remediation.action.params`.

## No values, only references

A finding references what it is about; it never contains it. `evidence` holds
ids, `measurements` holds numbers, and the only free text, `title`, `summary` and
`remediation.text`, comes from the rule's fixed templates filled with
measurements. No prompt, answer, detected value, key or response body enters a
finding. A request reference opens through the request list
(`GET /api/v1/management/requests?request_id=`).

## Versioning

- Producers validate with the newest v1 file; readers ignore keys they do not
  know.
- An added optional field keeps `schema_version: "1"` and updates the file.
- A removed, renamed or retyped field, or one that becomes required, is
  `finding-v2`, and both versions are served for one release.
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
  "playbook": "ee/docs/FINDINGS.md#gatewayretry_storm"
}
```
