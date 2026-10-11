# shim enterprise cookbook

Recipes for operators running `shim-enterprise` as described in
[customer-operated deployment](../deploy/README.md), reachable at
`http://localhost:8000`. Management and compliance routes under `/api/v1` take
a signed-in user's bearer token, never a gateway key: a Supabase access token,
or with `AUTH_MODE=oidc` a token for `OIDC_API_AUDIENCE`
([on-prem identity](ON_PREM_IDENTITY.md)). The examples read it from
`$USER_TOKEN`, and assume an owner or admin unless a recipe says otherwise.
Gateway keys are the `sk-shim-` plaintext that
`POST /api/v1/management/api-keys` returns once; the examples read one from
`$SHIM_KEY`. Calling the provider routes works as in the
[community cookbook](../../docs/COOKBOOK.md). All data in the examples is synthetic.

- [Attribute spend to teams](#attribute-spend-to-teams)
- [Alert on a budget](#alert-on-a-budget)
- [Change the privacy settings](#change-the-privacy-settings)
- [Change the gateway settings](#change-the-gateway-settings)
- [Write a tenant rule](#write-a-tenant-rule)
- [Keep a data type inside](#keep-a-data-type-inside)
- [Catch your customer list](#catch-your-customer-list)
- [Show masked values only to some teams](#show-masked-values-only-to-some-teams)
- [Cap tools, documents and history](#cap-tools-documents-and-history)
- [Stay under the price tier](#stay-under-the-price-tier)
- [Read the daily privacy card](#read-the-daily-privacy-card)
- [Send tenant alerts](#send-tenant-alerts)
- [Refuse provider keys sent in requests](#refuse-provider-keys-sent-in-requests)
- [Export and verify the audit trail](#export-and-verify-the-audit-trail)
- [Produce a KVKK exposure report](#produce-a-kvkk-exposure-report)
- [Register a private model deployment](#register-a-private-model-deployment)
- [Automate management with a service account](#automate-management-with-a-service-account)
- [Give someone exactly the access they need](#give-someone-exactly-the-access-they-need)
- [Plan, apply and undo a change](#plan-apply-and-undo-a-change)
- [See what changed after a prompt change](#see-what-changed-after-a-prompt-change)
- [Read and export findings](#read-and-export-findings)
- [Find truncated and refused answers](#find-truncated-and-refused-answers)
- [Is our model list complete?](#is-our-model-list-complete)
- [Record an incident](#record-an-incident)
- [Collect the monthly evidence file](#collect-the-monthly-evidence-file)
- [Prepare for ISO/IEC 42001](#prepare-for-isoiec-42001)

## Attribute spend to teams

Report tokens and cost per team, per cost center and per header tag.

1. Create a team: `POST /api/v1/management/teams` with a `name` of up to 128
   characters (owner or admin). It answers 201 with the team's `id`, or 409 when
   the name exists. The optional `daily_request_limit`, `monthly_request_limit`
   and `monthly_token_limit` are team quotas, described in
   [team access](team-access.md#quotas).
2. Put a key in the team: `PATCH /api/v1/management/api-keys/{id}` with
   `team_id`. Only owners and admins move a key between teams. The same call sets
   the key's billing label `team` and its `cost_center`, both lowercased and
   limited to `a-z`, `0-9`, `_`, `.`, `:` and `-`. A new key can carry the same
   fields in `POST /api/v1/management/api-keys`.
3. Read `GET /api/v1/management/billing/breakdown`. `group_by=team_id` groups by
   the key's team, with keys outside a team and older requests under
   `unassigned`. `group_by=team` groups by the label, `untagged` when it is
   unset. The other groupings are `model` (default), `tag`, `cost_center` and
   `provider`.

```console
TEAM_ID=$(curl -s -X POST http://localhost:8000/api/v1/management/teams \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "payments"}' | jq -r .id)

curl -X PATCH "http://localhost:8000/api/v1/management/api-keys/$KEY_ID" \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"team_id\": \"$TEAM_ID\", \"team\": \"payments\", \"cost_center\": \"payments\"}"

curl 'http://localhost:8000/api/v1/management/billing/breakdown?group_by=team_id' \
  -H "Authorization: Bearer $USER_TOKEN"
```

Each row has `key`, `label`, `request_count`, `prompt_tokens`, `completion_tokens`,
`cost_usd`, `unpriced_requests` and `cost_complete`; `cost_usd` is `null` when
any request in the row had no price. With `group_by=team_id`, `label` is the
team's current name, and `null` for `unassigned` or a deleted team; the other
groupings leave it `null`. The CSV export adds it as the last column, and the
PDF prints the name in place of the team id.

Notes:

- A key's `cost_center` becomes the cost center of every request it makes and
  wins over `X-Shim-Tag`. The header's tags are still recorded, and
  `group_by=tag` counts a multi-tag request once in each of its tag rows. Without
  a key cost center, the first valid header tag is the cost center, as in
  [community](../../docs/COOKBOOK.md#tag-requests-and-read-their-cost).
- The window is `start_date` to `end_date`, by default the last 30 days and at
  most 31 days; `limit` is 100 rows by default and at most 500.
  `GET /api/v1/management/billing/export` takes the same `group_by` with
  `format=csv` or `format=pdf`.
- Owners, admins and auditors read billing; members get 403. The full read scope
  is in [team access](team-access.md#read-scope).

## Alert on a budget

Get a Slack message or a webhook call when spend or tokens cross a share of a monthly limit.

1. `POST /api/v1/management/cost/budgets` (owner or admin) with:
   - `scope_type`: `org`, `tag`, `team` or `team_id`, and `scope_value` for the
     last three. `tag` matches requests carrying that `X-Shim-Tag` tag; `team`
     matches the key's billing label `team`; `team_id` matches the key's team,
     whatever its label, and takes the team's `id` (422 "Unknown team" for a
     malformed id or one outside your organization). For `tag` and `team`,
     `scope_value` is normalized the way those labels are: `Payments` is stored
     and matched as `payments`, and a value outside letters, digits, `.`, `_`,
     `:` and `-` (at most `COST_TAG_MAX_LENGTH`) answers 422.
   - `limit_usd`, `limit_tokens`, or both, each greater than 0.
   - `alert_thresholds`: one to 10 unique fractions greater than 0 and at most
     5; `0.8` means 80 percent and `1.5` means 150 percent. Default
     `[0.8, 1.0]`. Responses repeat them as percentages in
     `alert_thresholds_percent`.
   - `notify_targets`: one to 10 of `{"kind": "slack" | "webhook", "endpoint": ...}`;
     a budget nobody hears about answers 422. A webhook may add `"secret"` (at
     least 16 characters) to sign its deliveries. An endpoint must be a public
     HTTPS URL or an origin the operator approved in `ALERT_ALLOWED_ORIGINS`
     ([on-prem alerts](ON_PREM_IDENTITY.md#alert-delivery-on-a-closed-network)),
     otherwise 422 "Unsafe notification URL". Endpoint and secret are kept in
     the secret store; responses show only `endpoint_origin` and `signed`.
2. Wait for the reconciliation worker, which evaluates enabled budgets every
   `BUDGET_EVALUATION_INTERVAL_SECONDS` (default 300, from 30 to 86,400), or run
   `POST /api/v1/management/cost/budgets/evaluate` for an immediate pass.

```console
curl -X POST http://localhost:8000/api/v1/management/cost/budgets \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"scope_type": "tag", "scope_value": "checkout", "limit_usd": 500,
       "alert_thresholds": [0.5, 0.9, 1.0],
       "notify_targets": [{"kind": "webhook", "endpoint": "https://alerts.example.com/shim"}]}'

curl -X POST http://localhost:8000/api/v1/management/cost/budgets/evaluate \
  -H "Authorization: Bearer $USER_TOKEN"
```

The evaluate call answers `period` (`YYYY-MM`) and one result per enabled budget
with `budget_id`, `fraction`, `fired` (thresholds crossed now) and `enqueued`.
A budget's `scope_label` is the team's current name for a `team_id` scope, and
`null` otherwise or when the team no longer exists.

Notes:

- The period is the UTC calendar month. Each threshold fires once per budget per
  month. The fraction is the larger of known settled spend over `limit_usd` and
  tokens over `limit_tokens`.
- The outbox worker delivers the alert. A webhook receives
  `{"event": "budget.threshold_crossed", "payload": {...}}` with an
  `idempotency-key` header and, when it has a secret, `X-Shim-Signature:
  sha256=<hex HMAC-SHA256 of the raw body with the secret>`, the same scheme as
  compliance forward targets. `payload.percent_used` keeps full precision;
  Slack receives a text message with the percentage rounded to a whole number.
  For a `team_id` budget the payload carries `scope_label`, the team's name when
  the alert was raised (`null` once the team is deleted), and Slack names the
  team instead of its id.
- A `team_id` budget counts requests that recorded the key's team, which every
  request does since team ids were added to request records; older requests do
  not count. Renaming the team changes only `scope_label`.
- Budgets stored before these checks, with a zero limit, no threshold or no
  target, still evaluate and simply never alert; a `PATCH` that sends one of
  those values answers 422.
- A budget alerts and never refuses a request. For a hard stop, use a stored
  provider credential's `monthly_limit_usd`, which refuses with
  `SPEND_LIMIT_EXCEEDED`, or team quotas.
- One evaluate call handles at most 100 budgets and 100 potential deliveries;
  beyond that it answers 422.

## Change the privacy settings

Choose what shim does with each entity type for your tenant. All five group
switches are on by default, so every type is masked.

1. Read the current settings with `GET /api/v1/management/settings/pii`:
   the five switches, `entity_actions` (your per-type overrides) and
   `effective_actions` (the action every type gets).
2. Send only what you change in `PUT /api/v1/management/settings/pii`
   (owner or admin). A switch on masks its types and a switch off leaves them
   alone; an `entity_actions` entry wins for its type. `entity_actions` replaces
   the stored overrides whole, so send `{}` to remove them all.

| Action | What shim does |
| --- | --- |
| `mask` | Replaces the value with a placeholder and restores it in the answer. |
| `mask_last4` | `CREDIT_CARD` and `IBAN_CODE` only: masks, keeping the last four digits (card) or characters (IBAN) after the placeholder's hex, `<CREDIT_CARD_…~1111>`. |
| `monitor` | Sends the value unchanged and counts it in the request's `monitored_entities`. |
| `block` | Refuses the request with 400 `SECRET_BLOCKED` (`SECRET`, `DB_URI`) or `PII_BLOCKED` before any provider call. |
| `off` | Does not look for the type. |

| Switch | Entity types |
| --- | --- |
| `block_email` | `EMAIL_ADDRESS` |
| `block_phone` | `PHONE_NUMBER` |
| `block_credit_card` | `CREDIT_CARD` |
| `block_secrets` | `SECRET`, `US_SSN`, `IP_ADDRESS`, `MAC_ADDRESS`, `DB_URI`, `FILE_PATH` |
| `block_pii_tr` | `TR_NATIONAL_ID`, `TR_VKN`, `IBAN_CODE`, `TR_LICENSE_PLATE` |

```console
curl -X PUT http://localhost:8000/api/v1/management/settings/pii \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"block_pii_tr": false, "entity_actions": {"SECRET": "block", "EMAIL_ADDRESS": "monitor"}}'
```

`placeholder_mode` is `random` (default: a new placeholder per request) or
`stable`: the same value keeps its placeholder within the tenant for up to 30
days, so the provider's prompt cache works on prompts that carry a masked value,
and the provider can tell that two requests carry the same value; that linkage
can stay in the provider's logs after the window ends, and anyone who can read
those logs and send requests can confirm a guessed value. The key is derived
from `SECRET_KEY`, so rotating `SECRET_KEY` changes every placeholder. A leaked
`SECRET_KEY` lets its holder recompute the placeholders of low-entropy values
(phone numbers, national IDs) already in provider logs, and rotating afterwards
does not undo that.

`response_scan` is `off` (default) or `count`: after an answer is delivered,
shim counts the personal data in it that the request did not carry, and the
request list shows those counts as `response_entities`. The answer is never
changed or delayed.

`embeddings_monitor_types` (default `[]`) lists entity types an embeddings request
only counts: where their action is `mask`, `mask_last4` or `block`, an
`/v1/embeddings` or Gemini embed request sends them unchanged and counts them in
`monitored_entities`; chat keeps the action. Use it when the vectors go to an
internal store; otherwise prefer `placeholder_mode: stable`, so the same text gives
the same vector. The list replaces the stored one whole; an unknown type or `null`
is 422. Adding a type records `tenant.privacy_protection_relaxed` with
`embeddings_monitor_types.<TYPE>`; removing one does not.

`bulk_threshold` (default 50) raises a bulk-disclosure alert when one request
carries at least that many distinct detected values, across every type and
action; `null` turns it off. The request still goes on as its actions decide.
The request list shows `bulk_disclosure` on it, and every enabled
[forward target](#send-tenant-alerts) receives one alert with the counts by
type, the API key and the time, never a value.

Notes: an unknown type or action, `mask_last4` on a type other than
`CREDIT_CARD` or `IBAN_CODE`, `"entity_actions": null`, a `placeholder_mode`
other than `random` or `stable`, a `bulk_threshold` below 2 or above
2,147,483,647, or a
`response_scan` other than `off` or `count`, is 422. A blocked
request is listed under `/requests` as `rejected` with its `blocked_entities`.
Every change records a `tenant.privacy_policy_updated` audit event.
Turning a switch off, or moving a type down the order `block`, `mask`,
`mask_last4`, `monitor`, `off` through `entity_actions`, turning
`placeholder_mode` from `random` to `stable`, raising or clearing
`bulk_threshold`, or turning `response_scan` from `count` to `off`, also records
`tenant.privacy_protection_relaxed` and queues
one delivery to every enabled [forward target](#send-tenant-alerts) of the
tenant; turning it back on records only the update. Event details and the
forwarded body are in [decision evidence](POLICY_DECISIONS.md#management-change-details).

## Change the gateway settings

Turn the gateway's own switches on or off for your tenant. Every switch is off by
default; privacy switches stay under [privacy settings](#change-the-privacy-settings).

1. Read them with `GET /api/v1/management/gateway-settings` (`settings.read`:
   every built-in role): `settings` with every field, `revision` (0 until the first change),
   `updated_at`, `updated_by`, `available_analyzers`, and `unavailable`, which
   names a field that is "off, needs X" because an optional part is missing.
2. Send only what you change in `PATCH /api/v1/management/gateway-settings`
   (`settings.write`: owner or admin). The answer is the same body as the GET.

| Field | Default | What it does |
| --- | --- | --- |
| `response_analysis` | `[]` | Analyzers that read each completed answer after it was delivered, from `available_analyzers`; the request list shows their results as `response_analysis`. |
| `task_caps` | no cap, 3600 s | `max_calls`, `max_cost_usd` and `window_seconds` for one agent task (requests carrying `X-Shim-Task-Id` or a `traceparent`); see the [community recipe](../../docs/COOKBOOK.md#read-errors-and-retry). A PATCH changes only the fields it names; `null` removes a cap. |
| `agent_loop` | `count`, 5 | `action` (`off`, `count`, `block`) and `repeats` for the repeated-tool-call signal. |
| `inflight_sharing_api_key_ids` | `[]` | API keys (at most 1,000 of this organization) whose identical JSON requests in flight on one replica share the first one's answer; see the [community recipe](../../docs/COOKBOOK.md#read-errors-and-retry). |
| `restore_withheld` | `{}` | Per entity type or rule label, the teams and keys that get the value back in the answer; every other caller keeps the placeholder. See [show masked values only to some teams](#show-masked-values-only-to-some-teams). |
| `model_retiring_warning` | `"record"` | `header` also puts `MODEL_RETIRING` and `MODEL_RETIRED` in `X-Shim-Warnings`; the request list's `warnings` always has them. See [retiring models](MODEL_DEPLOYMENTS.md#retiring-models). |
| `price_tier_warning` | `false` | Add `PRICE_TIER_CROSSED` to `X-Shim-Warnings` when a request's approximate size is above a catalog model's large-context price tier; see [stay under the price tier](#stay-under-the-price-tier). |
| `injection_markers` | `"off"` | `count`: count instructions hidden in tool results and documents, shown as `injection_markers` in the request list; `warn`: also add `INJECTION_MARKERS` to `X-Shim-Warnings`. Nothing is blocked or changed; see the [community recipe](../../docs/COOKBOOK.md#count-instructions-hidden-in-tool-results). |

```console
curl -X PATCH http://localhost:8000/api/v1/management/gateway-settings \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"response_analysis": []}'
```

Notes: an unknown or repeated analyzer name, `null` for a field, or a field
that does not exist is 422. Names are stored in the order the analyzers run. A
change records `tenant.gateway_settings_updated` with the before and after of
the changed fields and increments `revision`; a PATCH that changes nothing
writes no event and keeps the revision. A change the setting's direction
classifies as relaxing also records `tenant.gateway_protection_relaxed`
([decision evidence](POLICY_DECISIONS.md#management-change-details));
`response_analysis` only measures, so it is neutral; moving `injection_markers`
down from `warn` to `count` or `off`, or from `count` to `off`, is relaxing;
`price_tier_warning` is a report, so turning it off is neutral, and so is
`model_retiring_warning`; raising or removing
a task cap, shortening its window, raising `agent_loop.repeats` or moving
`agent_loop.action` down from `block` are relaxing; listing a key in
`inflight_sharing_api_key_ids` is neutral, because each request still passes its
own limits and privacy and an answer never crosses keys, and an id this
organization lacks is 422. Gateways read the settings
from a cache that lives at most 300 seconds; a change clears it at once.
Enterprise ignores the community `SHIM_RESPONSE_ANALYSIS`,
`SHIM_INJECTION_MARKERS`, `SHIM_PRICE_TIER_WARNING`, `SHIM_TASK_*`, `SHIM_AGENT_LOOP*`
and `SHIM_INFLIGHT_SHARING` variables. Enterprise task counters live in Redis (`task:{organization}:{sha256 of
the task id}`); when Redis fails, calls go on with a `TASK_COUNTER_UNAVAILABLE`
verdict.

Rolling back to an older build is safe: a stored field or analyzer name that
build does not know is left out when it reads the settings (and logged once by
name), and a PATCH writes only the fields it names, so the newer build finds its
settings again after the rollback ends.

## Write a tenant rule

Keep your own words and codes out of prompts: project names, product codes,
customer lists. One set per tenant, replaced whole, beside the privacy
settings. Four kinds are available: `term` (a word list), `pattern` (code
shapes), `destination` ([a data type kept inside](#keep-a-data-type-inside)) and
`request_limit` ([caps](#cap-tools-documents-and-history)); the others are listed
as unavailable until their release.

1. Read the set with `GET /api/v1/management/rules` (`rules.read`: owner, admin
   or auditor):
   `revision` (0 until the first change), `rules`, `unavailable_rules`,
   `updated_by`, `updated_at`, `limits`, and `kinds`, where each kind says
   whether it is `available`, its `actions`, and why not when it is not.
   `unavailable_rules` holds stored rules this release cannot run, written by a
   later one: a `PUT` keeps them and cannot reuse their ids
   ([what they do](POLICY_DECISIONS.md#tenant-rules)).
2. Send the whole set back with `PUT /api/v1/management/rules` (`rules.write`:
   owner or admin), with the `revision` you read. The answer is the same body as the GET,
   at the next revision.

```console
curl -X PUT http://localhost:8000/api/v1/management/rules \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"revision": 0, "rules": []}'
```

Two rules, a term list and a project-code template:

```json
{"revision": 0, "rules": [
  {"id": "project_names", "name": "Project code names", "kind": "term",
   "action": "mask", "state": "monitor",
   "match": {"terms": ["Atlas", "İzmir Proje"]}},
  {"id": "project_codes", "name": "Project codes", "kind": "pattern",
   "action": "block", "state": "monitor", "scope": {"models": ["gpt-5-nano"]},
   "match": {"templates": ["PRJ-####"]}}
]}
```

| Kind | `match` | What it finds |
| --- | --- | --- |
| `term` | `terms` (up to 200 per rule, 2,000 per set, 3 to 128 characters each, with a letter or a digit), `label` (default `TERM`), `suffixes` (`tr`, the default, or `none`) | Each term between word edges: a space or punctuation, an underscore, a letter next to a digit, or a lower-case letter before a capital (`atlas_rapor.xlsx`, `Atlas2024`, `AtlasProje`). Letter case does not matter, and neither do Turkish marks: `İ`, `I`, `ı` and `i` are one letter and `ş ç ğ ö ü` match `s c g o u`, so `Şişli Kule` finds `SISLI KULE` and `İzmir Proje` finds `ızmir  proje`; every dash is a hyphen (`e–Devlet`). Two terms that differ only so are one term. With `suffixes: "tr"` a term also finds its Turkish forms: after an apostrophe any ending (`Atlas'ın`, `Atlas’ta`); without one the plural, possessive, case, equative, `-ki` and `-dIr` endings in any chain (`Atlasın`, `ATLASIN`, `Atlasımızın`, `Atlaslarındaki`, `Atlastır`, `Atlasça`, `Kulemiz`). A three-character term takes an ending without an apostrophe only as an acronym in capitals (`BKMnin`). Only the term is masked; the ending stays: `Atlasın` reaches the provider as `<TERM_…>ın`. |
| `pattern` | `templates` (up to 32 per rule, 64 per set, 64 characters each), `regexes` (up to 32 per rule, 64 per set, 256 characters each), `label` (default `PATTERN`), `ignore_case` (default `true`) | A template is literal text where `#` is one digit, `@` one letter and `\` makes the next character literal, between word boundaries; a hyphen takes any dash: `PRJ-####` finds `PRJ-1234`, `prj-1234` and `PRJ–1234`, not `PRJ-12345` or `XPRJ-1234`. A regex takes Python `re` syntax and, like a template, ignores letter case unless `ignore_case` is `false` (the flag covers the whole pattern; `(?-i:...)` turns it off for one part). Refused with 422 `RULE_PATTERN_UNSAFE`: syntax only the `regex` module knows (`\p{L}`), a backreference or a conditional group, a repeat of varying length inside another repeat (`(a+)+`, `(\d{2,})*x`; `(\d{3}-)+` is fine), or a pattern that runs slowly on a test input, checked with the same case setting. |

Not matched: consonant softening (`kitap`, `kitabı`), derivations (`Atlasçılık`,
`Kuleli`, `Kulesiz`), compounds (`Kuledibi`), misspellings, a term inside a longer
word (`XAtlas`, `Atlasian`) or number (`PRJ-2024-0012` for `PRJ-2024-001`), a
short term with an ending but no apostrophe unless written as an acronym (`Ata`
does not find `Atalar`), and a masking term inside a
value a built-in type masks (`atlas@example.com` stays an e-mail address; a
`block` or `require_approval` term there still acts). Tool
names, ids and other protocol identifiers are not searched. The `label` names
the placeholder, `<LABEL_…>`, which the provider sees: keep it generic.

An enforced `mask` replaces the value with a placeholder that the answer gets
back; `block` refuses the request with 400 `RULE_BLOCKED` before any provider
call; `warn` adds `RULE_WARN`; `monitor`, or any rule in `state: "monitor"`, only
counts. Overlapping matches follow the
[overlap rule](POLICY_DECISIONS.md#tenant-rules). While an enforced `mask`,
`block` or `require_approval` rule applies to a request, images and files in it
are refused, since they cannot be searched.

Monitor first: a new rule must start in `state: "monitor"`, where a match is
recorded as `RULE_WOULD_<ACTION>` and changes nothing. Filter the request list
with `GET /api/v1/management/requests?rule_id=project_names` to see what it
would have done, then send the set again with `"state": "enforced"`.

Notes: a stale `revision` is 409 `RULE_SET_REVISION_CONFLICT` with the current
revision; read again and resend. A refused set is 422 with `code` and the
`path` of the first problem (`rules[0].kind`): `RULE_SET_INVALID`,
`RULE_ID_DUPLICATE`, `RULE_KIND_UNAVAILABLE`, `RULE_ACTION_UNAVAILABLE`,
`RULE_MATCH_INVALID`, `RULE_PATTERN_UNSAFE`, `RULE_SCOPE_UNKNOWN` (a key or team id this organization
does not have), `RULE_SCOPE_REQUIRED` (a `destination` rule without a scope, or a `block`
scoped only by tags and endpoints) or
`RULE_MUST_START_IN_MONITOR`. A body over 1,000,000 bytes is
413. Every change records `tenant.rules_updated` with ids, kinds and counts,
never a term; weakening an enforced rule also records
`tenant.privacy_protection_relaxed` and alerts your forward targets
([decision evidence](POLICY_DECISIONS.md#tenant-rules)). Gateways pick up a new
revision at once.

## Keep a data type inside

Let your own model servers see real national ids while cloud models get a
placeholder, or nothing at all.

1. Register your servers as `internal` [model deployments](MODEL_DEPLOYMENTS.md)
   and the cloud ones as `external`. A catalog route (no deployment) is `unknown`,
   which rules treat as external.
2. Set the type's base action to what every target may see, here `monitor`:
   `PUT /api/v1/management/settings/pii` with
   `{"entity_actions": {"TR_NATIONAL_ID": "monitor"}}`.
3. Add a `destination` rule that tightens it for external targets, in `monitor`
   state first:

```json
{"revision": 3, "rules": [
  {"id": "tckn_stays_inside", "name": "National ids stay inside", "kind": "destination",
   "action": "mask", "state": "monitor", "scope": {"deployment_kinds": ["external"]},
   "match": {"entity_types": ["TR_NATIONAL_ID"]}}
]}
```

4. Watch `rule_matches` in the request list (`?rule_id=tckn_stays_inside`), then send
   the set again with `"state": "enforced"`. Requests to internal deployments keep the
   value; external and unclassified ones get a placeholder, restored in the answer.
   With `"action": "block"` they are refused with 400 `RULE_BLOCKED` and
   `X-Shim-Rule-Id: tckn_stays_inside` before any provider call.

Notes: a rule can only tighten; a base `mask` cannot be loosened to `monitor` for
internal targets. Changing a deployment from `external` to `internal` is recorded as
a relaxation, and the operator can restrict `internal` to listed origins with
`MODEL_DEPLOYMENT_INTERNAL_ORIGINS` ([model deployments](MODEL_DEPLOYMENTS.md)).

## Catch your customer list

Refuse, or count, requests that name one of your customers, without sending shim the list.

1. Create a records set: `POST /api/v1/management/record-sets` with
   `{"name": "customers", "kind": "records", "fields": [{"name": "Müşteri No", "kind":
   "token", "primary": true}, {"name": "Ad Soyad", "kind": "name"}]}`. Save `hash_key`
   from the answer into `key.txt`; it is shown once.
2. Hash and upload the list on your machine:

```console
python ee/scripts/hash_record_set.py --key-file key.txt --csv customers.csv \
  --field "Müşteri No=token:primary" --field "Ad Soyad=name" \
  --upload http://localhost:8000 --token "$USER_TOKEN" --set <set id>
```

3. Add a rule in `monitor`: `{"id": "customers", "name": "Customer list", "kind":
   "record_set", "action": "block", "state": "monitor", "match": {"set_id": "<set id>",
   "min_fields": 2}}`. A request holding a customer's number and name shows in
   `rule_matches` with `RULE_WOULD_BLOCK`; the number alone, or with another name, does
   not.
4. Enforce it: the same request answers 400 `RULE_BLOCKED` with `X-Shim-Rule-Id`.

For documents, create a `fingerprints` set, run the tool with `--documents <folder>`, and
use `warn` or `block` with `min_shared`. What is hashed, the key, rollback and the limits
are in [record sets](RECORD_SETS.md).

## Show masked values only to some teams

Let a risk team read national ids in answers while a call centre sees only the
placeholder. The provider gets the placeholder in both cases.

1. Create the teams and give each workload a gateway key in its team
   ([teams](team-access.md)).
2. List the type and who may see it in the gateway settings:

```console
curl -X PATCH http://localhost:8000/api/v1/management/gateway-settings \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"restore_withheld": {"TR_NATIONAL_ID": {"team_ids": ["<risk team id>"]}}}'
```

3. Keys in the risk team, and keys listed in `api_key_ids`, get the number back as
   before. Every other key gets `<TR_NATIONAL_ID_…>` in the answer text, tool-call
   arguments and streams (with `mask_last4`, `<CREDIT_CARD_…~1111>`). An empty grant,
   `{}`, means nobody gets the type back; a type not listed is restored for everyone.

Notes: the gateway knows the key and the key's team, not the person behind it.
`restore_withheld` is replaced whole by each PATCH; `{}` removes every grant. A key
is an entity type or a rule label, at most 64; each grant lists at most 200 team and
200 key ids of this organization (an unknown id is 422). Removing a type or adding an
id to a grant is a privacy relaxation (`tenant.privacy_protection_relaxed` with
`restore_withheld.<TYPE>`, forwarded to your targets); listing a type or removing an
id tightens. A Responses continuation follows the permission of the caller of each
request: the chain keeps every value, and a key with permission continuing it gets
them back. An application that reads the value from the answer, such as a tool that
looks a customer up by national id, gets the placeholder instead. The request list
shows `restore_withheld` counts and the `privacy.restore` verdict.

## Cap tools, documents and history

Stop a request that offers too many tools, attaches too many documents or carries
too long a history, before it spends any rate capacity or reaches the provider.

1. Add a `request_limit` rule to the [rule set](#write-a-tenant-rule), in `monitor`
   state first, with one or more caps:

| Field | Bound | Counts |
| --- | --- | --- |
| `max_tools` | 0 to 10,000 | tool definitions: `tools` (Gemini: each `functionDeclarations` entry, 1 for another tool) |
| `max_documents` | 0 to 1,000 | Chat `file` parts, Responses `input_file` items, Anthropic `document` blocks (inside `tool_result` too), Gemini `inlineData`/`fileData` parts that are not image, audio or video |
| `max_history` | 1 to 100,000 | items in `messages`, `input` (1 for a string) or `contents` |
| `max_input_bytes` | 1,024 to 32,000,000 | the request body's compact JSON bytes |
| `below_price_tier` | `true` | see [stay under the price tier](#stay-under-the-price-tier) |

```json
{"id": "tool_cap", "name": "At most five tools", "kind": "request_limit",
 "action": "block", "state": "monitor", "match": {"max_tools": 5}}
```

2. The rule matches when any cap is exceeded. In `monitor` state the request list
   shows it in `rule_matches`; enforced, `block` refuses with 400 `RULE_BLOCKED` and
   `X-Shim-Rule-Id` before the rate limits and the provider, and `warn` adds
   `RULE_WARN`.

Notes: images are not documents, and text pasted from a document is text. History
kept by the provider behind `previous_response_id` is not counted. Token counting
(`/v1/messages/count_tokens`) is never capped. Nothing is shortened to fit.

## Stay under the price tier

Some models price the whole request at a higher rate above a length (gpt-5.4 above
272,000 input tokens, Gemini 3.1 Pro preview above 200,000).

1. To be told before the call, turn on the gateway setting `price_tier_warning`:
   a request whose approximate size (bytes / 4) is above the tier gets
   `PRICE_TIER_CROSSED` in `X-Shim-Warnings`.
2. To keep requests under it, add a `request_limit` rule with
   `"match": {"below_price_tier": true}`. A request whose words alone exceed the tier
   certainly crosses it, and the rule's action applies (an enforced `block` refuses
   with `RULE_BLOCKED`). A request that only may cross it (approximate size above,
   word count not) is recorded as a `warn` match and gets `RULE_WARN` when the rule
   is enforced; it is never refused.

Notes: only catalog models with a tier are checked; registry deployments never
match. The settled tokens decide the price, and `LARGE_CONTEXT_PRICE` still marks a
request that was billed at the higher rate.

## Read the daily privacy card

See what shim caught on one day: personal data masked, watched or refused, pasted
secrets, bulk pastes and personal data the model sent back.

1. `GET /api/v1/compliance/privacy-card` (owner, admin or auditor) answers for
   yesterday in `Europe/Istanbul`. Pass `date=YYYY-MM-DD` for another day, at most
   400 days back and not in the future, and `tz` for another IANA time zone; the
   window is that local calendar day. Either one invalid is 422.
2. Read the counts:

| Field | Meaning |
| --- | --- |
| `requests` | Admitted requests that day. |
| `requests_with_personal_data` | Requests with any masked, monitored or blocked value. |
| `masked`, `monitored`, `blocked` | Distinct values by entity type, summed over the requests. |
| `secrets` | `SECRET` and `DB_URI` values across the three maps. |
| `blocked_requests` | Requests refused with `SECRET_BLOCKED` or `PII_BLOCKED`. |
| `bulk_disclosures` | Requests that reached the [bulk threshold](#change-the-privacy-settings). |
| `response_detections` | Values answers carried that their requests did not, when `response_scan` is `count`. |
| `window` | The day's `start` and `end` in UTC, and `tz`. |

```console
curl "http://localhost:8000/api/v1/compliance/privacy-card?date=2026-10-07&tz=Europe/Istanbul" \
  -H "Authorization: Bearer $USER_TOKEN"
```

Notes: the card holds counts only, never a value, placeholder, prompt or user.
Requests written before a count existed add zero to it. It reads the tenant's
request lifecycle for one day, so it is cheap to load on every visit. A user who
belongs to no organization gets a card of zeros, as the compliance overview
answers.

## Send tenant alerts

Receive tenant alerts, such as privacy protection turned off or a bulk
disclosure in one request, in Slack, a SIEM
webhook or e-mail. No compliance connector is needed.

1. `POST /api/v1/compliance/forward-targets` (owner or admin) with `kind`
   (`siem_webhook`, `slack` or `email`), `endpoint` (an HTTPS URL, or the
   recipient for `email`), an optional `secret` (SIEM webhooks only, at least 16
   characters), `min_severity` (default `high`, applies to connector findings)
   and `enabled` (default true). It answers 201 with the target's `id`;
   `connector_id` is null.
2. Optionally pass `?connector_id=<id>` to bind the target to a compliance
   connector: it then also receives that connector's findings and health
   alerts. A tenant-level target receives tenant alerts only. Deleting a
   connector deletes the targets bound to it.
3. List, change or delete targets with `GET /api/v1/compliance/forward-targets`
   (optionally `?connector_id=`), `PATCH` and `DELETE
   /api/v1/compliance/forward-targets/{id}`.

```console
curl -X POST http://localhost:8000/api/v1/compliance/forward-targets \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"kind": "slack", "endpoint": "https://hooks.slack.com/services/T000/B000/XXXX"}'
```

Notes: each alert is one delivery per enabled target, sent by the outbox worker
with an `idempotency-key` header. A signed SIEM webhook carries
`X-Shim-Signature: sha256=<hex HMAC-SHA256 of the raw body>`. An endpoint must
be public HTTPS or an origin approved in `ALERT_ALLOWED_ORIGINS`; e-mail goes
through Resend (`RESEND_API_KEY`, `COMPLIANCE_EMAIL_FROM`) and is unavailable
on a closed network, see
[on-prem alerts](ON_PREM_IDENTITY.md#alert-delivery-on-a-closed-network).

## Refuse provider keys sent in requests

Make every request use the provider keys stored for your tenant, so their
spending limits always apply.

1. Read the switch with `GET /api/v1/management/settings/provider-keys`. It is
   `true` by default.
2. Turn it off with `PUT /api/v1/management/settings/provider-keys` (owner or admin).

```console
curl -X PUT http://localhost:8000/api/v1/management/settings/provider-keys \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"allow_customer_provider_keys": false}'
```

Notes:

- With the switch on, a provider key the caller sends in `x-provider-key` (or
  `x-openai-api-key` on OpenAI routes) wins over the stored key on catalog
  models, for OpenAI, Anthropic and Gemini. The stored key's `monthly_limit_usd`
  does not apply to it, because the spend is on the caller's provider account;
  key and team quotas and budget alerts still do.
- With the switch off, such a request gets 403 `PROVIDER_KEY_NOT_ALLOWED` before
  any provider call, and the refusal is recorded in the audit trail. Requests
  without a provider key are unaffected.
- A [registered deployment](#register-a-private-model-deployment) always uses
  its stored key and ignores the header, whatever the switch says.
- Every change records a `tenant.provider_key_policy_updated` audit event.

## Export and verify the audit trail

Hand an auditor the tenant's audit chain and let them check it on their own machine.

1. Export with `GET /api/v1/compliance/audit/bundle?start=…&end=…`, as an owner,
   admin or auditor with a user session. A gateway key gets 401 and a member 403.
   `start` and `end` are optional; without them the whole chain is exported from
   sequence 1.
2. Verify offline with [`shim-audit-verify`](https://github.com/GetSHIM/shim-audit-verify).
   It exits 0 when the bundle verifies, 1 when it was altered, and 2 when the
   file is not a well-formed bundle.

```console
curl -OJ 'http://localhost:8000/api/v1/compliance/audit/bundle?start=2026-09-01T00:00:00Z&end=2026-09-30T23:59:59Z' \
  -H "Authorization: Bearer $USER_TOKEN"
uvx shim-audit-verify shim-audit-bundle-*.json
```

Notes:

- The export answers 422 above 10,000 rows or 366 anchors, or when `start` is
  after `end`, and 404 for a window without rows. A tenant writing more than
  10,000 rows a day exports hour-sized windows. The file is saved as
  `shim-audit-bundle-<organization id>.json`.
- The server-side check is `POST /api/v1/compliance/audit/verify?from=…&to=…`:
  its parameters are `from` and `to`, not `start` and `end`. With `from`, it
  starts after the latest daily anchor dated before `from` and checks that the
  chain still links to that anchor's tip (`anchor_link_mismatch` otherwise);
  without an earlier anchor, or without `from`, it starts at sequence 1. It reads
  at most 10,000 rows (422 beyond). With both bounds set, the window may span at
  most 31 days. It answers `ok`, `chain_start` (`from_seq`, `anchor_date`),
  `rows_checked`, `first_break`, `last_verified_seq`, `anchors_checked` and
  `anchor_mismatches`. A check that starts at an anchor trusts that stored
  anchor; see [decision evidence](POLICY_DECISIONS.md#audit-evidence-bundle).
- Exports, verifications and reports are themselves recorded in the audit chain.
- Read the verifier's "What it does not prove" before relying on a result. The
  format and limits are in [decision evidence](POLICY_DECISIONS.md#audit-evidence-bundle).
- Audit-chain appends that the outbox dead-lettered can be queued again from the
  enterprise image, where the scripts live under `ee/scripts`.
  `--dry-run` prints the count only; without it the events go back to pending
  and the count is printed. `--organization <uuid>` limits it to one tenant. The
  append deduplicates, so re-driving an event whose row exists adds no second row.

```console
python ee/scripts/redrive_audit_events.py --dry-run
python ee/scripts/redrive_audit_events.py
```

## Produce a KVKK exposure report

Produce the KVKK personal-data exposure report for a period, as PDF or CSV.

1. `POST /api/v1/compliance/reports/kvkk`, as an owner, admin or auditor, with
   an optional `connector_id`, `start` and `end` (default: the last 30 days, at
   most 31 days), and `format` `pdf` (default) or `csv`.
2. Save the attachment, named `kvkk_exposure_<YYYYMMDD>.pdf` or `.csv` after the end date.

```console
curl -X POST http://localhost:8000/api/v1/compliance/reports/kvkk \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"start": "2026-09-01T00:00:00Z", "end": "2026-09-30T23:59:59Z"}' \
  -o kvkk_exposure.pdf
```

Notes: the PDF is in Turkish and names the organization as
`Kurum: <name> (<id>)`. A tenant-wide report, one without `connector_id`, adds
the gateway's counts per entity type: masked, monitored, blocked and seen in
answers. The CSV ends with `source` and `count`: connector findings have
`source` `connector`, and a tenant-wide CSV adds one `gateway_masked`,
`gateway_monitored`, `gateway_blocked` or `gateway_response` row per entity type
and action. Filter on `source` if a spreadsheet expects connector rows only.
More than 10,000 findings answers 422. Details are in
[decision evidence](POLICY_DECISIONS.md#kvkk-exposure-report).

## Register a private model deployment

Route a gateway alias to your own OpenAI- or Anthropic-compatible model server.

1. As the platform operator, approve the server's origin in the gateway's
   environment and restart it: `MODEL_DEPLOYMENT_ALLOWED_ORIGINS` is a JSON list
   of exact scheme, host and port origins. For a private certificate authority,
   point `OUTBOUND_CA_BUNDLE` at its CA file; certificate verification stays
   on.
2. Store the server's credential: `POST /api/v1/management/providers` with
   `provider`, `key` (at least 10 characters) and an optional `name` (owner or
   admin with a verified email). It answers 201 with the credential's `id`.
3. Register the deployment: `POST /api/v1/management/model-deployments` with
   `alias`, `provider` (`openai` or `anthropic`), `upstream_model`, `base_url`,
   `provider_secret_id`, `deployment_kind` (`internal` or `external`),
   `declared_version`, `owner`, and optionally `timeout_seconds` (default 60, at
   most 300), `enabled`, `input_price_per_million` and `output_price_per_million`
   (decimal strings in USD, both or neither) and `context_window`. With a price,
   the deployment's requests are costed and counted in totals instead of
   hiding them, and a provider spend limit admits it; with a window, a request
   that certainly does not fit is refused with 400 `MODEL_CONTEXT_EXCEEDED`. An OpenAI-compatible `base_url` includes `/v1`; an
   Anthropic one is the server root. It answers 201, 422 for an origin that is
   not approved or a credential of another provider, and 409 for an alias that
   exists.
4. Check health: `POST /api/v1/management/model-deployments/{id}/health` asks
   the server's model list for 5 seconds and marks the deployment `healthy` on
   HTTP 200, otherwise `unhealthy`. An `unhealthy` mark refuses the alias with
   503 `DEPLOYMENT_UNHEALTHY` for 300 seconds; disable the deployment to keep
   traffic away for longer.
5. Call the alias as the model name, with a gateway key.

```text
MODEL_DEPLOYMENT_ALLOWED_ORIGINS=["https://models.internal:8443"]
OUTBOUND_CA_BUNDLE=/etc/shim/internal-ca.pem
```

```console
SECRET_ID=$(curl -s -X POST http://localhost:8000/api/v1/management/providers \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"provider\": \"openai\", \"name\": \"internal-llm\", \"key\": \"$MODEL_SERVER_KEY\"}" | jq -r .id)

DEPLOYMENT_ID=$(jq -n --arg secret "$SECRET_ID" '{
    alias: "support-llm", provider: "openai", upstream_model: "llama-3.3-70b-instruct",
    base_url: "https://models.internal:8443/v1", provider_secret_id: $secret,
    deployment_kind: "internal", declared_version: "2026-09-30", owner: "platform-team",
    input_price_per_million: "0.50", output_price_per_million: "1.50", context_window: 131072}' |
  curl -s -X POST http://localhost:8000/api/v1/management/model-deployments \
    -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' -d @- |
  jq -r .id)

curl -X POST "http://localhost:8000/api/v1/management/model-deployments/$DEPLOYMENT_ID/health" \
  -H "Authorization: Bearer $USER_TOKEN"
```

```python
import os

from openai import OpenAI

client = OpenAI(base_url="http://localhost:8000/v1", api_key=os.environ["SHIM_KEY"])
client.chat.completions.create(
    model="support-llm",
    messages=[{"role": "user", "content": "Summarise ticket 4521 for jane.doe@example.com"}],
)
```

Notes:

- A deployment marked `unhealthy` gets no traffic: its alias answers 503
  `DEPLOYMENT_UNHEALTHY` and leaves `/v1/models`. Nothing probes it
  automatically and nothing fails over. Run the health check again, or update the
  deployment with `PUT`, which resets it to `unknown`.
- With `MODEL_DEPLOYMENT_REQUIRED=true`, a model that is not a registered alias
  gets 403 `MODEL_NOT_REGISTERED`, and `/v1/models` lists only aliases. A
  disabled alias gets 403 `MODEL_NOT_ALLOWED`; one whose origin was later
  removed from the allow-list gets 503 `DEPLOYMENT_NOT_APPROVED`.
- A key with `allowed_models` must list the alias. An upstream model outside the
  public price catalog is unpriced, so a provider spending limit refuses it with
  403 `MODEL_PRICE_UNKNOWN`. The full contract is in
  [model deployments](MODEL_DEPLOYMENTS.md).

## Register an Azure OpenAI deployment

Route a gateway alias to your Azure OpenAI deployment, with an Azure key or an
Entra ID application, priced from the catalog model it serves.

1. As the platform operator, approve the resource: its exact origin in
   `MODEL_DEPLOYMENT_ALLOWED_ORIGINS`, or, on a hosted gateway,
   `MODEL_DEPLOYMENT_ALLOWED_ORIGIN_SUFFIXES=[".openai.azure.com"]`.
2. Store the credential: `POST /api/v1/management/providers` with
   `provider: "openai"` and either `key` (the Azure key) or
   `credential_kind: "azure_entra_client"` and `azure_entra` with `tenant_id`,
   `client_id`, `client_secret` and optionally `scope`. Give the Entra application
   the `Cognitive Services OpenAI User` role on the resource. The view shows
   `credential_kind` and `masked_key` (`entra:` and the masked client id), never the
   secret. `POST /providers/{id}/verify` asks Entra for a fresh token: 200 sets
   `verified_at`, a refusal answers 400. `PUT /providers/{id}` with `azure_entra`
   replaces all four values; a credential's kind never changes (422).
3. Register the deployment with `upstream: "azure_openai"`, `provider: "openai"`,
   `deployment_kind: "external"`, `base_url` ending in `/openai/v1`,
   `upstream_model` set to the Azure deployment name and `price_model` set to the
   catalog model it serves. Catalog prices are OpenAI's list prices; Azure's Data
   Zone, Regional and provisioned prices differ, so enter
   `input_price_per_million`, `output_price_per_million` and the cache prices when
   they apply. An Entra credential on a `generic` deployment answers 422 "An Entra
   credential can only serve an Azure OpenAI deployment".
4. Check health: a 200 or 404 from `/openai/v1/models` marks it `healthy`.
5. Call the alias as the model name.

```console
SECRET_ID=$(curl -s -X POST http://localhost:8000/api/v1/management/providers \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"provider\": \"openai\", \"name\": \"azure-bank\", \"credential_kind\": \"azure_entra_client\",
       \"azure_entra\": {\"tenant_id\": \"$AZURE_TENANT\", \"client_id\": \"$AZURE_CLIENT\",
                       \"client_secret\": \"$AZURE_SECRET\"}}" | jq -r .id)

jq -n --arg secret "$SECRET_ID" '{
    alias: "azure-mini", provider: "openai", upstream: "azure_openai",
    upstream_model: "kurum-mini", price_model: "gpt-5.6-luna",
    base_url: "https://bank.openai.azure.com/openai/v1", provider_secret_id: $secret,
    deployment_kind: "external", declared_version: "2026-10-11", owner: "platform-team"}' |
  curl -s -X POST http://localhost:8000/api/v1/management/model-deployments \
    -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' -d @-
```

Notes:

- A prompt Azure's content filter refuses answers 400 `PROVIDER_CONTENT_FILTERED`
  with the filtered categories; an Entra refusal answers 401
  `INVALID_PROVIDER_CREDENTIAL`.
- The gateway ignores the community `SHIM_AZURE_*` settings except
  `SHIM_AZURE_AUTHORITY_HOST` and `SHIM_AZURE_TOKEN_SCOPE`, and logs each other one
  that is set at startup.

## Automate management with a service account

Give a CI pipeline or an agent its own management key instead of a person's token.

1. As the owner, `POST /api/v1/management/service-accounts` with `name`, `role`
   (`admin` or `auditor`) and `expires_in_days` (1 to 365). It answers 201 with
   the account's `id` and the key in `plaintext`, shown once.
2. Call any management route the role allows with `Authorization: Bearer <key>`.
3. Rotate with `POST /api/v1/management/service-accounts/{id}/rotate`; the old key
   stops at once and the new one keeps its expiry. An expired key cannot be
   rotated (409): create a new account. Delete with
   `DELETE /api/v1/management/service-accounts/{id}`.

```console
SERVICE_KEY=$(curl -s -X POST http://localhost:8000/api/v1/management/service-accounts \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "terraform", "role": "admin", "expires_in_days": 90}' | jq -r .plaintext)

curl -X POST http://localhost:8000/api/v1/management/api-keys \
  -H "Authorization: Bearer $SERVICE_KEY" -H 'Content-Type: application/json' \
  -d '{"name": "payments-service"}'
```

Notes:

- A service account cannot become owner, accept invitations, manage service
  accounts, invite, remove members or change roles and team memberships. An
  auditor service account is read-only.
- Gateway keys a service account creates outlive its key's expiry. Delete the
  account to revoke them, or give each key its own `expires_in_days` (1 to 365)
  when you create it; an expired key answers 401 `INVALID_API_KEY` and drops out
  of `GET /api/v1/management/api-keys`.
- Any key failure answers 401 `INVALID_API_KEY`. The key is not a gateway key:
  model routes refuse it, and gateway keys do not open management routes.
- The audit log marks its actions `actor_type: service`. Details are in
  [team access](team-access.md#service-accounts).

## Give someone exactly the access they need

Let a finance colleague read billing without seeing privacy settings or holding
gateway keys.

1. As the owner, create a role with the permissions it needs:
   `POST /api/v1/management/roles` with `slug`, `name` and `permissions`
   ([the permission table](team-access.md#permissions)). It needs a plan with
   team access.
2. Give it to a member: `PATCH /api/v1/management/team/members/{member_id}` with
   `{"role": "member", "custom_role_id": "<role id>"}`.
3. The member's `GET /api/v1/management/auth/me` now lists exactly the role's
   `permissions`.

```console
ROLE_ID=$(curl -s -X POST http://localhost:8000/api/v1/management/roles \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"slug": "billing-viewer", "name": "Billing viewer", "permissions": ["usage.read"]}' | jq -r .id)

curl -X PATCH "http://localhost:8000/api/v1/management/team/members/$MEMBER_ID" \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"role\": \"member\", \"custom_role_id\": \"$ROLE_ID\"}"
```

Notes:

- A role without `keys.own` cannot go to someone who holds an active gateway
  key: the PATCH answers 409 `ROLE_HOLDERS_HAVE_KEYS`. Revoke the keys first.
- Owner-only permissions (`roles.manage`, `config.manage`), `keys.manage` and
  the ones that open content or decide approvals cannot be part of a custom
  role (422).
- `"custom_role_id": null` takes the role away; deleting a role someone holds
  answers 409. With OIDC, map groups to roles with `OIDC_GROUP_CUSTOM_ROLE_MAP`
  instead ([on-prem identity](ON_PREM_IDENTITY.md)).
- Details are in [team access](team-access.md#custom-roles).

## Plan, apply and undo a change

See what a policy change would have affected before it takes effect, apply it in
one step, and take it back in one step.

1. Create a plan (`plans.create`, owners and admins, plus the permission each
   change's own route asks for):
   `POST /api/v1/management/policy/plans` with up to 100 `changes`. A change is
   `{"resource", "item", "set": {...}}` to update, `"item": null` to create, or
   `{"resource", "item", "delete": true}`. The answer lists each change's
   `before`, `after`, `risk` and `impact` over the last `window_days` (default 7,
   at most 31).
2. Apply it (`plans.apply`): `POST /api/v1/management/policy/plans/{id}/apply`.
   A 409 `PLAN_STALE` names the items someone changed since the plan was made;
   create a new plan.
3. Undo: `POST /api/v1/management/policy/versions/{version}/restore` with an
   optional `reason`; restoring `current - 1` undoes the last change. Send the
   `expected_version` you read to get 409 `POLICY_VERSION_CHANGED` instead of
   undoing a change someone made since. Read the
   versions with `GET /api/v1/management/policy/versions` and the current state
   with `GET /api/v1/management/policy/state` (owners, admins and auditors).

```console
PLAN_ID=$(curl -s -X POST http://localhost:8000/api/v1/management/policy/plans \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"reason": "watch e-mail before masking it",
       "changes": [{"resource": "privacy", "item": "_",
                    "set": {"entity_actions": {"EMAIL_ADDRESS": "monitor"}}}]}' | jq -r .id)

curl -X POST "http://localhost:8000/api/v1/management/policy/plans/$PLAN_ID/apply" \
  -H "Authorization: Bearer $USER_TOKEN"

curl -X POST http://localhost:8000/api/v1/management/policy/versions/4/restore \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"reason": "back to masking"}'
```

Notes:

- Every write to privacy settings, teams, key model and team policies,
  deployments, budgets and oversight policies records a version, whether it came
  through a plan or not, so a tenant that never plans can still undo.
- A plan expires after 7 days; an expired, applied or rolled-back plan answers
  409 `PLAN_STATE_CONFLICT` on apply. The body is at most 256 KB.
- A restore cannot bring back a revoked key or delete a team, and a re-created
  budget has no notification targets: those are listed in `not_restored`, as is
  an item its own route would now refuse (a deleted provider secret, for
  example); everything else is restored. A
  deployment registered after the version is disabled instead of deleted
  (`approximated`).
- The resources, what counts as relaxing and the audit details are in
  [decision evidence](POLICY_DECISIONS.md#policy-versions-and-plans).

## See what changed after a prompt change

Compare how answers ended before and after your system prompt changed.

1. As an owner, admin or auditor, list the versions:
   `GET /api/v1/management/prompt-versions?start=…&end=…` (default the last 7
   days, at most 31), optionally with `api_key_id` or `model`.
2. Each version is a `system_prompt_hash` with `first_seen`, `last_seen`,
   `requests`, `outcomes` (`complete`, `truncated`, `empty`, `refused`,
   `filtered`), `failed` and `p95_shim_latency_ms`. Newest first.
3. List one version's requests with `GET /api/v1/management/requests?system_prompt_hash=…`.

```console
curl 'http://localhost:8000/api/v1/management/prompt-versions?start=2026-10-01T00:00:00Z' \
  -H "Authorization: Bearer $USER_TOKEN"
```

Notes: the hash is keyed per installation and tenant and never reveals the
prompt; prompt text is not stored. Requests without system instructions are one
item with `system_prompt_hash: null`. Details are in
[diagnostic metadata](DIAGNOSTIC_METADATA.md#system-instruction-hashing).

## Read and export findings

Let shim tell you about retry storms, repeated spend, unused deployments and
models that truncate or refuse answers.

1. As an owner, admin or auditor, list open findings:
   `GET /api/v1/management/findings?status=new`. Each one has a summary,
   evidence, impact and the fix.
2. Acknowledge or close one as an owner or admin:
   `PATCH /api/v1/management/findings/{id}` with `{"status": "in_progress"}`,
   `"suppressed"` or `"resolved"`.
3. Feed your SIEM or data lake from `GET /api/v1/management/findings/export`,
   one OCSF Detection Finding per line.

```console
curl 'http://localhost:8000/api/v1/management/findings?status=new' \
  -H "Authorization: Bearer $USER_TOKEN"

curl http://localhost:8000/api/v1/management/findings/export \
  -H "Authorization: Bearer $USER_TOKEN" -o findings.ndjson
```

Notes: the reconciliation worker evaluates the rules every
`FINDINGS_EVALUATION_INTERVAL_SECONDS` (default 900). The rules, their
thresholds and the OCSF mapping are in [findings](FINDINGS.md).

## Find truncated and refused answers

See which apps get cut-off or refused answers, then open those requests.

1. As an owner, admin or auditor, read the rates per app:
   `GET /api/v1/management/outcomes?group_by=api_key` (or `model`, `team`;
   default the last 7 days, at most 31). Each group has `truncation_rate` and
   `refusal_rate` (refused, filtered or empty).
2. Open the requests behind a rate:
   `GET /api/v1/management/requests?completion_outcome=truncated&api_key_id=…`.
   `refused`, `filtered`, `empty`, `complete` and `none` (no recorded outcome)
   work the same, in the CSV export too. The summary's `outcome_counts` count
   every class under the filters you set.

```console
curl 'http://localhost:8000/api/v1/management/outcomes?group_by=api_key' \
  -H "Authorization: Bearer $USER_TOKEN" | jq '.groups[] | {name, settled, truncation_rate, refusal_rate}'
```

Notes: a key with 50 or more answers in 24 hours and either rate at 5 percent
or more raises `gateway.truncation_rate` or `gateway.refusal_rate`
([findings](FINDINGS.md#gatewaytruncation_rate)). The classes are the
provider's own signals; text refusals ("yardımcı olamam") are counted only in
`soft_refusal_rate`, and only when the tenant enabled the refusal analyzer; the
`soft_refusal` request filter matches only answers it read. Details are in
[diagnostic metadata](DIAGNOSTIC_METADATA.md#outcome-filters-counts-and-rates).

## Is our model list complete?

Compare the registry with what the gateway actually served.

1. As an owner, admin or auditor, read
   `GET /api/v1/management/model-inventory?start=…&end=…` (default the last 30
   days, at most 31).
2. `registry` items are your registered deployments with their traffic;
   `catalog` items (`registered: false`) are models requests reached through a
   provider's public endpoint. `byok_requests` counts requests that brought their
   own provider key.

```console
curl 'http://localhost:8000/api/v1/management/model-inventory' \
  -H "Authorization: Bearer $USER_TOKEN" | jq '.items[] | {route, alias, model, requests, byok_requests}'
```

Notes: once a registry exists, catalog models with 5 or more requests in 7 days
raise `gateway.unregistered_model`, and keys sending their own provider key past
a stored one raise `gateway.byok_usage` ([findings](FINDINGS.md)). Refused
unknown model names and servers that never see traffic through shim are not in
the inventory. Details are in [model deployments](MODEL_DEPLOYMENTS.md#the-inventory).

## Record an incident

Keep one record per incident, with its owner, its evidence and the KVKK 72-hour
clock.

1. As an owner or admin, open it with what you know, linking the requests or
   findings involved: `POST /api/v1/compliance/incidents`. Keep personal data
   out of the title and description; it belongs in `breach`.
2. If personal data may have been exposed, set `is_suspected_breach: true`: the
   `kvkk_board` row gets a deadline 72 hours after `aware_at`, and
   `kvkk_data_subjects` a row without one. Add `gdpr_authority` with
   `PUT .../notifications/gdpr_authority` when GDPR applies.
3. Read `GET /api/v1/compliance/incidents/{id}`: `evidence_summary` lists the
   entity types and KVKK categories of the linked requests.
4. Record each stage you send:
   `POST .../notifications/kvkk_board/submissions` with the form or case number.
5. Move the status as work goes on, and close it at the end.

```console
curl -X POST http://localhost:8000/api/v1/compliance/incidents \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"title": "TCKN sent to a provider", "severity_id": 4, "is_suspected_breach": true,
       "aware_at": "2026-10-10T09:00:00Z", "links": {"request_ids": ["req_…"]}}'

curl -X POST http://localhost:8000/api/v1/compliance/incidents/$INCIDENT/notifications/kvkk_board/submissions \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"reference": "KVKK-2026-0042", "fields_sent": ["data_categories", "approx_subjects"]}'
```

Notes: forward targets get a reminder 24 hours before a deadline and another
once it passes without a submission. A submission after the deadline needs
`late_reason`. shim files nothing with a regulator, and the deadlines are for
your counsel to confirm. Auditors read and export
(`GET /api/v1/compliance/incidents/export`, OCSF Incident Finding). Details are
in [incidents](INCIDENTS.md).

## Collect the monthly evidence file

Hand an auditor last month's gateway evidence without generating anything by hand.

1. Run the ai_act worker (`python -m shim_enterprise.workers.ai_act`). On the
   first pass of each month it writes the previous month's PDF for every
   organization with traffic in that month.
2. Optionally add a [forward target](#send-tenant-alerts): it is told when the
   file is ready.
3. As an owner, admin or auditor, list the files with
   `GET /api/v1/compliance/evidence/monthly` and download one with
   `GET /api/v1/compliance/evidence/monthly/{YYYY-MM}`.

```console
curl http://localhost:8000/api/v1/compliance/evidence/monthly \
  -H "Authorization: Bearer $USER_TOKEN"

curl -OJ http://localhost:8000/api/v1/compliance/evidence/monthly/2026-09 \
  -H "Authorization: Bearer $USER_TOKEN"
```

Notes:

- Each list item has `period`, `kind`, `format`, `size_bytes`, `sha256` and
  `generated_at`. The download carries `X-Content-SHA256`; compare it with the
  list. Every download is recorded as `tenant.evidence_downloaded`.
- To see the month so far, an operator runs
  `python ee/scripts/generate_monthly_evidence.py --organization <uuid> --period <current YYYY-MM>`
  in the enterprise image, then downloads it with `?kind=monthly_partial`. Each
  kind and month is written once; the script refuses a second run.
- The file is in Turkish. Section 7, "Kim neye erişti", answers who read or
  exported evidence (audited actions by user id and current role) and which API
  keys and teams called which models.
- What the file contains and does not contain is in
  [decision evidence](POLICY_DECISIONS.md#monthly-evidence-file).

## Prepare for ISO/IEC 42001

See which Annex A controls your gateway traffic evidences, and record your own
statement for the rest. The report needs the `readiness_report` plan feature,
which stays off until the control numbering is verified
([how an operator turns it on](POLICY_DECISIONS.md#turning-the-readiness-report-on));
declarations work without it.

1. As an owner or admin, declare the controls shim cannot measure:
   `PUT /api/v1/compliance/readiness/iso42001/declarations/{control_id}` with
   `status` and an optional `note`.
2. As an owner, admin or auditor, produce the report:
   `POST /api/v1/compliance/reports/readiness`.

```console
curl -X PUT http://localhost:8000/api/v1/compliance/readiness/iso42001/declarations/A.3.2 \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"status": "implemented", "note": "AI roles are assigned in the RACI of 2026-09."}'

curl -X POST http://localhost:8000/api/v1/compliance/reports/readiness \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"framework": "iso42001", "start": "2026-07-01T00:00:00Z", "end": "2026-09-30T23:59:59Z", "format": "csv"}' \
  -o iso42001_readiness.csv
```

3. Read the gap list: every control whose status is `gap` or `partial`, gaps
   first, each with what is missing and the next steps. A step marked "in shim"
   points at the feature that produces the missing evidence; the others are for
   your organization, and shim does not check the documents they produce.
   Declare a control once your organization has done its steps.

Notes: the CSV starts with the cover sentences, one per row, and a blank row;
then come the columns `control_id`, `title`, `source` (`measured`, `input` or
`declared`), `evidence_present`, `evidence`, `rule`, `declaration`, `note`,
`status` (`ready`, `partial` or `gap`) and `next_steps` (empty for a ready
control, otherwise the steps joined with ` | `, each prefixed `in_shim: ` or
`organization: `). The PDF holds the same 38 rows with a status column, then
the gap list, with text over 900 characters cut and marked
"(truncated, see CSV)". The report is not an audit or a certification and
carries no score.
Sources, rules and the numbering caveat are in
[decision evidence](POLICY_DECISIONS.md#isoiec-42001-readiness-report).
