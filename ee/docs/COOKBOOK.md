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
- [Preview a rule before you enforce it](#preview-a-rule-before-you-enforce-it)
- [Import AIUC rules](#import-aiuc-rules)
- [Read the daily privacy card](#read-the-daily-privacy-card)
- [Send tenant alerts](#send-tenant-alerts)
- [Refuse provider keys sent in requests](#refuse-provider-keys-sent-in-requests)
- [Export and verify the audit trail](#export-and-verify-the-audit-trail)
- [Produce a KVKK exposure report](#produce-a-kvkk-exposure-report)
- [Register a private model deployment](#register-a-private-model-deployment)
- [Automate management with a service account](#automate-management-with-a-service-account)
- [Give someone exactly the access they need](#give-someone-exactly-the-access-they-need)
- [Plan, apply and undo a change](#plan-apply-and-undo-a-change)
- [Require a second admin for loosening changes](#require-a-second-admin-for-loosening-changes)
- [Hold a request for approval](#hold-a-request-for-approval)
- [See what changed after a prompt change](#see-what-changed-after-a-prompt-change)
- [Read and export findings](#read-and-export-findings)
- [Let shim suggest a fix](#let-shim-suggest-a-fix)
- [Turn on answer checks and read the findings](#turn-on-answer-checks-and-read-the-findings)
- [Why is my request expensive](#why-is-my-request-expensive)
- [Read latency per team and app](#read-latency-per-team-and-app)
- [How much more do Turkish answers cost on each model](#how-much-more-do-turkish-answers-cost-on-each-model)
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
| `four_eyes` | `"off"` | `"relaxing"`: a change that loosens protection needs a second administrator ([four eyes](#require-a-second-admin-for-loosening-changes)). |
| `finding_modes` | `{}` | Per finding rule, `observe`, `suggest` or `auto`, up to the rule's highest mode ([let shim suggest a fix](#let-shim-suggest-a-fix)); a PATCH merges per rule. |

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
`response_analysis` only measures, so it is neutral; turning `four_eyes` off is
relaxing, and a field without a direction counts as relaxing. Every change
records a [policy version](#plan-apply-and-undo-a-change). Gateways read the settings
from a cache that lives at most 300 seconds; a change clears it at once.
Enterprise ignores the community `SHIM_RESPONSE_ANALYSIS` variable.

Rolling back to an older build is safe: a stored field or analyzer name that
build does not know is left out when it reads the settings (and logged once by
name), and a PATCH writes only the fields it names, so the newer build finds its
settings again after the rollback ends.

## Write a tenant rule

Keep your own words and codes out of prompts: project names, product codes,
customer lists. One set per tenant, replaced whole, beside the privacy
settings. Two kinds are available: `term` (a word list) and `pattern` (code
shapes); the others are listed as unavailable until their release.

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
would have done, or [preview it](#preview-a-rule-before-you-enforce-it), then
send the set again with `"state": "enforced"`.

Notes: a stale `revision` is 409 `RULE_SET_REVISION_CONFLICT` with the current
revision; read again and resend. A refused set is 422 with `code` and the
`path` of the first problem (`rules[0].kind`): `RULE_SET_INVALID`,
`RULE_ID_DUPLICATE`, `RULE_KIND_UNAVAILABLE`, `RULE_ACTION_UNAVAILABLE`,
`RULE_MATCH_INVALID`, `RULE_PATTERN_UNSAFE`, `RULE_SCOPE_UNKNOWN` (a key or team id this organization
does not have) or `RULE_MUST_START_IN_MONITOR`. A body over 1,000,000 bytes is
413. Every change records `tenant.rules_updated` with ids, kinds and counts,
never a term; weakening an enforced rule also records
`tenant.privacy_protection_relaxed` and alerts your forward targets
([decision evidence](POLICY_DECISIONS.md#tenant-rules)). Gateways pick up a new
revision at once.

## Preview a rule before you enforce it

See how many requests a rule would have hit before it blocks anything.

1. As an owner or admin, send the rule as you would put it:
   `POST /api/v1/management/rules/preview` with `{"rule": {...}, "window_days": 7}`
   (1 to 31 days).
2. Read `basis`, `requests` and `by_scope` (the 20 largest API keys, teams and
   models):
   - `monitor_history`: the rule is in your set and has run unchanged; the count
     is its own monitor matches since its kind, scope or match last changed
     (`window.covered_days` says how much of the window that covers). A rename,
     a new action or a new state keeps the history.
   - `metadata`: the rule's kind can be counted from stored request metadata.
   - `none`: no history, and its kind cannot be counted without the prompts,
     which shim does not keep (`term` and `pattern` rules). Start it in monitor.

```console
curl -X POST http://localhost:8000/api/v1/management/rules/preview \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"rule": {"id": "project_names", "name": "Project code names", "kind": "term",
       "action": "block", "state": "enforced", "match": {"terms": ["Atlas"]}}}'
```

Notes: a rule that ran in monitor for 7 days shows its real count, which is the
number to read before you enforce it. A new rule may start enforced only when a
preview of exactly that rule (kind, action, scope and match) covered a whole
window of at least 7 days (`enforce_on_create: true`); the preview then holds
for 24 hours (`preview_expires_at`), through the PUT or a plan. A plan that
touches rules shows the same numbers as its impact. `errors` counts requests
where the rule's evaluation failed, and a request that matched more than 32 rules
may hide this one, which the `note` says. Previews are recorded as
`tenant.rule_previewed`; no term, pattern or matched text appears in the answer.

## Import AIUC rules

Bring a shim-security (AIUC) rule file into the gateway's rules once, as a plan.

1. As an owner or admin, send the file:
   `POST /api/v1/management/rules/import/aiuc` (at most 256 KB; `plans.create`
   and `rules.write`).
2. The answer is 201 with a draft `plan` and a `report`; 200 with `"plan": null`
   when nothing would change, so importing the same file again is safe.
3. Review the report, then [apply the plan](#plan-apply-and-undo-a-change); a
   restore undoes it.

| AIUC | Gateway |
| --- | --- |
| `term` rule | a `term` rule `aiuc_<id>` in state `monitor`, same action, Turkish endings on |
| `email`, `secret` rule | the `EMAIL_ADDRESS`, `SECRET` type, raised from `off` to `monitor` only |
| terms of 2 characters, or repeated after the Turkish fold | dropped, listed by position |
| `offlineAction`, `updatedAt`, `expiresAt`, `expectedRevision` | ignored, listed |

Notes: an `aiuc_<id>` rule that already exists keeps its scope and goes back to
`monitor`; an id taken by another kind, a term rule left without terms and a rule
that would pass a set limit are listed under `not_mapped`. The gateway matches a
term as a whole word with its Turkish endings, AIUC as an escaped literal, and
the gateway's `SECRET` type finds more formats than AIUC's four. Nothing is
exported back to AIUC. The import is recorded as `tenant.rules_imported`.

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

## Require a second admin for loosening changes

Make every change that loosens protection wait for a second administrator.

1. As an owner or admin, turn it on:
   `PATCH /api/v1/management/gateway-settings` with `{"four_eyes": "relaxing"}`.
   It needs two active people whose role can approve (owners and admins, not
   service accounts); with fewer the answer is 409 `FOUR_EYES_UNAVAILABLE`.
2. A direct write that loosens protection (masking off, a raised limit, a
   model added to a key, a new deployment, a deleted budget, ...) now answers
   409 `CHANGE_REQUIRES_APPROVAL` with `relaxed`, the `resource.item.field`
   names it would loosen, and writes nothing. Tightening and neutral writes are
   unchanged.
3. Make the change a [plan](#plan-apply-and-undo-a-change) instead. Applying a
   loosening plan answers 202 with the plan in `pending_approval` and alerts
   your [forward targets](#send-tenant-alerts) (`kind:
   policy_approval_requested`, ids and resource names only). A restore that
   loosens waits the same way.
4. Another owner or admin, neither the plan's creator nor the one who applied
   it, approves it: `POST /api/v1/management/policy/plans/{id}/approve`
   (`plans.approve`) with an optional `{"note": "..."}`. The plan is applied in
   the same call. `POST .../reject` closes it as `rejected` and changes nothing.

```console
curl -X PATCH http://localhost:8000/api/v1/management/gateway-settings \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"four_eyes": "relaxing"}'

curl -X POST "http://localhost:8000/api/v1/management/policy/plans/$PLAN_ID/approve" \
  -H "Authorization: Bearer $OTHER_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"note": "checked with the data officer"}'
```

Notes:

- A pending plan expires 72 hours after it was submitted. An approval that
  finds an item changed since answers 409 `PLAN_STALE` and the plan keeps
  waiting; reject it and plan again.
- The creator, the submitter and service accounts get 403
  `APPROVER_NOT_ELIGIBLE`. The note is kept on the plan (`context.decision_note`),
  never in the audit chain.
- Turning four eyes off is itself loosening, so it needs approval too. When
  fewer than two people can approve (an administrator left), an owner may turn
  it off directly; that write is audited as
  `tenant.four_eyes_single_admin_override` and alerted like a privacy
  relaxation.
- What counts as loosening per resource is in
  [decision evidence](POLICY_DECISIONS.md#policy-versions-and-plans).

## Hold a request for approval

Make requests that carry a term go out only after an administrator approves
them, once.

1. Add a `term` or `pattern` rule with action `require_approval` to the
   [rule set](POLICY_DECISIONS.md#tenant-rules). It starts in `monitor`: the
   requests it would hold are recorded with `RULE_WOULD_REQUIRE_APPROVAL` and
   the [rule preview](POLICY_DECISIONS.md#rule-previews) counts them. Move it
   to `enforced` when the numbers look right.
2. A matching request from a key in the rule's scope now answers 403
   `APPROVAL_REQUIRED` before any provider call, with the approval id in
   `X-Shim-Approval-Id` (and `error.param`), the rule in `X-Shim-Rule-Id` and
   `x-should-retry: false`. A stream is refused before its first byte. Sending
   the same request again returns the same id and holds nothing new. Your
   [forward targets](#send-tenant-alerts) get `kind:
   request_approval_requested` with rule ids, key id, model and deadline.
3. An owner or admin who does not own the key reads
   `GET /api/v1/management/approvals?status=pending` (or `/{id}`): the rules,
   key, requester, team, provider, model, `stream`, detected entity and rule
   counts, `input_bytes` and `estimated_input_tokens`. The content is not
   stored, so `content` is null. They decide with
   `POST /api/v1/management/approvals/{id}/approve` or `/reject`.
4. The client sends the identical request with
   `X-Shim-Approval-Id: <id>` within 60 minutes of the approval. It goes out
   once, with the term unmasked; a second send with the same id is held again
   under a new id. After a reject the same send answers 403
   `APPROVAL_REJECTED`.

```console
curl "http://localhost:8000/api/v1/management/approvals?status=pending" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

curl -X POST "http://localhost:8000/api/v1/management/approvals/$APPROVAL_ID/approve" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

curl http://localhost:8000/v1/chat/completions \
  -H "x-shim-key: $SHIM_API_KEY" -H "X-Shim-Approval-Id: $APPROVAL_ID" \
  -H 'Content-Type: application/json' -d @same-request.json
```

Notes:

- "The same request" is the same tenant, key, protocol, model, `stream` and
  body, field for field; key order and whitespace do not matter. Change
  anything and it needs its own approval.
- A pending approval lives 24 hours; at most 200 wait per tenant, after which
  new ones answer 403 `APPROVAL_QUEUE_FULL`. An approval is used up when the
  request is sent, even if the provider then fails.
- Token counting (`/v1/messages/count_tokens`) with a held term answers 403
  `APPROVAL_REQUIRED` and creates no approval: a count sends the content too.
- The key's owner and service accounts cannot decide (403
  `APPROVER_NOT_ELIGIBLE`); an auditor can read the list. Only a pending,
  unexpired approval can be decided (409 `APPROVAL_STATE_CONFLICT` otherwise).
- The request list shows `approval_id` on the held, refused and sending
  requests, and `GET /api/v1/management/requests?approval_id=<id>` finds them.

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

## Let shim suggest a fix

Have a finding carry the change that fixes it, ready to plan.

1. As an owner, admin or auditor, read each finding type's highest mode and
   action: `GET /api/v1/management/findings/rules`.
2. As an owner or admin, raise a rule:
   `PATCH /api/v1/management/gateway-settings` with
   `{"finding_modes": {"gateway.unused_deployment": "suggest"}}`.
3. After the next evaluation the rule's open findings carry `remediation.action`.
   Turn one into a plan with `POST /api/v1/management/findings/{id}/plan`, read
   its effect, and [apply it](#plan-apply-and-undo-a-change); a restore undoes it.

```console
curl -X PATCH http://localhost:8000/api/v1/management/gateway-settings \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"finding_modes": {"gateway.unused_deployment": "suggest"}}'

curl -X POST "http://localhost:8000/api/v1/management/findings/$FINDING_ID/plan" \
  -H "Authorization: Bearer $USER_TOKEN"
```

Notes: a mode above the rule's highest answers 422 naming the rule. `auto` is
accepted for `gateway.unused_deployment` but works as `suggest` until an executor
is installed. Setting a rule back to `observe` removes its action from open
findings at the next pass. Modes and actions are in [findings](FINDINGS.md#modes).

## Turn on answer checks and read the findings

Learn which apps get English answers to Turkish questions, answers that break
their schema, or polite refusals, without reading requests one by one.

1. As an owner or admin, turn the analyzers on:
   `PATCH /api/v1/management/gateway-settings` with
   `{"response_analysis": ["language", "schema", "refusal"]}`. They read each
   completed answer after it was delivered; they never change or delay it.
2. After traffic, read the findings per API key:
   `GET /api/v1/management/findings?rule_id=gateway.language_drift` (and
   `gateway.schema_errors`, `gateway.soft_refusals`).

```console
curl -X PATCH http://localhost:8000/api/v1/management/gateway-settings \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"response_analysis": ["language", "schema", "refusal"]}'
```

Notes: each rule needs its analyzer, and a minimum of answers in 24 hours (20,
20 and 50) before it judges a key. Analyzers that read the answer skip requests
that carried personal data, so those never count. An app that expects English
answers suppresses `gateway.language_drift` for its key. The rules and thresholds
are in [findings](FINDINGS.md#gatewaylanguage_drift).

## Why is my request expensive

Find the input an app pays for on every request and gets nothing for.

1. As an owner or admin, turn the `shape` analyzer on:
   `PATCH /api/v1/management/gateway-settings` with
   `{"response_analysis": ["shape"]}`. It records sizes and the offered tool names
   after the answer was delivered; requests are never changed.
2. Read the findings per API key: `gateway.oversized_parts` (tool definitions,
   history or one part over its limit), `gateway.dead_tools` (tools offered and
   never called) and `gateway.cache_order_churn` (tools in changing order, so the
   provider's prompt cache misses).

```console
curl 'http://localhost:8000/api/v1/management/findings?rule_id=gateway.oversized_parts' \
  -H "Authorization: Bearer $USER_TOKEN"
```

Notes: the fixes are in the app: send fewer tools or load them on demand, trim the
history, send the relevant part of a document, and send tools in a fixed order. The
token figure of an oversized finding is an estimate (characters over four) and
shows no money, since the repeated prefix is often billed at the cache price. The
rules are in [findings](FINDINGS.md#gatewayoversized_parts).

## Read latency per team and app

See how long each team, app, model or deployment waits, per hour or day.

1. As an owner, admin or auditor, read
   `GET /api/v1/management/latency?group_by=api_key&bucket=hour` (`group_by`:
   `team`, `api_key`, `tag`, `model`, `deployment`; `bucket`: `hour` for at most 7
   days, `day` for at most 31; default the last 24 hours, UTC buckets).
2. Each group (the 20 with the most requests, `truncated` beyond) has per bucket:
   `requests`, `streams`, `first_byte_ms` p50 and p95 for streams and for JSON,
   `shim_queue_ms` (shim's own time before the provider call), the median
   `output_tokens_per_second` of streams, `peak_concurrency`, `timeouts` and
   `provider_errors`.
3. Grouped by `model` or `deployment` over at most 48 hours, `head_of_line`
   compares the median TTFT of short streams (prompt up to 2,000 tokens) that
   started while a long request (20,000 tokens or more) of the same group was
   running with those that started with none.

```console
curl 'http://localhost:8000/api/v1/management/latency?group_by=team&bucket=hour' \
  -H "Authorization: Bearer $USER_TOKEN"
```

Notes: an app is an API key; apps sharing a key separate with `X-Shim-Tag` and
`group_by=tag` (a request with two tags counts in both). Requests without a team,
tag or deployment are one group with `id: null`. How speed and concurrency are
derived is in [diagnostic metadata](DIAGNOSTIC_METADATA.md#latency-per-group).

## How much more do Turkish answers cost on each model

Compare how many output tokens each model bills for the same amount of Turkish and
English answer text, on your own traffic.

1. As an owner or admin, turn the `language` analyzer on:
   `PATCH /api/v1/management/gateway-settings` with
   `{"response_analysis": ["language"]}`.
2. As an owner, admin or auditor, read
   `GET /api/v1/management/language-cost?group_by=model` (or `api_key`; default the
   last 30 days, at most 31). Each item is a model (the one the provider billed,
   so a deployment alias shows its upstream model) and an answer language, with
   `tokens_per_1000_characters` (the ratio of the sums), its p25 and p75 per
   request, and `output_usd_per_1000_characters` from each settlement's own output
   price.
3. `tr_vs_en` divides the Turkish ratio by the English one once a model has at
   least 30 eligible answers in each language; otherwise it is null with
   `comparison_unavailable_reason: "not_enough_answers"`.

```console
curl 'http://localhost:8000/api/v1/management/language-cost?group_by=model' \
  -H "Authorization: Bearer $USER_TOKEN"
```

Notes: only the output side is measured, on complete answers of at least 200
characters with no tool call, no reasoning and reported usage; `excluded` counts
the rest by reason and `analysed_share` says how much traffic the numbers stand on.
The ratio describes your tenant's answers; it is not a benchmark. The monthly
evidence file shows the same numbers per model. The method is in
[diagnostic metadata](DIAGNOSTIC_METADATA.md#tokens-per-character-by-language).

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
