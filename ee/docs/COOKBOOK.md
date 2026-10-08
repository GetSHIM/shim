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
- [Read the daily privacy card](#read-the-daily-privacy-card)
- [Send tenant alerts](#send-tenant-alerts)
- [Refuse provider keys sent in requests](#refuse-provider-keys-sent-in-requests)
- [Export and verify the audit trail](#export-and-verify-the-audit-trail)
- [Produce a KVKK exposure report](#produce-a-kvkk-exposure-report)
- [Register a private model deployment](#register-a-private-model-deployment)
- [Automate management with a service account](#automate-management-with-a-service-account)
- [See what changed after a prompt change](#see-what-changed-after-a-prompt-change)
- [Read and export findings](#read-and-export-findings)
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

Notes: a tenant-wide PDF, one without `connector_id`, adds a "Gateway
detections" section: per entity type, its KVKK category and the sum over
requests started in the window of the distinct values the gateway detected and
masked in each. A connector-scoped report and every CSV hold compliance
connector findings only. More than 10,000 findings answers 422. Details are in
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
  account to revoke them.
- Any key failure answers 401 `INVALID_API_KEY`. The key is not a gateway key:
  model routes refuse it, and gateway keys do not open management routes.
- The audit log marks its actions `actor_type: service`. Details are in
  [team access](team-access.md#service-accounts).

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

Notes: the CSV starts with the cover sentences, one per row, and a blank row;
then come the columns `control_id`, `title`, `source` (`measured`, `input` or
`declared`), `evidence_present`, `evidence`, `rule`, `declaration` and `note`.
The PDF holds the same 38 rows, with text over 900 characters cut and marked
"(truncated, see CSV)". The report is not an audit or a certification.
Sources, rules and the numbering caveat are in
[decision evidence](POLICY_DECISIONS.md#isoiec-42001-readiness-report).
