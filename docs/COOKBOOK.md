# shim cookbook

Recipes for engineers who point an application at the community gateway. Each
one assumes a gateway started as in the [README quickstart](../README.md#quickstart),
listening on `http://localhost:8000` with `SHIM_API_KEY=a-key-of-at-least-16-chars`.
Gateway settings are environment variables read at start-up. All data in the
examples is synthetic. Teams, budgets, audit export and private model deployments
are in the [enterprise cookbook](../ee/docs/COOKBOOK.md).

- [Use the OpenAI SDK](#use-the-openai-sdk)
- [Use the Anthropic SDK](#use-the-anthropic-sdk)
- [Use the Gemini SDK](#use-the-gemini-sdk)
- [Tag requests and read their cost](#tag-requests-and-read-their-cost)
- [Scan text before you send it](#scan-text-before-you-send-it)
- [Choose what happens to each data type](#choose-what-happens-to-each-data-type)
- [Read errors and retry](#read-errors-and-retry)
- [Read warnings](#read-warnings)
- [Analyse answers after delivery](#analyse-answers-after-delivery)
- [Stream long generations and read usage](#stream-long-generations-and-read-usage)
- [Observe the gateway](#observe-the-gateway)
- [Put shim behind LiteLLM](#put-shim-behind-litellm)
- [Put shim behind Portkey](#put-shim-behind-portkey)

## Use the OpenAI SDK

Send Chat Completions and Responses calls through shim by changing only the base URL.

1. Give the gateway a provider key: start it with `OPENAI_API_KEY`, or send the
   key on each request in `x-provider-key`. The header wins over the variable.
2. Set `base_url` to `http://localhost:8000/v1` and pass the shim key as
   `api_key`. The SDK sends it as `Authorization: Bearer`; shim never forwards it.

```console
docker run --rm -p 8000:8000 -e SHIM_API_KEY=a-key-of-at-least-16-chars \
  -e OPENAI_API_KEY ghcr.io/getshim/shim:latest
```

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8000/v1", api_key="a-key-of-at-least-16-chars")
chat = client.chat.completions.create(
    model="gpt-5-nano",
    messages=[{"role": "user", "content": "Email jane.doe@example.com about the invoice"}],
)
answer = client.responses.create(model="gpt-5-nano", input="Summarise the invoice dispute")
```

To send the provider key per request instead, add
`default_headers={"x-provider-key": os.environ["OPENAI_API_KEY"]}` to the client.

Notes: the model must be in shim's price catalog, which `GET /v1/models` lists;
any other model gets 400 `MODEL_NOT_PRICED`. With no provider key at all the
answer is 503 `PROVIDER_NOT_CONFIGURED`, and an empty `x-provider-key` is 400
`INVALID_PROVIDER_CREDENTIAL`. `background=true` Responses requests are rejected.

## Use the Anthropic SDK

Send Messages and token-count calls through shim.

1. Give the gateway `ANTHROPIC_API_KEY`, or send the key per request in `x-provider-key`.
2. Set `base_url` to `http://localhost:8000`, without `/v1`: the SDK adds
   `/v1/messages` itself. Pass the shim key as `api_key`; the SDK sends it as
   `x-api-key`, which shim reads as the shim key and never treats as a provider key.

```python
import os

from anthropic import Anthropic

client = Anthropic(
    base_url="http://localhost:8000",
    api_key="a-key-of-at-least-16-chars",
    # Leave this out when the gateway has ANTHROPIC_API_KEY.
    default_headers={"x-provider-key": os.environ["ANTHROPIC_API_KEY"]},
)
messages = [{"role": "user", "content": "Email jane.doe@example.com about the invoice"}]
reply = client.messages.create(model="claude-sonnet-4-6", max_tokens=256, messages=messages)
count = client.messages.count_tokens(model="claude-sonnet-4-6", messages=messages)
```

Notes: `x-api-key` is accepted as the shim key only on `/v1/messages`,
`/v1/messages/count_tokens` and `/v1/models`; other routes need
`Authorization: Bearer` or `x-shim-key`. `count_tokens` counts the masked payload
that would go upstream, and does not stream.

## Use the Gemini SDK

Send `generateContent` and streaming calls through shim.

1. Give the gateway `GOOGLE_API_KEY`, or send the key per request in `x-provider-key`.
2. Pass the shim key as `api_key` and `http://localhost:8000` as the base URL.
   The SDK sends the shim key in `x-goog-api-key`. On Gemini routes shim reads
   that header only as the shim key, so a Google key placed there is never used
   upstream.

```python
import os

from google import genai
from google.genai.types import HttpOptions

client = genai.Client(
    api_key="a-key-of-at-least-16-chars",
    http_options=HttpOptions(
        base_url="http://localhost:8000",
        # Leave this out when the gateway has GOOGLE_API_KEY.
        headers={"x-provider-key": os.environ["GOOGLE_API_KEY"]},
    ),
)
reply = client.models.generate_content(
    model="gemini-3.5-flash", contents="Email jane.doe@example.com about the invoice"
)
for chunk in client.models.generate_content_stream(model="gemini-3.5-flash", contents="Draft a reply"):
    print(chunk.text, end="")
```

Notes: the routes are `/v1beta/models/{model}:generateContent` and
`/v1beta/models/{model}:streamGenerateContent?alt=sse`. Gemini calls use
`GOOGLE_TIMEOUT_SECONDS` (60 by default), not the OpenAI and Anthropic read timeouts.

## Tag requests and read their cost

Attribute each request's tokens and cost to a feature, team or customer.

1. Send `X-Shim-Tag` with one or more comma-separated tags. The header stays at
   shim; it is not forwarded to the provider.
2. Read the usage event shim writes for each inference request that passed
   authentication and request validation, admitted or refused: one JSON line on
   the gateway's **stderr**. Token counting writes none unless it is refused.
   Structured logs go to stdout. Uvicorn's start-up lines also go to stderr, so
   keep only lines whose `version` is 4 and whose `event` is `request`.

Tag rules, from `src/shim/billing/attribution.py`:

- each tag is trimmed and lowercased, may contain only `a-z`, `0-9`, `_`, `.`,
  `:` and `-`, and may be at most `COST_TAG_MAX_LENGTH` characters (default 64,
  maximum 256);
- a tag that breaks a rule is dropped without an error, and duplicates are dropped;
- the first valid tag becomes the event's `cost_center`; with none, `cost_center`
  is `untagged` and `tags` is empty.

```python
client.chat.completions.create(
    model="gpt-5-nano",
    messages=[{"role": "user", "content": "Summarise the invoice dispute"}],
    extra_headers={"X-Shim-Tag": "checkout,Team-A"},  # tags: ["checkout", "team-a"]
)
```

```console
docker run --rm -p 8000:8000 -e SHIM_API_KEY=a-key-of-at-least-16-chars \
  -e OPENAI_API_KEY ghcr.io/getshim/shim:latest 2>> shim-usage.log
jq -cR 'fromjson? | select(.version == 4 and .event == "request") | {cost_center, tags, model, estimated_cost_usd}' shim-usage.log
```

Each event has `version`, `event` (`request`), `request_id`, `ts`, `protocol`,
`stream`, `provider`, `model`, `outcome`,
`shim_latency_ms`, `prompt_tokens`, `completion_tokens`, `estimated_cost_usd`,
`estimated`, `provider_finish_reasons`, `completion_outcome`, `ttft_ms`,
`provider_latency_ms`, `answer_characters`, `tool_call_names`, `reasoning_seen`,
`repeat_chain_length`, `cost_center`, `tags`, `system_prompt_hash`,
`deployment_kind`, `privacy_counts`, `monitored_entities`, `blocked_entities`,
`bulk_disclosure`, `warnings` and `policy_verdicts`. The three count maps give values by
entity type: masked, sent unchanged under `monitor`, and refused under `block`;
each is `{}` when empty. `bulk_disclosure` is `null` unless the request reached
the bulk threshold (see [Choose what happens to each data type](#choose-what-happens-to-each-data-type)). `outcome` is `completed` for a finished request and `rejected` for one
refused at admission or by a privacy block; other values name a failure.
`ts` is the request's start in UTC (`2026-10-08T09:15:02.123Z`), so events can be
grouped by hour. `protocol` is `openai_chat`, `openai_responses`,
`anthropic_messages`, `anthropic_count_tokens` (only a refused or failed token
count writes a line) or `gemini`, and `stream` says whether the caller streamed.
`provider_latency_ms` is the milliseconds from before the provider call to the
parsed answer of a JSON request (`null` for a stream, which has `ttft_ms`);
`answer_characters` is the answer text's length without reasoning text;
`tool_call_names` lists the tools the answer called; `reasoning_seen` is `true`
when the answer carried reasoning or reported reasoning tokens, which distort a
tokens-per-character ratio. A refused or failed line has `null`, `null`, `[]` and
`false`.

Notes: `estimated_cost_usd` is a decimal string that can use exponent form
(`6.5E-7`), so parse it as a decimal; it is `null` for a model without a catalog
price. When the provider reports its prompt-cache split (Anthropic
`cache_read_input_tokens` and `cache_creation_input_tokens`, OpenAI
`cached_tokens`, Gemini `cachedContentTokenCount`), cached reads and cache writes
are priced at the catalog's cache prices, an Anthropic one-hour write at twice
the input price (OpenAI reports no writes, so its uncached input is priced at the
higher of the input and cache-write prices), and the event carries `cache_read_tokens` and
`cache_write_tokens`; `prompt_tokens` stays the total. Without that split both
are `null` and every input token is priced at the model's highest input rate
(for Anthropic the one-hour write price), so the figure can only be above the
provider's bill. `estimated` is `true` when token counts were estimated rather than
reported by the provider. The writer queue is bounded and drops the newest event
when full, counted by `shim_local_usage_dropped_total`. Community keeps no request
history; durable per-team reports are enterprise.

Upgrading from a release that wrote `"version": 3`: version 4 adds `event`,
`cache_read_tokens`, `cache_write_tokens`, `monitored_entities`,
`blocked_entities`, `bulk_disclosure` and `warnings` to the request line, fills
`system_prompt_hash`, and adds the `response_privacy` line, so a reader that
selected `version == 3` must select `version == 4` and `event == "request"`.
The `privacy.input` verdict's `policy_version` now hashes the effective action
of every type, so it changes once for every tenant on the first request after
the upgrade, also in enterprise, without any setting having changed.

## Scan text before you send it

Find out what shim would mask in a text, without calling a provider.

1. `POST /v1/scan` with `{"text": ...}`, at most 50,000 characters.
2. Read `verdict`: `warn` when anything was found, otherwise `clean`. `entities`
   gives each finding's `type`, `score` and `start`/`end` offsets into your text;
   `entity_types` lists the distinct types; `policy` is always `warn` in community.
   Enterprise answers `warn` as well, for gateway keys and signed-in users alike,
   unless the plan's `scan_policy` feature is `block`.
   The full response is shown in the [README quickstart](../README.md#quickstart).

```python
import httpx

scan = httpx.post(
    "http://localhost:8000/v1/scan",
    headers={"x-shim-key": "a-key-of-at-least-16-chars"},
    json={"text": "Customer jane.doe@example.com, IBAN TR33 0006 1005 1978 6457 8413 26"},
).json()
if scan["verdict"] == "warn":
    print(scan["entity_types"])  # ['EMAIL_ADDRESS', 'IBAN_CODE']
```

The types shim detects are `EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`,
`IBAN_CODE`, `TR_NATIONAL_ID`, `TR_VKN`, `TR_LICENSE_PLATE`, `SECRET`, `US_SSN`,
`IP_ADDRESS`, `MAC_ADDRESS`, `DB_URI` and `FILE_PATH`. The
[README](../README.md#what-it-does) gives examples and known false positives.

Each entity also carries its `action` (see the next recipe); a type whose action
is `off` is not reported. Enterprise names the list `entities_found` and gives
each entry the same `action`, taken from the tenant's privacy settings. The response also carries the `request_id` in
`X-Shim-Request-Id`. This route takes
the shim key in `Authorization: Bearer` or `x-shim-key`, not `x-api-key`, and its
errors use the `{"detail": ...}` shape; text over the limit is 422.

## Choose what happens to each data type

Mask most types, watch some, and refuse a request that carries a pasted key.

1. Set `PII_ENTITY_ACTIONS` to a JSON object from entity type to action and
   restart the gateway. A type you leave out is masked.

   | Action | What shim does |
   | --- | --- |
   | `mask` | Replaces the value with a placeholder and restores it in the answer. |
   | `mask_last4` | `CREDIT_CARD` and `IBAN_CODE` only: masks like `mask`, with the last four digits (card) or characters (IBAN, upper-cased) after the placeholder's hex, `<CREDIT_CARD_…~1111>`. |
   | `monitor` | Sends the value unchanged and counts it in `monitored_entities`. |
   | `block` | Refuses the request with 400 before any provider call, `count_tokens` included. |
   | `off` | Does not look for the type. |

2. A blocked request answers in the provider's error shape with
   `SECRET_BLOCKED` when a blocked type is `SECRET` or `DB_URI`, otherwise
   `PII_BLOCKED`. The message names the types, never the value.

```console
docker run --rm -p 8000:8000 -e SHIM_API_KEY=a-key-of-at-least-16-chars \
  -e PII_ENTITY_ACTIONS='{"SECRET":"block","EMAIL_ADDRESS":"monitor"}' \
  -e OPENAI_API_KEY ghcr.io/getshim/shim:latest
```

```python
import openai

try:
    client.chat.completions.create(
        model="gpt-5-nano",
        messages=[{"role": "user", "content": "Deploy with sk-proj-00000000000000000000000000000000"}],
    )
except openai.BadRequestError as error:
    print(error.response.headers["x-shim-error-code"])  # SECRET_BLOCKED
    print(error.body["message"])  # Request blocked by privacy policy: SECRET.
```

To let the provider's prompt cache work on prompts that carry a masked value,
such as a system prompt with a support address, set `PII_PLACEHOLDER_MODE=stable`
and `PII_PLACEHOLDER_KEY` to a secret of at least 32 characters. The same value
then gets the same placeholder for up to 30 days (fixed UTC windows), derived
from the key with HMAC-SHA256; the provider can tell that two requests carry the
same value, never the value itself; that linkage can stay in the provider's
logs after the window ends, and anyone who can read those logs and send
requests through shim can confirm a guessed value. Two spellings of a value are
two values. Changing the key changes every placeholder. Generate the key with
`openssl rand -hex 32` and never share it between installs: every community
install uses the same public tenant id, so two installs with one key give the
provider the same placeholders.

A pasted customer list is masked like any other text, so shim also counts the
distinct values it found in one request, across every type and action. When
that count reaches `PII_BULK_THRESHOLD` (default 50; `0` turns the alarm off,
otherwise at least 2), the usage event carries
`"bulk_disclosure": {"distinct_values": 60, "threshold": 50}`, the
`privacy.bulk` verdict (`allow`, `BULK_DISCLOSURE`) is added and
`shim_privacy_bulk_disclosures_total` counts it. The request itself goes on as
its actions decide. A repeated value counts once, and a Responses continuation
does not count the values it inherits.

To learn when a model answers with personal data the request did not carry, set
`PII_RESPONSE_SCAN=count`. After the answer has been delivered (after the last
chunk of a stream) shim scans its text and tool-call arguments with the same
actions and writes a second line for the request:

```json
{"version":4,"event":"response_privacy","request_id":"req_…","response_entities":{"TR_NATIONAL_ID":1},"truncated":false}
```

`response_entities` counts distinct values by type. A value the request itself
carried, masked or monitored, is the caller's own and is not counted, also when
the model reformats it without spaces or hyphens. Only the first 1,000,000
characters are scanned (`truncated: true` beyond); a scan that fails writes
`"response_entities": null, "error": true`. The answer, its first token and its
timing are unchanged.

Notes: an unknown type or action, `mask_last4` on another type, `stable`
without a key, an invalid bulk threshold, or a `PII_RESPONSE_SCAN` other than
`off` or `count`, stops the gateway at start-up with the setting named. A tailed placeholder is restored
whether the model writes it back with or without its tail; with a different
tail it is left as written. The tail reaches only the provider: events and
metrics carry counts. The types are those listed in [Scan text before you send it](#scan-text-before-you-send-it).
Where two detections overlap, as an e-mail inside a file path, the span takes
the stronger action (`block`, then `mask`, then `mask_last4`, then `monitor`), so
watching one type never sends a value another type masks or blocks.
A type set to `monitor` or `off` is not checked in provider protocol
identifiers, and a blocked type found there is refused with `SECRET_BLOCKED` or
`PII_BLOCKED` like one in content. A gateway where no type is `mask` or `block`
also accepts images and files it cannot inspect. Enterprise sets the same actions per tenant;
see the [enterprise cookbook](../ee/docs/COOKBOOK.md).

## Read errors and retry

Tell a refusal shim made from one the provider made, and retry only when a retry can succeed.

1. Read the `X-Shim-Error-Code` response header. Every provider-route error whose
   code shim knows carries it, in the OpenAI, Anthropic and Gemini shapes alike.
   OpenAI and Anthropic bodies repeat it in `error.code`, Gemini bodies in an
   `ErrorInfo` `reason`. Shapes and the full code list are in
   [current architecture](CURRENT_ARCHITECTURE.md#native-responses-streams-and-errors).
2. Read the hint: one sentence on what to do next, in `error.hint` (OpenAI and
   Anthropic) or `ErrorInfo.metadata.hint` (Gemini). An error raised after the
   shim key was accepted also carries `X-Shim-Request-Id`; quote it when you
   report a problem.
3. Decide from the table below.

```python
import openai

try:
    client.chat.completions.create(
        model="gpt-5-nano", messages=[{"role": "user", "content": "Summarise the invoice dispute"}]
    )
except openai.APIStatusError as error:
    code = error.response.headers.get("x-shim-error-code")
    if code == "RATE_LIMIT_EXCEEDED" and error.response.headers.get("x-should-retry") == "false":
        ...  # this request alone exceeds the tokens-per-minute limit: send less
    elif code == "PROVIDER_RATE_LIMITED":
        ...  # the provider's quota for your provider key, not a shim limit
```

| Refusal | Status and code | Retry signal |
| --- | --- | --- |
| Requests per minute over `DEFAULT_RPM_LIMIT` (default 60) | 429 `RATE_LIMIT_EXCEEDED` | `Retry-After: 60` |
| Approximate tokens per minute over `DEFAULT_TPM_LIMIT` (default 1,000,000) | 429 `RATE_LIMIT_EXCEEDED` | `Retry-After: 60` |
| One request larger than the whole `DEFAULT_TPM_LIMIT`; the message gives its approximate size and the limit | 429 `RATE_LIMIT_EXCEEDED` | `x-should-retry: false`, no `Retry-After` |
| More than `LOOP_REPEAT_LIMIT` (default 8) identical prompts within `LOOP_WINDOW_SECONDS` (default 300) | 429 `RATE_LIMIT_EXCEEDED` | `Retry-After: <LOOP_WINDOW_SECONDS>` |
| One client IP over `GLOBAL_RATE_LIMIT_PER_MINUTE` (default 1,000) | 429 `RATE_LIMIT_EXCEEDED` on provider routes; elsewhere 429 `{"detail": "Too Many Requests"}` without a code | `Retry-After: 60` |
| Provider answered 429 | 429 `PROVIDER_RATE_LIMITED` | the provider's `retry-after`, when it sent seconds or an HTTP date |
| Provider refused the request (400, 403, 404, 413, 422) | the provider's status, `PROVIDER_REJECTED_REQUEST`; for 400, 404, 413 and 422 the message is the provider's own | none: correct the request |
| Provider refused the provider key (401) | 401 `INVALID_PROVIDER_CREDENTIAL` | none: correct the provider key |
| The provider SDK refused the request before sending it | 400 `INVALID_REQUEST` | none: correct the request |
| Provider answered another error | the provider's status, `PROVIDER_TIMEOUT` for a timeout status, otherwise `PROVIDER_UNAVAILABLE` | none from shim |
| Provider call timed out | 504 `PROVIDER_TIMEOUT` | none from shim |
| Provider unreachable, or its circuit is open | 503 `PROVIDER_UNAVAILABLE` | none from shim |
| Body over `MAX_REQUEST_BODY_SIZE` (default 32,000,000 bytes) | 413 `REQUEST_TOO_LARGE` | none |
| A detected type whose action is `block` | 400 `SECRET_BLOCKED` (`SECRET`, `DB_URI`) or `PII_BLOCKED` | none: remove the value the message names |
| An enforced tenant rule blocks (enterprise) | 400 `RULE_BLOCKED`; `X-Shim-Rule-Id` and `error.param` name the rule | none: change the request or ask the tenant admin |
| An enforced tenant rule needs approval (enterprise) | 403 `APPROVAL_REQUIRED`, `X-Shim-Approval-Id`; `APPROVAL_REJECTED` once refused, `APPROVAL_QUEUE_FULL` without an id | `x-should-retry: false`: after approval, send the same request with `X-Shim-Approval-Id` |
| The approval store cannot be reached (enterprise) | 503 `APPROVAL_UNAVAILABLE` | `Retry-After: 5` |
| The input certainly does not fit the model's context window or input limit | 400 `MODEL_CONTEXT_EXCEEDED` | none: shorten the input or lower the output limit |
| The catalog says the model lacks tools, structured output or an input modality the request uses | 400 `MODEL_CAPABILITY_UNSUPPORTED` | none: remove what the message names or change model |

In OpenAI-shaped bodies, `error.param` names which limit refused: `requests`,
`tokens` or `repeated_requests`.

Notes:

- Approximate tokens are the request body's compact JSON size in bytes divided
  by four, rounded up. A refused amount is not added to the window that refused it,
  and a request larger than the whole limit is refused before any window is
  counted, so it does not use up a request either. A request exactly at the limit
  is admitted.
- Rate windows are fixed 60-second windows, kept per process, so replicas do not share them.
- A repeat is the same prompt-bearing fields (`messages`, `input`,
  `instructions`, `system`, `contents`, `systemInstruction`) and model, with
  whitespace normalised; client metadata does not make prompts different.
  The default 300-second `Retry-After` is longer than the pinned SDKs honour
  (120 seconds for `openai`, 60 for `anthropic`), so their automatic retry comes
  sooner and is refused again. Handle `repeated_requests` in your own code.
- After five provider failures with no success in between, the provider's
  circuit opens for 60 seconds. A provider 429 neither opens nor closes it.
- The per-IP limit counts the connecting address. Behind a proxy, list the
  proxy's IP addresses (not ranges) in `TRUSTED_PROXIES`, comma-separated or as a
  JSON list. shim then takes the client from `cf-connecting-ip`, `x-real-ip`, or
  the right-most untrusted `x-forwarded-for` entry.

## Read warnings

Learn when a request costs more than it seems, or may not fit, without being refused.

1. Read `X-Shim-Warnings`, a comma-separated list of codes, on the response.
   Browsers may read it. A stream carries only the codes known before it
   starts; the usage event's `warnings` lists them all.
2. Decide from the table.

| Code | When | What to do |
| --- | --- | --- |
| `MODEL_DEPRECATED` | The catalog marks the model deprecated. It is still served. | Move to a current model before the provider retires it. |
| `CONTEXT_MAY_EXCEED` | The request's approximate size (bytes / 4, plus the output limit where it counts against the window) is above the context window of the model's own catalog entry, but not certainly. | Count tokens (`/v1/messages/count_tokens`, which is never refused) or shorten the input. |
| `LARGE_CONTEXT_PRICE` | The settled input is above the model's large-context price threshold; the whole request is priced at the higher tier. | Keep the input under the threshold the catalog lists. |
| `CACHE_NOT_APPLIED` | An Anthropic request had `cache_control` but the usage shows no cache write and no cache read; Anthropic returns no error for this. | Make the cached prefix longer than the model's minimum cacheable length. |
| `RULE_WARN` | An enforced tenant rule with action `warn` matched (enterprise); the request went ahead unchanged. | Read the rule with your tenant admin; the request list shows which one. |

shim refuses before the provider only what certainly fails. It counts the
whitespace-separated words of the prompt text, a lower bound for the public
tokenizers (OpenAI's and the open-weight families), which split on whitespace
before merging; for Claude and Gemini, whose tokenizers are not published, the
same bound is assumed, not proven. Tool definitions, protocol fields, JSON keys
and earlier turns' thinking or reasoning are not counted, so the real size is
usually much larger. The output limit counts against the window only for OpenAI
models and deployments: Gemini's is separate, and Claude stops at the window. A
request with Responses `truncation: "auto"`, `context_management`, `compaction`
or a compaction block is never refused for size. Refusals use only a model's own
catalog entry, never a longer model name matched by prefix. A capability is
refused only when the catalog says the model lacks it; an unknown capability is
never refused, and an OpenAI file part is never refused as a PDF.

## Analyse answers after delivery

Have named analyzers read each completed answer after it reached the caller and
record what they measured, never what was written.

1. Set `SHIM_RESPONSE_ANALYSIS` to a comma-separated list (or a JSON list) of
   analyzer names and restart the gateway. It is empty by default, and an empty
   list keeps nothing and adds no work.
2. Read a third JSONL line for each completed request:

```json
{"version":4,"event":"response_analysis","request_id":"req_…","results":{"<name>":{…},"versions":{"<name>":"1"}}}
```

Analyzers run in the order shim defines, after the last byte of a JSON answer or
after a stream ended, in one background task shared with
`PII_RESPONSE_SCAN=count`; the answer, its first token and its timing are
unchanged. They see the masked request and up to 1,000,000 characters of the
answer and its tool calls. Results hold counts, labels, ids, protocol field
names and JSON pointers, never request or answer text and never a restored
value. An analyzer that fails records `{"error": true}`, and a result larger
than 4,096 characters records `{"error": true, "reason": "too_large"}`; the
others still run. A request that failed or was refused gets no analysis.

Notes: an unknown name stops the gateway at start-up with the setting and the
name in the message; a repeated name is dropped. This release defines no
analyzer yet. `shim_response_analysis_total{analyzer, result}` counts the runs.

## Stream long generations and read usage

Stream long answers without losing exact token accounting.

1. Stream anything long. A non-streaming request is bounded by the provider read
   timeout, `OPENAI_READ_TIMEOUT_SECONDS` or `ANTHROPIC_READ_TIMEOUT_SECONDS`
   (600 seconds by default).
2. On OpenAI Chat Completions streams, shim asks the provider for
   `stream_options.include_usage` so it can meter real token counts. If you did
   not ask for it, the extra usage chunk is withheld from your stream; ask for it
   to receive it. shim changes no other stream this way.
3. For timing, read `X-Shim-Request-Id` on every successful response and
   `X-Shim-Latency-Ms` on non-streaming ones: the milliseconds shim itself spent,
   provider wait excluded. For a stream, the usage event carries `shim_latency_ms`
   and `ttft_ms`.

```python
stream = client.chat.completions.create(
    model="gpt-5-nano",
    messages=[{"role": "user", "content": "Draft a long reply to the invoice dispute"}],
    stream=True,
    stream_options={"include_usage": True},  # optional: shim meters either way
)
for chunk in stream:
    if chunk.usage:
        print(chunk.usage.prompt_tokens, chunk.usage.completion_tokens)
    elif chunk.choices:
        print(chunk.choices[0].delta.content or "", end="")

raw = client.chat.completions.with_raw_response.create(
    model="gpt-5-nano", messages=[{"role": "user", "content": "Summarise the invoice dispute"}]
)
print(raw.headers["x-shim-request-id"], raw.headers["x-shim-latency-ms"])
completion = raw.parse()
```

The usage event's `completion_outcome` says whether the caller got a whole
answer: `complete`, `truncated`, `empty`, `refused` or `filtered`, and `null`
when the request failed. The mapping from provider finish reasons is in
[diagnostic metadata](../ee/docs/DIAGNOSTIC_METADATA.md). A stream that fails
after its headers were sent ends with a sanitized terminal event, described in
[current architecture](CURRENT_ARCHITECTURE.md#native-responses-streams-and-errors).

## Observe the gateway

Export traces, logs, error reports and metrics without exporting prompt or response text.

1. Set the settings you need and restart the gateway:

   | Setting | Effect |
   | --- | --- |
   | `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP over HTTP; spans go to `<endpoint>/v1/traces`. Unset means no tracing. |
   | `OTEL_SERVICE_NAME` | `service.name` of the spans, default `shim`. |
   | `SENTRY_DSN` | Error reports only, no performance traces. Request body, URL, query string, cookies and exception messages are stripped. |
   | `LOG_LEVEL` | `DEBUG`, `INFO` (default), `WARNING`, `ERROR` or `CRITICAL`; JSON lines on stdout. |
   | `SYSTEM_PROMPT_HASH_KEY` | A secret of at least 32 characters. The usage event's `system_prompt_hash` becomes an HMAC of the system and developer instructions, so a changed prompt shows as a changed hash. Unset means `null`. Another installation's key gives other hashes for the same prompt. |

2. Read the cost and usage of a settled request from its span attributes:
   `gen_ai.request.model` (`unpriced` for a model without a catalog price),
   `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`,
   `gen_ai.response.finish_reasons`, `shim.cost_usd` and `shim.usage_estimated`.
   Span attributes come from a fixed allow-list.
3. Scrape `GET /metrics` (Prometheus text). It needs no key and is not in the
   OpenAPI document, so keep it off public networks.

```console
docker run --rm -p 8000:8000 -e SHIM_API_KEY=a-key-of-at-least-16-chars \
  -e OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318 ghcr.io/getshim/shim:latest
curl -s http://localhost:8000/metrics | grep -E '^(requests|provider_|shim_)'
```

| Metric | Labels |
| --- | --- |
| `requests_total` | `endpoint`, `status`, `tenant_tier` |
| `provider_requests_total` | `provider`, `model`, `status` |
| `provider_latency_ms` (histogram, buckets up to 600,000 ms) | `provider`, `model` |
| `stream_terminal_state_total` | `terminal_state` |
| `privacy_detection_total` | `entity_type` |
| `shim_privacy_bulk_disclosures_total` | `provider` |
| `shim_privacy_response_detection_total` | `entity_type` |
| `shim_completion_outcomes_total` | `provider`, `outcome` |
| `shim_local_usage_dropped_total` | `reason` |
| `shim_time_to_first_token_seconds` (histogram, streams only) | `provider`, `model` |
| `shim_requests_in_flight` (gauge, provider calls in progress) | `provider` |
| `shim_response_analysis_total` | `analyzer`, `result` |

Notes: every label takes its value from a fixed set. Values taken from requests
go through the vocabulary in `src/shim/observability/metrics.py`, and anything
outside it is recorded as `other`: `model` is a family (`gpt-*`, `claude-*`,
`gemini-*`, `other`), never a full model id, and `endpoint` is the route
template. `reason` is `queue_unavailable` or `sink_failure`.

## Put shim behind LiteLLM

Keep an existing LiteLLM proxy and add shim's privacy and accounting behind it.
Verified with LiteLLM 1.104.1 against a community gateway for OpenAI, Anthropic
and Gemini models: answers arrive, personal data is masked at the provider and
restored for the client, the shim key never reaches the provider, and a provider
error is one attempt.

1. Point each model at shim and give LiteLLM the shim key as that provider's
   key. LiteLLM sends it where shim reads it: `Authorization: Bearer` for
   OpenAI, `x-api-key` for Anthropic, `x-goog-api-key` for Gemini. The OpenAI
   base ends in `/v1`, the Anthropic base is the shim root, and the Gemini base
   ends in `/v1beta`, because LiteLLM appends `/models/...` to it.
2. Set `num_retries: 0`. With LiteLLM's defaults one client request reached the
   provider three times when it failed; shim already makes exactly one attempt
   and sends `x-should-retry` and `Retry-After` where a retry can succeed.
3. Keep the provider keys on the shim side (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
   `GOOGLE_API_KEY`). LiteLLM recent releases also need a master key for their own
   clients.

```yaml
model_list:
  - model_name: shim-openai
    litellm_params:
      model: openai/gpt-5-nano
      api_base: http://localhost:8000/v1
      api_key: a-key-of-at-least-16-chars
  - model_name: shim-anthropic
    litellm_params:
      model: anthropic/claude-haiku-5-5
      api_base: http://localhost:8000
      api_key: a-key-of-at-least-16-chars
  - model_name: shim-gemini
    litellm_params:
      model: gemini/gemini-3.5-flash-lite
      api_base: http://localhost:8000/v1beta
      api_key: a-key-of-at-least-16-chars
litellm_settings:
  num_retries: 0
router_settings:
  num_retries: 0
general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
```

Without the proxy, LiteLLM's SDK takes the same values on each call:

```python
import litellm

for model, api_base in (
    ("openai/gpt-5-nano", "http://localhost:8000/v1"),
    ("anthropic/claude-haiku-5-5", "http://localhost:8000"),
    ("gemini/gemini-3.5-flash-lite", "http://localhost:8000/v1beta"),
):
    litellm.completion(
        model=model,
        api_base=api_base,
        api_key="a-key-of-at-least-16-chars",
        num_retries=0,
        messages=[{"role": "user", "content": "Email jane.doe@example.com about the invoice"}],
    )
```

## Put shim behind Portkey

Route the open-source Portkey gateway's OpenAI and Anthropic traffic through
shim. Verified with `@portkey-ai/gateway` 1.15.2 against a community gateway:
answers arrive, personal data is masked at the provider and restored, the shim
key never reaches the provider, and a provider error is one attempt (Portkey
retries only when a retry config asks it to; leave it unset).

1. Send each request to Portkey with `x-portkey-provider` (`openai` or
   `anthropic`) and `x-portkey-custom-host` set to shim's `/v1`, for both
   providers.
2. Put the shim key in `Authorization: Bearer`; Portkey passes it to shim as the
   provider's own key header.

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8787/v1",
    api_key="a-key-of-at-least-16-chars",
    default_headers={
        "x-portkey-provider": "anthropic",
        "x-portkey-custom-host": "http://localhost:8000/v1",
    },
)
client.chat.completions.create(
    model="claude-haiku-5-5",
    max_tokens=256,
    messages=[{"role": "user", "content": "Email jane.doe@example.com about the invoice"}],
)
```

Notes: Gemini behind Portkey does not work: Portkey sends the Gemini key as a
`?key=` query parameter and adds a `model` field to the body, and shim reads the
key only from a header and refuses fields the Gemini route does not define. Send
Gemini traffic to shim directly or through LiteLLM.
