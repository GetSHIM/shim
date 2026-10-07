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
- [Read errors and retry](#read-errors-and-retry)
- [Stream long generations and read usage](#stream-long-generations-and-read-usage)
- [Observe the gateway](#observe-the-gateway)

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
   the gateway's **stderr**. Token counting writes none. Structured logs go to
   stdout. Uvicorn's start-up lines also go to stderr, so keep only lines whose
   `version` is 3.

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
jq -cR 'fromjson? | select(.version == 3) | {cost_center, tags, model, estimated_cost_usd}' shim-usage.log
```

Each event has `version`, `request_id`, `provider`, `model`, `outcome`,
`shim_latency_ms`, `prompt_tokens`, `completion_tokens`, `estimated_cost_usd`,
`estimated`, `provider_finish_reasons`, `completion_outcome`, `ttft_ms`,
`repeat_chain_length`, `cost_center`, `tags`, `system_prompt_hash`,
`deployment_kind`, `privacy_counts` and `policy_verdicts`. `outcome` is
`completed` for a finished request and `rejected` for one refused at admission;
other values name a failure.

Notes: `estimated_cost_usd` is a decimal string that can use exponent form
(`6.5E-7`), so parse it as a decimal; it is `null` for a model without a catalog
price. `estimated` is `true` when token counts were estimated rather than
reported by the provider. The writer queue is bounded and drops the newest event
when full, counted by `shim_local_usage_dropped_total`. Community keeps no request
history; durable per-team reports are enterprise.

## Scan text before you send it

Find out what shim would mask in a text, without calling a provider.

1. `POST /v1/scan` with `{"text": ...}`, at most 50,000 characters.
2. Read `verdict`: `warn` when anything was found, otherwise `clean`. `entities`
   gives each finding's `type`, `score` and `start`/`end` offsets into your text;
   `entity_types` lists the distinct types; `policy` is always `warn` in community.
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

Notes: community has no privacy switches; every type above is always on. The
response also carries the `request_id` in `X-Shim-Request-Id`. This route takes
the shim key in `Authorization: Bearer` or `x-shim-key`, not `x-api-key`, and its
errors use the `{"detail": ...}` shape; text over the limit is 422.

## Read errors and retry

Tell a refusal shim made from one the provider made, and retry only when a retry can succeed.

1. Read the `X-Shim-Error-Code` response header. Every provider-route error whose
   code shim knows carries it, in the OpenAI, Anthropic and Gemini shapes alike.
   OpenAI bodies repeat it in `error.code`, Gemini bodies in an `ErrorInfo`
   `reason`; Anthropic bodies keep only their native keys, so read the header.
   Shapes and the full code list are in
   [current architecture](CURRENT_ARCHITECTURE.md#native-responses-streams-and-errors).
2. Decide from the table below.

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
| Approximate tokens per minute over `DEFAULT_TPM_LIMIT` (default 10,000) | 429 `RATE_LIMIT_EXCEEDED` | `Retry-After: 60` |
| One request larger than the whole `DEFAULT_TPM_LIMIT` | 429 `RATE_LIMIT_EXCEEDED` | `x-should-retry: false`, no `Retry-After` |
| More than `LOOP_REPEAT_LIMIT` (default 8) identical prompts within `LOOP_WINDOW_SECONDS` (default 300) | 429 `RATE_LIMIT_EXCEEDED` | `Retry-After: <LOOP_WINDOW_SECONDS>` |
| One client IP over `GLOBAL_RATE_LIMIT_PER_MINUTE` (default 1,000) | 429 `RATE_LIMIT_EXCEEDED` on provider routes; elsewhere 429 `{"detail": "Too Many Requests"}` without a code | `Retry-After: 60` |
| Provider answered 429 | 429 `PROVIDER_RATE_LIMITED` | the provider's `retry-after`, when it sent seconds or an HTTP date |
| Provider answered another error | the provider's status, `PROVIDER_TIMEOUT` for a timeout status, otherwise `PROVIDER_UNAVAILABLE` | none from shim |
| Provider call timed out | 504 `PROVIDER_TIMEOUT` | none from shim |
| Provider unreachable, or its circuit is open | 503 `PROVIDER_UNAVAILABLE` | none from shim |
| Body over `MAX_REQUEST_BODY_SIZE` (default 32,000,000 bytes) | 413 `REQUEST_TOO_LARGE` | none |

In OpenAI-shaped bodies, `error.param` names which limit refused: `requests`,
`tokens` or `repeated_requests`.

Notes:

- Approximate tokens are the request body's compact JSON size in bytes divided
  by four, rounded up. A refused amount is not added to the window that refused it.
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
| `provider_latency_ms` (histogram) | `provider`, `model` |
| `stream_terminal_state_total` | `terminal_state` |
| `privacy_detection_total` | `entity_type` |
| `shim_completion_outcomes_total` | `provider`, `outcome` |
| `shim_local_usage_dropped_total` | `reason` |

Notes: every label takes its value from a fixed set. Values taken from requests
go through the vocabulary in `src/shim/observability/metrics.py`, and anything
outside it is recorded as `other`: `model` is a family (`gpt-*`, `claude-*`,
`gemini-*`, `other`), never a full model id, and `endpoint` is the route
template. `reason` is `queue_unavailable` or `sink_failure`.
