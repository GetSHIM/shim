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
- [Send embeddings through shim](#send-embeddings-through-shim)
- [Use Azure OpenAI](#use-azure-openai)
- [Tag requests and read their cost](#tag-requests-and-read-their-cost)
- [Scan text before you send it](#scan-text-before-you-send-it)
- [Choose what happens to each data type](#choose-what-happens-to-each-data-type)
- [Read errors and retry](#read-errors-and-retry)
- [Read warnings](#read-warnings)
- [Count instructions hidden in tool results](#count-instructions-hidden-in-tool-results)
- [Analyse answers after delivery](#analyse-answers-after-delivery)
- [Check structured output](#check-structured-output)
- [Use the provider's cache discount](#use-the-providers-cache-discount)
- [Load tools on demand](#load-tools-on-demand)
- [Stop paying for old thinking](#stop-paying-for-old-thinking)
- [Shrink JSON tool results](#shrink-json-tool-results)
- [Read images at a cheaper detail level](#read-images-at-a-cheaper-detail-level)
- [Shrink oversized images](#shrink-oversized-images)
- [Stream long generations and read usage](#stream-long-generations-and-read-usage)
- [See what each lever saved](#see-what-each-lever-saved)
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
any other model gets 400 `MODEL_NOT_PRICED`. A model id is at most 200 letters,
digits, `.`, `_`, `:` and `-`; any other id is refused the same way, and the usage
event records it as `unsupported`, never the id itself. With no provider key at all the
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

## Send embeddings through shim

Embed documents through the same address, with the same privacy rules as chat.

1. Call `client.embeddings.create(model="text-embedding-3-small", input=[...])`
   with the OpenAI SDK set up as above (`POST /v1/embeddings`), or
   `client.models.embed_content(model="gemini-embedding-001", contents=[...])` with
   the Gemini SDK (it calls `:batchEmbedContents`; `:embedContent` works too).
2. Read the vectors as the provider returned them. Without `encoding_format`, shim
   asks OpenAI for `"float"`; a format you send is forwarded as given.

Your text is scanned and masked with your actions, and a masked value becomes a
placeholder in the vector: with random placeholders the same document gives a
different vector each time. Set `PII_PLACEHOLDER_MODE=stable` so it does not, or,
when the vectors stay in your own store, list the types in
`PII_EMBEDDINGS_MONITOR` (comma-separated, for example `TR_NATIONAL_ID,IBAN_CODE`):
for embeddings those types are only counted and sent unchanged, while chat keeps
masking them. Token ids (`input` of integers) cannot be scanned, so they are refused
with 400 `PRIVACY_POLICY_BLOCKED` while any type is masked or blocked
(`PERSON_NAME_TR` only when you set it), or an enforced tenant rule in scope masks,
blocks or holds text. The texts of one request are scanned in one pass, unless a tenant rule is in scope (a record match must not join
two texts). Errors on `/v1/embeddings` come in OpenAI's own error shape. The usage
event's `protocol` is `openai_embeddings` or `gemini_embed`, `completion_tokens` is
0, `completion_outcome` is null, and the cost is the input tokens at the model's
input price; Gemini reports no count, so its tokens are estimated as four
characters a token of the text sent (`estimated` is `true`). Embeddings models answer only these routes and are not in `/v1/models`;
`gemini-embedding-2` is not priced yet (its audio rate is above its text rate).
Behind LiteLLM, the OpenAI `api_base` ends in `/v1` as for chat.

## Use Azure OpenAI

Send catalog OpenAI requests to your own Azure OpenAI resource, with an Azure key or
a Microsoft Entra ID application.

1. Set `SHIM_AZURE_OPENAI_ENDPOINT` to the resource, for example
   `https://bank.openai.azure.com`. shim calls its v1 API at `/openai/v1` (a trailing
   `/openai/v1` in the setting is accepted), with no `api-version`. Leave
   `OPENAI_BASE_URL` unset: the two exclude each other.
2. Set one credential: `SHIM_AZURE_OPENAI_API_KEY`, or all three of
   `SHIM_AZURE_TENANT_ID`, `SHIM_AZURE_CLIENT_ID` and `SHIM_AZURE_CLIENT_SECRET` for
   an Entra application with the `Cognitive Services OpenAI User` role. shim asks
   Entra for a token (scope `SHIM_AZURE_TOKEN_SCOPE`, by default
   `https://cognitiveservices.azure.com/.default`; authority
   `SHIM_AZURE_AUTHORITY_HOST`, by default `https://login.microsoftonline.com`) and
   renews it 300 seconds before it expires. A key a caller sends in
   `x-provider-key` still wins.
3. Map catalog model names to your deployment names in
   `SHIM_AZURE_OPENAI_DEPLOYMENTS`, a JSON object such as
   `{"gpt-5.6-luna": "kurum-mini"}` (at most 200 entries). Applications keep asking
   for `gpt-5.6-luna`; Azure receives `kurum-mini`. A model the map does not list is
   sent under its own name. Admission, prices, warnings and the usage event keep the
   catalog name.

```bash
SHIM_AZURE_OPENAI_ENDPOINT=https://bank.openai.azure.com
SHIM_AZURE_OPENAI_API_KEY=...
SHIM_AZURE_OPENAI_DEPLOYMENTS='{"gpt-5.6-luna": "kurum-mini"}'
```

Chat Completions, Responses and embeddings go to `/openai/v1/chat/completions`,
`/openai/v1/responses` and `/openai/v1/embeddings`. A prompt Azure's content filter
refuses answers 400 `PROVIDER_CONTENT_FILTERED`; the message names the categories
that filtered it, such as `Categories: violence.`, and nothing else of Azure's body.
A filtered answer keeps `finish_reason: "content_filter"`, and Azure's
`prompt_filter_results` and `content_filter_results` fields pass through. Startup
fails, naming the setting, when the settings do not form one route: no credential or
two, Entra values or a map without an endpoint, a map key that is not a catalog
OpenAI model, or an `http` endpoint that is not loopback. An empty value counts as
unset. Prices are the catalog's OpenAI list prices; Azure's Data Zone, Regional and
provisioned prices can differ. The enterprise gateway ignores these settings except
the authority host and scope, and registers each Azure deployment instead.

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
`repeat_chain_length`, `cost_center`, `tags`, `task_id`, `trace_id`,
`tool_call_repeats`, `task_calls`, `inflight_duplicate_of`, `system_prompt_hash`,
`deployment_kind`, `privacy_counts`, `monitored_entities`, `blocked_entities`,
`bulk_disclosure`, `warnings` and `policy_verdicts`, `injection_markers` when
[the marker scan](#count-instructions-hidden-in-tool-results) is on, and
`inflight_share` on a request that received an identical request's answer (see
[identical requests in flight](#read-errors-and-retry)). The three count maps give values by
entity type: masked, sent unchanged under `monitor`, and refused under `block`;
each is `{}` when empty. `bulk_disclosure` is `null` unless the request reached
the bulk threshold (see [Choose what happens to each data type](#choose-what-happens-to-each-data-type)). `outcome` is `completed` for a finished request and `rejected` for one
refused at admission or by a privacy block; other values name a failure.
`ts` is the request's start in UTC (`2026-10-08T09:15:02.123Z`), so events can be
grouped by hour. `protocol` is `openai_chat`, `openai_responses`,
`anthropic_messages`, `anthropic_count_tokens` (only a refused or failed token
count writes a line) or `gemini`, and `stream` says whether the caller streamed.
`provider_latency_ms` is the milliseconds of the provider call of a JSON request,
from its start to the SDK returning the parsed answer, without credential
resolution before it or shim's restoring of masked values after it (`null` for a
stream, which has `ttft_ms`);
`answer_characters` is the answer text's length without reasoning text (a stream
also counts tool-call arguments, which a JSON answer does not, so the two differ
for a tool call); a stream that ended early records what it had sent in
`answer_characters` and `tool_call_names`, so compute ratios over `completed`
lines only; `tool_call_names` lists the tools the answer called; `reasoning_seen` is `true`
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
reported by the provider. A stream that ends before the provider's final usage, for
example because the client hung up after the first token, records the reserved
maximum output as `completion_tokens` (the request's `max_tokens`, or the model's
output limit, times the candidates asked for) and its cost at that size, as a JSON
answer without usage does: the provider may already have billed hidden reasoning
and more output than reached the client. The writer queue is bounded and drops the
newest event when full, counted by `shim_local_usage_dropped_total`. Community
keeps no request history; durable per-team reports are enterprise.

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
`IP_ADDRESS`, `MAC_ADDRESS`, `DB_URI`, `FILE_PATH` and `PERSON_NAME_TR`
(Turkish person names). The
[README](../README.md#what-it-does) gives examples and known false positives.
Digits of any script count as the number they are: a TCKN, IBAN, card or phone
number written in Arabic-Indic, Devanagari or fullwidth digits is found and
masked like one written in 0-9, and so is a rule term or template. Marks and
invisible characters on the digits (an accent after each digit, a variation
selector, a keycap, a zero-width joiner, any other format character such as
U+180E or a tag character, an unassigned default-ignorable code point such as
U+2065) do not hide the number; they are masked with it and restored with it,
and so are marks on the letters of an email or an IBAN. Every Unicode dash and
the minus sign (non-breaking hyphen, en and em dash, wave dash, their small and
fullwidth forms) reads as a hyphen, between digit groups and in rule matches. A
TCKN, card, IBAN or phone number with a space between every character
(`1 0 0 0 0 0 0 0 1 4 6`) or in hyphenated groups of one size
(`TR3-300-061-005-...`) is read without the separators when it has ten digits or
more, and an email broken over a line after its `@` is read whole. Text after a
right-to-left override (U+202E) is also read in the order it is shown, so a value
stored reversed is found; the mask covers the separators and the reversed text.
A line with JSON string escapes (`\u015f`, `\/`, `\"`, `\n`, surrogate pairs), as
`json.dumps` and PHP `json_encode` write tool results by default, is read both as
written and decoded until no escape is left (JSON nested in a JSON string
up to eight levels deep), so `Ay\u015fe Y\u0131lmaz`, a nested
`{\"password\": \"...\"}` and a rule term are found while a Windows path such as
`C:\temp\new` still is; the mask covers whole escapes. Injection markers are read
with the escapes decoded.
A number after `fatura no`, `sipariş no`, `order no`, `invoice no` or `takip no`
(and `numarası`, `numaranız`) is not taken for a phone; after `tel no`,
`telefon no` or `cep no` it is. A date such as `05.03.2026` is not a phone.

Each entity also carries its `action` (see the next recipe); a type whose action
is `off` is not reported. Enterprise names the list `entities_found` and gives
each entry the same `action`, taken from the tenant's privacy settings. The response also carries the `request_id` in
`X-Shim-Request-Id`. This route takes
the shim key in `Authorization: Bearer` or `x-shim-key`, not `x-api-key`, and its
errors use the `{"detail": ...}` shape; text over the limit is 422.

## Choose what happens to each data type

Mask most types, watch some, and refuse a request that carries a pasted key.

1. Set `PII_ENTITY_ACTIONS` to a JSON object from entity type to action and
   restart the gateway. A type you leave out is masked, `PERSON_NAME_TR`
   included.

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

Turkish person names are masked by default: "Sayın Ahmet Yılmaz'ın başvurusu"
reaches the provider as "Sayın <PERSON_NAME_TR_…>'ın başvurusu", and the name is
restored in the answer. To send them unchanged, add `"PERSON_NAME_TR":"off"`; to
send them and count them, `"monitor"`; to refuse the request, `"block"`.
Detection is list based (common first names, frequent surnames, cues such as
`Sayın`, `Hanım`, `Dr.`), measured on a held-out synthetic corpus written by a
different author: precision 0.992, recall 0.952. It does not catch a first
name alone ("Ahmet aradı"), two first names without a surname ("Mehmet Ali
geldi"), a rare first name without a cue, a first name that is also a word
("Deniz", "Umut") without a cue or a listed surname, or a name written surname
first ("YILMAZ Ahmet"). A name next to a place or institution word ("Ahmet
Yılmaz Caddesi", "Mehmet Akif Ersoy Üniversitesi") is left alone.

Notes: an unknown type or action, `mask_last4` on another type, `stable`
without a key, an invalid bulk threshold, or a `PII_RESPONSE_SCAN` other than
`off` or `count`, stops the gateway at start-up with the setting named. A tailed placeholder is restored
whether the model writes it back with or without its tail; with a different
tail it is left as written. Inside tool-call arguments, which are JSON text, a
restored value is JSON-escaped, so a quote or backslash in it stays part of the
string. A value masked inside JSON in a message text (tool-call history, a
`json.dumps` tool result, NDJSON, JSON after a label or inside prose) is kept
decoded, as the model reads it. The tail reaches only the provider: events and
metrics carry counts. The types are those listed in [Scan text before you send it](#scan-text-before-you-send-it).
Where two detections overlap, as an e-mail inside a file path, the span takes
the stronger action (`block`, then `mask`, then `mask_last4`, then `monitor`), so
watching one type never sends a value another type masks or blocks.
A type set to `monitor` or `off` is not checked in provider protocol
identifiers, and a blocked type found there is refused with `SECRET_BLOCKED` or
`PII_BLOCKED` like one in content. Enterprise sets the same actions per tenant;
see the [enterprise cookbook](../ee/docs/COOKBOOK.md).

Images, PDFs and other files (image, file, document, audio and Gemini inline or
file data parts) cannot be scanned. With `SHIM_MEDIA_INPUTS=block`, the default,
a request carrying one is refused with 400 `PRIVACY_POLICY_BLOCKED` ("PII
scrubbing does not support opaque media inputs.") while any type is `mask`,
`mask_last4` or `block`. `PERSON_NAME_TR` counts only when `PII_ENTITY_ACTIONS` sets
it: names masked by default do not refuse media, so a gateway with every other type
`off` lets it through, while `"PERSON_NAME_TR":"mask"` refuses it as before. With
`SHIM_MEDIA_INPUTS=allow`, or when nothing else masks or blocks, the part reaches the provider byte for byte and unscanned: its
base64 or data URL is never read, while its file name, title and other text are
scanned as usual and its URL and file id are checked like any identifier. The usage event
then carries `media_parts` (parts by kind: `image`, `pdf`, `docx`, `text`,
`audio`, `video`, `other`), `media_unscanned` (parts forwarded unscanned) and, for
inline images with a readable header, `media_images`: `[width, height,
decoded_bytes]` for at most 16 of them, with `media_images_truncated: true`
beyond. The kind comes from the part type, the declared MIME type, the file name
and the first bytes; when they disagree it is `other`. shim never fetches a URL
or a file id.

A request whose media is forwarded is sized by its parts, not its base64: its
text by bytes, an image with a readable header at what its provider bills for the
model (read 2026-10-14: Claude its 28 px tiles after its own resize; OpenAI's tile
families a base plus a price per 512 px tile, `gpt-4o-mini` 2,833 + 5,667; its patch
families their 32 px patches times 1.2, or 1.62 for `gpt-4.1-mini`), elsewhere
`ceil(width / 28) × ceil(height / 28)` tokens up to 4,784, another image 1,600, an inline PDF 3,000
per page object found (up to 1,000 pages, else its decoded bytes / 4), a PDF by URL
or file id 30,000, a Word or text file its decoded bytes / 4, all parts together
at most the model's context window; audio, video and other parts stay measured
by their bytes. The rate limits and the reservation use this estimate; a document
shim reads adds its text's UTF-8 bytes to the spend reservation once read. The
provider's reported tokens still settle the request. A `max_input_bytes` request
limit always measures the body as sent.

Image metadata (EXIF with GPS, XMP, JPEG comments) is a known gap: on an image that
is forwarded as it came it is neither scanned nor removed; only a downscaled image
loses it.

PDF, Word and text files can be read and checked like message text instead. Install
the extra for PDFs (`pip install 'shim-gateway[documents]'`, which adds pypdf; the
community and enterprise images have it; the gateway logs a warning at start when
the setting is on without it), then set `SHIM_DOCUMENTS`:

| `SHIM_DOCUMENTS` | An inline PDF, `.docx`, or text file (`text/plain`, `text/markdown`, `text/csv`, `application/json`) |
| --- | --- |
| `as_media` (default) | Follows `SHIM_MEDIA_INPUTS`, as above. |
| `scan` | Its text is read and scanned with the same actions and rules as message text. Nothing to mask: it is forwarded as it came, except that a PDF goes as its scanned text while any type masks or blocks or a rule hides values (a provider reads a PDF's drawn pages, which hold images and appearances no scan saw). A value to mask: 400 `PII_BLOCKED` (`SECRET_BLOCKED` for `SECRET` and `DB_URI`) naming the types and saying to turn on conversion; no provider call. A type whose action is `block`: refused as for message text. |
| `scan_and_convert` | The same, except that a document with a value to mask is sent as its masked text, and the answer gets the values back. |

A document shim cannot read (a URL or file id, a PDF without pypdf, an encrypted or
corrupt file, a PDF without a text layer, over 32 MB decoded, 1,000 pages, 1,000,000
characters, 4,000,000 characters in one request, a page stream over 4 MB decoded, or
10 seconds of reading a file and 20 seconds for the request's whole scan) is refused
with 400 `DOCUMENT_UNSCANNABLE` naming the reason while media is refused, and
forwarded unscanned otherwise. A PDF is read with its form field values,
annotation texts and document information, in one of two worker processes with 1 GB
of memory each, so a hostile file never holds the gateway. Two more files may wait
for a worker; a fifth at the same moment counts as `too_slow`, as does a file whose
worker was stopped for another file's timeout. Word files are read from
their body, headers, footers, notes, comments, deleted text, glossary and document
properties (author, title, custom properties); a `.docx` with more than 1,000 parts,
a part over 20 MB or 50 MB in all, more than 1,000,000 XML elements, or a DTD in any
encoding is not read.

`SHIM_DOCUMENT_FORMAT=by_provider` also sends a clean document as text where the
provider bills that less: PDFs as text to Anthropic and OpenAI, natively to Gemini
(which does not bill the embedded text, so its pages reach the model unscanned even
while values are masked), Word files as text everywhere. A document in a Gemini
function response stays a file: a clean one is sent as it came, one with a value to
mask is refused with 400 `PII_BLOCKED`. A converted
document loses its layout, images and figures; the model reads its text only. A
document sent as text becomes, in Anthropic, a `document` with a `text` source (title,
context, citations and cache control kept); in chat a `text` part and in Responses an
`input_text` part, each starting `[document: <file name>]`; in Gemini a `text` part.
The usage event carries `documents` (scanned, converted, native, unscannable by
reason) and `document_entities`, and each conversion adds a `document_text` entry to
`transforms_applied`.

## Read errors and retry

Tell a refusal shim made from one the provider made, and retry only when a retry can succeed.
shim never retries on its own; only an enterprise tenant's rule can add a second
attempt, and then the answer carries `X-Shim-Attempts` and the request id of the
attempt that served it.

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
| An agent task reached `SHIM_TASK_MAX_CALLS` calls, or its recorded cost reached `SHIM_TASK_MAX_COST_USD`, within `SHIM_TASK_WINDOW_SECONDS` | 429 `TASK_LIMIT_EXCEEDED`; the message names the cap | `x-should-retry: false`: start a new task or raise the cap |
| With `SHIM_AGENT_LOOP=block`, the same tool call repeated more than `SHIM_AGENT_LOOP_REPEATS` times in one task within `LOOP_WINDOW_SECONDS` | 429 `AGENT_LOOP_DETECTED` | `x-should-retry: false`: change the agent's step |
| With `SHIM_CONCURRENCY_TOKEN_LIMIT` set, the provider target already runs that many tokens of requests and none ended within `SHIM_CONCURRENCY_MAX_WAIT_MS` | 429 `CONCURRENCY_LIMITED` | `Retry-After: 5` |
| Provider answered 429 | 429 `PROVIDER_RATE_LIMITED` | the provider's `retry-after`, when it sent seconds or an HTTP date |
| Provider refused the request (400, 403, 404, 413, 422) | the provider's status, `PROVIDER_REJECTED_REQUEST`; for 400, 404, 413 and 422 the message is the provider's own | none: correct the request |
| Provider refused the provider key (401), or Entra ID refused the configured client credential | 401 `INVALID_PROVIDER_CREDENTIAL` | none: correct the provider key |
| Azure's content filter refused the prompt | 400 `PROVIDER_CONTENT_FILTERED`; the message names the categories | none: change the prompt; sending it unchanged fails again |
| A Bedrock deployment's inference profile leaves the regions the tenant allows (enterprise) | `BEDROCK_REGION_NOT_ALLOWED` | none: use a deployment inside the allowed regions |
| The provider SDK refused the request before sending it | 400 `INVALID_REQUEST` | none: correct the request |
| A string holds an unpaired UTF-16 surrogate (`"\ud800"` in the JSON), before privacy reads it | 400 `INVALID_REQUEST` | none: correct the request |
| Provider answered another error | the provider's status, `PROVIDER_TIMEOUT` for a timeout status, otherwise `PROVIDER_UNAVAILABLE` | none from shim |
| Provider call timed out | 504 `PROVIDER_TIMEOUT` | none from shim |
| Provider unreachable, or its circuit is open | 503 `PROVIDER_UNAVAILABLE` | none from shim |
| Body over `MAX_REQUEST_BODY_SIZE` (default 32,000,000 bytes) | 413 `REQUEST_TOO_LARGE` | none |
| With any entity type on or a tenant rule in scope, the request's distinct strings (keys included, inline file data not) are over 4,000,000 characters or 50,000 strings | 413 `PRIVACY_SCAN_TOO_LARGE` before any is scanned; the message names both counts, `error.param` the limit (`characters` or `texts`) | none: send less text, or split it |
| The privacy scan, message text and documents together, has not finished 20 seconds after the privacy stage received the request (time waiting for a scanning thread counts) | 413 `PRIVACY_SCAN_TIMEOUT`, at most one 16,384-character window of scanning past the 20 seconds; no provider call | none: send less text, or split it |
| A detected type whose action is `block` | 400 `SECRET_BLOCKED` (`SECRET`, `DB_URI`) or `PII_BLOCKED` | none: remove the value the message names |
| With `SHIM_DOCUMENTS=scan`, a document holds a value to mask | 400 `PII_BLOCKED` or `SECRET_BLOCKED`; the message names the types | none: remove the values, or turn on `scan_and_convert` |
| With document scanning on, a document cannot be read and media is refused | 400 `DOCUMENT_UNSCANNABLE`; the message names the reason | none: send the document's text instead, or ask the admin |
| An enforced tenant rule blocks (enterprise) | 400 `RULE_BLOCKED`; `X-Shim-Rule-Id` and `error.param` name the rule | none: change the request or ask the tenant admin |
| An enforced tenant rule needs approval (enterprise) | 403 `APPROVAL_REQUIRED`, `X-Shim-Approval-Id`; `APPROVAL_REJECTED` once refused, `APPROVAL_QUEUE_FULL` without an id | `x-should-retry: false`: after approval, send the same request with `X-Shim-Approval-Id` |
| The approval store cannot be reached (enterprise) | 503 `APPROVAL_UNAVAILABLE` | `Retry-After: 5` |
| The input certainly does not fit the model's context window or input limit | 400 `MODEL_CONTEXT_EXCEEDED` | none: shorten the input or lower the output limit |
| The catalog says the model lacks tools, structured output or an input modality the request uses | 400 `MODEL_CAPABILITY_UNSUPPORTED` | none: remove what the message names or change model |
| The model is not in the catalog, or its id is longer than 200 characters or has a character other than letters, digits, `.`, `_`, `:` and `-` | 400 `MODEL_NOT_PRICED`; enterprise, 403 `MODEL_NOT_REGISTERED` | none: use a model `GET /v1/models` lists |

In OpenAI-shaped bodies, `error.param` names which limit refused: `requests`,
`tokens` or `repeated_requests`.

Notes:

- Approximate tokens are the request body's compact JSON size in bytes divided
  by four, rounded up; forwarded images and files count as estimated tokens
  instead (see [choose what happens to each data type](#choose-what-happens-to-each-data-type)). A refused amount is not added to the window that refused it,
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
- Agent tasks. A request names its task with `X-Shim-Task-Id` (or the incoming
  `traceparent`, see [observe the gateway](#observe-the-gateway)). Task caps are off
  until set: `SHIM_TASK_MAX_CALLS` (1 to 100,000) caps calls exactly;
  `SHIM_TASK_MAX_COST_USD` (more than 0, at most 100,000) stops the next call once
  the task's settled cost of priced requests has reached it, so one admitted call can
  cross it, concurrent calls can each pass before any cost lands, and unpriced
  requests add nothing; `SHIM_TASK_WINDOW_SECONDS` (60 to 86,400, default 3600)
  is how long a task's counters live from its first call. A request without a task
  id is never capped, and a call the quota refuses is given back to its task. Task caps are advisory: the caller names its task, so a
  caller that rotates or omits its task id is not capped; use key and team limits
  for a hard bound. Counters live in the process; when it is full, expired tasks
  go first, then the least recently used. The loop signal is on by
  default: `SHIM_AGENT_LOOP=count` digests the latest assistant turn's tool calls in
  the request's history (name and canonical arguments, never the text; a latest
  turn that only answers has none) and counts them per task
  (else per key) within `LOOP_WINDOW_SECONDS`; the usage event's
  `tool_call_repeats` shows the count, `task_calls` the task's calls after this one,
  and at `SHIM_AGENT_LOOP_REPEATS` (3 to 100, default 5) the `task.agent_loop`
  verdict reads `AGENT_LOOP_SUSPECTED`. `block` refuses above the threshold; `off`
  computes nothing. An agent loop grows its history every turn, so the exact-repeat
  limit above never catches it.
- Identical requests in flight. A request whose body, provider, protocol, model
  and stream flag match a request of the same tenant that is still in flight
  carries that request's id in `inflight_duplicate_of`
  (`shim_inflight_duplicates_total{shared}` counts them). Identical means the same
  bytes: a client that sends the same fields in another order sends another
  request. Nothing else changes unless you set `SHIM_INFLIGHT_SHARING=on`; then a
  JSON chat, Anthropic messages or Gemini `generateContent` request of the same key
  waits for the first one's answer and returns the same body bytes with its own
  `X-Shim-Request-Id` and `X-Shim-Latency-Ms`, without a provider call of its own.
  It still passes its own rate limits, repeat check and privacy first. Never shared:
  streams, Responses (provider-side conversation state), token counts, `n` above 1
  or Gemini `candidateCount` above 1, an explicit `temperature` above 0, and other
  keys. If the first request fails or is cancelled, the second calls the provider
  itself, once; so does one that arrives after the first one's answer is in, while
  it is still finishing. Its usage event reads 0 tokens and cost `"0"`, and `inflight_share`
  holds `leader_request_id`, the shared answer's `prompt_tokens` and
  `completion_tokens`, and `avoided_cost_usd` at its own price; the first request's
  event carries the provider call and its cost, so the events add up to the
  provider bill. The shared answer is scanned and analysed once, on the first
  request's event. Nothing is kept after the first request ends: this is not a
  cache. The registry lives in the process (at most 10,000 requests, 900 seconds
  each), so a duplicate on another replica is not seen.
- After five provider failures with no success in between, the provider's
  circuit opens for 60 seconds. A provider 429 neither opens nor closes it.
- The per-IP limit counts the connecting address. Behind a proxy, list the
  proxy's IP addresses (not ranges) in `TRUSTED_PROXIES`, comma-separated or as a
  JSON list. shim then takes the client from `cf-connecting-ip`, `x-real-ip`, or
  the right-most untrusted `x-forwarded-for` entry.
- Work in flight. `SHIM_CONCURRENCY_TOKEN_LIMIT` (1 to 100,000,000, unset by default)
  caps the tokens of requests one provider target runs at once in this process, a
  request counting its approximate input tokens plus its output limit. A request that
  does not fit waits up to `SHIM_CONCURRENCY_MAX_WAIT_MS` (0 to 60,000, default 0), in
  arrival order, then answers 429 `CONCURRENCY_LIMITED` with `Retry-After: 5`. A
  request larger than the whole limit runs when nothing else is in flight. The usage
  event's `queue_wait_ms` says how long a request waited (0 when admitted at once);
  `shim_concurrency_admissions_total{outcome}` counts `immediate`, `after_wait` and
  `refused`. Replicas do not share the count.

## Read warnings

Learn when a request costs more than it seems, or may not fit, without being refused.

1. Read `X-Shim-Warnings`, a comma-separated list of codes, on the response.
   Browsers may read it. A stream carries only the codes known before it
   starts; the usage event's `warnings` lists them all.
2. Decide from the table.

| Code | When | What to do |
| --- | --- | --- |
| `MODEL_DEPRECATED` | The catalog marks the model deprecated. It is still served. | Move to a current model before the provider retires it. |
| `MODEL_RETIRING` | The provider has announced the model's retirement within 90 days. The request goes ahead. | Move to the replacement the provider names before the date. |
| `MODEL_RETIRED` | The model's retirement date has passed. The request is still sent; the provider answers with its own error, passed on as usual. | Move to the replacement. |
| `CONTEXT_MAY_EXCEED` | The request's approximate size (bytes / 4, plus the output limit where it counts against the window) is above the context window of the model's own catalog entry, but not certainly. | Count tokens (`/v1/messages/count_tokens`, which is never refused) or shorten the input. |
| `PRICE_TIER_CROSSED` | `SHIM_PRICE_TIER_WARNING=on` and the request's approximate size (bytes / 4) is above the model's large-context price threshold, so the whole request may be priced at the higher tier. Known before the call, so streams carry it too. | Shorten the input, or count tokens first; the settled tokens still decide the price. |
| `LARGE_CONTEXT_PRICE` | The settled input is above the model's large-context price threshold; the whole request is priced at the higher tier. | Keep the input under the threshold the catalog lists. |
| `CACHE_NOT_APPLIED` | An Anthropic request had `cache_control` but the usage shows no cache write and no cache read; Anthropic returns no error for this. | Make the cached prefix longer than the model's minimum cacheable length. |
| `RULE_WARN` | An enforced tenant rule with action `warn` matched (enterprise); the request went ahead unchanged. | Read the rule with your tenant admin; the request list shows which one. |
| `INJECTION_MARKERS` | `SHIM_INJECTION_MARKERS=warn` and a tool result or document in the request carries an instruction marker; the request went ahead unchanged. | Check where the tool's text came from before the model acts on it. |

`PRICE_TIER_CROSSED` is off by default; set `SHIM_PRICE_TIER_WARNING=on` (or `off`)
and restart the gateway. Catalog models with a tier: Gemini 2.5 Pro and 3.1 Pro
preview above 200,000 tokens, OpenAI gpt-5.4 and later above 272,000; Anthropic
models have none. It is never added to a token count, and a request warned before
the call and confirmed after it carries both codes.

`MODEL_RETIRING` and `MODEL_RETIRED` are always written to the usage event's
`warnings`; they reach `X-Shim-Warnings` (JSON and streams) only with
`SHIM_MODEL_RETIRING_WARNING=header` (default `record`), so default responses keep
their headers. The dates come from `src/shim/billing/model_lifecycle.json`, filled
from the providers' deprecation pages (OpenAI, Anthropic, Google publish no API for
this) and reviewed like the price catalog; each entry names its `source` and when it
was `checked_on`. An entry covers its own name and longer dated names, but never a
name the catalog prices as a model of its own: a retiring `gpt-4` does not warn
`gpt-4.1`. An undated alias retires with its dated snapshots when every snapshot
the catalog lists for it retires, on the last of their dates: `claude-sonnet-4-5`
warns with `claude-sonnet-4-5-20250929`, while `gpt-4o` does not warn for
`gpt-4o-2024-05-13` alone, since it may point at a later snapshot. Point `SHIM_MODEL_LIFECYCLE_FILE` at a file
of the same format to add or override dates; there a provider key may also be
`registry`, with deployment aliases as model names. A malformed file stops the
gateway at startup with the setting named. shim never refuses, reroutes or
substitutes a model because of a date.

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

## Count instructions hidden in tool results

Learn when a web page, a ticket or a document your agent passed back to the model
carries instructions of its own, without blocking or changing anything.

1. Set `SHIM_INJECTION_MARKERS` to `count` or `warn` and restart the gateway. It
   is `off` by default, and `off` scans nothing.
2. Read `injection_markers` in the usage event: per marker, how many tool results
   or documents in the request carried it, `{}` when none did. With `warn`, a
   request that carries one also gets `INJECTION_MARKERS` in `X-Shim-Warnings`,
   on JSON answers and on streams alike.

```json
{"version":4,"event":"request","request_id":"req_…","injection_markers":{"INSTRUCTION_OVERRIDE":1},"warnings":["INJECTION_MARKERS"]}
```

The markers are those shim-cli flags, in English and Turkish, typed with or
without Turkish letters: `INSTRUCTION_OVERRIDE` ("ignore all previous
instructions", "önceki tüm talimatları yok say"; only an order, so "kuralları yok
saydık" is not one), `ROLE_REASSIGNMENT` ("you are now", "bundan sonra sen
yöneticisin"), `SYSTEM_IMPERSONATION` (a `[sistem]` line, or a `System:` line
that goes on as a sentence, so YAML `system: production` and a `## System:
overview` heading are not one; `<important_instructions>`), `SECRECY_REQUEST`
("do not tell the user", "kullanıcıya söyleme") and `HIDDEN_TEXT` (zero-width
characters, bidi controls and Unicode tag characters, read before anything is
removed). A phrase may run across a line break; only a full stop ends it. Text
under 24 characters is skipped, and each tool result or document is read up to
its first 1,000,000 characters.

What is read: Chat `tool` and `function` messages; Responses
`function_call_output`, `custom_tool_call_output` and `mcp_call` outputs; Anthropic
`tool_result` (with any `document` inside it), `search_result` and text
`document` blocks; Gemini
`functionResponse.response`. What you type, system prompts, answers and images are
never read: they are your own instructions. Nothing is ever blocked, rewritten or
said to the model; a scan that fails records `{"error": true}` and the request
goes on. The scan runs on the same worker thread as the privacy scan.
`shim_injection_markers_total{marker}` counts the tool results and documents per
marker. Enterprise sets it per tenant as the `injection_markers` gateway setting.

## Analyse answers after delivery

Have named analyzers read each completed answer after it reached the caller and
record what they measured, never what was written.

1. Set `SHIM_RESPONSE_ANALYSIS` to a comma-separated list (or a JSON list) of
   analyzer names and restart the gateway. It is empty by default, and an empty
   list keeps nothing and adds no work.
2. Read the `response_analysis` line written after each completed request's
   `request` line (and after its `response_privacy` line when the scan is on):

```json
{"version":4,"event":"response_analysis","request_id":"req_…","results":{"<name>":{…},"versions":{"<name>":"1"}}}
```

Analyzers run in the order shim defines, after the last byte of a JSON answer or
after a stream ended, in one background task shared with
`PII_RESPONSE_SCAN=count`; the answer, its first token and its timing are
unchanged. They see the masked request and up to 1,000,000 characters of the
answer text and its tool calls. The answer text is the same for a JSON answer
and a stream: the text the model wrote, without refusal fields, reasoning,
Gemini thought parts or tool-call arguments, which come as separate calls. An
analyzer that reads the answer (`language`, `schema`, `refusal`) does not run
for a request that carried personal data, that is any detected value, masked or
monitored: nothing derived from such an answer is recorded. `shape` reads only
the masked request and still runs. The answer is extracted and, for a stream,
kept only while an analyzer that reads it runs. Results hold counts, labels,
ids, protocol field names and JSON pointers, never request or answer text and
never a restored value. An analyzer that fails, or returns anything but a JSON object, records
`{"error": true}`. A result larger than 4,096 characters keeps its counts and
digests and records its lists as `null`; one still larger records
`{"error": true, "reason": "too_large"}`. The others still run either way. A run
checks a one-second budget before each analyzer, and one it no longer starts
records `{"error": true, "reason": "timeout"}`. A request that failed or was
refused gets no analysis.

Notes: an unknown name stops the gateway at start-up with the setting and the
name in the message; a repeated name is dropped. Analysis has a worker thread of
its own with room for 64 pending requests; a request beyond that is not
analysed. The response scan has its own thread and the same bound; a scan it
cannot take writes `"response_entities": null, "error": true`.
`shim_response_analysis_total{analyzer, result}` counts the runs as `ok`,
`none`, `error` or `dropped`.

| Analyzer | What it records |
| --- | --- |
| `shape` | What the request is made of, to find oversized parts, tools no one calls and tool order that defeats the provider's prompt cache. Sizes are characters of the request as the provider saw it: where an entity type masks, a detected value counts as its placeholder; under `monitor` or `off` the value counts as written. `message_count`, `system_chars`, `history_chars` (every turn before the final one, tool results included, so an agent loop measures the same in every protocol), `last_user_chars`, `largest_part_chars`, `tool_result_count`, `tool_result_chars`, `largest_tool_result_chars`, `tool_count`, `tool_definition_chars` (the compact JSON of `tools`), `tools_offered` (names in the order sent; built-in tools as `builtin:<type>`; a name is kept only as 1 to 64 of `A-Za-z0-9_.:-`, others are dropped and counted in `tool_names_dropped`), `tools_called_in_history` (calls replayed in the request), `tools_order_digest` and `tools_set_digest` (16 hex characters of sha256 over the names in order, and sorted: the same set in a new order changes only the first), `image_count`, `document_count` (images and documents inside tool results too; a text document's characters count as text), `largest_image` (`bytes`, `width`, `height` of the largest inline image, read from its header; a data URL that is not base64 counts its characters) and `truncated`. Tool names are recorded in clear; tool definitions are never stored. At most 128 tool names, 20,000 parts and 64 levels of nesting are read; beyond them `truncated` is true. A request offering many long tool names can exceed the 4,096-character result bound; then `tools_offered` and `tools_called_in_history` are `null` and the counts and digests stay. |
| `language` | Whether the last user question and the answer are Turkish or English, to spot a Turkish question answered in English: `request` and `answer`, each `tr`, `en`, `other` or `unknown`, `answer_mixed`, and `request_words` and `answer_words`. A word and letter heuristic, no model: Turkish letters (`ğ`, `ı`, `ş` count most) and about 200 Turkish and 180 English function words, matched with and without Turkish letters, so `cok guzel, yardim eder misin` is Turkish. The first 4,000 characters are read, without code blocks, inline code, URLs, e-mail addresses and placeholders. Fewer than 3 words or 12 letters is `unknown`; text mostly in other scripts, or in another Latin language, is `other`. English needs at least 2 English function words and at least a fifth of the words, so a long Dutch or Italian text with a few English-looking words stays `other`; Turkish needs a Turkish letter or 2 Turkish function words. When only one side qualifies, that side is the label; when both do, the larger, mixed when the smaller scores at least 0.3 of it. The answer is `unknown` when the request asked for JSON output or the answer has no text. It knows Turkish and English only: Azerbaijani can read as Turkish, two Turkish names in a short English sentence can mark it mixed, and a short ASCII-typed Turkish sentence with no listed word (`Hesabima neden para yatmadi bilmiyorum`) is `other`. |
| `schema` | Whether the answer, or each tool call, matches the schema the request asked for; see [Check structured output](#check-structured-output). |
| `refusal` | Whether a complete answer refuses in words, for answers a provider ended normally: `soft_refusal` and the `marker` id (`tr.yardimci_olamam`, `en.cant_help`, ...). It reads the first 200 characters of answers up to 1,500 characters, Turkish with or without its letters, for seven groups of phrases (`yardımcı olamam`, `bu isteği yerine getiremem`, `I can't help with`, `I'm sorry, but I can't`, ...). A phrase counts only as whole words (`yapamamanız` is not `yapamam`). It does not count after an open quote on its line (an odd number of `"` or of `'` that are not apostrophes), when followed within 60 characters by `but here`, `so here`, `instead`, `bunun yerine` or `ama`/`ancak` with an offer (`şu`, `şunu`, `şunları`), or when reported speech follows it directly (`diye`, `dedi`, `dediğim`), so a quoted refusal or a partial answer is not one. A refusal discussed without quote marks is still counted: a known gap. It runs only when `completion_outcome` is `complete`; a provider's own refusal stays `refused` there, and this result never changes that field. |

## Check structured output

Learn how often answers and tool calls miss the format your app asked for,
including on providers and local models that do not enforce it.

1. Add `schema` to `SHIM_RESPONSE_ANALYSIS` and restart the gateway.
2. Read `response_analysis.schema` in the `response_analysis` line: `expected`
   (`json_schema`, `json_object`, `tool_args` or `none`), `valid` (`true`,
   `false`, or `null` when it could not be decided), `error_path` (a JSON
   Pointer into the answer, `/count` or `/tool_calls/1/count`), `error_keyword`
   (`type`, `required`, `enum`, `parse`, `unknown_tool`, ...), `error_tool`,
   `unsupported` and `unsupported_keywords`, `strict` (whether the provider was
   asked to enforce the schema itself) and `reason`.

What is read: OpenAI `response_format` and Responses `text.format`
(`json_schema` or `json_object`), Anthropic `output_config.format` and
`output_format`, Gemini `responseJsonSchema`, `responseSchema` (OpenAPI types)
and `responseMimeType: application/json` (another type, such as `text/x.enum`,
is not JSON and is not checked), and each offered tool's parameters, Chat's
legacy `functions` included. With tool calls in the answer, every call is
checked against its tool; a call to a tool that was not offered is
`unknown_tool`, with `error_tool` set only when the name is one a provider
would accept, and a built-in tool's call is skipped. A detected value inside an
`enum` or `const` (e-mail addresses) is restored before the check, as the
answer was; property names and `required` entries stay masked.

shim checks a subset of JSON Schema, with no dependency: `type`, `enum`,
`const`, `properties`, `required`, `additionalProperties`, `minProperties`,
`maxProperties`, `items`, `prefixItems`, `minItems`, `maxItems`, `uniqueItems`,
`minLength`, `maxLength`, `minimum`, `maximum`, `exclusiveMinimum`,
`exclusiveMaximum`, `multipleOf`, `allOf`, `anyOf`, `oneOf` and `$ref` within
the document. Any other keyword, `pattern` included, is listed in
`unsupported_keywords` (a keyword outside JSON Schema's own vocabulary is
listed as `unknown`, so no schema text is recorded) and makes `valid` `null` instead of guessing; `pattern`
is never run, so a tenant's expression cannot stall the gateway. `valid` is
`null` with a `reason` when the answer was truncated (`truncated`), refused,
filtered or empty, when the answer or the schema is too large (`too_large`),
when nesting or `$ref` chains pass 32 levels (`depth`) or 10,000 values
(`nodes`), and when the schema itself is broken (`bad_schema`). The answer is
never changed, retried or refused; the check runs after it was delivered.
`error_path` names schema properties and array indices only, never a value or
an unexpected key (that path ends in `/*`).

## Use the provider's cache discount

Let a repeated prompt prefix be billed at the provider's cache-read rate, without
changing your application.

1. For Anthropic, set `SHIM_ANTHROPIC_AUTO_CACHE=5m` (or `1h`). A messages request
   that carries no `cache_control` anywhere (top level, `system`, `tools`, message
   content, content inside a `tool_result`) gets a top-level
   `"cache_control": {"type": "ephemeral"}` (`"ttl": "1h"` with `1h`); Anthropic
   places that breakpoint on the last cacheable block and moves it as the
   conversation grows. The same marker goes on the last `system` block (a string
   `system` becomes one text block), so independent requests that share a system
   prompt read it back instead of each writing their own entry: two of Anthropic's
   four breakpoints. A request with your own breakpoints is sent as it is.
2. For OpenAI, set `SHIM_OPENAI_PROMPT_CACHE_KEY=key` (one routing key per shim key)
   or `tenant` (shared by every key). A chat or Responses request without a
   `prompt_cache_key` gets `shim-` and 32 hex characters, derived from the scope,
   the model and the request's leading `system` and `developer` messages (and
   Responses `instructions`) and `tools`, so requests with the same prefix share
   a key and different prefixes do not. The value says nothing the prompt does
   not; `prompt_cache_retention` is never set.
3. Read `cache_read_tokens` and `cache_write_tokens` on the usage event; its
   `settings_applied` lists `anthropic_auto_cache` or `openai_prompt_cache_key` when
   the step changed the request.

Notes: Anthropic bills a cache write at 1.25 times the input price (2 times for
`1h`) and a read at 0.1 times, so a prompt sent once above the model's minimum
cacheable length (512 to 4,096 tokens) costs more, and a repeated one less; a
shorter prompt is not cached and costs no write. With random placeholders
(`PII_PLACEHOLDER_MODE=random`, the default) a request that masked a value
changes on every send, so the Anthropic step leaves it alone; set
`PII_PLACEHOLDER_MODE=stable` to cache such prompts. OpenAI caches automatically
above 1,024 tokens and the key only steers routing; it guarantees no hit.
`CACHE_NOT_APPLIED` is raised only for breakpoints you placed. Gemini requests and
token counting are never changed. Leave these settings, and those of the next two
recipes, off when
`ANTHROPIC_BASE_URL` or `OPENAI_BASE_URL` points at something other than the
provider: another server may refuse a parameter it does not know.

## Load tools on demand

Let the model open only the tool definitions it needs, through the provider's own
tool search, for apps that send answers back unchanged.

1. Set `SHIM_TOOL_SEARCH=regex` (or `bm25`), and `SHIM_TOOL_SEARCH_MIN_TOOLS` (2 to
   10,000, default 10) for the fewest tools a request must offer.
2. Name tools that stay loaded in `SHIM_TOOL_SEARCH_KEEP_LOADED` (comma-separated or
   a JSON list, at most 64 names).

A messages request to Claude Opus, Sonnet or Haiku 4.5 or later, a 5.x model, Fable
or Mythos, or a Responses request to GPT-5.4 or later, offering at least the minimum
of its own function tools, gets `"defer_loading": true` on every such tool except the
kept ones, the tool `tool_choice` forces, the tools an `allowed_tools` choice names,
Anthropic tools carrying `cache_control`, and, when nothing else would stay loaded,
the first tool. One search tool is appended: `tool_search_tool_regex_20251119` or
`tool_search_tool_bm25_20251119` for Anthropic, `{"type": "tool_search"}` for
OpenAI. Every definition is still sent, in its order; the same tools give the same
bytes on every turn, so the prompt cache holds.

Notes: the model may answer with a search step first (`server_tool_use` and
`tool_search_tool_result` blocks, or `tool_search_call` and `tool_search_output`
items); shim returns them as the provider sent them, and your app must keep them in
its history, as the provider SDKs' agent loops do. An app that drops unknown blocks
can fail on its next request: try one app first (enterprise scopes the setting by
key). A request is left alone, with a `settings.tool_search` verdict saying why, when
the model is older (`SETTING_MODEL_UNSUPPORTED`), the client already sends a search
tool or a `defer_loading` (`SETTING_CLIENT_OWNED`), or an Anthropic request has
thinking on or thinking blocks in its history (`SETTING_THINKING_BOUND`: changing
tools mid-conversation invalidates earlier thinking). Server tools, MCP toolsets and
namespaces are never deferred. Turning the setting on or off changes the tool
prefix once per conversation, one cache write.

## Stop paying for old thinking

Stop earlier turns' thinking from being billed as input again on every turn.

1. For Anthropic, set `SHIM_ANTHROPIC_KEEP_THINKING_TURNS` to the thinking turns to
   keep (1 to 8; 0 is off). A messages request with `thinking.type` `enabled` or
   `adaptive` and no `context_management` of its own gets
   `"context_management": {"edits": [{"type": "clear_thinking_20251015", "keep":
   {"type": "thinking_turns", "value": N}}]}`, sent on Anthropic's beta API with
   `anthropic-beta: context-management-2025-06-27` after any flags your client sends.
   The answer's `context_management.applied_edits` says what was cleared.
2. For OpenAI, set `SHIM_OPENAI_REASONING_CONTEXT=current_turn`. A Responses request
   to the GPT-5.6 family or later without `reasoning.context` gets
   `"reasoning": {"context": "current_turn"}`; earlier models already default to it.

Notes: when thinking blocks are cleared, Anthropic rewrites the prompt cache from the
cleared block onward on each turn that clears one, so the saving is the old thinking
minus that write. Not rendering earlier reasoning can change OpenAI answer quality.
Tool results are never cleared (`clear_tool_uses` is not offered), and neither
setting touches chat completions, Gemini (its thought blocks and signatures pass as
sent) or token counting. A client's own `context_management` or `reasoning.context`
wins, with a `SETTING_CLIENT_OWNED` verdict. With both settings off, Anthropic models
that keep earlier thinking keep billing it as input, as `prompt_tokens` show.

## Shrink JSON tool results

Send pretty-printed JSON your tools return without its indentation, so every later
turn that resends the history pays for fewer input tokens.

1. Set `SHIM_JSON_COMPACTION=on`.
2. Read `transforms_applied` on the usage event: `{"id": "json_compaction",
   "version": 1, "before_chars", "after_chars", "items"}` when a tool result changed,
   `[]` when the band ran and nothing qualified.

Only tool results are read: chat `role: "tool"` content (a string, or `text` parts),
Responses `function_call_output` output (a string, or `input_text` parts), Anthropic
`tool_result` content (a string, or `text` blocks), and every string inside a Gemini
`functionResponse.response`. A string changes only when it is a whole JSON object or
array of 64 to 1,000,000 characters with space, tab, CR or LF between tokens: those
characters are dropped and everything else, string contents, number literals such as
`1.10` and duplicate keys included, is copied byte for byte, and the result is kept
only when it parses to the same value and is shorter. System, user and assistant
text, tool call arguments, tool definitions and documents are never changed, nor are
embeddings requests, nor is token counting, which counts the request as you sent it.

Notes: the same input always gives the same output, so from the first request with
the setting on the provider's prompt cache holds; on the request where the setting
flips, a conversation in progress sends its earlier tool results in the other form
once, writing the cache again from the first one. An Anthropic request with thinking
on, or with thinking blocks in its history, is left alone (a
`transforms.json_compaction` `skip` verdict, `TRANSFORM_THINKING_BOUND`): changing an
earlier turn invalidates every later thinking block. A Responses request that carries
a `reasoning` input item (encrypted reasoning replayed by the client) is left alone
the same way. Claude Code users get the same
compaction at the source from shim-cli. Tool results over 65,536 characters in total
are compacted off the event loop. `shim_transforms_total{transform, result}` counts
the step per request.

## Read images at a cheaper detail level

Let OpenAI and Gemini 3 read images at a level that costs fewer image tokens, where your
app did not choose one. It needs images to pass (`SHIM_MEDIA_INPUTS=allow`, or a
gateway that masks nothing but Turkish names by default; see [choose what happens to each data type](#choose-what-happens-to-each-data-type)).

1. Set `SHIM_IMAGE_DETAIL_OPENAI` to `low` or `high` and `SHIM_IMAGE_DETAIL_GEMINI` to
   `low` or `medium` (both `off` by default).
2. Optionally name the models it applies to in `SHIM_IMAGE_DETAIL_MODELS`
   (comma-separated, at most 100, as your app sends them; empty is every model).

A chat `image_url` part without `detail` (or with `"auto"`) gets `detail` set, and so does
a Responses `input_image`; a Gemini 3 image part gets `"mediaResolution": {"level":
"MEDIA_RESOLUTION_LOW"}` (or `_MEDIUM`). A level is set only where the provider's own
table says it lowers the model's default image budget (read 2026-10-08):

| Model family | Default | Levels that lower it |
| --- | --- | --- |
| `gpt-4o`, `gpt-4o-mini`, `gpt-4.1`, `gpt-5.1` | 512 px tiles | `low` |
| `gpt-4.1-mini`, `gpt-5.2` | the same patches at every level | none |
| `gpt-5.4`, `gpt-5.4-mini`, `gpt-5.4-nano` | as `high`; `low` allows more patches | none |
| `gpt-5.5`, `gpt-5.6-sol`, `gpt-5.6-terra`, `gpt-5.6-luna`, `gpt-6-astra` | as `original` | `low`, `high` |
| Gemini 3 (`gemini-3*-`) | 1,120 tokens an image | `low` (280), `medium` (560) |

A dated snapshot counts as its family (`gpt-4o-2024-08-06`); any other model is left
alone with a `settings.image_detail` verdict `SETTING_MODEL_UNSUPPORTED`. `gpt-5.4` is
never changed because its `low` can cost more than `high`. Anthropic has no detail
parameter, so its images are never changed. Never changed either: a level your app
set (`SETTING_CLIENT_OWNED`; a Gemini request-wide `generationConfig.mediaResolution`
counts), computer-use screenshots, PDFs and other files, and a Responses request
replaying encrypted reasoning (`SETTING_THINKING_BOUND`). The usage event's
`settings_applied` lists `image_detail` when a part changed.

Notes: a lower level reads the image at lower resolution, which can cost answer
quality for small text in images; try one model first with
`SHIM_IMAGE_DETAIL_MODELS`. The same image gets the same level on every turn, so the
provider's prompt cache holds; changing the setting changes the cached prefix once.
Leave it off when `OPENAI_BASE_URL` points at another server.

## Shrink oversized images

Send images no larger than the size the provider would resize them to anyway, so
requests are smaller and an image the provider refused for its byte size may fit.

1. Install the extra (`pip install 'shim-gateway[images]'`, which adds Pillow; the
   community and enterprise images have it). Without it the gateway logs a warning at start and the
   setting stays off.
2. Set `SHIM_IMAGE_DOWNSCALE=on` (and let images through, see
   [choose what happens to each data type](#choose-what-happens-to-each-data-type)).

An inline PNG, JPEG or static WEBP in an Anthropic messages, chat or Responses request
to a catalog model is reduced to the size the provider's page publishes for that model
and detail level, and re-encoded in its own format: PNG losslessly, JPEG and WEBP at
quality 90; EXIF and other metadata are dropped, an ICC profile is kept, and a result
that is not smaller is discarded. The sizes (read 2026-10-08):

| Provider and model | Size |
| --- | --- |
| Claude before 4.7 | at most 1,568 px long edge and 1,568 tokens of 28 px tiles |
| Claude 4.7 and later | at most 2,576 px and 4,784 tokens |
| `gpt-4o`, `gpt-4o-mini`, `gpt-4.1`, `gpt-5.1`, `high` or no detail | fit 2,048 px, then the short side 768 px |
| `gpt-4.1-mini`, `gpt-5.2` | 2,048 px and 6,144 patches of 32 px |
| `gpt-5.4` family | `low` 2,048 px and 6,144 patches; `high` or none 2,048 px and 2,500; `original` 6,000 px and 10,000 |
| `gpt-5.5` | `low` 512 px; `high` 2,048 px and 2,500 patches; `original` or none 6,000 px and 10,000 |
| `gpt-5.6-sol`, `-terra`, `-luna`, `gpt-6-astra` | `low` 512 px; `high` 2,500 patches (2,048 px except `gpt-6-astra`); otherwise 65,535 px |

The token bill does not change: providers bill image tokens from the size after their
own resize, and this is that size. What it saves is bytes and upload time. Never
touched: Gemini (no published size), images by URL or file id, GIFs and animated
WEBP, images at or below the size, images with an EXIF rotation, in an Anthropic
`tool_result`, marked `transformations.oversized_image: "error"`, computer-use
screenshots, requests bound to thinking (`TRANSFORM_THINKING_BOUND`), token counts,
images over 32 MB or 64 megapixels, images past a request's 128 megapixels decoded
(counted in payload order, `too_large`), and a decode over 10 seconds (`too_slow`). The
usage event's `transforms_applied` gets an
`image_downscale` entry with the sizes and bytes before and after and the images
skipped by reason, also when every image was skipped (`items` 0);
`shim_image_downscale_total{outcome}` counts each image.

Notes: the same image gives the same bytes on every turn, so the provider's prompt
cache holds; a Pillow upgrade changes the output bytes once. Decoding runs in one of
two worker processes shared with PDF reading, at most two at once per gateway process;
a 12-megapixel JPEG takes about 150 ms. Leave it off when
`ANTHROPIC_BASE_URL` or `OPENAI_BASE_URL` points at another server.

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

## See what each lever saved

Learn what the settings you turned on saved on your own traffic, measured apart from
estimated.

A completed request whose lever had a figure carries `savings` on its usage event:

```json
{"version":4,"event":"request","request_id":"req_…","savings":{"version":1,"measured":{"provider_cache":{"usd":"-0.0010000000","read_tokens":0,"write_tokens":4000}}}}
```

| Lever | Measured (saved) | Estimated or not attributed (never add) |
| --- | --- | --- |
| In-flight sharing (`SHIM_INFLIGHT_SHARING`) | `usd`: the provider call the shared answer avoided; `tokens` | the same fields under `estimated` when the first request's usage was estimated, not reported |
| Anthropic breakpoint (`SHIM_ANTHROPIC_AUTO_CACHE`) | `usd`: cache reads at the input rate minus the read rate, less writes above the input rate, at the request's own rates; can be negative | none |
| OpenAI cache key (`SHIM_OPENAI_PROMPT_CACHE_KEY`) | nothing | `not_attributed`: OpenAI caches without the key |
| JSON compaction | `chars` removed | `tokens` at four characters a token, and their `usd` |
| Image downscaling | `bytes` not sent; the token bill is the same | none |
| Clearing old thinking | `tokens` Anthropic reported clearing | `usd`, gross of the cache rewrite clearing causes |

Image detail, tool search, reasoning context and parameter pins have no figure: the
providers report no tokens for them, and `settings_applied` already counts them. Sum
the saved money per lever over a log file:

```console
jq -s '[.[] | select(.event == "request" and .savings.measured) | .savings.measured
  | to_entries[] | select(.value.usd != null) | {lever: .key, usd: (.value.usd | tonumber)}]
  | group_by(.lever) | map({lever: .[0].lever, usd: (map(.usd) | add)})' usage.jsonl
```

Never add `estimated` or `not_attributed` to that sum. A price the gateway does not know
gives `"usd": null, "unpriced": true`. Failed and refused requests saved nothing and
carry no record.

## Observe the gateway

Export traces, logs, error reports and metrics without exporting prompt or response text.

1. Set the settings you need and restart the gateway:

   | Setting | Effect |
   | --- | --- |
   | `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP over HTTP; spans go to `<endpoint>/v1/traces`. Unset means no tracing. |
   | `OTEL_SERVICE_NAME` | `service.name` of the spans, default `shim`. |
   | `SENTRY_DSN` | Error reports only, no performance traces. Request body, URL, query string, cookies and exception messages are stripped. |
   | `LOG_LEVEL` | `DEBUG`, `INFO` (default), `WARNING`, `ERROR` or `CRITICAL`; JSON lines on stdout. |
   | `SHIM_TRACE_PARENT` | `ignore` (default): every request starts a new trace. `honor`: a request carrying a valid W3C `traceparent` (and `tracestate`) becomes a child of the caller's span, so an agent's calls are one trace. The tracer's sampler follows the caller's sampled flag, so an unsampled caller gets no gateway spans. |
   | `SYSTEM_PROMPT_HASH_KEY` | A secret of at least 32 characters. The usage event's `system_prompt_hash` becomes an HMAC of the system and developer instructions, so a changed prompt shows as a changed hash. Unset means `null`. Another installation's key gives other hashes for the same prompt. |

2. Name the agent task a request belongs to with `X-Shim-Task-Id`: up to 128 of
   `A-Za-z0-9._:/-`, starting with a letter or digit. Another value, and ten or more
   digits alone (the shape of a national id or a phone number), is ignored and
   counted in `shim_task_id_rejected_total`, never refused. The task id is recorded
   and exported, so it must never carry personal data. Without it, the trace id
   of a valid incoming `traceparent` is the task id. The usage event records
   `task_id` and `trace_id` (the incoming trace id, also with `ignore`), `null` when
   absent. Neither header is sent to the provider.
3. Read the cost and usage of a settled request from its span attributes:
   `gen_ai.request.model` (`unpriced` for a model without a catalog price),
   `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`,
   `gen_ai.response.finish_reasons`, `shim.cost_usd` and `shim.usage_estimated`.
   Span attributes come from a fixed allow-list. The request span (`gateway.request`)
   also carries `gen_ai.operation.name` (`chat` for Chat, Responses and Messages,
   `generate_content` for Gemini, `embeddings` for OpenAI and Gemini embeddings),
   `gen_ai.provider.name` (`openai`, `anthropic`,
   `gcp.gemini`) and `shim.task_id`, named as the OpenTelemetry GenAI conventions
   at schema `https://opentelemetry.io/schemas/1.44.0`, which the tracer declares.
4. Scrape `GET /metrics` (Prometheus text). It needs no key and is not in the
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
| `shim_injection_markers_total` | `marker` |
| `shim_media_parts_total` | `kind`, `outcome` (`forwarded`, `blocked`) |
| `shim_image_downscale_total` | `outcome` (`downscaled`, `below_threshold`, `not_smaller`, `unsupported`, `client_opt_out`, `unknown_model`, `too_large`, `corrupt`, `thinking_bound`) |
| `shim_documents_total` | `kind`, `outcome` (`scanned`, `converted`, `stopped`, `unscannable`) |
| `shim_transforms_total` | `transform`, `result` (`applied`, `unchanged`, `skipped`) |
| `shim_extra_attempts_total` (enterprise tenant rules only) | `reason`, `outcome` (`started`, `skipped`, `not_admitted`) |
| `shim_shadow_copies_total` (enterprise only) | `outcome` (`sent`, `no_candidate`, `skipped_guard`, `dropped_saturated`, `failed`) |

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
