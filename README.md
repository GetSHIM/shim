<p align="center">
  <a href="https://getshim.tech">
    <img src="https://raw.githubusercontent.com/GetSHIM/shim/main/docs/assets/shim-logo.svg" alt="shim" width="280">
  </a>
</p>

<h1 align="center">shim</h1>

<p align="center">
  <strong>One trust boundary for your AI traffic, without rewriting the payload.</strong><br>
  An OpenAI request leaves as OpenAI, an Anthropic request as Anthropic. shim
  applies privacy, admission, accounting and error policy on the way through.
</p>

<p align="center">
  <a href="https://getshim.tech">Website</a> ·
  <a href="https://getshim.tech/docs">Documentation</a> ·
  <a href="https://getshim.tech/playground">Playground</a> ·
  <a href="https://github.com/GetSHIM/shim-cli">shim-cli</a>
</p>

<p align="center">
  <a href="https://github.com/GetSHIM/shim/actions/workflows/test.yml"><img src="https://github.com/GetSHIM/shim/actions/workflows/test.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.13-blue?logo=python&logoColor=white" alt="Python 3.13">
  <a href="https://github.com/GetSHIM/shim/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green.svg" alt="Apache-2.0"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/GetSHIM/shim"><img src="https://api.scorecard.dev/projects/github.com/GetSHIM/shim/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://www.bestpractices.dev/projects/14372"><img src="https://www.bestpractices.dev/projects/14372/badge" alt="OpenSSF Best Practices"></a>
</p>

> [!NOTE]
> shim is alpha software. Interfaces can still change between releases.
>
> The community gateway under `src/shim` is Apache-2.0 and is what this
> repository is for. The enterprise layer under `ee/` is source-available under
> the Elastic License 2.0, which is not an open-source licence: you can read it,
> and outside contributions to it are not accepted. Tenancy, durable accounting,
> stored audit evidence, roles and budgets live there.

## What it does

One HTTP boundary between your application and the model provider. On every
request it:

- **Detects and replaces personal data before the request leaves.** Email
  addresses, phone numbers, credit cards (Troy included), IBANs, Turkish
  national ID and tax numbers, Turkish licence plates (`34 ABC 123`; not
  `16 GB 512`), provider secrets such as AWS keys and GitHub,
  Google, Slack, Hugging Face and GitLab tokens, and password assignments,
  Turkish (`şifre:`, `parola:`) included. A bare digit run counts as a phone
  number only with a Turkish phone shape or a phone cue such as `Tel:`, so
  order numbers and ids glued to names (`claude-sonnet-4-5-20250929`) stay
  intact. Each detected value becomes a placeholder before the request leaves,
  and is restored in the answer before it reaches your caller.
- **Decides admission.** Requests-per-minute and tokens-per-minute limits, a
  model allow-list taken from the checked-in price catalog, and repeat-loop
  detection. Tokens per minute are counted as approximate tokens (request
  bytes divided by four), a refused request does not use up its own window, and
  every limit refusal says when to retry in `Retry-After`.
- **Accounts usage and cost per request**, from that same catalog, attributed
  by the `X-Shim-Tag` header. In enterprise an API key's assigned cost center
  takes precedence, and header tags remain breakdown dimensions.
- **Sanitizes provider errors**, so a provider error body does not reach your
  caller unchanged.
- **Makes at most one billable provider attempt per admitted request**, because
  outbound SDK retries are disabled.

It does not translate payloads. When a provider ships a new field, a new model,
or changes streaming behaviour, you are not waiting on shim to catch up.

## Quickstart

```console
docker run --rm -p 8000:8000 -e SHIM_API_KEY=a-key-of-at-least-16-chars \
  ghcr.io/getshim/shim:latest
```

The container publishes a port, so it refuses to start without a key. Replace
that value with your own before anything but a local trial.

Ask it what it finds in a prompt. This route calls no provider, so it needs no
provider key:

```console
curl http://localhost:8000/v1/scan \
  -H 'Authorization: Bearer a-key-of-at-least-16-chars' \
  -H 'Content-Type: application/json' \
  -d '{"text":"Customer jane.doe@example.com, IBAN TR33 0006 1005 1978 6457 8413 26"}'
```

```json
{
  "request_id": "scan_73ac33b589af4b82a1430b777a82d493",
  "verdict": "warn",
  "entities": [
    {"type": "EMAIL_ADDRESS", "score": 1.0, "start": 9, "end": 29},
    {"type": "IBAN_CODE", "score": 1.0, "start": 36, "end": 68}
  ],
  "entity_types": ["EMAIL_ADDRESS", "IBAN_CODE"],
  "policy": "warn"
}
```

Then point an existing client at it. No SDK change, only a base URL:

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8000/v1", api_key="a-key-of-at-least-16-chars")
client.chat.completions.create(
    model="gpt-5-nano",
    messages=[{"role": "user", "content": "Email jane.doe@example.com about the invoice"}],
)
```

Gemini works the same way; the shim key goes where the SDK puts its API key:

```python
from google import genai
from google.genai.types import HttpOptions

client = genai.Client(
    api_key="a-key-of-at-least-16-chars",
    http_options=HttpOptions(base_url="http://localhost:8000"),
)
```

Under a masking policy the provider receives placeholders in place of the
detected values, in the form `<EMAIL_ADDRESS_75344f3b9ce7dabdf18cb32cabf22e43>`.
They are generated per request, so the same value gets a different placeholder
next time, and the reply is restored before it reaches your caller.

Provider credentials come from `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` or
`GOOGLE_API_KEY`, or per request through `x-provider-key`. The shim key
authenticates your caller and is never forwarded to a provider. On a keyless
loopback gateway, a Google key also goes in `x-provider-key` or `GOOGLE_API_KEY`,
never in `x-goog-api-key`, which shim reads only as the shim key. The default bind
is loopback; set a `SHIM_API_KEY` of at least 16 characters before binding
anywhere else. A non-streaming request is bounded by the provider read timeout
(`OPENAI_READ_TIMEOUT_SECONDS`, `ANTHROPIC_READ_TIMEOUT_SECONDS`, 600 seconds by
default), so long generations should stream.

Community exposes `/v1/chat/completions`, `/v1/messages`, `/v1/responses`, the
Gemini `generateContent` routes, `/v1/models`, `/v1/scan`, `/health` and
`/metrics`. The checked-in contract is [`openapi/community.json`](openapi/community.json).
OTLP traces, structured logs and Sentry error reports are enabled by
`OTEL_EXPORTER_OTLP_ENDPOINT`, `LOG_LEVEL` and `SENTRY_DSN`; each request's closing
span carries its model, input and output tokens, finish reasons and cost, never
prompt or response text.

To run from source instead, see [the developer guide](DEVELOPER_GUIDE.md).
For customer-operated enterprise installations, see [deployment and recovery](ee/deploy/README.md).

## Limitations

- Detection is best-effort and can miss a sensitive value. shim narrows the
  exposure, it does not remove it.
- In community mode the rate, circuit, privacy-continuation and usage state is
  process-local and bounded. It is not shared across replicas, so limits apply
  per process.
- shim validates the routing, privacy and admission fields of a provider
  payload. The rest of the provider's JSON passes through unvalidated.
- `background=true` Responses requests are not supported.
- Stored audit evidence, retained records, roles and budgets are enterprise
  features. Community keeps no request history.
- SDK compatibility is pinned to `openai==2.53.0` and `anthropic==0.121.0`. A
  new provider SDK does not arrive automatically.
- Community mode needs no PostgreSQL, Redis or Supabase, and runs no workers.
  Anything that depends on those is enterprise.

## Documentation

- [Developer guide](DEVELOPER_GUIDE.md)
- [Current architecture](docs/CURRENT_ARCHITECTURE.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](https://github.com/GetSHIM/shim/security/policy)

## Related projects

- [shim-cli](https://github.com/GetSHIM/shim-cli): the same boundary on a developer's
  laptop, for Claude Code, Codex CLI and GitHub Copilot CLI. It masks secrets and
  personal data in what the coding agent reads where the client allows it, and
  `shim watch` measures what a session sent and what it cost. shim covers the
  traffic your applications send.

## Licensing

Files outside `ee/` are licensed under the Apache License 2.0 in
[`LICENSE`](LICENSE), with scope recorded in [`NOTICE`](NOTICE). Files under
`ee/` are source-available under the Elastic License 2.0 in
[`ee/LICENSE`](ee/LICENSE), with the licensor named in
[`ee/NOTICE`](ee/NOTICE). `shim-enterprise` depends on the separately licensed
`shim-gateway` distribution.

There is no CLA. Running `shim-enterprise` with `ENVIRONMENT=production`
requires `SHIM_LICENSE_KEY`, an Ed25519-signed licence verified offline against
a public key shipped in the package. `shim-gateway` needs no licence and never
checks for one.
