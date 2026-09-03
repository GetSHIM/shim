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
  <a href="https://github.com/GetSHIM/shim-guard">shim Guard</a>
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
  addresses, phone numbers, credit cards, IBANs, Turkish national ID and tax
  numbers, and provider secrets such as AWS keys and GitHub tokens. Each value
  becomes a placeholder, and policy decides whether the request is masked,
  blocked, or recorded.
- **Decides admission.** Requests-per-minute and tokens-per-minute limits, a
  model allow-list taken from the checked-in price catalog, and repeat-loop
  detection.
- **Accounts usage and cost per request**, from that same catalog, attributed
  by the `X-Shim-Tag` header.
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
  "verdict": "block",
  "entities": [
    {"type": "EMAIL_ADDRESS", "score": 1.0, "start": 9, "end": 29},
    {"type": "IBAN_CODE", "score": 1.0, "start": 36, "end": 68}
  ],
  "entity_types": ["EMAIL_ADDRESS", "IBAN_CODE"],
  "policy": "block"
}
```

Then point an existing client at it. No SDK change, only a base URL:

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8000/v1", api_key="your-shim-key")
client.chat.completions.create(
    model="gpt-5-nano",
    messages=[{"role": "user", "content": "Email jane.doe@example.com about the invoice"}],
)
```

Under a masking policy the provider receives placeholders in place of the
detected values, in the form `<EMAIL_ADDRESS_75344f3b9ce7dabdf18cb32cabf22e43>`.
They are generated per request, so the same value gets a different placeholder
next time, and the reply is restored before it reaches your caller.

Provider credentials come from `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` or
`GOOGLE_API_KEY`, or per request through `x-provider-key`. The shim key
authenticates your caller and is never forwarded to a provider. The default bind
is loopback; set a `SHIM_API_KEY` of at least 16 characters before binding
anywhere else.

Community exposes `/v1/chat/completions`, `/v1/messages`, `/v1/responses`, the
Gemini `generateContent` routes, `/v1/models`, `/v1/scan`, `/health` and
`/metrics`. The checked-in contract is [`openapi/community.json`](openapi/community.json).

To run from source instead, see [the developer guide](DEVELOPER_GUIDE.md).

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
- [Target architecture](docs/TARGET_ARCHITECTURE.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](https://github.com/GetSHIM/shim/security/policy)

## Related projects

- [shim Guard](https://github.com/GetSHIM/shim-guard) — local pre-submit privacy
  protection for coding-agent CLIs. It redacts before a prompt leaves your
  machine; shim covers the traffic your applications send.

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
