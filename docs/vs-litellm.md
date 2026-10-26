# shim and LiteLLM

This page compares the shim gateway with LiteLLM on the points where the two
differ, with evidence for each row. It is not a feature list. LiteLLM supports
far more providers and features than shim, and the first section says where it
is ahead.

Versions:

- **LiteLLM 1.107.0 incident:** LiteLLM's
  [incident post](https://docs.litellm.ai/blog/security-incident-oct-21-2026) and
  [attack-chain post](https://docs.litellm.ai/blog/security-incident-oct-21-2026-attack-chain),
  and the reports by [Socket](https://socket.dev/blog/litellm-compromise) and
  [JFrog](https://research.jfrog.com/post/litellm-hijacked-again/), 21 to 23 October 2026.
- **LiteLLM lab:** `ghcr.io/berriai/litellm:v1.101.0`, image signature checked
  with cosign, pinned by digest, single instance, every upstream call sent to a
  recording mock. 29 to 30 September 2026. No real provider was called.
- **shim:** v0.4.5 code for the release rows; the 0.1.6 image for the lab rows.

A row about LiteLLM describes the version named in it. Later versions can
behave differently.

## Where LiteLLM is ahead or equal

Measured in the same lab, v1.101.0:

- **Providers and features.** LiteLLM covers over a hundred providers, routing,
  fallbacks and an MCP gateway. shim covers OpenAI, Anthropic, Google and Azure
  OpenAI, plus Amazon Bedrock in enterprise, and has no MCP gateway.
- **Budgets.** LiteLLM reserves worst-case cost before the call. A $0.01 key
  under 20 parallel requests let exactly 5 through, with no overshoot. Multiple
  instances were not tested.
- **Metrics.** The built-in Prometheus endpoint has per-provider latency
  histograms and cost metrics by team, key and model, with no licence.
- **Output scanning.** With `mode: post_call` and
  `presidio_filter_scope: output`, LiteLLM masks PII in the reply.
- **Tool results.** `role: tool` content and Anthropic `tool_result` blocks are
  masked by default.
- **Prompt storage.** Off by default. With `store_prompts_in_spend_logs` unset
  or `false`, no prompt or reply text is stored.

## Release and supply chain

| | LiteLLM 1.107.0 (public reports) | shim v0.4.5 | Evidence |
|---|---|---|---|
| Release path | A stolen owner token overrode branch protection on the private release repository and pointed the build at the fork `Berri-AI/litellm`; a second stolen token approved the production gate ([LiteLLM attack-chain post](https://docs.litellm.ai/blog/security-incident-oct-21-2026-attack-chain)) | A pushed tag in the public repository; no manual dispatch, no workflow input; publishes with the run's own short-lived token. An admin token could still change the workflow. | `.github/workflows/release.yml` |
| Signature and provenance | The pipeline signed and published the release built from the fork. The build provenance recorded `vcs:source` as `https://github.com/Berri-AI/litellm` ([Socket](https://socket.dev/blog/litellm-compromise)). | Signed provenance and SBOM; `docs/SUPPLY_CHAIN.md` shows how to check the signer, the tag and the recorded source | `release.yml`, `docs/SUPPLY_CHAIN.md` |
| Long-lived secrets readable by a workflow run | Maintainer tokens stored as repository secrets were posted out by throwaway-branch workflows | The community release uses no repository secret. The enterprise release reads a cosign key from a repository secret with no protected environment. | `release.yml`, `enterprise-release.yml` |
| Python startup hooks | `cook.pth` and `sitecustomize.py` shipped inside the wheels | CI and the release smoke run the image with `SHIM_STARTUP_GUARD=enforce`, so an image with a startup hook outside the allowlist does not pass; `shim serve` reports one at boot, or refuses to start under `enforce` | `src/shim/core/startup_guard.py`, `.github/workflows/test.yml` |
| Exfiltration and metadata reads | POST to `www.litellm[.]dev/healthcheck`; requests to AWS, Azure and GCP instance metadata | Once `shim serve` has started, the egress guard reports lookups of hosts outside the configured providers and exporters, and connections to metadata and other link-local addresses, or refuses them under `enforce`. A connection to a literal public IP is not checked. | `src/shim/core/egress_guard.py`, `tests/core/test_supply_chain_demo.py` |
| Floating tags | `latest`, `main-latest`, `main-stable` served the bad image | `latest` exists; the docs install by digest | `README.md` |
| Code that runs before the application | Ran | Runs too. shim's guards start after it. | `docs/SUPPLY_CHAIN.md` |

## What the gateway keeps

The 1.107.0 collector tried to read LiteLLM's `LiteLLM_CredentialsTable` and
`LiteLLM_ProxyModelTable` through `DATABASE_URL`. What a gateway stores decides
what such a read returns.

| | LiteLLM v1.101.0 (lab) | shim | Evidence |
|---|---|---|---|
| Provider credentials | In the proxy database (`LiteLLM_CredentialsTable`, per the 1.107.0 reports) | Community: request header or environment, no database. Enterprise: Fernet-encrypted store or an external secret manager | `docs/SUPPLY_CHAIN.md` |
| Prompt text, storage on | `store_prompts_in_spend_logs: true` stores the full prompt and reply as plaintext JSONB | Community keeps no request history | lab `S1-spendlogs.txt`; `README.md` "Limitations" |
| Prompt text, storage on, PII guardrail on | The spend log keeps the raw pre-mask text | Not applicable | lab `S11-litellm-log.txt` |
| Response cache | With caching on, the reply is stored in plaintext in Redis (TTL 60 s in the lab) | No response cache | lab `S6.txt` |

## Provider attempts per request

| | LiteLLM v1.101.0 (lab) | shim | Evidence |
|---|---|---|---|
| A request to a failing deployment with one fallback | 4 upstream calls: 3 to the failing deployment (router default `num_retries: 2`) and 1 fallback. The header and the spend log report `attempted_retries: 0`. The 3 failed attempts appear in no spend row. | One provider attempt per admitted request; SDK retries are off. In enterprise only a tenant-written rule adds attempts, each with its own request id and ledger row. | lab `S3-captures.txt`, `S3-headers.txt`, `S3-spendlogs.txt`; `docs/CURRENT_ARCHITECTURE.md` |

## Turkish PII round trip

LiteLLM v1.101.0 with its Presidio guardrail and `output_parse_pii: true`. The
input is `data/tr_pii.txt`. The mock echoes the request.

Status upstream, checked on 26 October 2026: the overlap corruption
([BerriAI/litellm#42130](https://github.com/BerriAI/litellm/issues/42130)) is
fixed on LiteLLM `main` by [#47024](https://github.com/BerriAI/litellm/pull/47024),
merged on 17 October 2026, and no release on `BerriAI/litellm` contains it yet: the
newest is v1.106.4, and the withdrawn 1.107.0 has no tag or release there any more. The cross-message token collision
([BerriAI/litellm#31959](https://github.com/BerriAI/litellm/issues/31959)) is
open. Check both again before quoting them.

| Case | LiteLLM v1.101.0 (lab) | shim 0.1.6 (lab) | Evidence |
|---|---|---|---|
| Valid TCKN, default recognizers | Reached the model in clear | Masked (`TR_NATIONAL_ID`, with checksum) | lab `S4a.md`, `S11a.md` |
| Overlapping spans | The model received `<PERSON_4>BER_5>`; the caller got `BER_5>` back in the reply | Restored with no corruption | lab `S4a.md`, `S11a.md` |
| Two messages, two people | Placeholder numbers restart per message. "Mehmet Demir" came back to the caller as "Zeynep Kaya". | One hashed placeholder per value per request (today's form: `<TYPE_32hex>`) | lab `S4-token-collision.md` |

shim's own limits from the same lab, 0.1.6:

- The phone-number recognizer also masked an invalid order number and an
  invalid invoice number. Same class of false positive as Presidio.
- Person names were not detected. v0.4.0 added Turkish person names as the
  type `PERSON_NAME_TR`, masked by default since v0.4.2. English names are not
  covered.

## Reproduce

[Q3: link to the published lab setup.] The lab pins every image by digest,
binds every port to `127.0.0.1`, and sends every upstream call to a mock. It
needs no provider key.
