# Benchmarks

What shim does to your traffic, measured, next to LiteLLM, a widely used open-source
AI gateway that offers a PII guardrail. Two parts:

- **[A. Security](#a-security)**, for teams that must keep personal data away from
  model providers: detection quality on Turkish and English text, resistance to
  disguised identifiers, and what leaves the machine.
- **[B. Performance and cost](#b-performance-and-cost)**, for developers and platform
  teams: the latency shim adds, and what its cost levers save on real provider bills.

Everything here can be re-run from this repository with
[one command](#how-to-reproduce). The rules we hold ourselves to:

- Exact versions, image digests and configurations are published below.
- Every system gets the same corpus, the same machine and the same mock upstream.
- LiteLLM runs in the strongest configuration its documentation supports, not a
  crippled one. Where we chose, we chose in its favour, and say so.
- shim's weak spots are reported with the same weight as its strengths.
- Every run is kept. Latency is reported as the median of runs with the spread.

> **Status: draft.** The method and the scripts are final; the numbers marked
> `TBD` are filled in by the first full run.

## Systems under test

| System | Version | How it runs |
| --- | --- | --- |
| shim | `main` at `TBD` | in-process for detection; the repository `Dockerfile` for latency |
| shim | v0.3.0 (`ca6b2e9`) | in-process from that commit; `ghcr.io/getshim/shim:0.3.0@sha256:9d8153451522…b57b59` |
| LiteLLM | v1.103.2, published 2026-10-01 | `ghcr.io/berriai/litellm:v1.103.2@sha256:f63fb81b831b…30bbfd`, one worker, no database |
| Presidio (LiteLLM's guardrail) | 2.2.364 | analyzer and anonymizer built from Microsoft's own Dockerfiles at tag `2.2.364` |
| Presidio (plain library) | 2.2.364, spaCy `en_core_web_lg` 3.8.0 | `AnalyzerEngine()` with every default |

LiteLLM v1.103.2 is the newest stable release that was at least 14 days old on
2026-10-15. Presidio 2.2.364 is the version shim pins; Microsoft's registry stops at
2.2.362, which ships no Turkish recognizer, so both Presidio services are built from
the 2.2.364 tag instead. The full pins are in
[`scripts/bench/litellm/docker-compose.yml`](../scripts/bench/litellm/docker-compose.yml).

Machine: `TBD` (model, cores, memory, OS, Docker resources), idle: load average below
2, no other containers, recorded per run.

### How LiteLLM is configured

[`scripts/bench/litellm/config.yaml`](../scripts/bench/litellm/config.yaml) sets up the
Presidio guardrail as LiteLLM's
[PII masking guide](https://docs.litellm.ai/docs/proxy/guardrails/pii_masking_v2) does:
`mode: pre_call`, `presidio_language: en`, and no entity filter, so every entity the
analyzer reports is masked. On top of the documented setup:

- Presidio's own Turkish recognizers are switched on (`TrNationalIdRecognizer`,
  `TrLicensePlateRecognizer`, and `TR` added to the phone recognizer's regions;
  [`presidio_registry.py`](../scripts/bench/litellm/presidio_registry.py)). They ship
  disabled. This is the strongest Turkish support Presidio and LiteLLM offer.
- No ad-hoc regex recognizers. Neither project ships one for the Turkish tax number
  (VKN); a regex we wrote would measure us, not them.
- No database, Redis or logging callbacks, `num_retries: 0`: the leanest, fastest proxy.

## A. Security

### A1. Detection quality on Turkish and English text

**Corpus.** [`scripts/bench/pii_corpus.py`](../scripts/bench/pii_corpus.py) renders 16
realistic templates 30 times each with seed `20261015`: 480 texts. Support chats, bank
emails in both languages, application logs, an `.env` file, a Python snippet, a curl
command in a ticket, an incident chat mixing Turkish and English, an HR note, a CRM
export, a JSON tool result, a complaint, release notes, a campaign text, secrets pasted
into a chat, and a database error. The generator prints the SHA-256 of its output; for
the default seed it is `55b25333a34c5638e58441970c0a05a9aadbf8fc3760db1e96c7aea1a3584dc1`.

| Labelled identifier | Count | Notes |
| --- | ---: | --- |
| Turkish ID (TCKN) | 210 | checksum-valid |
| Turkish tax ID (VKN) | 90 | checksum-valid (the algorithm of `python-stdnum`) |
| TR IBAN | 90 | mod-97 valid, grouped or not |
| Payment card | 90 | Luhn-valid Visa, Mastercard (5- and 2-series), Amex, Troy |
| Phone | 240 | Turkish mobile and landline, US, UK, DE; all `phonenumbers`-valid; E.164, national and international formats |
| Email | 240 | |
| IP address | 60 | IPv4 documentation and private ranges, IPv6 |
| AWS access key | 60 | |
| GitHub token | 60 | classic (`ghp_`, `gho_`, `ghs_`) and fine-grained (`github_pat_`) |
| JWT | 60 | |
| Person name | 420 | 270 Turkish, 150 English |

**Hard negatives**, 1,440 of them, look like identifiers and are not: 11-digit order
numbers and 10-digit invoice numbers that fail the TCKN and VKN checksums, tracking
numbers, EAN-13 barcodes, dates, prices, timestamps, four-part version numbers, commit
hashes, UUIDs, ticket and case numbers. They make precision mean something.

**Names are held out.** No name in the corpus was used to tune shim's Turkish name
detector. Most Turkish ones are common names and appear in the dictionary shim ships
(derived from Faker's `tr_TR` data): 44 of 50 male and 32 of 35 female first names, 46
of 51 surnames. shim has no English name detector, and its Turkish one is off by
default; both shim configurations are reported.

**How each system is scored.** The same 480 texts go to each:

- shim in-process: spans from `/v1/scan`, and the body that reached a recording
  upstream from `/v1/chat/completions`. Default settings, and again with
  `PERSON_NAME_TR` set to `mask`.
- Plain Presidio: the spans `AnalyzerEngine().analyze(text, language="en")` returns.
- LiteLLM: a chat request with the guardrail on; the spans are what the Presidio
  analyzer answered LiteLLM (recorded by a relay), the body is what the mock upstream
  received.

**Matching.** An identifier counts as detected when the detected spans cover every
non-space character of it, whatever type the system called it: masking is what
protects it. A detection is a false positive when it overlaps no labelled identifier
and either overlaps a hard negative or is one of the identifier types above.
Detections of other types elsewhere (Presidio's `DATE_TIME` or `LOCATION` in prose)
are counted but not scored. **Leaked** means the whole identifier can still be read in
what reached the provider.

Results: `TBD`

| Type | n | shim main | shim main, names on | shim v0.3.0 | Presidio | LiteLLM + Presidio |
| --- | ---: | --- | --- | --- | --- | --- |
| (precision / recall / F1 per type, hard-negative mask rates, leaked identifiers per type) | | | | | | |

### A2. Evasion resistance

The same kinds of identifiers (TCKN, IBAN, card, Turkish phone, email), 20 of each per
disguise, inside a short Turkish or English sentence:

| Disguise | What it does |
| --- | --- |
| `plain` | none, the control |
| `arabic_indic_digits`, `extended_arabic_indic_digits`, `devanagari_digits` | digits written in another script |
| `fullwidth` | fullwidth forms (`１２３`, `ａ＠ｂ．ｃｏｍ`) |
| `combining_mark_per_char` | a combining accent after every character |
| `zero_width_joiner` | U+200D between every character |
| `space_per_char`, `hyphen_groups` | a space between digits; hyphens every three |
| `bidi_override_wrap` | wrapped in a right-to-left override |
| `bidi_override_reversed` | reversed inside a right-to-left override, so it displays correctly |
| `mixed_case`, `line_break` | emails only |

A disguised identifier **leaked** when, after undoing the disguise (compatibility
normalisation, any script's digits to ASCII, combining marks, format characters,
spaces and hyphens removed), the identifier appears in what reached the provider. A
model reads through all of these disguises, so a leak is a real leak.

shim v0.3.0 is measured too: it leaked identifiers written in other scripts' digits
and identifiers broken up by combining marks, both fixed in v0.3.1.

Results: `TBD` (leak rate per disguise and type, per system).

### A3. What leaves the machine

- **shim**: the in-process run installs a Python audit hook before the first request
  and records every socket the process opens (`socket.connect`, `getaddrinfo`,
  `sendto`, `bind`). Expected: zero, and exactly one upstream call per chat request.
  Result: `TBD`.
- **LiteLLM**: one upstream call per chat request: `TBD`. Detection itself is two
  further services, the Presidio analyzer and anonymizer, called over HTTP: `TBD`
  analyzer calls and `TBD` anonymizer calls per request. They stay on the local
  network, but they are containers to deploy, patch, scale and monitor.

| Deployment | Containers for detection | Image size | Memory after the load run |
| --- | ---: | ---: | ---: |
| shim | 1 (the gateway) | `TBD` | `TBD` |
| LiteLLM + Presidio | 3 (proxy, analyzer, anonymizer) | `TBD` | `TBD` |

## B. Performance and cost

### B1. Overhead

**In-process** ([`scripts/bench_middleware.py`](../scripts/bench_middleware.py)): the
community app behind `httpx.ASGITransport`, an `httpx.MockTransport` provider that
answers at once, so the time is the middleware path. Per prompt size, each request goes
to `/v1/chat/completions` (`chat wall`) and the same text to `/v1/scan`.

| Column | Source |
| --- | --- |
| `chat wall` | client-side `perf_counter` around the request |
| `X-Shim-Latency-Ms` | the gateway's own header: time with provider calls excluded, whole milliseconds |
| `scan` | `/v1/scan` wall time: authentication plus privacy detection only |
| `privacy share` | median `scan` divided by median `chat wall` |

The prompt is mixed Turkish and English prose with an email address, a TCKN and a TR
IBAN at the start, middle and end. A size is that many thousand characters (`50 KB` is
50,000, also `/v1/scan`'s input cap). Each prompt starts with a serial number, so the
repeat-loop detector never trips.

**Over HTTP, against LiteLLM**
([`scripts/bench/overhead.py`](../scripts/bench/overhead.py)): every system in its
container, all calling the same instant mock upstream, the same OpenAI chat body as
above. `mock` is the client calling the upstream directly; what a gateway adds is its
time minus that. Sizes 1, 4, 16, 32 and 50 KB; one request at a time and 8 at once; 200
measured requests and 20 warm-up per block, blocks in a seeded random order, three full
sweeps, all kept.

| Target | What it is |
| --- | --- |
| `shim-main` | shim at the commit under test, default settings |
| `shim-main-noprivacy` | the same image with every entity type off |
| `shim-v030` | the released v0.3.0 image |
| `litellm` | LiteLLM without a guardrail |
| `litellm-presidio` | LiteLLM with the Presidio guardrail (per request) |

The detection share is (with detection − without) ÷ (with detection − `mock`), for
shim against `shim-main-noprivacy` and for LiteLLM against `litellm`.

Every process runs one worker, as each image ships: shim's `shim serve`, LiteLLM's
`--num_workers 1`, and one gunicorn worker per Presidio service. LiteLLM with its
guardrail therefore uses three processes to shim's one.

Results: `TBD`

| ms | p50 (min–max of runs) | p95 | p99 | req/s at c=8 | added p50 vs `mock` | detection share |
| --- | --- | --- | --- | --- | --- | --- |
| (per target, size and concurrency) | | | | | | |

**Last published in-process run** (2026-10-11, `ca6b2e9` plus the script, Apple M1,
8 cores, 8 GB, macOS 26.4, Python 3.13.5, idle; 200 requests and 20 warm-up per size;
two runs on `ca6b2e9` and one on the night-1 branch gave the same medians, this is the
second `ca6b2e9` run):

| ms | chat wall p50 | p95 | p99 | `X-Shim-Latency-Ms` p50 | p95 | p99 | `scan` p50 | p95 | p99 | privacy share |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 KB | 8.5 | 9.0 | 9.6 | 8.0 | 8.0 | 8.0 | 6.7 | 6.9 | 7.3 | 79% |
| 32 KB | 104.4 | 107.1 | 128.1 | 103.0 | 105.0 | 126.6 | 102.3 | 104.4 | 109.0 | 98% |
| 50 KB | 160.9 | 192.9 | 278.2 | 159.0 | 189.6 | 276.0 | 158.6 | 163.3 | 177.5 | 99% |

Privacy dominates and grows roughly linearly with size, about 3.2 ms per KB at the
median. **shim's own budget is under 100 ms for prompts up to 32 KB, and it is not met
yet**: it is crossed at about 30 KB of this PII-dense text.

### B2. Savings on real providers

[`scripts/bench/savings.py`](../scripts/bench/savings.py) sends the same requests
through the community app once per setting, to the real provider, and reads the
`usage` the provider billed. Money is at list prices from shim's model catalog
(`models.dev:056578ed0334d50e2d531f60`); "per 1M requests" is the median saving per
request times a million. Spend is capped at $2 by the script.

| Lever | Setting | Requests | Models |
| --- | --- | --- | --- |
| JSON compaction | `SHIM_JSON_COMPACTION=on` | a 150-order pretty-printed tool result, chat and messages | `gpt-5.6-luna`, `claude-haiku-5-5` |
| Tool search | `SHIM_TOOL_SEARCH=regex`, `bm25` | a 50-tool agent, three tasks that each need one tool; whether the right tool was called is recorded | `claude-haiku-5-5` (messages), `gpt-5.6-luna` (Responses) |
| Prompt cache | `SHIM_ANTHROPIC_AUTO_CACHE=5m`, `SHIM_OPENAI_PROMPT_CACHE_KEY=key` | eight requests sharing a 7,000-token system prefix | `claude-haiku-5-5`, `gpt-5.6-luna` |
| Image downscaling | `SHIM_IMAGE_DOWNSCALE=on` | two photos (12 and 23 MP), a scanned page, two screenshots | `claude-haiku-5-5`, `gpt-5.4-nano` |
| Image detail | `SHIM_IMAGE_DETAIL_OPENAI=low` | the same images | `gpt-5.6-luna` |

Image downscaling sends the size the provider would resize to anyway. The providers
bill image tokens after their own resize, so **we expect no token saving from it**; it
saves upload bytes, and lets an image that is over a provider's byte limit through. The
benchmark measures both and reports whichever is true. Image detail is the setting that
lowers image tokens, at a cost in fine detail.

**The Turkish token tax.** The same six texts in Turkish and English
([`data/parallel_tr_en.json`](../scripts/bench/data/parallel_tr_en.json), written for
this benchmark), counted by each provider's free token-count endpoint: tokens per
character, and how many more tokens Turkish needs for the same content. This is a fact
about the providers' tokenizers that Turkish teams budget for; shim does not change it.

Results: `TBD`

| Lever | Model | Arm | input tokens | cache read share | USD / request | saved | USD saved per 1M requests |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| (per lever, model and setting) | | | | | | | |

| Model | TR tokens per character | EN tokens per character | TR ÷ EN tokens, same text |
| --- | ---: | ---: | ---: |
| (OpenAI, two Anthropic, Gemini) | | | |

Image credits (Wikimedia Commons): Nevit Dilmen (CC BY-SA 3.0), Jorge Franganillo
(CC BY 4.0), Internet Archive Book Images (no known restrictions), MediaWiki authors
(CC BY-SA 4.0), Killarnee (CC BY-SA 4.0). Files are fetched at run time and checked
against their Commons SHA-1.

## How to reproduce

From the repository root, with uv 0.12.5+ and Docker (the images take several GB):

```bash
scripts/bench/run_all.sh --corpus --detection --evasion     # A1, A2, A3
scripts/bench/run_all.sh --middleware --overhead            # B1: idle machine only
scripts/bench/run_all.sh --savings --env path/to/.env       # B2: real providers, under $2
scripts/bench/run_all.sh --report                           # every table above
```

`--all` runs everything in order. Results, raw samples and the report go to
`scripts/bench/results/<date>/`. Comparing shim v0.3.0 needs a checkout of `ca6b2e9`
(`git worktree add ../bench-base ca6b2e9`, then `SHIM_V030=../bench-base`). The `.env`
file holds `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` and `GOOGLE_API_KEY`; the scripts never
print them. The latency steps refuse to start while the load average is above 2.

## What we don't claim

- **Not a general PII benchmark.** The corpus is synthetic and built around the
  identifiers regulated Turkish and English teams handle. It has no addresses,
  passport numbers, health data or free-text personal facts, and its names are a
  short held-out list. A different corpus gives different numbers.
- **Not Presidio's best.** Plain Presidio runs with defaults, and LiteLLM's Presidio
  with what the two projects ship. Custom recognizers, a transformer NER model or
  tuned thresholds would score higher, for any system that adds them.
- **Not English names.** shim does not detect English person names; that column is
  reported as measured.
- **Not production latency.** Latency is one machine, one worker per process and a
  mock provider that answers at once. Network, TLS and the provider's own time are
  not in it. Throughput at higher concurrency or with more workers, streaming, cold
  start and the enterprise app (with its database and Redis) are not measured.
- **Not a statement about the model.** Leaks are counted in what reached the
  provider, not in what a model would do with it.
- **Not savings on your traffic.** Savings are for the requests described, at list
  prices on the date of the catalog. Cached-prefix and tool-search savings depend on
  how your prompts repeat and how many tools you send.
- **No claim beyond what is listed.** Features not measured here are not compared.
