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

> **Status:** sections A and B2 ran on 2026-10-15, on v0.4.0 and again on `main` at
> `1f2eed6`, which fixes what the first run found ([found by this
> benchmark](#found-by-this-benchmark)). B1 is **pending an idle run**: its latency
> numbers are only taken on an idle machine.

## Systems under test

| System | Version | How it runs |
| --- | --- | --- |
| shim | `main` at `1f2eed6` (after the fixes) | in-process for detection; the repository `Dockerfile` for latency |
| shim | v0.4.0 (`f33a59d`) | in-process |
| shim | v0.3.0 (`ca6b2e9`) | in-process from that commit; `ghcr.io/getshim/shim:0.3.0@sha256:9d8153451522…b57b59` |
| LiteLLM | v1.103.2, published 2026-10-01 | `ghcr.io/berriai/litellm:v1.103.2@sha256:f63fb81b831b…30bbfd`, one worker, no database |
| Presidio (LiteLLM's guardrail) | 2.2.364 | analyzer and anonymizer built from Microsoft's own Dockerfiles at tag `2.2.364` |
| Presidio (plain library) | 2.2.364, spaCy `en_core_web_lg` 3.8.0 | `AnalyzerEngine()` with every default |

LiteLLM v1.103.2 is the newest stable release that was at least 14 days old on
2026-10-15. Presidio 2.2.364 is the version shim pins; Microsoft's registry stops at
2.2.362, which ships no Turkish recognizer, so both Presidio services are built from
the 2.2.364 tag instead. The full pins are in
[`scripts/bench/litellm/docker-compose.yml`](../scripts/bench/litellm/docker-compose.yml).

Machine: Apple M1, 8 cores, 8 GB, macOS 26.4, Python 3.13.5; Docker 29.1.3 with 8 CPUs
and 3.8 GiB. Sections A and B2 count, they do not time, so they ran with other work
on the machine. The latency runs in B1 need load average below 2 and no other
containers.

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
default. The headline row is shim with its defaults; a second row has Turkish person
names on (`PERSON_NAME_TR=mask`). English names are published as measured.

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
protects it. Recall is therefore given per type, and precision only over all types:
a detection is a false positive when it overlaps no labelled identifier and either
overlaps a hard negative or is one of the identifier types above. Detections of other
types elsewhere (Presidio's `DATE_TIME` or `LOCATION` in prose) are counted but not
scored. **Leaked** means the whole identifier can still be read in what reached the
provider; for the plain library, in the text with its detections masked.

Results, 2026-10-15, corpus sha256
`55b25333a34c5638e58441970c0a05a9aadbf8fc3760db1e96c7aea1a3584dc1`. The headline column
is shim `main` with its defaults; v0.4.0 is the release before the fixes.

| Recall | n | **shim `1f2eed6`** | shim `1f2eed6`, Turkish names on | shim v0.4.0 | shim v0.3.0 | Presidio | LiteLLM + Presidio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TCKN | 210 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| VKN | 90 | 100.0% | 100.0% | 100.0% | 90.0% | 100.0% | 100.0% |
| IBAN | 90 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| Card | 90 | 100.0% | 100.0% | 100.0% | 100.0% | 72.2% | 72.2% |
| Phone | 240 | 99.6% | 99.6% | 99.6% | 99.2% | 99.2% | 99.2% |
| Email | 240 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| IP | 60 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| Secret (AWS key, GitHub token, JWT) | 180 | 100.0% | 100.0% | 100.0% | 100.0% | 7.8% | 7.8% |
| Person, Turkish | 270 | 0.0% | 88.5% | 0.0% | 0.0% | 54.1% | 54.1% |
| Person, English | 150 | 0.0% | 0.0% | 0.0% | 0.0% | 95.3% | 95.3% |
| **all identifiers** | 1,620 | 74.0% | 88.8% | 74.0% | 73.4% | 80.0% | 80.0% |
| false positives | | 40 | 40 | 147 | 147 | 2,228 | 2,394 |
| **precision** | | 96.8% | 97.3% | 89.1% | 89.0% | 36.8% | 35.1% |
| **F1** | | 0.839 | 0.928 | 0.808 | 0.804 | 0.504 | 0.488 |

v0.4.0 with Turkish names on scored 88.8% recall and 90.7% precision (F1 0.897).

| Hard negatives masked | n | shim `1f2eed6` | shim v0.4.0 and v0.3.0 | Presidio | LiteLLM + Presidio |
| --- | ---: | ---: | ---: | ---: | ---: |
| invoice number, fails the VKN checksum | 90 | 7.8% | 86.7% | 100.0% | 100.0% |
| order number, fails the TCKN checksum | 240 | 5.4% | 8.3% | 100.0% | 100.0% |
| date | 270 | 0.0% | 10.0% | 100.0% | 100.0% |
| version number, four parts | 120 | 10.8% | 10.8% | 18.3% | 18.3% |
| tracking number | 60 | 0.0% | 3.3% | 100.0% | 100.0% |
| timestamp | 210 | 2.4% | 2.4% | 100.0% | 100.0% |
| commit hash | 90 | 1.1% | 1.1% | 5.6% | 5.6% |
| price | 240 | 0.4% | 0.4% | 1.7% | 7.5% |
| barcode, case number, ticket number, UUID | 120 | 0.0% | 0.0% | 84.2% | 85.0% |

| Leaked to the provider | n | shim `1f2eed6` | shim `1f2eed6`, Turkish names on | shim v0.4.0 | shim v0.3.0 | Presidio | LiteLLM + Presidio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TCKN, IBAN, email, IP | 600 | 0 | 0 | 0 | 0 | 0 | 0 |
| VKN | 90 | 0 | 0 | 0 | 9 | 0 | 0 |
| Card | 90 | 0 | 0 | 0 | 0 | 14 | 14 |
| Phone | 240 | 0 | 0 | 0 | 0 | 1 | 1 |
| Secret | 180 | 0 | 0 | 0 | 0 | 157 | 157 |
| Person | 420 | 420 | 181 | 420 | 420 | 110 | 110 |
| **all** | 1,620 | 420 | 181 | 420 | 429 | 282 | 282 |

What this says:

- **Identifiers: shim masks all of them.** Every TCKN, VKN, IBAN, card, phone, email,
  IP and secret was masked, and none reached the provider. LiteLLM with Presidio let
  157 of 180 secrets, 14 of 90 cards (it misses Troy and 2-series Mastercard numbers)
  and 1 phone through.
- **Precision: shim masks far less that is not personal data.** 40 false positives
  against 2,394 for LiteLLM's guardrail, which masked every order, invoice, tracking,
  ticket and case number, every date and every timestamp in the corpus.
- **shim's weak spot is names.** shim has no English person-name detector, and its
  Turkish one is opt-in, off by default, so with its defaults shim masks no names.
  With Turkish names on, it finds 88.5% of Turkish names and adds no false positive;
  English names still pass. Presidio's spaCy model finds 95.3% of English and 54.1%
  of Turkish names, while tagging Turkish words as names elsewhere. By the leak count,
  LiteLLM's guardrail lets 282 identifiers through, shim with defaults 420 (all of
  them names), shim with Turkish names on 181 (150 of them English names).
- **The fixes cut shim's false positives from 147 to 40** with no recall lost. v0.4.0
  masked 86.7% of invoice numbers as phone numbers ("Fatura no: 6726182317": it read
  "no" as a phone cue) and 10% of dates; `1f2eed6` masks 7.8% and none.
- **Held-out check.** The fixes were written against this corpus, so we generated a
  second one with another seed (`20261016`, sha256 `637ab1ef…3baa`) after they were
  merged: `1f2eed6` scored 74.1% recall, 54 false positives and 95.7% precision there
  (Presidio 80.9%, 2,246 and 36.8%).

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

Results, 2026-10-15, evasion corpus sha256
`498f01fb8f6de91c5b1bdcd4f086e9686ab068fdd37e21392f018109d0586147`. Share of disguised
identifiers that reached the provider (lower is better):

| Disguise | n | **shim `1f2eed6`** | shim v0.4.0 | shim v0.3.0 | Presidio | LiteLLM + Presidio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| plain (control) | 100 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| Arabic-Indic digits | 80 | 0.0% | 0.0% | 73.8% | 52.5% | 52.5% |
| Extended Arabic-Indic digits | 80 | 0.0% | 0.0% | 70.0% | 47.5% | 47.5% |
| Devanagari digits | 80 | 0.0% | 0.0% | 73.8% | 57.5% | 57.5% |
| fullwidth | 100 | 0.0% | 0.0% | 0.0% | 52.0% | 52.0% |
| zero-width joiner | 100 | 0.0% | 0.0% | 0.0% | 92.0% | 92.0% |
| bidi override, wrapped | 100 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| mixed case (email) | 20 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| combining mark per character | 100 | 0.0% | 40.0% | 100.0% | 74.0% | 74.0% |
| hyphens every three | 80 | 0.0% | 48.8% | 48.8% | 70.0% | 70.0% |
| space between digits | 80 | 0.0% | 70.0% | 70.0% | 43.8% | 43.8% |
| bidi override, reversed | 100 | 0.0% | 86.0% | 86.0% | 29.0% | 29.0% |
| line break in an email | 20 | 0.0% | 100.0% | 100.0% | 0.0% | 0.0% |
| **all disguises** | 940 | **0.0%** | 25.6% | 50.5% | 49.4% | 49.4% |

No disguised identifier reached the provider through shim `1f2eed6`. LiteLLM's
guardrail let half of them through; it is defeated most by zero-width characters
(92%) and combining marks (74%).

Read this with its history. v0.4.0 leaked a quarter of them: five disguises got
through, and on three of them (spaces between digits, a reversed value inside a
right-to-left override, an email broken after the `@`) LiteLLM did better. This
benchmark found them and `1f2eed6` fixes them, so the zero is measured on the
disguises the fix was written for. On the held-out seed the result is the same, 0 of
940 (Presidio 48.6%), but that seed changes the values, not the kinds of disguise; a
disguise not in this list is not measured.

### A3. What leaves the machine

- **shim**: the in-process run installs a Python audit hook before the first request
  and records every socket the process opens (`socket.connect`, `getaddrinfo`,
  `sendto`, `bind`), with its target and the code that opened it. Each run starts with
  an empty `tldextract` cache, as a fresh container does.

  **Result: zero.** In each of four runs on v0.4.1 (`8e87dcd`; A1 and A2, with and
  without Turkish names), shim made exactly one upstream call per chat request (480
  and 1,040) and **its process opened no other socket**.

  This benchmark is why. On v0.4.0 and `1f2eed6` every run opened one more
  connection, an HTTPS request to `publicsuffix.org`, the first time the process
  checked an email address: Presidio's email recognizer, which shim's extends,
  validates the domain with `tldextract`, which downloads the Public Suffix List when
  its cache is empty, with no timeout. It carried nothing from the prompt, but a fresh
  container made it once per start. Since #227 the recognizer uses `tldextract`'s
  built-in list only (snapshot of 2025-04-07), and since #229 any well-formed domain
  counts, so the list decides only punycode suffixes.
- **LiteLLM**: **480 upstream calls** for 480 chat requests, so nothing extra reaches
  the provider. Detection itself is two further services called over HTTP: **960
  analyzer calls** (two per request: the prompt, and again the answer) and **461
  anonymizer calls** (one per request that had something to mask). The Presidio
  analyzer container makes the same Public Suffix List download: its `tldextract`
  cache was empty when it started and filled after the run. We did not audit the
  containers' other traffic.

| Deployment | Containers for detection | Image size | Memory |
| --- | ---: | ---: | ---: |
| shim | 1 (the gateway) | pending the B1 run | pending the B1 run |
| LiteLLM + Presidio | 3 (proxy, analyzer, anonymizer) | 1.68 GB + 1.53 GB + 356 MB | 606 + 796 + 61 MiB after the A1 and A2 runs |

### Found by this benchmark

Each was found by writing or running this benchmark, reported, and fixed in shim
before the numbers above were published.

| Finding | Effect in v0.4.0 | Status |
| --- | --- | --- |
| VKN checksum left out a step | rejected about 60% of valid tax numbers, including python-stdnum's example `4540536920` | fixed in v0.4.0 (#223) |
| five disguises not undone | 25.6% of disguised identifiers reached the provider | fixed in `1f2eed6` (#226) |
| "no" read as a phone cue | 86.7% of invoice numbers masked as phones | fixed in `1f2eed6` (#226) |
| Anthropic auto-cache had one breakpoint, after the last message | independent requests over a shared system prompt paid 25% more input | fixed in `1f2eed6` (#226), see B2 |
| Public Suffix List download | one outbound HTTPS request per fresh process | fixed in v0.4.1 (#227) |

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
| `litellm-presidio` | LiteLLM with the Presidio guardrail (per request), Presidio as its images ship: one worker per service. **The default.** |
| `litellm-presidio-scaled` | the same with **two workers per Presidio service** (`PRESIDIO_WORKERS=2`) |

The detection share is (with detection − without) ÷ (with detection − `mock`), for
shim against `shim-main-noprivacy` and for LiteLLM against `litellm`.

Every process runs one worker, as each image ships: shim's `shim serve`, LiteLLM's
`--num_workers 1`, and one gunicorn worker per Presidio service. LiteLLM with its
guardrail therefore uses three processes to shim's one. The scaled arm gives Presidio
two workers per service (five processes in all), so the concurrency-8 numbers are not
only a measure of Presidio's default; both arms are reported, labelled. Two is the most
the 3.8 GiB Docker VM holds: each analyzer worker loads its own spaCy model, about
800 MiB.

Results: **pending an idle run.**

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
(`models.dev:056578ed0334d50e2d531f60`) at the plain input rate, and at cache rates
only for the cache lever, so a cache hit elsewhere does not count as a saving. Each
saving compares the same cases in both arms (cases that failed in either are left out
and counted), and "per 1M requests" is the mean input-cost saving per request times a
million. Spend is capped at $2 by the script.

| Lever | Setting | Requests | Models |
| --- | --- | --- | --- |
| JSON compaction | `SHIM_JSON_COMPACTION=on` | a 150-order pretty-printed tool result, Responses and messages | `gpt-5.6-luna`, `claude-haiku-5-5` |
| Tool search | `SHIM_TOOL_SEARCH=regex`, `bm25` | a 50-tool agent, three tasks; whether the model called a tool for the right record is recorded | `claude-haiku-5-5` (messages), `gpt-5.6-luna` (Responses) |
| Prompt cache | `SHIM_ANTHROPIC_AUTO_CACHE=5m`, `SHIM_OPENAI_PROMPT_CACHE_KEY=key` | eight requests on one system prompt of about 17,000 tokens: independent questions, and one conversation growing a turn per request | `claude-haiku-5-5`, `gpt-5.6-luna` |
| Image downscaling: **saves bytes** | `SHIM_IMAGE_DOWNSCALE=on` | two photos (12 and 23 MP), a scanned page, two screenshots | `claude-haiku-5-5`, `gpt-5.4-nano` |
| Image detail: **saves tokens** | `SHIM_IMAGE_DETAIL_OPENAI=low` | the same images | `gpt-5.6-luna` |

The models are the first choice per role. At run time the script asks each provider
whether our keys reach the model (a free metadata call) and falls back to the next one
listed in `CANDIDATES` in the script (`gpt-5.6-terra`, `gpt-5.4-mini`,
`claude-haiku-4-5`, `gemini-flash-latest`); the exact ids used are printed, recorded in
the results and listed with the tables.

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

Results, 2026-10-15. Models used: `gpt-5.6-luna`, `gpt-5.4-nano`, `claude-haiku-5-5`
(all first choices were reachable). The prompt-cache rows are from `main` at
`1f2eed6`; the others from v0.4.0, whose levers `1f2eed6` does not change. Total spend
for the B2 runs: about $0.26 at shim's conservative accounting price, including a
first attempt that a harness bug spoiled (kept, not used).

| Lever | Model | Cases | Input tokens per request, off → on | Input cost saved | USD saved per 1M requests |
| --- | --- | ---: | ---: | ---: | ---: |
| JSON compaction | `gpt-5.6-luna` | 1 | 20,069 → 13,658 | **31.9%** | 1,282 |
| JSON compaction | `claude-haiku-5-5` | 1 | 30,432 → 23,741 | **22.0%** | 669 |
| Tool search, regex | `claude-haiku-5-5` | 3 | 7,708 → 1,756 | **77.2%** | 595 |
| Tool search, bm25 | `claude-haiku-5-5` | 3 | 7,708 → 1,894 | **75.4%** | 581 |
| Tool search, regex or bm25 | `gpt-5.6-luna` | 3 | 2,799 → 2,391 | 14.6% | 82 |
| Prompt cache, growing conversation | `claude-haiku-5-5` | 8 | 17,776 → 17,776, 87% read from cache | **75.5%** | 1,342 |
| Prompt cache, growing conversation | `gpt-5.6-luna` | 8 | 87% read from cache in both arms | 0.0% | 0 |
| Prompt cache, independent questions | `claude-haiku-5-5` | 8 | 17,669 → 17,672, 87% read from cache | **75.5%** | 1,333 |
| Prompt cache, independent questions, v0.4.0 | `claude-haiku-5-5` | 8 | every request writes the cache, none reads it | −25.0% | −442 |
| Prompt cache, independent questions | `gpt-5.6-luna` | 8 | 87% read from cache in both arms | 0.0% | 0 |
| Image detail `low` (saves tokens) | `gpt-5.6-luna` | 5 | 10,374 → 208 | **98.0%** | 2,033 |
| Image downscaling (saves bytes) | `claude-haiku-5-5` | 4 | 3,641 → 3,641; 1.4 M base64 characters fewer per request | 0.0% | 0 |
| Image downscaling (saves bytes) | `gpt-5.4-nano` | 5 | 2,687 → 2,697; 5.9 M base64 characters fewer per request | −0.4% | −2 |

- **JSON compaction and tool search save what they promise.** Dropping the whitespace
  from a pretty-printed tool result cut a fifth to a third of the input. Deferring 50
  tool definitions behind Anthropic's tool search cut three quarters. OpenAI bills the
  same 50 definitions as about 2,800 tokens against Claude's 7,700, so there is less
  to save. The model called a
  tool for the right record in every task with and without tool search on Claude
  (3/3), and in 2/3 on GPT in every arm (it asked for confirmation before cancelling a
  subscription, as the tool description tells it to).
- **The Anthropic cache setting cuts input cost by three quarters** for a growing
  conversation and for independent questions over a shared system prompt alike. In
  v0.4.0 it put one breakpoint, after the last message, so independent questions each
  wrote a cache entry nobody read and paid 25% more; `1f2eed6` adds a breakpoint at
  the end of the system prompt, and from the second request on 17,644 of 17,672 input
  tokens are read from the cache. OpenAI caches the prefix by itself, and the routing
  key changed nothing here.
- **Image downscaling saves bytes, not tokens**, as its documentation says. It also
  carried the 23-megapixel photo (18 MB, 24 MB as base64) past Anthropic's 10 MB image
  limit: refused with the setting off, answered with it on. **Image detail is the token
  saver**: `gpt-5.6-luna` reads an image at full resolution by default, about 10,000
  tokens for these images, and about 200 at `low`, which costs fine detail.

The Turkish token tax, from each provider's token-count endpoint:

| Model | TR tokens per 1k characters | EN tokens per 1k characters | TR ÷ EN tokens, same text |
| --- | ---: | ---: | ---: |
| `gpt-5.6-luna` | 270.6 | 180.8 | 1.49× |
| `gemini-3.8-flash` | 253.1 | 181.2 | 1.39× |
| `claude-haiku-4-5` | 418.3 | 193.7 | 2.15× |
| `claude-haiku-5-5`, `claude-sonnet-5-5` | 524.8 | 283.5 | 1.84× |

The same Turkish text costs 1.4 to 2.2 times the tokens of its English version. Claude
Haiku 4.5's 2.15× matches what shim's end-to-end tests measured on real Turkish
traffic (2.06×, 415.6 against 202.2 tokens per 1k characters). Haiku 5.5 and Sonnet
5.5 count identically; they use more tokens per character than Haiku 4.5 in both
languages, and the Turkish gap narrows to 1.84×.

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
`scripts/bench/results/<date>/`. Raw samples are not committed; the corpus is not
either, because the generator and its seed reproduce it byte for byte (compare the
SHA-256 it prints with the one cited above each table).

The held-out corpus is `python -m scripts.bench.pii_corpus --seed 20261016 --out <dir>`;
score it with `pii_score run` as `run_all.sh` does. The shim runs start each process
with an empty `tldextract` cache, as a fresh container does, so A3 still shows the
Public Suffix List download on builds before v0.4.1.

**Presidio is built from source.** The compose file builds the Presidio analyzer and
anonymizer from Microsoft's own Dockerfiles at git tag `2.2.364`, the version shim
pins. Microsoft's registry stops at 2.2.362, which has no Turkish ID (TCKN) recognizer,
so with the published images LiteLLM's guardrail could not detect a TCKN at all. The
first build takes a while and needs network access. Comparing shim v0.3.0 needs a checkout of `ca6b2e9`
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
- **Not English names.** shim has no English person-name detector, and its Turkish
  one is opt-in (`PERSON_NAME_TR`, off by default). Both gaps are reported as measured.
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
