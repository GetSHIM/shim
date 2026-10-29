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
> benchmark](#found-by-this-benchmark)). On 2026-10-16 A1, A2 and A3 ran again on
> v0.4.1 (`8e87dcd`, released as `fcdb645`): detection and evasion are identical to
> `1f2eed6`, and egress is now zero. B1 ran on v0.4.1 on 2026-10-16. On 2026-10-17
> A1, A2 and A3 ran on v0.4.2 (`de2b0de`), which masks Turkish person names by default:
> its defaults now score what v0.4.1 scored with Turkish names on, and nothing else moved.

## Systems under test

| System | Version | How it runs |
| --- | --- | --- |
| shim | v0.4.1 (`fcdb645`; `main` at `1f2eed6` and `8e87dcd` before the release) | in-process for detection; the repository `Dockerfile` for latency |
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
| GitHub token | 60 | classic (`ghp_`, `gho_`, `ghs_`) and fine-grained (`github_pat_`), after `GH_PAT=` and in a `Bearer` header, where no key name gives them away (since v0.4.7) |
| JWT | 60 | |
| Person name | 420 | 270 Turkish, 150 English |

**Hard negatives**, 1,440 of them, look like identifiers and are not: 11-digit order
numbers and 10-digit invoice numbers that fail the TCKN and VKN checksums, tracking
numbers, EAN-13 barcodes, dates, prices, timestamps, four-part version numbers, commit
hashes, UUIDs, ticket and case numbers. They make precision mean something.

**Names are held out.** No name in the corpus was used to tune shim's Turkish name
detector. Most Turkish ones are common names and appear in the dictionary shim ships
(derived from Faker's `tr_TR` data): 44 of 50 male and 32 of 35 female first names, 46
of 51 surnames. shim has no English name detector. Its Turkish one masks by default
since v0.4.2 (it was opt-in before), so the headline column is shim with its defaults,
and a second column keeps v0.4.1's defaults (Turkish names off) for comparison.
English names are published as measured.

**How each system is scored.** The same 480 texts go to each:

- shim in-process: spans from `/v1/scan`, and the body that reached a recording
  upstream from `/v1/chat/completions`. Default settings, and again with
  `PERSON_NAME_TR` set to `off` (v0.4.1's default).
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

Results, 2026-10-15 on `1f2eed6` and rerun 2026-10-17 on v0.4.2 (`de2b0de`, identical
numbers), corpus sha256
`55b25333a34c5638e58441970c0a05a9aadbf8fc3760db1e96c7aea1a3584dc1`. The headline column
is shim v0.4.2 with its defaults; v0.4.0 is the release before the fixes.

| Recall | n | **shim v0.4.2** (defaults) | shim v0.4.1 defaults (names off) | shim v0.4.0 | shim v0.3.0 | Presidio | LiteLLM + Presidio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TCKN | 210 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| VKN | 90 | 100.0% | 100.0% | 100.0% | 90.0% | 100.0% | 100.0% |
| IBAN | 90 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| Card | 90 | 100.0% | 100.0% | 100.0% | 100.0% | 72.2% | 72.2% |
| Phone | 240 | 99.6% | 99.6% | 99.6% | 99.2% | 99.2% | 99.2% |
| Email | 240 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| IP | 60 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| Secret (AWS key, GitHub token, JWT) | 180 | 100.0% | 100.0% | 100.0% | 100.0% | 7.8% | 7.8% |
| Person, Turkish | 270 | 88.5% | 0.0% | 0.0% | 0.0% | 54.1% | 54.1% |
| Person, English | 150 | 0.0% | 0.0% | 0.0% | 0.0% | 95.3% | 95.3% |
| **all identifiers** | 1,620 | 88.8% | 74.0% | 74.0% | 73.4% | 80.0% | 80.0% |
| false positives | | 40 | 40 | 147 | 147 | 2,228 | 2,394 |
| **precision** | | 97.3% | 96.8% | 89.1% | 89.0% | 36.8% | 35.1% |
| **F1** | | 0.928 | 0.839 | 0.808 | 0.804 | 0.504 | 0.488 |

v0.4.0 with Turkish names on scored 88.8% recall and 90.7% precision (F1 0.897).

| Hard negatives masked | n | shim v0.4.2 | shim v0.4.0 and v0.3.0 | Presidio | LiteLLM + Presidio |
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

| Leaked to the provider | n | **shim v0.4.2** (defaults) | shim v0.4.1 defaults (names off) | shim v0.4.0 | shim v0.3.0 | Presidio | LiteLLM + Presidio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TCKN, IBAN, email, IP | 600 | 0 | 0 | 0 | 0 | 0 | 0 |
| VKN | 90 | 0 | 0 | 0 | 9 | 0 | 0 |
| Card | 90 | 0 | 0 | 0 | 0 | 14 | 14 |
| Phone | 240 | 0 | 0 | 0 | 0 | 1 | 1 |
| Secret | 180 | 0 | 0 | 0 | 0 | 157 | 157 |
| Person | 420 | 181 | 420 | 420 | 420 | 110 | 110 |
| **all** | 1,620 | 181 | 420 | 420 | 429 | 282 | 282 |

**Corpus change in v0.4.7.** The tables above placed the GitHub tokens after
`GITHUB_TOKEN=` and `Authorization: token`, where shim's key-name rules mask any
value, so they measured the context rather than the token rule. v0.4.7 moves them
after `GH_PAT=` and into a `Bearer` header (corpus sha256
`832e0f6658dcac31d318fece6a00faa8d747d029424b70e93787a1b111dcff9c`;
`tests/test_bench_corpus.py` checks that neither context masks a value by
itself). Measured 2026-10-21 on that corpus, in-process: shim v0.4.4 finds 43.3% of
the GitHub tokens and leaks 34 of 180 secrets (fine-grained tokens in both
contexts); v0.4.7 finds all of them and leaks none. Every other shim number is the
same on both corpora, and the change adds no false positive (42 for v0.4.4 and
v0.4.7 on either corpus; the 40 above is v0.4.2). Presidio and LiteLLM were not
re-run on the new corpus.

What this says:

- **Identifiers: shim masks all of them.** Every TCKN, VKN, IBAN, card, phone, email,
  IP and secret was masked, and none reached the provider. LiteLLM with Presidio let
  157 of 180 secrets, 14 of 90 cards (it misses Troy and 2-series Mastercard numbers)
  and 1 phone through.
- **Precision: shim masks far less that is not personal data.** 40 false positives
  against 2,394 for LiteLLM's guardrail, which masked every order, invoice, tracking,
  ticket and case number, every date and every timestamp in the corpus.
- **Overall, shim now finds more than LiteLLM's guardrail and masks far less by
  mistake:** 88.8% recall and 97.3% precision (F1 0.928), against 80.0% and 35.1%
  (F1 0.488). By the leak count, 181 identifiers reach the provider through shim and
  282 through LiteLLM's guardrail.
- **shim's weak spot is English names.** shim has no English person-name detector, so
  150 of those 181 are English names. Its Turkish detector finds 88.5% of Turkish names
  and adds no false positive; it masks by default since v0.4.2 (v0.4.1 masked no names
  by default: 74.0% recall, 420 leaked). Presidio's spaCy model finds 95.3% of English
  and 54.1% of Turkish names, while tagging Turkish words as names elsewhere. An
  English detector built from US name lists (PRD S69) missed its bar on an independent
  corpus (precision 0.871, recall 0.818) and is not shipped.
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
| shim | 1 (the gateway) | 827 MB | 398 MiB after the B1 load run |
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

#### Results (2026-10-16, v0.4.1)

Each block started with load average below 2. The over-HTTP p50 is the median of three
sweeps, with the lowest and highest sweep in brackets. Raw samples went to
`scripts/bench/results/2026-10-16/`, which is not committed ([how to
reproduce](#how-to-reproduce)).

**PII detection on, one request at a time** (p50, ms):

| Prompt | shim v0.4.1 | LiteLLM + Presidio | LiteLLM + Presidio, 2 workers | shim faster |
| --- | ---: | ---: | ---: | ---: |
| 1 KB | 12.5 (12.4–16.1) | 43.7 (38.8–50.2) | 37.2 (37.0–42.0) | 3.5× |
| 4 KB | 26.3 (22.5–42.1) | 83.5 (82.7–94.2) | 82.8 (81.6–86.9) | 3.2× |
| 16 KB | 81.1 (65.3–81.6) | 269.2 (268.2–345.9) | 269.4 (265.5–285.2) | 3.3× |
| 32 KB | 129.2 (119.0–153.2) | 631.6 (554.9–815.0) | 565.0 (556.8–604.7) | 4.9× |
| 50 KB | 243.0 (181.6–295.2) | 1,112.6 (915.5–1,138.6) | 943.2 (912.4–987.7) | 4.6× |

**PII detection on, eight requests at once** (p50, ms; requests per second in brackets):

| Prompt | shim v0.4.1 | LiteLLM + Presidio | LiteLLM + Presidio, 2 workers |
| --- | ---: | ---: | ---: |
| 1 KB | 125.1 (64/s) | 289.2 (27/s) | 236.0 (33/s) |
| 4 KB | 214.7 (36/s) | 680.4 (11/s) | 594.6 (13/s) |
| 16 KB | 713.8 (11/s) | 2,421.7 (3/s) | 2,118.4 (4/s) |
| 32 KB | 1,605.9 (5/s) | 4,460.3 (2/s) | 4,536.2 (2/s) |
| 50 KB | 1,729.2 (5/s) | 7,315.0 (1/s) | 7,383.2 (1/s) |

No request failed in any block.

**Without detection** both gateways are fast. shim with every entity type off has a p50 of
4.5–8.4 ms one at a time and 20–50 ms at eight at once. LiteLLM without its guardrail has
7.1–9.6 ms and 36–46 ms. Detection is 68–98% of shim's added time and 84–99% of
LiteLLM's, so the comparison above is a comparison of detectors.

**What it costs to run:** shim is one container: an 827 MB image, using 398 MiB after the
load run. LiteLLM with its guardrail is three: 1.68 GB, 1.53 GB and 356 MB of images,
using about 1.4 GiB. A second Presidio worker per service adds about 800 MiB and, at
eight requests at once, gains 12–18% at 1–16 KB and nothing at 32–50 KB.

**Where shim is weak:**
- It runs one process, and detection is CPU-bound. At eight requests at once its
  latency grows about eightfold, the same as LiteLLM's. More workers per container is
  the upgrade path.
- **shim's own budget is under 100 ms for prompts up to 32 KB, and it is not met
  yet**: 106.6 ms in-process and 129 ms over HTTP at 32 KB of this PII-dense text.
- **Text that is nearly all matches scans 10 to 35 times slower than this prose.** In
  one analyzer pass its cost grows with the square of the matches, because Presidio
  compares every match with every other: a log of IP addresses took 4.3 s at 32 KB and
  50 s at 128 KB on the scrubber alone. Since 2026-10-21 text over 16,384 characters is
  read in windows of that length, overlapping by 1,024 characters on each side and cut
  only where no detection and no word crosses (a word is letters, digits and `_-.`, the
  characters of every token-shaped secret), and the overlap check after it no longer
  compares every pair, so the cost is linear. A value that only matches whole, such as
  a JWT, is never read in part: a window that sees one cross its start decides it. On the scrubber alone (load average about 13):
  IP addresses 2.9 s at 32 KB and 11.9 s at 128 KB, phone numbers 1.2 s and 4.7 s, this
  prose 93 ms and 340 ms, and 2.7 s at 1 MB. A window of IP addresses costs about 1.5 s.
  Windows cost this prose 2.5 ms at 32 KB (89.6 against 92.1 ms, best of 15) and nothing
  at 16 and 50 KB, and the word rule (2026-10-21) costs nothing measurable. One value
  longer than a window (a connection string or a word over about 14,000 characters, or
  a private key without its end line) is masked to the window's end, and the text after
  it is scanned as text, not masked whole as in one pass. A value with spaces in it that
  only matches whole, such as a quoted password, is found whole up to 2,048 characters.
- **A request's scan must end 20 seconds after the privacy stage received it**, time
  waiting for a thread included. The deadline is checked before and after every
  window, so a refusal (`PRIVACY_SCAN_TIMEOUT`) comes at most one window late and
  nothing scanned late reaches the provider: 256 KB and 990 KB of IP addresses are
  refused in 20.3 and 20.6 s over HTTP, where 256 KB took 180 s and passed before. A
  request with more than 16,384 bytes scans on two threads of its own, so short requests
  never queue behind it: with twelve 32 KB IP-address requests at once, six passed
  (6, 12 and 18 s), six were refused at 20.6 s, and a small request meanwhile took
  290 ms p50 and 446 ms at most (16 ms idle; 1.5 s and 41 s before). Before scanning, a
  request over 4,000,000 characters or 50,000 distinct strings is refused
  (`PRIVACY_SCAN_TOO_LARGE`): about 11 s of this prose at 2.7 ms per KB, or 15 s of
  short strings at about 0.3 ms each; denser text meets the deadline first.
- Over HTTP, v0.4.1 and v0.3.0 are within each other's sweep-to-sweep spread at every
  size (32 KB one at a time: 129.2 and 120.5 ms). In-process, below, they time the
  same. The added evasion handling of v0.4.1 has no measurable cost.

**In-process** (200 requests and 20 warm-up per size; p50 / p95 / p99, ms):

| Prompt | v0.4.1 chat wall | v0.4.1 `scan` | v0.3.0 chat wall | v0.3.0 `scan` | v0.4.1 privacy share |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 KB | 8.8 / 10.6 / 13.5 | 6.7 / 7.8 / 9.1 | 8.5 / 8.9 / 9.6 | 6.8 / 6.9 / 7.4 | 77% |
| 4 KB | 18.1 / 19.9 / 21.9 | 16.0 / 17.4 / 39.6 | 17.9 / 19.5 / 36.1 | 16.1 / 17.5 / 26.2 | 88% |
| 16 KB | 55.9 / 58.8 / 78.3 | 52.9 / 54.2 / 57.7 | 55.5 / 59.5 / 111.9 | 53.4 / 57.5 / 77.1 | 95% |
| 32 KB | 106.6 / 115.0 / 188.3 | 103.1 / 110.2 / 130.2 | 104.9 / 113.3 / 192.8 | 102.7 / 110.5 / 134.9 | 97% |
| 50 KB | 163.4 / 169.5 / 276.3 | 159.5 / 165.2 / 241.2 | 161.0 / 169.6 / 298.6 | 158.6 / 163.6 / 173.5 | 98% |

Privacy grows roughly linearly with size, about 3.2 ms per KB at the median.

**v0.4.7 against v0.4.6** (2026-10-29, same script, two interleaved rounds each, load
about 5, so not comparable with the table above): the wider secret recognizers of v0.4.7
cost nothing measurable. `chat wall` p50 per round, v0.4.6 then v0.4.7: 1 KB 9.7, 8.9 /
10.6, 9.7 ms; 16 KB 54.3, 52.6 / 52.3, 51.7 ms; 32 KB 101.1, 99.3 / 101.5, 99.3 ms;
50 KB 147.9, 144.4 / 146.6, 145.8 ms.

**Found while running B1.** The first sweep timed the mock upstream itself at 46 ms per
request. Python's `http.server` sends the headers and the body as two writes, and with
Nagle's algorithm on the body waited for the client's delayed ACK. shim's upstream calls
paid it and LiteLLM's did not. The mock now sets `TCP_NODELAY` and answers in about
2 ms. That sweep is discarded, and its raw file is kept as `overhead-nagle-invalid.jsonl`.
A shim sweep started at load 4.5 is kept apart in `overhead-shim-main-busy.jsonl`.

### B1b. Event-loop hold of a long agent session (v0.4.7)

Each provider SDK walks every turn and content part of a body before sending it. Up to
v0.4.6 that walk ran on the event loop, so one long agent session held every tenant's
requests on that process. From v0.4.7 the SDK's own transform (Google: genai's typing
and conversion of `contents`) runs on a worker thread, and its result is sent through
`extra_body`; the JSON body is the same. `scripts/bench/loop_hold.py` times the longest
gap a 1 ms ticker sees while requests are built and sent to a local mock.

Measured 2026-10-29 on an M1 on AC power, at load about 5 (macOS media analysis was
running, so not idle). Each cell is the median of three runs; the "4 at once" column is
the noisiest (Google 18,000 turns: 793–969 ms).

| Provider | Turns | Before, 1 request | After, 1 request | After, 4 at once |
| --- | ---: | ---: | ---: | ---: |
| OpenAI chat | 6,000 | 1,510 ms | 17 ms | 204 ms |
| OpenAI chat | 18,000 | 3,991 ms | 154 ms | 254 ms |
| Anthropic messages | 6,000 | 2,126 ms | 16 ms | 226 ms |
| Anthropic messages | 18,000 | 6,596 ms | 55 ms | 300 ms |
| Google generateContent | 6,000 | 836 ms | 99 ms | 383 ms |
| Google generateContent | 18,000 | 2,579 ms | 223 ms | 929 ms |

What is left on the loop: serializing the body (a few MB at 18,000 turns), genai's
merge of `extra_body`, and, on the Gemini routes only, the route's own typing of the
body into genai's models (about 0.5 s at 18,000 turns). The thread holds the GIL while
it walks, which slows the loop rather than stopping it. A body is refused past 150,000
list entries (413 `REQUEST_TOO_MANY_ITEMS`), about ten times the longest agent session
measured, which bounds all of it.

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
- **Not English names.** shim has no English person-name detector; its Turkish one
  masks by default since v0.4.2 (`PERSON_NAME_TR`). The gap is reported as measured.
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
