# Benchmarks

`scripts/bench_middleware.py` measures what the gateway itself adds to a request.
Refresh it before a release tag.

## What is measured

The community app runs in-process behind `httpx.ASGITransport`. The provider is an
`httpx.MockTransport` that answers instantly with a fixed completion, so the time is
the middleware path: authenticate, admission, privacy, provider spend, postprocess,
plus the ASGI hop and JSON handling.

Per prompt size, after a warm-up, each request is sent to `/v1/chat/completions`
(`chat wall`) and then the same text to `/v1/scan`. Reported in milliseconds:

| Column | Source |
| --- | --- |
| `chat wall` | client-side `perf_counter` around the request |
| `X-Shim-Latency-Ms` | the gateway's own response header: time with provider calls excluded, whole milliseconds |
| `scan` | `/v1/scan` wall time: authentication plus privacy detection only |
| `privacy share` | median `scan` divided by median `chat wall` |

The app exposes no per-stage timing, and the script adds none. `privacy share` is
therefore an estimate. `/v1/scan` detects with policy `warn`, so it does not do the
masking and restoring that chat does, and it pays for authentication and the HTTP
hop once.

The prompt is mixed Turkish and English prose with an email address, a TCKN and a
TR IBAN at the start, middle and end, so the privacy path does real work. A size is
that many thousand characters (`50 KB` is 50,000, which is also `/v1/scan`'s input
cap). Each prompt starts with a serial number so the repeat-loop detector never
trips. Rate limits are raised so no request is throttled.

## What is not measured

- Network, TLS, the real provider, and provider-side latency.
- Streaming: only non-streaming chat completions.
- Concurrency: requests run one at a time, so this is per-request overhead, not
  throughput or queueing.
- The enterprise app, with its database and Redis.
- Cold start. Warm-up requests are discarded.

## Command

```bash
uv run python scripts/bench_middleware.py                 # 1, 32, 50 KB; 200 requests, 20 warm-up
uv run python scripts/bench_middleware.py --sizes 1 32 --requests 500 --warmup 50
```

## Run

| | |
| --- | --- |
| Date | 2026-10-11 |
| Commit | `ca6b2e9` (`origin/main`) plus the benchmark script |
| Machine | Apple M1, 8 cores, 8 GB, macOS 26.4 |
| Python | 3.13.5 |
| Settings | defaults: 200 requests and 20 warm-up per size |

The machine was not idle: other worktrees and test runs were using it (load average
about 3 on 8 cores). Read the numbers as a trend, not as a guarantee. The p99 column
at 32 KB and 50 KB moved between runs by more than 2x.

| ms | chat wall p50 | p95 | p99 | `X-Shim-Latency-Ms` p50 | p95 | p99 | `scan` p50 | p95 | p99 | privacy share |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 KB | 8.5 | 9.8 | 10.5 | 7.0 | 8.1 | 9.0 | 6.7 | 7.5 | 8.0 | 78% |
| 32 KB | 109.3 | 138.1 | 278.8 | 108.0 | 135.2 | 274.2 | 107.0 | 144.2 | 203.7 | 98% |
| 50 KB | 168.7 | 275.0 | 330.4 | 167.0 | 258.7 | 324.0 | 165.4 | 188.2 | 275.9 | 98% |

Privacy dominates and grows roughly linearly with size: about 3.4 ms per KB at the
median. On this run the 100 ms budget for 32 KB prompts is crossed at p50, not
only at the tail.
