"""Gateway overhead over HTTP: each system in its container, one instant mock upstream.

Every target gets the same OpenAI chat body (bench_middleware.prompt: PII-dense mixed
Turkish and English prose) and calls the same mock, so the difference from `mock`
(the client calling the upstream directly) is what the gateway adds. A sweep runs every
(target, size) block in a seeded random order; --runs repeats the sweep and every run
is kept in --out.

    python -m scripts.bench.overhead --targets mock shim-main litellm --out R.jsonl
    python -m scripts.bench.overhead --report R.jsonl
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import random
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from statistics import median, quantiles
from time import perf_counter

import httpx

from scripts.bench.pii_score import LITELLM_KEY
from scripts.bench_middleware import KEY, MODEL, prompt

SHIM = {"Authorization": f"Bearer {KEY}", "x-provider-key": "sk-bench-upstream"}
LITELLM = {"Authorization": f"Bearer {LITELLM_KEY}"}
# name -> (base URL, headers, extra body). Ports come from litellm/docker-compose.yml.
TARGETS = {
    "mock": ("http://127.0.0.1:8080", {}, {}),
    "shim-main": ("http://127.0.0.1:8001", SHIM, {}),
    "shim-main-noprivacy": ("http://127.0.0.1:8002", SHIM, {}),
    "shim-v030": ("http://127.0.0.1:8003", SHIM, {}),
    "litellm": ("http://127.0.0.1:4000", LITELLM, {}),
    "litellm-presidio": (
        "http://127.0.0.1:4000",
        LITELLM,
        {"guardrails": ["presidio-pii"]},
    ),
}
# Pairs whose difference is detection: (with, without).
DETECTION = {"shim-main": "shim-main-noprivacy", "litellm-presidio": "litellm"}


async def block(
    target: str,
    size_kb: int,
    concurrency: int,
    requests: int,
    warmup: int,
    serial: list[int],
) -> tuple[list[float], float]:
    url, headers, extra = TARGETS[target]
    limits = httpx.Limits(
        max_connections=concurrency, max_keepalive_connections=concurrency
    )
    async with httpx.AsyncClient(
        base_url=url, headers=headers, limits=limits, timeout=300
    ) as http:

        async def one() -> float:
            serial[0] += 1  # A fresh prompt each time: no repeat detector, no cache.
            body = {
                "model": MODEL,
                "messages": [{"role": "user", "content": prompt(size_kb, serial[0])}],
                **extra,
            }
            started = perf_counter()
            reply = await http.post("/v1/chat/completions", json=body)
            elapsed = (perf_counter() - started) * 1_000
            reply.raise_for_status()
            return elapsed

        for _ in range(warmup):
            await one()
        samples: list[float] = []
        remaining = [requests]

        async def worker() -> None:
            while remaining[0] > 0:
                remaining[0] -= 1
                samples.append(await one())

        started = perf_counter()
        await asyncio.gather(*(worker() for _ in range(concurrency)))
        return samples, perf_counter() - started


async def sweep(args: argparse.Namespace) -> None:
    order = [
        (target, size, concurrency)
        for target in args.targets
        for size in args.sizes
        for concurrency in args.concurrency
    ]
    meta = {
        "date": datetime.now(UTC).isoformat(timespec="seconds"),
        "machine": f"{platform.machine()} {platform.platform()}, {os.cpu_count()} CPUs",
        "load_average_at_start": os.getloadavg(),
        "requests": args.requests,
        "warmup": args.warmup,
        "seed": args.seed,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    serial = [0]
    with args.out.open("a", encoding="utf-8") as out:
        out.write(json.dumps({"meta": meta}) + "\n")
        for run in range(args.runs):
            random.Random(args.seed + run).shuffle(order)
            for target, size, concurrency in order:
                samples, wall = await block(
                    target, size, concurrency, args.requests, args.warmup, serial
                )
                row = {
                    "run": run,
                    "target": target,
                    "size_kb": size,
                    "concurrency": concurrency,
                    "rps": len(samples) / wall,
                    "samples_ms": [round(s, 3) for s in samples],
                }
                out.write(json.dumps(row) + "\n")
                out.flush()
                p50, p95, p99 = cuts(samples)
                print(
                    f"run {run} {target:>20} {size:>3} KB c={concurrency}: p50 {p50:.1f} p95 {p95:.1f} p99 {p99:.1f} ms"
                )


def cuts(samples: list[float]) -> tuple[float, float, float]:
    points = quantiles(samples, n=100, method="inclusive")
    return points[49], points[94], points[98]


def report(path: Path) -> None:
    runs: dict[tuple[str, int, int], list[tuple[float, float, float, float]]] = (
        defaultdict(list)
    )
    for line in path.read_text().splitlines():
        row = json.loads(line)
        if "meta" in row:
            print(f"- {row['meta']}")
            continue
        key = (row["target"], row["size_kb"], row["concurrency"])
        runs[key].append((*cuts(row["samples_ms"]), row["rps"]))
    print(
        "\n| Target | KB | c | p50 ms (min–max over runs) | p95 | p99 | req/s | added p50 vs mock | detection share |"
    )
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    p50 = {key: median(r[0] for r in rows) for key, rows in runs.items()}
    for key in sorted(runs, key=lambda k: (k[2], k[1], k[0])):
        target, size, concurrency = key
        rows = runs[key]
        base = p50.get(("mock", size, concurrency))
        added = (
            f"{p50[key] - base:.1f}" if base is not None and target != "mock" else ""
        )
        share = ""
        without = DETECTION.get(target)
        if without and (without, size, concurrency) in p50 and base is not None:
            share = f"{(p50[key] - p50[(without, size, concurrency)]) / (p50[key] - base):.0%}"
        print(
            f"| {target} | {size} | {concurrency} | {p50[key]:.1f} "
            f"({min(r[0] for r in rows):.1f}–{max(r[0] for r in rows):.1f}) | "
            f"{median(r[1] for r in rows):.1f} | {median(r[2] for r in rows):.1f} | "
            f"{median(r[3] for r in rows):.0f} | {added} | {share} |"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--targets", nargs="+", choices=list(TARGETS), default=list(TARGETS)
    )
    parser.add_argument("--sizes", type=int, nargs="+", default=[1, 4, 16, 32, 50])
    parser.add_argument("--concurrency", type=int, nargs="+", default=[1, 8])
    parser.add_argument("--requests", type=int, default=200, help="measured per block")
    parser.add_argument("--warmup", type=int, default=20, help="discarded per block")
    parser.add_argument("--runs", type=int, default=3, help="whole sweeps, all kept")
    parser.add_argument("--seed", type=int, default=20261015)
    parser.add_argument("--out", type=Path, help="append raw samples here")
    parser.add_argument(
        "--report", type=Path, help="print the table for a results file"
    )
    args = parser.parse_args()
    if args.report:
        report(args.report)
    elif args.out:
        asyncio.run(sweep(args))
    else:
        parser.error("--out or --report is required")


if __name__ == "__main__":
    main()
