"""Score PII detection, leakage and egress for shim, plain Presidio and LiteLLM.

`run` sends every case of a corpus through one system and writes one JSON line per
case: the detected spans and, for a gateway, the request body that reached the
upstream. `report` turns result files into the tables in docs/BENCHMARKS.md.

    python -m scripts.bench.pii_score run --system shim --corpus C --out R [--names TYPE ...]
    python -m scripts.bench.pii_score run --system presidio --corpus C --out R
    python -m scripts.bench.pii_score run --system litellm --corpus C --out R --captures D
    python -m scripts.bench.pii_score report --corpus C --evasion E R1 R2 ...

shim runs in-process, as in bench_middleware.py: spans from /v1/scan, the upstream
body from /v1/chat/completions against a recording httpx transport, and an audit hook
that records every socket the process opens. Presidio is the library's default
`AnalyzerEngine()`. LiteLLM is the proxy from scripts/bench/litellm: spans are the
Presidio analyzer answers its relay recorded, the body is what the mock upstream got.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import traceback
import unicodedata
from collections import Counter, defaultdict
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

import httpx

FAMILY = {
    "TR_NATIONAL_ID": "TCKN",
    "TR_VKN": "VKN",
    "IBAN_CODE": "IBAN",
    "CREDIT_CARD": "CARD",
    "PHONE_NUMBER": "PHONE",
    "EMAIL_ADDRESS": "EMAIL",
    "IP_ADDRESS": "IP",
    "SECRET": "SECRET",
    "PERSON_NAME_TR": "PERSON",
    "PERSON": "PERSON",
}
GOLD_FAMILY = {"AWS_KEY": "SECRET", "GITHUB_TOKEN": "SECRET", "JWT": "SECRET"}
FAMILIES = ("TCKN", "VKN", "IBAN", "CARD", "PHONE", "EMAIL", "IP", "SECRET", "PERSON")
LITELLM_KEY = "sk-bench-litellm-master-key"
SOCKET_EVENTS = {"socket.connect", "socket.getaddrinfo", "socket.sendto", "socket.bind"}


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def strings(value: object) -> list[str]:
    """Every string in a decoded JSON body, so escapes such as \\n are real characters."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for item in value.values() for s in strings(item)]
    if isinstance(value, list):
        return [s for item in value for s in strings(item)]
    return []


def git_commit(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()


def base_meta(system: str, corpus: Path) -> dict:
    return {
        "system": system,
        "corpus": corpus.name,
        "date": datetime.now(UTC).isoformat(timespec="seconds"),
        "machine": f"{platform.machine()} {platform.platform()}",
        "python": platform.python_version(),
    }


async def run_shim(cases: list[dict], names: list[str]) -> tuple[dict, list[dict]]:
    # A fresh container has no tldextract cache; nor does this run, unless one is given.
    os.environ.setdefault(
        "TLDEXTRACT_CACHE", tempfile.mkdtemp(prefix="bench-tldextract-")
    )
    import shim
    from shim.application import create_community_app
    from shim.core.community_config import CommunitySettings

    from scripts.bench_middleware import COMPLETION, KEY, MODEL

    sockets: list[str] = []

    def audit(event: str, args: tuple) -> None:
        if event in SOCKET_EVENTS:
            # The target (connect: args[1]; getaddrinfo: host and port) and the frames
            # outside the standard library and the HTTP stack that led to it.
            target = args[1] if event == "socket.connect" else args[:2]
            frames = [
                f"{Path(f.filename).parent.name}/{Path(f.filename).name}:{f.lineno}"
                for f in traceback.extract_stack()[:-1]
                if any(k in f.filename for k in ("/shim/", "presidio", "tldextract"))
            ]
            path = frames[:3] + frames[-1:] if len(frames) > 4 else frames
            sockets.append(f"{event} {target!r} via {' > '.join(path)}"[:400])

    upstream: list[bytes] = []

    async def record(request: httpx.Request) -> httpx.Response:
        upstream.append(request.content)
        return httpx.Response(200, json=COMPLETION)

    settings = CommunitySettings(
        OPENAI_BASE_URL="https://upstream.test/v1",
        BACKEND_CORS_ORIGINS=[],
        SHIM_API_KEY=KEY,
        GLOBAL_RATE_LIMIT_PER_MINUTE=10_000_000,
        DEFAULT_RPM_LIMIT=10_000_000,
        DEFAULT_TPM_LIMIT=10_000_000_000,
        PII_ENTITY_ACTIONS=dict.fromkeys(names, "mask"),
        _env_file=None,
    )
    app = create_community_app(
        settings,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(record)),
        event_stream=open(os.devnull, "w"),
    )
    headers = {"Authorization": f"Bearer {KEY}", "x-provider-key": "sk-bench-provider"}
    sys.addaudithook(audit)  # From here on, any socket the process opens is recorded.
    rows = []
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://shim.test",
            headers=headers,
        ) as http,
    ):
        for case in cases:
            scan = await http.post("/v1/scan", json={"text": case["text"]})
            scan.raise_for_status()
            sent = len(upstream)
            chat = await http.post(
                "/v1/chat/completions",
                json={
                    "model": MODEL,
                    "messages": [{"role": "user", "content": case["text"]}],
                },
            )
            rows.append(
                {
                    "id": case["id"],
                    "spans": [
                        [e["start"], e["end"], e["type"]]
                        for e in scan.json()["entities"]
                    ],
                    "status": chat.status_code,
                    "upstream": [json.loads(body) for body in upstream[sent:]],
                }
            )
    package = Path(shim.__file__).parent
    meta = {
        "label": f"shim {version('shim-gateway')} ({git_commit(package)})"
        + "".join(f" + {name}" for name in names),
        "egress": {
            "chat_requests": len(cases),
            "upstream_calls": len(upstream),
            "process_sockets": len(sockets),
            "socket_events": sorted(Counter(sockets).items())[:20],
            "tldextract_cache": os.environ["TLDEXTRACT_CACHE"],
        },
    }
    return meta, rows


def run_presidio(cases: list[dict]) -> tuple[dict, list[dict]]:
    import spacy
    from presidio_analyzer import AnalyzerEngine

    engine = (
        AnalyzerEngine()
    )  # Library default: spaCy en_core_web_lg, default recognizers.
    rows = [
        {
            "id": case["id"],
            "spans": [
                [r.start, r.end, r.entity_type]
                for r in engine.analyze(text=case["text"], language="en")
            ],
        }
        for case in cases
    ]
    model = spacy.util.get_package_version("en_core_web_lg")
    meta = {
        "label": f"Presidio {version('presidio-analyzer')} default (en_core_web_lg {model})"
    }
    return meta, rows


def new_lines(path: Path, seen: int) -> list[dict]:
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    return [json.loads(line) for line in lines[seen:]]


def run_litellm(cases: list[dict], url: str, captures: Path) -> tuple[dict, list[dict]]:
    from scripts.bench_middleware import MODEL

    logs = {
        name: captures / f"{name}.jsonl"
        for name in ("upstream", "presidio-analyzer", "presidio-anonymizer")
    }
    seen = {name: len(new_lines(path, 0)) for name, path in logs.items()}
    calls: Counter[str] = Counter()
    rows = []
    with httpx.Client(
        base_url=url, headers={"Authorization": f"Bearer {LITELLM_KEY}"}, timeout=120
    ) as http:
        litellm = http.get("/openapi.json").json()["info"]["version"]
        for case in cases:
            reply = http.post(
                "/v1/chat/completions",
                json={
                    "model": MODEL,
                    "messages": [{"role": "user", "content": case["text"]}],
                    "guardrails": ["presidio-pii"],
                },
            )
            fresh: dict[str, list[dict]] = {}
            for _ in range(50):  # The bind mount can lag the response by a few ms.
                fresh = {
                    name: new_lines(path, seen[name]) for name, path in logs.items()
                }
                if reply.status_code != 200 or fresh["upstream"]:
                    break
                time.sleep(0.02)
            for name, items in fresh.items():
                seen[name] += len(items)
                calls[name] += len(items)
            if not fresh["presidio-analyzer"]:
                raise SystemExit(f"{case['id']}: the Presidio guardrail did not run")
            spans = []
            for item in fresh["presidio-analyzer"]:
                offset = case["text"].find(item["request"]["text"])
                spans += [
                    [offset + r["start"], offset + r["end"], r["entity_type"]]
                    for r in item["response"]
                ]
            rows.append(
                {
                    "id": case["id"],
                    "spans": spans,
                    "status": reply.status_code,
                    "upstream": [item["body"] for item in fresh["upstream"]],
                }
            )
    meta = {
        "label": f"LiteLLM {litellm} + Presidio guardrail",
        "egress": {
            "chat_requests": len(cases),
            "upstream_calls": calls["upstream"],
            "presidio_analyzer_calls": calls["presidio-analyzer"],
            "presidio_anonymizer_calls": calls["presidio-anonymizer"],
        },
    }
    return meta, rows


def run(args: argparse.Namespace) -> None:
    cases = load(args.corpus)
    if args.system == "shim":
        meta, rows = asyncio.run(run_shim(cases, args.names))
    elif args.system == "presidio":
        meta, rows = run_presidio(cases)
    else:
        meta, rows = run_litellm(cases, args.url, args.captures)
    meta = base_meta(args.system, args.corpus) | meta
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as out:
        for row in ({"meta": meta}, *rows):
            out.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"{meta['label']}: {len(rows)} cases -> {args.out}")


# Scoring.


def norm(text: str) -> str:
    """Undo the disguises: compatibility forms, any script's digits, marks, spacing."""
    out = []
    for ch in unicodedata.normalize("NFKD", text):  # Decomposed, so marks come off.
        if unicodedata.category(ch) in {"Mn", "Me", "Cf"} or ch.isspace() or ch == "-":
            continue
        digit = unicodedata.decimal(ch, None)
        out.append(str(digit) if digit is not None else ch)
    return "".join(out).casefold()


def leaked(value: str, upstream: list) -> bool:
    """The whole identifier is recoverable from what reached the provider."""
    sent = norm("\n".join(strings(upstream)))
    target = norm(value)
    return target in sent or target[::-1] in sent


def sent(row: dict, text: str) -> list:
    """What reached the provider; for a library, the text with its detections masked."""
    if "upstream" in row:
        return row["upstream"]
    masked = list(text)
    for start, end, _ in row["spans"]:
        masked[start:end] = ["\0"] * (end - start)
    return [re.sub("\0+", "<MASKED>", "".join(masked))]


def covered(start: int, end: int, text: str, spans: list) -> bool:
    return all(
        text[i].isspace() or any(s <= i < e for s, e, _ in spans)
        for i in range(start, end)
    )


def overlaps(start: int, end: int, spans: list) -> list:
    return [span for span in spans if span[0] < end and start < span[1]]


def pct(part: int, whole: int) -> str:
    return f"{part / whole:.1%}" if whole else "n/a"


def score(cases: dict, rows: list[dict]) -> dict:
    tally: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        case = cases[row["id"]]
        text, spans = case["text"], row["spans"]
        gold = [s for s in case["spans"] if not s["label"].startswith("NEG_")]
        negatives = [s for s in case["spans"] if s["label"].startswith("NEG_")]
        for g in gold:
            family = GOLD_FAMILY.get(g["label"], g["label"])
            sub = g.get("lang") or (g["label"] if g["label"] != family else None)
            keys = [family, *([f"{family}:{sub}"] if sub else [])]
            hit = covered(g["start"], g["end"], text, spans)
            touched = bool(overlaps(g["start"], g["end"], spans))
            for key in keys:
                tally[key]["n"] += 1
                tally[key]["tp" if hit else "fn"] += 1
                tally[key]["partial"] += touched and not hit
            value = text[g["start"] : g["end"]]
            for key in keys:
                tally[key]["leaked"] += leaked(value, sent(row, text))
        for s, e, kind in spans:
            if any(g["start"] < e and s < g["end"] for g in gold):
                continue
            family = FAMILY.get(kind, "OTHER")
            if overlaps(s, e, [[n["start"], n["end"], n["label"]] for n in negatives]):
                tally[family]["fp"] += 1
            elif family != "OTHER":
                tally[family]["fp"] += 1
            else:
                tally["OTHER"]["ignored"] += 1
        for n in negatives:
            tally[n["label"]]["n"] += 1
            tally[n["label"]]["hit"] += bool(overlaps(n["start"], n["end"], spans))
    return tally


def detection_tables(cases: dict, results: list[tuple[dict, list]]) -> str:
    scored = [(meta["label"], score(cases, rows)) for meta, rows in results]
    # Recall per type is type-agnostic (masked is masked); a false positive is counted
    # under the type the system gave it, so precision is only meaningful over all types.
    out = ["| Recall | n | " + " | ".join(label for label, _ in scored) + " |"]
    out.append("| --- | ---: |" + " ---: |" * len(scored))
    for family in FAMILIES:
        out.append(
            f"| {family} | {scored[0][1][family]['n']} | "
            + " | ".join(pct(t[family]["tp"], t[family]["n"]) for _, t in scored)
            + " |"
        )
    totals = []
    for _, t in scored:
        tp = sum(t[f]["tp"] for f in FAMILIES)
        n = sum(t[f]["n"] for f in FAMILIES)
        fp = sum(t[f]["fp"] for f in (*FAMILIES, "OTHER"))
        p, r = tp / (tp + fp) if tp + fp else 0.0, tp / n if n else 0.0
        totals.append((tp, n, fp, p, r, 2 * p * r / (p + r) if p + r else 0.0))
    n = totals[0][1]
    out.append(
        f"| **all types** | {n} | " + " | ".join(pct(x[0], x[1]) for x in totals) + " |"
    )
    out.append("| false positives | | " + " | ".join(str(x[2]) for x in totals) + " |")
    out.append(
        "| **precision** | | " + " | ".join(f"{x[3]:.1%}" for x in totals) + " |"
    )
    out.append("| **F1** | | " + " | ".join(f"{x[5]:.3f}" for x in totals) + " |")
    out.append(
        "| other-type detections, not scored | | "
        + " | ".join(str(t["OTHER"]["ignored"]) for _, t in scored)
        + " |"
    )
    out += [
        "",
        "| Subtype | n | "
        + " | ".join(f"{label} recall" for label, _ in scored)
        + " |",
    ]
    out.append("| --- | ---: |" + " ---: |" * len(scored))
    subtypes = sorted({k for _, t in scored for k in t if ":" in k})
    for key in subtypes:
        out.append(
            f"| {key} | {scored[0][1][key]['n']} | "
            + " | ".join(pct(t[key]["tp"], t[key]["n"]) for _, t in scored)
            + " |"
        )
    out += [
        "",
        "| Hard negative | n | "
        + " | ".join(f"{label} masked" for label, _ in scored)
        + " |",
    ]
    out.append("| --- | ---: |" + " ---: |" * len(scored))
    for key in sorted({k for _, t in scored for k in t if k.startswith("NEG_")}):
        out.append(
            f"| {key} | {scored[0][1][key]['n']} | "
            + " | ".join(pct(t[key]["hit"], t[key]["n"]) for _, t in scored)
            + " |"
        )
    out += [
        "",
        "| Leaked to the provider | n | "
        + " | ".join(label for label, _ in scored)
        + " |",
    ]
    out.append("| --- | ---: |" + " ---: |" * len(scored))
    for family in FAMILIES:
        out.append(
            f"| {family} | {scored[0][1][family]['n']} | "
            + " | ".join(
                f"{t[family]['leaked']} ({t[family]['partial']} partial)"
                for _, t in scored
            )
            + " |"
        )
    total = sum(scored[0][1][f]["n"] for f in FAMILIES)
    out.append(
        f"| all | {total} | "
        + " | ".join(str(sum(t[f]["leaked"] for f in FAMILIES)) for _, t in scored)
        + " |"
    )
    return "\n".join(out)


def evasion_table(cases: dict, results: list[tuple[dict, list]]) -> str:
    out = [
        "| Disguise | n | " + " | ".join(meta["label"] for meta, _ in results) + " |"
    ]
    out.append("| --- | ---: |" + " ---: |" * len(results))
    leaks: dict[str, list[Counter]] = defaultdict(lambda: [Counter() for _ in results])
    for column, (_, rows) in enumerate(results):
        for row in rows:
            case = cases[row["id"]]
            g = case["spans"][0]
            hit = leaked(g["value"], sent(row, case["text"]))
            for key in (case["disguise"], f"{case['disguise']}:{g['label']}"):
                leaks[key][column]["n"] += 1
                leaks[key][column]["leaked"] += hit
    for key in sorted(leaks, key=lambda k: (k.split(":")[0], ":" in k, k)):
        counters = leaks[key]
        label = key if ":" not in key else f"&nbsp;&nbsp;{key.split(':')[1]}"
        out.append(
            f"| {label} | {counters[0]['n']} | "
            + " | ".join(pct(c["leaked"], c["n"]) for c in counters)
            + " |"
        )
    return "\n".join(out)


def report(args: argparse.Namespace) -> None:
    corpora = {"corpus.jsonl": args.corpus, "evasion.jsonl": args.evasion}
    loaded = {name: {c["id"]: c for c in load(path)} for name, path in corpora.items()}
    results: dict[str, list[tuple[dict, list]]] = defaultdict(list)
    for path in args.results:
        meta, *rows = load(path)
        results[meta["meta"]["corpus"]].append((meta["meta"], rows))
    for meta, _ in results["corpus.jsonl"] + results["evasion.jsonl"]:
        print(
            f"- {meta['label']}: {meta['date']}, {meta['machine']}, Python {meta['python']}"
        )
    for name, path in corpora.items():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        print(f"- {name}: sha256 `{digest}`")
    if results["corpus.jsonl"]:
        print("\n### Detection\n")
        print(detection_tables(loaded["corpus.jsonl"], results["corpus.jsonl"]))
    if results["evasion.jsonl"]:
        print("\n### Evasion: identifiers that reached the provider\n")
        print(evasion_table(loaded["evasion.jsonl"], results["evasion.jsonl"]))
    print("\n### Egress\n")
    for meta, _ in results["corpus.jsonl"]:
        if "egress" in meta:
            print(
                f"- {meta['label']}: {json.dumps(meta['egress'], ensure_ascii=False)}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    commands = parser.add_subparsers(dest="command", required=True)
    runner = commands.add_parser("run")
    runner.add_argument(
        "--system", choices=("shim", "presidio", "litellm"), required=True
    )
    runner.add_argument("--corpus", type=Path, required=True)
    runner.add_argument("--out", type=Path, required=True)
    runner.add_argument(
        "--names",
        nargs="+",
        default=[],
        metavar="TYPE",
        help="shim: opt-in name types to mask, e.g. PERSON_NAME_TR PERSON_NAME_EN",
    )
    runner.add_argument("--url", default="http://127.0.0.1:4000", help="LiteLLM proxy")
    runner.add_argument(
        "--captures", type=Path, help="LiteLLM: the mock and relay logs"
    )
    reporter = commands.add_parser("report")
    reporter.add_argument("--corpus", type=Path, required=True)
    reporter.add_argument("--evasion", type=Path, required=True)
    reporter.add_argument("results", type=Path, nargs="+")
    args = parser.parse_args()
    if args.command == "run" and args.system == "litellm" and args.captures is None:
        parser.error("--captures is required for litellm")
    if args.command == "run":
        run(args)
    else:
        report(args)


if __name__ == "__main__":
    main()
