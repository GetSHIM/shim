"""What shim's cost levers save, measured on the providers' own bills.

Each lever runs the same requests through the community app in-process twice or more,
once per setting, against the real provider. The saving is read from the `usage` the
provider returned, priced at list prices from shim's model catalog (its version is
printed). The Turkish token tax uses the providers' free token-count endpoints and
does not go through shim.

    python -m scripts.bench.savings --env ../cli-shimbot/.env --out R.jsonl [--levers ...]
    python -m scripts.bench.savings --report R.jsonl

Keys are read from --env and sent only as request headers; nothing prints them.
Spend stops at --budget-usd (default 2), priced from each answer's usage.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import random
import tempfile
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import httpx

import shim
from shim.application import create_community_app
from shim.billing.pricing import DEFAULT_PRICE_BOOK
from shim.core.community_config import CommunitySettings

KEY = "shim-bench-gateway-key-0123456789"
HERE = Path(__file__).parent
_CATALOG = json.loads(
    (Path(shim.__file__).parent / "billing/model_catalog.json").read_text()
)
CATALOG, CATALOG_PRICES = _CATALOG["version"], _CATALOG["providers"]
# Per role, the models to try in order; the first one the keys reach is used, and the
# ids used are printed and recorded. The fallbacks support the same levers.
CANDIDATES = {
    "openai": ("gpt-5.6-luna", "gpt-5.6-terra"),
    # gpt-5.6 models are downscaled only at a set detail; the gpt-5.4 family always is.
    "openai_images": ("gpt-5.4-nano", "gpt-5.4-mini"),
    "anthropic": ("claude-haiku-5-5", "claude-haiku-4-5"),
    "google": ("gemini-3.8-flash", "gemini-flash-latest"),
}
TOKEN_MODELS = (
    "gpt-5.6-luna",
    "claude-haiku-5-5",
    "claude-haiku-4-5",
    "claude-sonnet-5-5",
    "gemini-3.8-flash",
)
MODELS = {role: models[0] for role, models in CANDIDATES.items()}
# Wikimedia Commons originals: (file, URL, SHA-1 from Commons, licence and credit).
IMAGES = (
    (
        "photo-12mp.jpg",
        "https://upload.wikimedia.org/wikipedia/commons/a/a3/Galata_Mevlevihanesi%2C_semahane_8354_Nevit.jpg",
        "cb542161da797274755a9b484ee5936e25c4d0e9",
        "CC BY-SA 3.0, Nevit Dilmen",
    ),
    (
        "photo-23mp.jpg",
        "https://upload.wikimedia.org/wikipedia/commons/a/a2/Istanbul_-_Galata_Tower.jpg",
        "16a6a1919ecb884796489729c8678874ddc760dc",
        "CC BY 4.0, Jorge Franganillo",
    ),
    (
        "scan.jpg",
        "https://upload.wikimedia.org/wikipedia/commons/c/c5/Canadian_forest_industries_1901-1902_%281902%29_%2820499573316%29.jpg",
        "8a30e9ee4b1033c77b4803bed26bf452049eb58c",
        "No known restrictions, Internet Archive Book Images",
    ),
    (
        "screenshot-ui.png",
        "https://upload.wikimedia.org/wikipedia/commons/b/b9/Instant_Diffs_screenshot_light_en.png",
        "c74f8a99f108ffed1c8e47fe1ab6f0c8edb921cd",
        "CC BY-SA 4.0, MediaWiki authors",
    ),
    (
        "screenshot-1080p.png",
        "https://upload.wikimedia.org/wikipedia/commons/a/aa/Screenshot_DarkCosmos_Alpha.png",
        "87ede83f95dfb0bdec9ceee751ed97e31c21d0ab",
        "CC BY-SA 4.0, Killarnee",
    ),
)
BASE_SETTINGS = {
    "SHIM_API_KEY": KEY,
    "BACKEND_CORS_ORIGINS": [],
    "GLOBAL_RATE_LIMIT_PER_MINUTE": 10_000,
    "DEFAULT_RPM_LIMIT": 10_000,
    "DEFAULT_TPM_LIMIT": 1_000_000_000,
    # Same in every arm: a masked value keeps its placeholder, so prefixes can cache.
    "PII_PLACEHOLDER_MODE": "stable",
    "PII_PLACEHOLDER_KEY": "shim-bench-placeholder-key-000000000000",
}


def orders(count: int) -> list[dict]:
    rng = random.Random(7)
    rows = []
    for n in range(count):
        status = rng.choice(
            ("delivered", "delivered", "delivered", "failed", "pending")
        )
        rows.append(
            {
                "id": f"ORD-2026-{n + 1:06d}",
                "status": status,
                "total": f"{rng.randint(100, 9_999)}.{rng.randint(0, 99):02d}",
                "currency": "TRY",
                "created_at": f"2026-10-{rng.randint(1, 14):02d}T{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:00Z",
                "items": [
                    {
                        "sku": f"SKU-{rng.randint(1_000, 9_999)}",
                        "quantity": rng.randint(1, 4),
                    }
                    for _ in range(rng.randint(1, 3))
                ],
                "failure_reason": rng.choice(
                    ("card_declined", "address_invalid", "out_of_stock")
                )
                if status == "failed"
                else None,
            }
        )
    return rows


NOUNS = {
    "order": "a customer order, with its items, totals and status",
    "invoice": "an invoice issued for one or more orders",
    "customer": "a customer account and its contact preferences",
    "shipment": "a shipment, its courier, tracking state and delivery address",
    "refund": "a refund against a paid order",
    "ticket": "a support ticket and its conversation",
    "subscription": "a recurring subscription and its billing period",
    "product": "a catalogue product, its price and stock level",
    "coupon": "a discount coupon and its usage limits",
    "payment": "a payment attempt and its processor result",
}
VERBS = {
    "get": "Fetch one {noun} by its id. Use this when the user names a specific {noun}.",
    "list": "List {noun}s matching filters, newest first. Use this to search or report.",
    "create": "Create {what}. Only call this when the user clearly asks for a new {noun}.",
    "update": "Change fields of an existing {noun}. Send only the fields that change.",
    "cancel": "Cancel {what}. This cannot be undone; confirm the id with the user first.",
}


def tools() -> list[dict]:
    """Fifty back-office tools, the size of a typical agent's MCP tool list."""
    out = []
    for noun, what in NOUNS.items():
        for verb, doc in VERBS.items():
            properties: dict = {
                f"{noun}_id": {"type": "string", "description": f"The {noun} id."}
            }
            if verb == "list":
                properties = {
                    "status": {"type": "string", "description": "Only this status."},
                    "from_date": {
                        "type": "string",
                        "description": "ISO date, inclusive.",
                    },
                    "to_date": {
                        "type": "string",
                        "description": "ISO date, inclusive.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "At most this many, 1 to 100.",
                    },
                }
            if verb in {"create", "update"}:
                properties |= {
                    "fields": {
                        "type": "object",
                        "description": f"The {noun} fields to set.",
                    },
                    "note": {
                        "type": "string",
                        "description": "Audit note shown to staff.",
                    },
                }
            if verb == "cancel":
                properties["reason"] = {
                    "type": "string",
                    "description": "Why it is cancelled.",
                }
            out.append(
                {
                    "name": f"{verb}_{noun}",
                    "description": doc.format(noun=noun, what=what),
                    "parameters": {
                        "type": "object",
                        "properties": properties,
                        "required": [f"{noun}_id"]
                        if verb in {"get", "update", "cancel"}
                        else [],
                    },
                }
            )
    return out


TASKS = (
    (
        "Order ORD-2026-004417 arrived broken. Issue a full refund for it now.",
        "create_refund",
    ),
    (
        "Change the delivery address of shipment SHP-88123 to Bagdat Caddesi 200, Kadikoy.",
        "update_shipment",
    ),
    (
        "Cancel subscription SUB-5531, the customer asked us to stop billing.",
        "cancel_subscription",
    ),
)


def responses_tools() -> list[dict]:
    return [{"type": "function", **tool} for tool in tools()]


def anthropic_tools() -> list[dict]:
    return [
        {
            "name": t["name"],
            "description": t["description"],
            "input_schema": t["parameters"],
        }
        for t in tools()
    ]


def cost(provider: str, model: str, usage: dict) -> tuple[int, int, Decimal]:
    """Billed input tokens, output tokens and list-price cost of one answer."""
    if provider == "anthropic":
        read = usage.get("cache_read_input_tokens") or 0
        write = usage.get("cache_creation_input_tokens") or 0
        tokens_in = (usage.get("input_tokens") or 0) + read + write
        tokens_out = usage.get("output_tokens") or 0
        split = (read, write, 0)
    else:
        details = (
            usage.get("prompt_tokens_details")
            or usage.get("input_tokens_details")
            or {}
        )
        tokens_in = usage.get("prompt_tokens") or usage.get("input_tokens") or 0
        tokens_out = usage.get("completion_tokens") or usage.get("output_tokens") or 0
        split = (details.get("cached_tokens") or 0, 0, 0)
    return (
        tokens_in,
        tokens_out,
        DEFAULT_PRICE_BOOK.compute(model, tokens_in, tokens_out, provider, split),
    )


class Runner:
    def __init__(self, keys: dict[str, str], out: Path, budget: Decimal) -> None:
        self.keys, self.out, self.budget, self.spent = keys, out, budget, Decimal(0)

    async def arm(
        self, lever: str, arm: str, settings: dict, requests: list[tuple]
    ) -> None:
        """Send (case, provider, model, path, body) requests through one app; record bills."""
        with tempfile.NamedTemporaryFile("w+", suffix=".jsonl", delete=False) as events:
            app = create_community_app(
                CommunitySettings(**BASE_SETTINGS, **settings, _env_file=None),
                event_stream=events,
            )
            rows = []
            stop = None
            async with (
                app.router.lifespan_context(app),
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app),
                    base_url="http://shim.test",
                    timeout=300,
                ) as http,
            ):
                for case, provider, model, path, body in requests:
                    if self.spent >= self.budget:
                        # Stop after writing what was already paid for, not before.
                        stop = f"budget of ${self.budget} reached, stopping"
                        break
                    headers = {
                        "Authorization": f"Bearer {KEY}",
                        "x-provider-key": self.keys[provider],
                        "anthropic-version": "2023-06-01",
                    }
                    try:
                        reply = await http.post(path, json=body, headers=headers)
                    except httpx.TransportError as error:
                        # Recorded as a failed request; the arm's earlier rows still land.
                        reply = httpx.Response(599, text=repr(error)[:500])
                    try:
                        answer = reply.json()
                    except ValueError:
                        answer = {"error": reply.text[:500]}
                    usage = answer.get("usage") or {}
                    tokens_in, tokens_out, usd = cost(provider, model, usage)
                    self.spent += usd
                    rows.append(
                        {
                            "lever": lever,
                            "arm": arm,
                            "case": case,
                            "provider": provider,
                            "model": model,
                            "status": reply.status_code,
                            "request_bytes": len(json.dumps(body)),
                            "input_tokens": tokens_in,
                            "output_tokens": tokens_out,
                            "usd": str(usd),
                            "usage": usage,
                            "tools_called": called_tools(answer),
                            "error": None
                            if reply.is_success
                            else answer.get("error", answer),
                            "request_id": reply.headers.get("X-Shim-Request-Id"),
                        }
                    )
            events.seek(0)
            by_id = {
                e.get("request_id"): e
                for e in map(json.loads, events.read().splitlines())
                if e.get("event") == "request"
            }
        os.unlink(events.name)
        with self.out.open("a", encoding="utf-8") as out:
            for row in rows:
                event = by_id.get(row["request_id"], {})
                row["shim"] = {
                    key: event.get(key)
                    for key in (
                        "settings_applied",
                        "transforms_applied",
                        "savings",
                        "policy_verdicts",
                    )
                }
                out.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(
            f"{lever:>16} {arm:>10}: {len(rows)} requests, spent so far ${self.spent:.4f}"
        )
        if stop:
            raise SystemExit(stop)


def called_tools(answer: dict) -> list[str]:
    names = [
        b.get("name")
        for b in answer.get("content") or []
        if b.get("type") == "tool_use"
    ]
    names += [
        i.get("name")
        for i in answer.get("output") or []
        if i.get("type") == "function_call"
    ]
    for choice in answer.get("choices") or []:
        names += [
            c["function"]["name"] for c in choice["message"].get("tool_calls") or []
        ]
    return names


async def json_compaction(run: Runner) -> None:
    """S56: a pretty-printed tool result, billed with and without its whitespace."""
    result = json.dumps(orders(150), indent=2)
    question = "Which orders failed and why? Answer in two sentences."
    # gpt-5.6 refuses function tools on chat completions with reasoning on: Responses.
    responses = {
        "model": MODELS["openai"],
        "max_output_tokens": 2_000,
        "tools": responses_tools(),
        "input": [
            {"role": "user", "content": question},
            {
                "type": "function_call",
                "call_id": "call_1",
                "name": "list_order",
                "arguments": "{}",
            },
            {"type": "function_call_output", "call_id": "call_1", "output": result},
        ],
    }
    messages = {
        "model": MODELS["anthropic"],
        "max_tokens": 300,
        "tools": anthropic_tools(),
        "messages": [
            {"role": "user", "content": question},
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_1",
                        "name": "list_order",
                        "input": {},
                    }
                ],
            },
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1", "content": result}
                ],
            },
        ],
    }
    requests = [
        ("orders-150", "openai", MODELS["openai"], "/v1/responses", responses),
        ("orders-150", "anthropic", MODELS["anthropic"], "/v1/messages", messages),
    ]
    for arm in ("off", "on"):
        await run.arm("json_compaction", arm, {"SHIM_JSON_COMPACTION": arm}, requests)


async def tool_search(run: Runner) -> None:
    """S55: a 50-tool agent; tools deferred and found through the provider's tool search."""
    requests = []
    for text, expected in TASKS:
        requests.append(
            (
                expected,
                "anthropic",
                MODELS["anthropic"],
                "/v1/messages",
                {
                    "model": MODELS["anthropic"],
                    "max_tokens": 500,
                    "tools": anthropic_tools(),
                    "messages": [{"role": "user", "content": text}],
                },
            )
        )
        requests.append(
            (
                expected,
                "openai",
                MODELS["openai"],
                "/v1/responses",
                {
                    "model": MODELS["openai"],
                    "max_output_tokens": 2_000,
                    "tools": responses_tools(),
                    "input": text,
                },
            )
        )
    for arm in ("off", "regex", "bm25"):
        await run.arm("tool_search", arm, {"SHIM_TOOL_SEARCH": arm}, requests)


async def prompt_cache(run: Runner, turns: int = 8) -> None:
    """S54: a long prefix sent again and again, with the cache settings off and on.

    Two shapes: independent questions over one system prompt (a support bot), and one
    conversation that grows by a turn per request (an agent or a chat).
    """
    # About 17,000 Anthropic and 13,500 OpenAI tokens: above every minimum cacheable prefix.
    context = "Order export for the support team:\n" + json.dumps(orders(150))
    questions = [
        f"How many orders were created on 2026-10-{day:02d}? Reply with a number."
        for day in range(1, turns + 1)
    ]
    settings = {
        "SHIM_ANTHROPIC_AUTO_CACHE": "5m",
        "SHIM_OPENAI_PROMPT_CACHE_KEY": "key",
    }
    for lever, growing in (
        ("prompt_cache", False),
        ("prompt_cache_conversation", True),
    ):
        for arm, arm_settings in (("off", {}), ("on", settings)):
            # A fresh prefix per arm: nothing cached by an earlier run or arm.
            system = f"Session {uuid.uuid4()}.\n{context}"
            requests = []
            for n in range(turns):
                if growing:
                    history = []
                    for question in questions[:n]:
                        history += [
                            {"role": "user", "content": question},
                            {"role": "assistant", "content": "Noted."},
                        ]
                    turn = [*history, {"role": "user", "content": questions[n]}]
                else:
                    turn = [{"role": "user", "content": questions[n]}]
                requests.append(
                    (
                        f"turn-{n}",
                        "anthropic",
                        MODELS["anthropic"],
                        "/v1/messages",
                        {
                            "model": MODELS["anthropic"],
                            "max_tokens": 50,
                            "system": system,
                            "messages": turn,
                        },
                    )
                )
                requests.append(
                    (
                        f"turn-{n}",
                        "openai",
                        MODELS["openai"],
                        "/v1/chat/completions",
                        {
                            "model": MODELS["openai"],
                            "max_completion_tokens": 1_000,
                            "messages": [{"role": "system", "content": system}, *turn],
                        },
                    )
                )
            await run.arm(lever, arm, arm_settings, requests)


def image_bytes(cache: Path) -> list[tuple[str, bytes]]:
    cache.mkdir(parents=True, exist_ok=True)
    out = []
    for name, url, sha1, _ in IMAGES:
        path = cache / name
        data = path.read_bytes() if path.exists() else b""
        if hashlib.sha1(data).hexdigest() != sha1:
            reply = httpx.get(
                url,
                # Wikimedia refuses clients that do not name themselves.
                headers={
                    "User-Agent": "shim-bench/1.0 (https://github.com/GetSHIM/shim)"
                },
                follow_redirects=True,
                timeout=120,
            )
            reply.raise_for_status()
            data = reply.content
            if hashlib.sha1(data).hexdigest() != sha1:
                raise SystemExit(
                    f"{name}: SHA-1 does not match the pinned Commons file"
                )
            path.write_bytes(data)
        out.append((name, data))
    return out


async def images(run: Runner, cache: Path) -> None:
    """S64 image downscaling (bytes; the docs expect no token change), plus image detail."""
    prompt = "Describe this image in one sentence."
    downscale, detail = [], []
    for name, data in image_bytes(cache):
        kind = "image/png" if name.endswith(".png") else "image/jpeg"
        b64 = base64.b64encode(data).decode()
        url = f"data:{kind};base64,{b64}"
        downscale.append(
            (
                name,
                "anthropic",
                MODELS["anthropic"],
                "/v1/messages",
                {
                    "model": MODELS["anthropic"],
                    "max_tokens": 100,
                    "messages": [
                        {
                            "role": "user",
                            "content": [
                                {
                                    "type": "image",
                                    "source": {
                                        "type": "base64",
                                        "media_type": kind,
                                        "data": b64,
                                    },
                                },
                                {"type": "text", "text": prompt},
                            ],
                        }
                    ],
                },
            )
        )
        for model, target in (
            (MODELS["openai_images"], downscale),
            (MODELS["openai"], detail),
        ):
            target.append(
                (
                    name,
                    "openai",
                    model,
                    "/v1/chat/completions",
                    {
                        "model": model,
                        "max_completion_tokens": 1_000,
                        "messages": [
                            {
                                "role": "user",
                                "content": [
                                    {"type": "text", "text": prompt},
                                    {"type": "image_url", "image_url": {"url": url}},
                                ],
                            }
                        ],
                    },
                )
            )
    media = {"SHIM_MEDIA_INPUTS": "allow"}
    for arm in ("off", "on"):
        await run.arm(
            "image_downscale", arm, media | {"SHIM_IMAGE_DOWNSCALE": arm}, downscale
        )
    for arm in ("off", "low"):
        await run.arm(
            "image_detail", arm, media | {"SHIM_IMAGE_DETAIL_OPENAI": arm}, detail
        )


async def token_tax(keys: dict[str, str], out: Path, models: list[str]) -> None:
    """Tokens per character for parallel Turkish and English texts, from free count calls."""
    pairs = json.loads((HERE / "data/parallel_tr_en.json").read_text())["pairs"]
    texts = {lang: "\n\n".join(p[lang] for p in pairs) for lang in ("tr", "en")}
    async with httpx.AsyncClient(timeout=60) as http:
        with out.open("a", encoding="utf-8") as log:
            for model in models:
                counts = {}
                for lang, text in texts.items():
                    if model.startswith("claude"):
                        reply = await http.post(
                            "https://api.anthropic.com/v1/messages/count_tokens",
                            headers={
                                "x-api-key": keys["anthropic"],
                                "anthropic-version": "2023-06-01",
                            },
                            json={
                                "model": model,
                                "messages": [{"role": "user", "content": text}],
                            },
                        )
                        counts[lang] = reply.json()["input_tokens"]
                    elif model.startswith("gemini"):
                        reply = await http.post(
                            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:countTokens",
                            headers={"x-goog-api-key": keys["google"]},
                            json={"contents": [{"parts": [{"text": text}]}]},
                        )
                        counts[lang] = reply.json()["totalTokens"]
                    else:
                        reply = await http.post(
                            "https://api.openai.com/v1/responses/input_tokens",
                            headers={"Authorization": f"Bearer {keys['openai']}"},
                            json={"model": model, "input": text},
                        )
                        counts[lang] = reply.json()["input_tokens"]
                row = {
                    "lever": "token_tax",
                    "model": model,
                    "tokens": counts,
                    "characters": {lang: len(text) for lang, text in texts.items()},
                }
                log.write(json.dumps(row) + "\n")
                print(f"token_tax {model}: {counts}")


# A task is handled when the model calls a tool for the right record: looking the order
# up before refunding it is as right as refunding it at once.
RELEVANT = {
    "create_refund": {"create_refund", "get_order", "get_refund"},
    "update_shipment": {"update_shipment", "get_shipment"},
    "cancel_subscription": {"cancel_subscription", "get_subscription"},
}


def input_usd(row: dict) -> Decimal:
    """Input cost at the catalog's list prices.

    shim's own accounting bills an OpenAI token it cannot see as cached at the higher
    cache-write price; a benchmark of savings uses the plain list input price. Only the
    cache levers get cache rates: a hit elsewhere (the previous arm sent the same image)
    is not the lever's saving.
    """
    price = CATALOG_PRICES[row["provider"]][row["model"]]
    rate = Decimal(price["input_per_million"])
    usage = row["usage"]
    read = write = 0
    if row["lever"].startswith("prompt_cache"):
        details = (
            usage.get("prompt_tokens_details")
            or usage.get("input_tokens_details")
            or {}
        )
        read = usage.get("cache_read_input_tokens") or details.get("cached_tokens") or 0
        write = usage.get("cache_creation_input_tokens") or 0
    read_rate = Decimal(
        price.get("cache_read_per_million") or price["input_per_million"]
    )
    write_rate = Decimal(price.get("cache_write_per_million") or rate * Decimal("1.25"))
    plain = row["input_tokens"] - read - write
    return (plain * rate + read * read_rate + write * write_rate) / 1_000_000


def report(path: Path) -> None:
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    print(f"Prices: shim model catalog `{CATALOG}`, list input prices.")
    for row in rows:
        if row["lever"] == "meta":
            print(f"Models used: {row['models']}; token tax: {row['token_models']}")
    rows = [row for row in rows if row["lever"] != "meta"]
    groups: dict[tuple, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        if row["lever"] != "token_tax":
            groups[(row["lever"], row["model"], row["arm"])][row["case"]].append(row)
    print(
        "\nPaired: only cases that succeeded in both arms; per case, the mean over runs.\n"
        "\n| Lever | Model | Arm | cases | failed | input tokens / request | cache read share | "
        "characters shim removed / request | input USD / request | input saved vs off | "
        "USD saved per 1M requests |"
    )
    print("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for key in sorted(groups):
        lever, model, arm = key
        cases = groups[key]
        failed = sum(r["status"] != 200 for runs in cases.values() for r in runs)
        base = groups.get((lever, model, "off"), {})
        ok = sorted(
            case
            for case in cases
            if all(r["status"] == 200 for r in cases[case])
            and (
                arm == "off"
                or (case in base and all(r["status"] == 200 for r in base[case]))
            )
        )
        if not ok:
            print(f"| {lever} | {model} | {arm} | 0 | {failed} | | | | | | |")
            continue

        def mean(values: list) -> float:
            return sum(values) / len(values)

        def per_case(arm_cases: dict, field) -> list:
            return [mean([field(r) for r in arm_cases[case]]) for case in ok]

        tokens = mean(per_case(cases, lambda r: r["input_tokens"]))
        usd = mean(per_case(cases, lambda r: float(input_usd(r))))
        reads = sum(
            r["usage"].get("cache_read_input_tokens")
            or (
                r["usage"].get("prompt_tokens_details")
                or r["usage"].get("input_tokens_details")
                or {}
            ).get("cached_tokens")
            or 0
            for case in ok
            for r in cases[case]
        )
        share = reads / sum(r["input_tokens"] for case in ok for r in cases[case])
        removed = mean(
            per_case(
                cases,
                lambda r: sum(
                    t["before_chars"] - t["after_chars"]
                    for t in r["shim"]["transforms_applied"] or []
                ),
            )
        )
        saved = per_million = ""
        if arm != "off":
            base_usd = mean(per_case(base, lambda r: float(input_usd(r))))
            saved = f"{1 - usd / base_usd:.1%}"
            per_million = f"{(base_usd - usd) * 1_000_000:,.0f}"
        print(
            f"| {lever} | {model} | {arm} | {len(ok)} | {failed} | {tokens:,.0f} | {share:.0%} | "
            f"{removed:,.0f} | {usd:.8f} | {saved} | {per_million} |"
        )
    tool_rows = [r for r in rows if r["lever"] == "tool_search"]
    if tool_rows:
        handled: dict[tuple, list[int]] = defaultdict(lambda: [0, 0])
        for r in tool_rows:
            handled[(r["model"], r["arm"])][0] += bool(
                RELEVANT[r["case"]] & set(r["tools_called"])
            )
            handled[(r["model"], r["arm"])][1] += 1
        print(
            "\nTool search, tasks where the model called a tool for the right record: "
            + ", ".join(
                f"{m} {a} {h}/{n}" for (m, a), (h, n) in sorted(handled.items())
            )
        )
        print(
            "Tools called: "
            + "; ".join(
                f"{r['model']} {r['arm']} {r['case']}: {r['tools_called']}"
                for r in tool_rows
            )
        )
    print(
        "\n| Model | TR tokens | EN tokens | TR tokens per 1k characters | EN tokens per 1k characters | TR ÷ EN tokens, same text |"
    )
    print("| --- | ---: | ---: | ---: | ---: | ---: |")
    for row in (r for r in rows if r["lever"] == "token_tax"):
        t, c = row["tokens"], row["characters"]
        print(
            f"| {row['model']} | {t['tr']} | {t['en']} | {1000 * t['tr'] / c['tr']:.1f} | "
            f"{1000 * t['en'] / c['en']:.1f} | {t['tr'] / t['en']:.2f}× |"
        )


def read_keys(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text().splitlines():
        name, sep, value = line.partition("=")
        if sep and not name.lstrip().startswith("#"):
            values[name.strip()] = value.strip().strip("'\"")
    return {
        provider: values[variable]
        for provider, variable in (
            ("openai", "OPENAI_API_KEY"),
            ("anthropic", "ANTHROPIC_API_KEY"),
            ("google", "GOOGLE_API_KEY"),
        )
        if values.get(variable)
    }


def provider_of(model: str) -> str:
    return (
        "anthropic"
        if model.startswith("claude")
        else "google"
        if model.startswith("gemini")
        else "openai"
    )


async def reachable(keys: dict[str, str], model: str) -> bool:
    """The provider lists the model for this key (a free metadata call)."""
    provider = provider_of(model)
    if provider not in keys:
        return False
    url, headers = {
        "anthropic": (
            f"https://api.anthropic.com/v1/models/{model}",
            {"x-api-key": keys.get("anthropic", ""), "anthropic-version": "2023-06-01"},
        ),
        "google": (
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}",
            {"x-goog-api-key": keys.get("google", "")},
        ),
        "openai": (
            f"https://api.openai.com/v1/models/{model}",
            {"Authorization": f"Bearer {keys.get('openai', '')}"},
        ),
    }[provider]
    async with httpx.AsyncClient(timeout=30) as http:
        return (await http.get(url, headers=headers)).status_code == 200


async def main_async(args: argparse.Namespace) -> None:
    keys = read_keys(args.env)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.touch()
    print(f"{datetime.now(UTC).isoformat(timespec='seconds')} catalog {CATALOG}")
    for role, candidates in CANDIDATES.items():
        found = [model for model in candidates if await reachable(keys, model)]
        if not found:
            raise SystemExit(
                f"no {role} model is reachable: tried {', '.join(candidates)}"
            )
        MODELS[role] = found[0]
    token_models = [m for m in args.token_models if await reachable(keys, m)]
    skipped = sorted(set(args.token_models) - set(token_models))
    with args.out.open("a", encoding="utf-8") as out:
        meta = {"models": MODELS, "token_models": token_models, "unreachable": skipped}
        out.write(json.dumps({"lever": "meta", "catalog": CATALOG, **meta}) + "\n")
    print(f"models used: {MODELS}; token tax: {token_models}; unreachable: {skipped}")
    run = Runner(keys, args.out, Decimal(str(args.budget_usd)))
    if "json_compaction" in args.levers:
        await json_compaction(run)
    if "tool_search" in args.levers:
        await tool_search(run)
    if "prompt_cache" in args.levers:
        await prompt_cache(run)
    if "images" in args.levers:
        await images(run, args.image_cache)
    if "token_tax" in args.levers:
        await token_tax(keys, args.out, token_models)
    print(f"spent ${run.spent:.4f} at list prices")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    levers = ("json_compaction", "tool_search", "prompt_cache", "images", "token_tax")
    parser.add_argument(
        "--env",
        type=Path,
        help="file with OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY",
    )
    parser.add_argument("--out", type=Path)
    parser.add_argument("--levers", nargs="+", choices=levers, default=list(levers))
    parser.add_argument("--budget-usd", type=float, default=2.0)
    parser.add_argument("--image-cache", type=Path, default=HERE / "results/images")
    parser.add_argument(
        "--token-models",
        nargs="+",
        default=list(TOKEN_MODELS),
    )
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.report:
        report(args.report)
    elif args.env and args.out:
        asyncio.run(main_async(args))
    else:
        parser.error("--env and --out, or --report, are required")


if __name__ == "__main__":
    main()
