"""Measure the gateway's own overhead per request, with an instant fake provider.

Runs the community app in-process, so the numbers are middleware cost
(authenticate, admission, privacy, spend, postprocess) plus the ASGI hop, not network.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from statistics import median, quantiles
from time import perf_counter

import httpx

from shim.application import create_community_app
from shim.core.community_config import CommunitySettings

KEY = "shim-bench-gateway-key-0123456789"
MODEL = "gpt-5.6-luna"
PROSE = (
    "Müşteri hizmetleri ekibi dün gelen talepleri gözden geçirdi and agreed on a new "
    "escalation order. Faturalandırma sorunları öncelikli, while feature requests go "
    "to the product backlog. Lütfen yanıtları kısa tutun; the customer prefers short, "
    "plain answers, özellikle teknik olmayan konularda. "
)
PII = " Contact: ayse.demir@example.com, TCKN 10000000146, IBAN TR33 0006 1005 1978 6457 8413 26. "
COMPLETION = {
    "id": "chatcmpl_bench",
    "object": "chat.completion",
    "created": 1,
    "model": MODEL,
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
}


def prompt(size_kb: int, serial: int) -> str:
    """size_kb * 1,000 characters of prose with PII at the start, middle and end.

    The serial defeats the repeat-loop detector. 50 KB is also /v1/scan's input cap.
    """
    head = f"#{serial}{PII}"
    body_length = size_kb * 1_000 - len(head) - 2 * len(PII)
    body = (PROSE * (body_length // len(PROSE) + 1))[:body_length]
    half = body_length // 2
    return f"{head}{body[:half]}{PII}{body[half:]}{PII}"


def percentiles(samples: list[float]) -> str:
    cuts = quantiles(samples, n=100, method="inclusive")
    return f"{cuts[49]:7.1f} {cuts[94]:7.1f} {cuts[98]:7.1f}"


async def main(
    sizes: list[int], requests: int, warmup: int, entity_actions: dict
) -> None:
    logging.disable(logging.INFO)

    async def upstream(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=COMPLETION)

    settings = CommunitySettings(
        OPENAI_BASE_URL="https://upstream.test/v1",
        BACKEND_CORS_ORIGINS=[],
        SHIM_API_KEY=KEY,
        GLOBAL_RATE_LIMIT_PER_MINUTE=10_000_000,
        DEFAULT_RPM_LIMIT=10_000_000,
        DEFAULT_TPM_LIMIT=10_000_000_000,
        PII_ENTITY_ACTIONS=entity_actions,
        _env_file=None,
    )
    app = create_community_app(
        settings,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
        event_stream=open(os.devnull, "w"),
    )
    headers = {"Authorization": f"Bearer {KEY}", "x-provider-key": "sk-bench-provider"}
    print(
        "ms         chat wall (p50 p95 p99) | X-Shim-Latency-Ms (p50 p95 p99) | scan (p50 p95 p99) | privacy share"
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://shim.test",
            headers=headers,
        ) as http,
    ):

        async def timed_post(path: str, body: dict) -> tuple[float, httpx.Response]:
            started = perf_counter()
            reply = await http.post(path, json=body)
            elapsed = (perf_counter() - started) * 1_000
            reply.raise_for_status()
            return elapsed, reply

        serial = 0
        for size_kb in sizes:
            chat, header, scan = [], [], []
            for index in range(warmup + requests):
                serial += 1
                text = prompt(size_kb, serial)
                messages = [{"role": "user", "content": text}]
                elapsed, reply = await timed_post(
                    "/v1/chat/completions", {"model": MODEL, "messages": messages}
                )
                scan_elapsed, _ = await timed_post("/v1/scan", {"text": text})
                if index >= warmup:
                    chat.append(elapsed)
                    header.append(float(reply.headers["X-Shim-Latency-Ms"]))
                    scan.append(scan_elapsed)
            share = median(scan) / median(chat)
            print(
                f"{size_kb:>4} KB   {percentiles(chat)} | {percentiles(header)} | "
                f"{percentiles(scan)} | {share:.0%}"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sizes", type=int, nargs="+", default=[1, 32, 50], help="prompt sizes in KB"
    )
    parser.add_argument(
        "--requests", type=int, default=200, help="measured requests per size"
    )
    parser.add_argument(
        "--warmup", type=int, default=20, help="discarded requests per size"
    )
    parser.add_argument(
        "--entity-actions",
        type=json.loads,
        default={},
        help='PII_ENTITY_ACTIONS as JSON, e.g. \'{"PERSON_NAME_EN": "mask"}\'',
    )
    args = parser.parse_args()
    asyncio.run(main(args.sizes, args.requests, args.warmup, args.entity_actions))
