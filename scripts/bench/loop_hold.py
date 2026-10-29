"""How long building one provider request holds the event loop (S10).

Each provider SDK walks every turn and content part of a body before sending it.
This times the longest gap a 1 ms ticker sees while one request (or several at
once) is built and sent to a local mock, first with the SDK call as it was, then
with the gateway's off-loop path (``transform_off_loop``, ``_sdk_contents``).
No network, no keys. Run: ``uv run python scripts/bench/loop_hold.py``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
import time

import anthropic
from anthropic._utils import maybe_transform as anthropic_transform
from google import genai
from google.genai import types
import httpx
import openai
from openai._utils import maybe_transform as openai_transform

from shim.gateway.pipeline.google_execution import _CONTENTS_PLACEHOLDER, _sdk_contents
from shim.gateway.pipeline.provider_execution import transform_off_loop

TURNS = (6_000, 18_000)
CONCURRENT = 4


def _answer(request: httpx.Request) -> httpx.Response:
    return httpx.Response(400, json={"error": {"code": 400, "message": "stop"}})


def _http() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(_answer))


def _chat(turns: int) -> list[dict]:
    messages: list[dict] = []
    for index in range(turns // 3):
        messages += [
            {"role": "user", "content": [{"type": "text", "text": f"q{index}"}] * 4},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": f"c{index}",
                        "type": "function",
                        "function": {"name": "f", "arguments": "{}"},
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": f"c{index}",
                "content": [{"type": "text", "text": "r"}] * 3,
            },
        ]
    return messages


def _messages(turns: int) -> list[dict]:
    messages: list[dict] = []
    for index in range(turns // 2):
        messages += [
            {"role": "user", "content": [{"type": "text", "text": f"q{index}"}] * 4},
            {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": f"t{index}", "name": "f", "input": {}}
                ],
            },
        ]
    return messages + [{"role": "user", "content": "go on"}]


def _contents(turns: int) -> list[dict]:
    contents: list[dict] = []
    for index in range(turns // 3):
        contents += [
            {"role": "user", "parts": [{"text": f"q{index}"}] * 4},
            {"role": "model", "parts": [{"functionCall": {"name": "f", "args": {}}}]},
            {
                "role": "user",
                "parts": [{"functionResponse": {"name": "f", "response": {"r": index}}}]
                * 3,
            },
        ]
    return contents


async def _hold(calls: list[Callable[[], Awaitable[object]]]) -> float:
    worst, done = 0.0, False

    async def tick() -> None:
        nonlocal worst
        last = time.perf_counter()
        while not done:
            await asyncio.sleep(0.001)
            now = time.perf_counter()
            worst, last = max(worst, now - last), now

    ticker = asyncio.create_task(tick())
    await asyncio.sleep(0.02)
    await asyncio.gather(*(call() for call in calls), return_exceptions=True)
    done = True
    await ticker
    return worst


async def _openai(turns: int, off_loop: bool) -> None:
    client = openai.AsyncOpenAI(api_key="k", max_retries=0, http_client=_http())
    create = client.chat.completions.create
    kwargs = {"model": "gpt-5.6-luna", "messages": _chat(turns)}
    if off_loop:
        kwargs = await transform_off_loop(create, kwargs, openai_transform)
    await create(**kwargs)


async def _anthropic(turns: int, off_loop: bool) -> None:
    client = anthropic.AsyncAnthropic(api_key="k", max_retries=0, http_client=_http())
    create = client.messages.create
    kwargs = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 16,
        "messages": _messages(turns),
    }
    if off_loop:
        kwargs = await transform_off_loop(create, kwargs, anthropic_transform)
    await create(**kwargs)


async def _google(turns: int, off_loop: bool) -> None:
    contents: object = _contents(turns)
    extra = None
    if off_loop:
        extra = {
            "contents": await asyncio.to_thread(
                _sdk_contents, "gemini-3.5-flash", contents
            )
        }
        contents = _CONTENTS_PLACEHOLDER
    client = genai.Client(
        api_key="k",
        http_options=types.HttpOptions(
            api_version="v1beta",
            retry_options=types.HttpRetryOptions(attempts=1),
            httpx_async_client=_http(),
            extra_body=extra,
        ),
    )
    await client.aio.models.generate_content(
        model="gemini-3.5-flash", contents=contents
    )


async def main() -> None:
    providers = {
        "openai chat": _openai,
        "anthropic messages": _anthropic,
        "google generateContent": _google,
    }
    print(
        "| Provider | Turns | Before, 1 request | After, 1 request | After, 4 at once |"
    )
    print("| --- | ---: | ---: | ---: | ---: |")
    for name, build in providers.items():
        await _hold([lambda: build(100, True)])  # one-time SDK setup is not the walk
        for turns in TURNS:
            before = await _hold([lambda: build(turns, False)])
            after = await _hold([lambda: build(turns, True)])
            together = await _hold([lambda: build(turns, True)] * CONCURRENT)
            print(
                f"| {name} | {turns:,} | {before * 1000:,.0f} ms | "
                f"{after * 1000:,.0f} ms | {together * 1000:,.0f} ms |"
            )


if __name__ == "__main__":
    asyncio.run(main())
