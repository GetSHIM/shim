"""An instant OpenAI-shaped upstream, or a recording relay in front of Presidio.

Standard library only; runs in a plain python image.

- Without RELAY_TO it answers every chat completion at once with a fixed reply.
- With RELAY_TO it forwards each request there and returns the answer unchanged.

With RECORD set, each request (and, for the relay, its answer) is appended to that
JSONL file before the reply is sent, so a client that has its response can read it.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RELAY_TO = os.environ.get("RELAY_TO", "").rstrip("/")
RECORD = os.environ.get("RECORD")
COMPLETION = json.dumps(
    {
        "id": "chatcmpl-bench",
        "object": "chat.completion",
        "created": 1,
        "model": "gpt-5.6-luna",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "ok"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
    }
).encode()
lock = threading.Lock()


def record(entry: dict) -> None:
    if RECORD:
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        with lock, open(RECORD, "a", encoding="utf-8") as log:
            log.write(line)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # Keep-alive, as a real provider offers.
    # Headers and body go out as two writes; with Nagle on, the body waits for the
    # client's delayed ACK, about 40 ms on every keep-alive request.
    disable_nagle_algorithm = True

    def reply(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self.reply(
            200,
            b'{"object": "list", "data": [{"id": "gpt-5.6-luna", "object": "model"}]}',
        )

    def do_POST(self) -> None:
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if not RELAY_TO:
            record({"path": self.path, "body": json.loads(raw or b"{}")})
            return self.reply(200, COMPLETION)
        forward = urllib.request.Request(
            RELAY_TO + self.path,
            data=raw,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(forward, timeout=120) as answer:
                status, body = answer.status, answer.read()
        except urllib.error.HTTPError as error:
            status, body = error.code, error.read()
        record(
            {
                "path": self.path,
                "status": status,
                "request": json.loads(raw),
                "response": json.loads(body),
            }
        )
        self.reply(status, body)

    def log_message(self, format: str, *args: object) -> None:
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(
        ("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler
    ).serve_forever()
