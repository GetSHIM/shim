"""Disposable TLS fixture and smoke client; never include in a release image."""

from __future__ import annotations

from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urljoin

import httpx


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass  # Authorization codes, session cookies, and credentials are not logs.

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def do_DELETE(self):
        self.respond()

    def respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        port = self.server.server_port
        if port in {8443, 8444}:
            origin = (
                "http://smoke-dashboard:3000" if port == 8443 else "http://vault:8200"
            )
            headers = {
                key: value
                for key, value in self.headers.items()
                if key.lower() not in {"host", "connection", "content-length"}
            }
            with httpx.Client(trust_env=False, timeout=30) as client:
                result = client.request(
                    self.command, origin + self.path, headers=headers, content=body
                )
            self.send_response(result.status_code)
            for key, value in result.headers.multi_items():
                if key.lower() not in {
                    "connection",
                    "content-length",
                    "transfer-encoding",
                    "content-encoding",
                }:
                    self.send_header(key, value)
            output = result.content
        else:
            assert self.command == "POST", "Only native model POSTs are expected"
            payload = json.loads(body)
            assert payload["messages"] and not payload.get("stream"), (
                "Nonstream smoke contract"
            )
            if self.path == "/openai/chat/completions":
                assert (
                    self.headers.get("Authorization")
                    == "Bearer disposable-model-secret"
                )
                result_body = {
                    "id": "chatcmpl-smoke",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": payload["model"],
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "internal openai fixture",
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 7,
                        "completion_tokens": 4,
                        "total_tokens": 11,
                    },
                }
            else:
                assert self.path == "/anthropic/v1/messages", self.path
                assert self.headers.get("x-api-key") == "disposable-model-secret"
                result_body = {
                    "id": "msg-smoke",
                    "type": "message",
                    "role": "assistant",
                    "model": payload["model"],
                    "content": [{"type": "text", "text": "internal anthropic fixture"}],
                    "stop_reason": "end_turn",
                    "stop_sequence": None,
                    "usage": {"input_tokens": 7, "output_tokens": 4},
                }
            output = json.dumps(result_body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(output)))
        self.end_headers()
        self.wfile.write(output)


def serve():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    for port in (8443, 8444, 8445):
        server = ThreadingHTTPServer(("0.0.0.0", port), Fixture)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Event().wait()


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None
        self.fields = {}

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "form" and values.get("id") == "kc-form-login":
            self.action = values["action"]
        if tag == "input" and values.get("name") and values.get("type") == "hidden":
            self.fields[values["name"]] = values.get("value", "")


def denied():
    for address in ("1.1.1.1", "8.8.8.8"):
        try:
            with socket.create_connection((address, 443), timeout=3):
                raise AssertionError(f"Public egress is reachable: {address}")
        except (TimeoutError, OSError):
            pass
    print("PASS public-IP egress denied from gateway pod", flush=True)


def smoke():
    denied()
    context = ssl.create_default_context(cafile="/var/run/shim-ca/ca.pem")
    origin = "https://fixture:8443"
    with httpx.Client(
        verify=context, timeout=30, follow_redirects=True, trust_env=False
    ) as client:
        response = client.get(origin + "/api/v1/auth/login")
        response.raise_for_status()
        form = LoginForm()
        form.feed(response.text)
        assert form.action, "Keycloak login form missing"
        response = client.post(
            urljoin(str(response.url), form.action),
            data=form.fields
            | {"username": "pilot", "password": "disposable-pilot-password"},
        )
        response.raise_for_status()
        assert response.url.path == "/dashboard", response.url.path
        assert client.cookies.get("shim_session")
        session = client.get(origin + "/api/v1/auth/session")
        session.raise_for_status()
        assert session.json()["user"]["role"] == "owner"
        client.headers["Origin"] = origin

        def api(method, path, **kwargs):
            response = client.request(method, origin + "/api/v1" + path, **kwargs)
            assert response.is_success, (
                f"{method} {path}: HTTP {response.status_code} {response.text[:300]}"
            )
            return response.json() if response.content else None

        created = api(
            "POST", "/management/api-keys", json={"name": "isolated chart smoke"}
        )
        key = created["plaintext"]
        for provider, upstream in (
            ("openai", "gpt-4o-mini"),
            ("anthropic", "claude-3-5-haiku-latest"),
        ):
            secret = api(
                "POST",
                "/management/providers",
                json={"provider": provider, "key": "disposable-model-secret"},
            )
            alias = "smoke-" + provider
            api(
                "POST",
                "/management/model-deployments",
                json={
                    "alias": alias,
                    "provider": provider,
                    "upstream_model": upstream,
                    "base_url": "https://fixture:8445/" + provider,
                    "provider_secret_id": secret["id"],
                    "deployment_kind": "internal",
                    "declared_version": "fixture-v1",
                    "owner": "isolated-test",
                },
            )
            payload = {
                "model": alias,
                "messages": [{"role": "user", "content": "Hello internal fixture"}],
                "max_tokens": 16,
            }
            path = "/v1/chat/completions" if provider == "openai" else "/v1/messages"
            response = client.post(
                "http://smoke-gateway:8000" + path,
                json=payload,
                headers={"x-shim-key": key, "anthropic-version": "2023-06-01"},
            )
            assert response.status_code == 200, (
                f"{provider}: {response.status_code} {response.text[:300]}"
            )
            assert "internal " in response.text
        deadline = time.monotonic() + 60
        while True:
            usage = api("GET", "/management/requests")
            audit = api("GET", "/compliance/audit/logs")
            rows = [
                row
                for row in usage["items"]
                if row["model"] in {"smoke-openai", "smoke-anthropic"}
            ]
            request_ids = {row["request_id"] for row in rows}
            audit_rows = [
                row for row in audit["items"] if row["request_id"] in request_ids
            ]
            if len(rows) == 2 and len(audit_rows) == 2:
                assert all(
                    row["prompt_tokens"] == 7 and row["completion_tokens"] == 4
                    for row in rows
                )
                assert api("POST", "/compliance/audit/verify", json={})["ok"]
                break
            assert time.monotonic() < deadline, "Usage/audit did not become visible"
            time.sleep(1)
        api("DELETE", "/management/api-keys/" + created["id"])
        response = client.post(
            "http://smoke-gateway:8000/v1/chat/completions",
            json={
                "model": "smoke-openai",
                "messages": [{"role": "user", "content": "revoked"}],
            },
            headers={"x-shim-key": key},
        )
        assert response.status_code == 401
        api("POST", "/auth/logout")
        assert client.get(origin + "/api/v1/auth/session").status_code == 401
    print(
        "PASS TLS/custom CA, real Keycloak login, Vault secret writes, both internal models, usage/audit, revoke/logout",
        flush=True,
    )


if __name__ == "__main__":
    {"serve": serve, "smoke": smoke, "denied": denied}[sys.argv[1]]()
