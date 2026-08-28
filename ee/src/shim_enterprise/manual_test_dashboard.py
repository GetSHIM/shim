"""Dev-only browser client for exercising SHIM's public HTTP boundaries."""

from __future__ import annotations

import base64
import json
import secrets
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from shim_enterprise.core.config import settings


DASHBOARD_PATH = "/_dev/manual-test"
_SENSITIVE_LOG_FIELDS = (
    "access_token",
    "apikey",
    "authorization",
    "key",
    "password",
    "refresh_token",
    "token",
    "x-shim-key",
)


def install_manual_test_dashboard(application: FastAPI) -> None:
    if not settings.MANUAL_TEST_DASHBOARD_ENABLED:
        return
    application.add_api_route(
        DASHBOARD_PATH,
        manual_test_dashboard,
        methods=["GET"],
        include_in_schema=False,
    )


def manual_test_dashboard() -> HTMLResponse:
    nonce = secrets.token_urlsafe(24)
    supabase_origin = _supabase_origin(settings.SUPABASE_URL)
    public_key = _public_supabase_key(settings.SUPABASE_KEY)
    payload = {
        "email": settings.SHIM_TEST_USER_EMAIL or "",
        "managementPrefix": f"{settings.API_PREFIX}/management",
        "supabaseKey": public_key,
        "supabaseUrl": supabase_origin,
    }
    html = (
        _HTML.replace("__NONCE__", nonce)
        .replace("__CONFIG__", _json_for_html(payload))
        .replace("__SENSITIVE_FIELDS__", _json_for_html(_SENSITIVE_LOG_FIELDS))
    )
    connect_src = f" 'self' {supabase_origin}" if supabase_origin else " 'self'"
    content_security_policy = (
        "default-src 'none'; "
        f"script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}';"
        f" connect-src{connect_src}; img-src 'none'; font-src 'none';"
        " frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    )
    return HTMLResponse(
        html,
        headers={
            "Cache-Control": "no-store, max-age=0",
            "Content-Security-Policy": content_security_policy,
            "Pragma": "no-cache",
            "X-Robots-Tag": "noindex, nofollow, noarchive",
        },
    )


def _supabase_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
    ):
        return ""
    try:
        port = parsed.port
    except ValueError:
        return ""
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    if port is not None:
        host = f"{host}:{port}"
    return f"https://{host}"


def _public_supabase_key(value: str | None) -> str:
    if not value:
        return ""
    if value.startswith("sb_publishable_"):
        return value
    parts = value.split(".")
    if len(parts) != 3:
        return ""
    try:
        padding = "=" * (-len(parts[1]) % 4)
        claims: Any = json.loads(
            base64.urlsafe_b64decode(parts[1] + padding).decode("utf-8")
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return ""
    if isinstance(claims, dict) and claims.get("role") == "anon":
        return value
    return ""


def _json_for_html(value: object) -> str:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>SHIM manual test dashboard</title>
  <style nonce="__NONCE__">
    :root { color-scheme: dark; font: 15px/1.45 system-ui, sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; background: #101419; color: #e6edf3; }
    main { width: min(1180px, 100%); margin: auto; padding: 24px; }
    h1, h2 { margin: 0 0 12px; }
    h1 { font-size: 24px; }
    h2 { font-size: 17px; }
    p { color: #9da7b3; margin: 6px 0 16px; }
    .warning { color: #f0c36a; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(330px, 1fr)); gap: 14px; }
    .card { background: #171d24; border: 1px solid #2b3540; border-radius: 8px; padding: 16px; }
    label { display: block; color: #aeb8c4; margin: 8px 0 4px; }
    input, textarea, select, button { font: inherit; }
    input, textarea, select { width: 100%; color: #e6edf3; background: #0d1117; border: 1px solid #3a4652; border-radius: 5px; padding: 8px; }
    textarea { min-height: 86px; resize: vertical; }
    button { color: #e6edf3; background: #263241; border: 1px solid #415165; border-radius: 5px; padding: 8px 11px; margin: 8px 6px 0 0; cursor: pointer; }
    button:hover { background: #304157; }
    button:disabled { cursor: not-allowed; opacity: .45; }
    .status { min-height: 22px; color: #7ee787; }
    .output, #log { white-space: pre-wrap; overflow-wrap: anywhere; background: #0d1117; border: 1px solid #2b3540; border-radius: 5px; padding: 10px; min-height: 70px; max-height: 340px; overflow: auto; }
    #log { min-height: 300px; }
    .wide { grid-column: 1 / -1; }
  </style>
</head>
<body>
<main>
  <h1>SHIM manual test dashboard</h1>
  <p class="warning">Local development only. Calls go directly to the existing public and management endpoints; credentials stay in this page's memory and are redacted from the log.</p>

  <section class="grid">
    <div class="card">
      <h2>Credentials</h2>
      <label for="email">Supabase email</label><input id="email" autocomplete="username">
      <label for="password">Supabase password</label><input id="password" type="password" autocomplete="current-password">
      <label for="api-key">SHIM API key</label><input id="api-key" type="password" autocomplete="off">
      <button id="sign-in">Supabase sign in</button>
      <button id="profile">JWT profile</button>
      <div id="auth-status" class="status">Not signed in.</div>
    </div>

    <div class="card">
      <h2>Basic checks</h2>
      <button id="health">Health</button>
      <button id="models">Models</button>
      <button id="privacy">Privacy settings</button>
      <button id="billing">Billing usage</button>
      <button id="api-keys">API keys</button>
      <button id="providers">Providers</button>
      <pre id="basic-output" class="output"></pre>
    </div>

    <div class="card">
      <h2>PII scan presets</h2>
      <label for="scan-preset">Sample</label>
      <select id="scan-preset">
        <option value="email">Email</option>
        <option value="phone">Phone</option>
        <option value="card">Card</option>
        <option value="turkish">Turkish PII</option>
        <option value="secret">Secret</option>
      </select>
      <label for="scan-text">Text</label><textarea id="scan-text"></textarea>
      <button id="scan">Scan</button>
      <pre id="scan-output" class="output"></pre>
    </div>

    <div class="card">
      <h2>Chat completions</h2>
      <label for="model">Model</label><input id="model" value="gpt-5-nano">
      <label for="prompt">Prompt</label><textarea id="prompt">Reply with one short sentence confirming SHIM reached the configured provider.</textarea>
      <button id="chat">Normal chat</button>
      <button id="stream">Streaming chat</button>
      <button id="abort" disabled>Abort stream</button>
      <pre id="chat-output" class="output"></pre>
    </div>

    <div class="card">
      <h2>Responses API</h2>
      <label for="responses-input">Input</label><textarea id="responses-input">Reply with a short Responses API confirmation.</textarea>
      <button id="responses">POST /v1/responses</button>
      <pre id="responses-output" class="output"></pre>
    </div>

    <div class="card wide">
      <h2>Raw request / response log</h2>
      <button id="clear-log">Clear</button>
      <pre id="log"></pre>
    </div>
  </section>
</main>

<script id="dashboard-config" type="application/json" nonce="__NONCE__">__CONFIG__</script>
<script nonce="__NONCE__">
(() => {
  "use strict";
  const config = JSON.parse(document.getElementById("dashboard-config").textContent);
  const sensitiveFields = new Set(__SENSITIVE_FIELDS__);
  const state = { jwt: "", streamController: null };
  const byId = (id) => document.getElementById(id);
  const logNode = byId("log");

  byId("email").value = config.email;

  const samples = {
    email: "Contact alice@example.com about the account.",
    phone: "Call +90 532 123 45 67 for support.",
    card: "Test card: 4111 1111 1111 1111.",
    turkish: "T.C. Kimlik No: 10000000146, IBAN: TR330006100519786457841326.",
    secret: "api_key=sk-test_1234567890abcdef"
  };
  byId("scan-text").value = samples.email;

  function redacted(value) {
    if (Array.isArray(value)) return value.map(redacted);
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([key, item]) => [
        key,
        sensitiveFields.has(key.toLowerCase()) ? "[redacted]" : redacted(item)
      ]));
    }
    return value;
  }

  function appendLog(value) {
    const line = JSON.stringify(redacted(value), null, 2);
    logNode.textContent += (logNode.textContent ? "\n\n" : "") + line;
    logNode.scrollTop = logNode.scrollHeight;
  }

  function display(id, value) {
    byId(id).textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  }

  function apiKey() {
    const value = byId("api-key").value.trim();
    if (!value) throw new Error("Enter a SHIM API key.");
    return value;
  }

  function jwt() {
    if (!state.jwt) throw new Error("Sign in to obtain a Supabase JWT first.");
    return state.jwt;
  }

  async function request(label, url, options = {}) {
    const headers = { Accept: "application/json", ...(options.headers || {}) };
    if (options.body !== undefined) headers["Content-Type"] = "application/json";
    const requestBody = options.body === undefined ? undefined : options.body;
    appendLog({ label, request: { method: options.method || "GET", url, headers, body: requestBody } });
    const response = await fetch(url, {
      method: options.method || "GET",
      headers,
      body: requestBody === undefined ? undefined : JSON.stringify(requestBody),
      signal: options.signal
    });
    const text = await response.text();
    let body = text;
    try { body = text ? JSON.parse(text) : null; } catch (_) {}
    appendLog({ label, response: { status: response.status, headers: Object.fromEntries(response.headers), body } });
    if (!response.ok) throw new Error(`${label} failed (${response.status})`);
    return body;
  }

  async function run(outputId, operation) {
    try {
      display(outputId, await operation());
    } catch (error) {
      display(outputId, String(error));
    }
  }

  function jwtHeaders() { return { Authorization: `Bearer ${jwt()}` }; }
  function apiHeaders() { return { "x-shim-key": apiKey() }; }

  byId("scan-preset").addEventListener("change", (event) => {
    byId("scan-text").value = samples[event.target.value];
  });
  byId("clear-log").addEventListener("click", () => { logNode.textContent = ""; });

  byId("sign-in").addEventListener("click", async () => {
    try {
      if (!config.supabaseUrl || !config.supabaseKey) throw new Error("A hosted Supabase URL and publishable/anon key are required.");
      const result = await request("Supabase password sign in", `${config.supabaseUrl}/auth/v1/token?grant_type=password`, {
        method: "POST",
        headers: { apikey: config.supabaseKey },
        body: { email: byId("email").value.trim(), password: byId("password").value }
      });
      state.jwt = result.access_token;
      byId("auth-status").textContent = "Signed in; JWT held in page memory.";
    } catch (error) {
      state.jwt = "";
      byId("auth-status").textContent = String(error);
    }
  });

  const basicCalls = {
    health: () => request("Health", "/health"),
    models: () => request("Models", "/v1/models", { headers: apiHeaders() }),
    profile: () => request("JWT profile", `${config.managementPrefix}/auth/me`, { headers: jwtHeaders() }),
    privacy: () => request("Privacy settings", `${config.managementPrefix}/settings/pii`, { headers: jwtHeaders() }),
    billing: () => request("Billing usage", `${config.managementPrefix}/billing/usage`, { headers: jwtHeaders() }),
    "api-keys": () => request("API keys", `${config.managementPrefix}/api-keys`, { headers: jwtHeaders() }),
    providers: () => request("Providers", `${config.managementPrefix}/providers`, { headers: jwtHeaders() })
  };
  for (const [id, call] of Object.entries(basicCalls)) {
    byId(id).addEventListener("click", () => run("basic-output", call));
  }

  byId("scan").addEventListener("click", () => run("scan-output", () => request("PII scan", "/v1/scan", {
    method: "POST",
    headers: state.jwt ? jwtHeaders() : apiHeaders(),
    body: { text: byId("scan-text").value, source: "unknown" }
  })));

  function chatBody(stream) {
    return {
      model: byId("model").value.trim(),
      messages: [{ role: "user", content: byId("prompt").value }],
      stream
    };
  }

  byId("chat").addEventListener("click", () => run("chat-output", () => request("Chat completion", "/v1/chat/completions", {
    method: "POST", headers: apiHeaders(), body: chatBody(false)
  })));

  byId("stream").addEventListener("click", async () => {
    const output = byId("chat-output");
    const abort = byId("abort");
    output.textContent = "";
    state.streamController = new AbortController();
    abort.disabled = false;
    try {
      const headers = { Accept: "text/event-stream", "Content-Type": "application/json", ...apiHeaders() };
      const body = chatBody(true);
      appendLog({ label: "Streaming chat", request: { method: "POST", url: "/v1/chat/completions", headers, body } });
      const response = await fetch("/v1/chat/completions", {
        method: "POST", headers, body: JSON.stringify(body), signal: state.streamController.signal
      });
      if (!response.ok || !response.body) {
        const errorBody = await response.text();
        appendLog({ label: "Streaming chat", response: { status: response.status, body: errorBody } });
        throw new Error(`Streaming chat failed (${response.status})`);
      }
      appendLog({ label: "Streaming chat", response: { status: response.status, stream: "started" } });
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        const text = decoder.decode(chunk.value, { stream: true });
        output.textContent += text;
        appendLog({ label: "Streaming chat", responseChunk: text });
      }
    } catch (error) {
      const message = error.name === "AbortError" ? "Stream aborted by developer." : String(error);
      output.textContent += `\n${message}`;
      appendLog({ label: "Streaming chat", terminal: message });
    } finally {
      state.streamController = null;
      abort.disabled = true;
    }
  });
  byId("abort").addEventListener("click", () => state.streamController?.abort());

  byId("responses").addEventListener("click", () => run("responses-output", () => request("Responses API", "/v1/responses", {
    method: "POST",
    headers: apiHeaders(),
    body: { model: byId("model").value.trim(), input: byId("responses-input").value }
  })));
})();
</script>
</body>
</html>
"""
