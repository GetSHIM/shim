"""The egress guard. An audit hook cannot be removed, so every test that installs one
runs it in a child process; this process only calls the pure decision."""

from __future__ import annotations

import json
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace

from pydantic import ValidationError
import pytest

from shim.core.community_config import CommunitySettings
from shim.core.egress_guard import allowed_hosts, decide

ROOT = Path(__file__).resolve().parents[2]
HOSTS = frozenset({"localhost", "api.openai.com", "*.example.com"})
INET = SimpleNamespace(family=socket.AF_INET)
INET6 = SimpleNamespace(family=socket.AF_INET6)
UNIX = SimpleNamespace(family=socket.AF_UNIX)
# .invalid never resolves (RFC 2606): a guard that fails here sends no real query.
EXFIL = "exfil.shim-test.invalid"


@pytest.mark.parametrize(
    ("host", "denied"),
    [
        ("api.openai.com", None),
        ("API.OpenAI.com.", None),
        (b"api.openai.com", None),
        ("a.example.com", None),
        ("deep.a.example.com", None),
        ("example.com", ("host", "example.com")),
        ("notexample.com", ("host", "notexample.com")),
        ("www.litellm.dev", ("host", "www.litellm.dev")),
        (b"www.litellm.dev", ("host", "www.litellm.dev")),
        (None, None),
        ("localhost", None),
        ("127.0.0.1", None),
        ("::1", None),
        ("0.0.0.0", None),
        ("203.0.113.9", None),
        ("169.254.169.254", ("metadata", "169.254.169.254")),
        ("169.254.169.254.", ("metadata", "169.254.169.254")),
        ("fd00:ec2::254", ("metadata", "fd00:ec2::254")),
        ("169.254.170.2", ("metadata", "169.254.170.2")),
        ("169.254.170.23", ("metadata", "169.254.170.23")),
        ("fd00:ec2::23", ("metadata", "fd00:ec2::23")),
        ("::ffff:169.254.169.254", ("metadata", "169.254.169.254")),
        ("169.254.1.1", ("link_local", "169.254.1.1")),
        ("fe80::1%en0", ("link_local", "fe80::1")),
        # Other spellings of an address are names, and no name is listed for them.
        ("2852039166", ("host", "2852039166")),
        ("0xa9fea9fe", ("host", "0xa9fea9fe")),
    ],
)
def test_a_lookup_is_decided_by_name_or_address(host, denied) -> None:
    for event in (
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyname_ex",
        "socket.gethostbyaddr",
    ):
        assert decide(event, (host, 443, 0, 0, 0), HOSTS) == denied


@pytest.mark.parametrize("event", ["socket.connect", "socket.connect_ex"])
def test_a_connect_is_decided_by_its_address(event: str) -> None:
    assert decide(event, (INET, ("169.254.169.254", 80)), HOSTS) == (
        "metadata",
        "169.254.169.254",
    )
    assert decide(event, (INET6, ("fe80::1", 80, 0, 0)), HOSTS) == (
        "link_local",
        "fe80::1",
    )
    assert decide(event, (INET, ("127.0.0.1", 80)), HOSTS) is None
    assert decide(event, (INET, ("198.51.100.7", 443)), HOSTS) is None
    # A name passed to connect is resolved inside it, unaudited: the name rule applies.
    assert decide(event, (INET, ("www.litellm.dev", 80)), HOSTS) == (
        "host",
        "www.litellm.dev",
    )
    assert decide(event, (UNIX, "/var/run/socket"), HOSTS) is None


def test_other_events_are_not_decided() -> None:
    assert decide("socket.bind", (INET, ("169.254.169.254", 80)), HOSTS) is None
    assert decide("open", ("/etc/passwd", "r", 0), HOSTS) is None


def test_the_allowlist_holds_the_configured_destinations() -> None:
    plain = CommunitySettings(_env_file=None)
    assert allowed_hosts(plain) == {
        "localhost",
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
    }
    configured = CommunitySettings(
        ANTHROPIC_BASE_URL="https://Proxy.Corp.example:8443/anthropic",
        SHIM_AZURE_OPENAI_ENDPOINT="https://shim.openai.azure.com",
        SHIM_AZURE_TENANT_ID="tenant",
        SHIM_AZURE_CLIENT_ID="00000000-0000-4000-8000-000000000000",
        SHIM_AZURE_CLIENT_SECRET="secret",
        OTEL_EXPORTER_OTLP_ENDPOINT="http://otel-collector:4318",
        SENTRY_DSN="https://key@o1.ingest.sentry.io/2",
        SHIM_EGRESS_ALLOW_HOSTS="*.internal.example",
        _env_file=None,
    )
    assert allowed_hosts(configured) == {
        "localhost",
        "api.openai.com",
        "proxy.corp.example",
        "generativelanguage.googleapis.com",
        "shim.openai.azure.com",
        "login.microsoftonline.com",
        "otel-collector",
        "o1.ingest.sentry.io",
        "*.internal.example",
    }


def test_the_authority_host_is_listed_only_with_entra_credentials() -> None:
    keyed = CommunitySettings(
        SHIM_AZURE_OPENAI_ENDPOINT="https://shim.openai.azure.com",
        SHIM_AZURE_OPENAI_API_KEY="azure-key",
        _env_file=None,
    )
    assert "login.microsoftonline.com" not in allowed_hosts(keyed)


def test_guards_report_by_default() -> None:
    settings = CommunitySettings(_env_file=None)
    assert settings.SHIM_STARTUP_GUARD == "report"
    assert settings.SHIM_EGRESS_GUARD == "report"
    assert settings.SHIM_EGRESS_ALLOW_HOSTS == []


def test_allowed_hosts_are_parsed_and_normalised() -> None:
    settings = CommunitySettings(
        SHIM_EGRESS_ALLOW_HOSTS=" Proxy.Corp. , *.Example.com,llm_gw ", _env_file=None
    )
    assert settings.SHIM_EGRESS_ALLOW_HOSTS == [
        "proxy.corp",
        "*.example.com",
        "llm_gw",
    ]
    assert CommunitySettings(SHIM_EGRESS_ALLOW_HOSTS="", _env_file=None)


@pytest.mark.parametrize(
    "value",
    [
        "https://proxy.corp",
        "proxy.corp/path",
        "proxy.corp:8080",
        "a.example,,b.example",
        "a.example, ",
        "*",
        "*.",
        "a.*.example",
        "proxy corp",
        "[::1]",
    ],
)
def test_allowed_hosts_refuse_anything_but_a_host_or_suffix(value: str) -> None:
    with pytest.raises(ValidationError, match="SHIM_EGRESS_ALLOW_HOSTS"):
        CommunitySettings(SHIM_EGRESS_ALLOW_HOSTS=value, _env_file=None)


def test_unknown_guard_modes_are_refused() -> None:
    for name in ("SHIM_STARTUP_GUARD", "SHIM_EGRESS_GUARD"):
        with pytest.raises(ValidationError, match=name):
            CommunitySettings(**{name: "warn"}, _env_file=None)


_CHILD = """
import json, logging, socket, sys
from prometheus_client import REGISTRY
from shim.core import egress_guard
from shim.core.community_config import CommunitySettings
from shim.observability.logging import configure_logging

configure_logging("INFO")
settings = CommunitySettings(SHIM_EGRESS_GUARD=sys.argv[1], _env_file=None)
"""

_RESULT = """
def denied(kind, mode):
    return REGISTRY.get_sample_value(
        "shim_egress_denied_total", {"kind": kind, "mode": mode}
    ) or 0

def attempt(call):
    try:
        call()
        return None
    except BaseException as error:
        return type(error).__name__

def connect(address):
    with socket.socket() as sock:
        sock.settimeout(0.2)
        sock.connect(address)
"""


def _child(mode: str, body: str) -> tuple[dict, list[dict]]:
    """Run `body` after the child's setup; it prints one JSON line with key result."""

    script = _CHILD + _RESULT + body
    result = subprocess.run(
        [sys.executable, "-c", script, mode],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    lines = [json.loads(line) for line in result.stdout.splitlines()]
    (answer,) = [line["result"] for line in lines if "result" in line]
    return answer, [line for line in lines if line.get("message") == "egress_denied"]


def test_enforce_refuses_an_unlisted_lookup_before_any_dns_query() -> None:
    answer, logs = _child(
        "enforce",
        f"""
egress_guard.install(settings)
print(json.dumps({{"result": {{
    "exfil": attempt(lambda: socket.getaddrinfo("{EXFIL}", 80)),
    "metadata": attempt(lambda: connect(("169.254.169.254", 80))),
    "listed": attempt(lambda: socket.getaddrinfo("localhost", 80)),
    "denied": [denied("host", "enforce"), denied("metadata", "enforce")],
}}}}))
""",
    )

    # gaierror would mean the lookup reached the resolver.
    assert answer == {
        "exfil": "PermissionError",
        "metadata": "PermissionError",
        "listed": None,
        "denied": [1.0, 1.0],
    }
    assert [(log["kind"], log["destination"], log["mode"]) for log in logs] == [
        ("host", EXFIL, "enforce"),
        ("metadata", "169.254.169.254", "enforce"),
    ]


def test_a_process_adds_hosts_and_kinds_and_learns_hosts_while_running() -> None:
    answer, logs = _child(
        "enforce",
        """
egress_guard.install(settings, {"db.shim-test.invalid"}, allow_kinds={"metadata"})
learned = [attempt(lambda: socket.getaddrinfo("idp.shim-test.invalid", 80))]
egress_guard.allow("IdP.shim-test.invalid.", None)
learned.append(attempt(lambda: socket.getaddrinfo("idp.shim-test.invalid", 80)))
print(json.dumps({"result": {
    "extra": attempt(lambda: socket.getaddrinfo("db.shim-test.invalid", 80)),
    "learned": learned,
    "metadata": attempt(lambda: socket.getaddrinfo("169.254.169.254", 80)),
    "link_local": attempt(lambda: socket.getaddrinfo("169.254.1.1", 80)),
}}))
""",
    )

    # gaierror: the lookup passed the guard and reached the resolver.
    assert answer == {
        "extra": "gaierror",
        "learned": ["PermissionError", "gaierror"],
        "metadata": None,
        "link_local": "PermissionError",
    }
    assert [(log["kind"], log["destination"]) for log in logs] == [
        ("host", "idp.shim-test.invalid"),
        ("link_local", "169.254.1.1"),
    ]


def test_report_lets_calls_through_and_logs_each_destination_once() -> None:
    answer, logs = _child(
        "report",
        f"""
egress_guard.install(settings)
errors = [
    attempt(lambda: socket.getaddrinfo("{EXFIL}", 80)),
    attempt(lambda: socket.getaddrinfo("{EXFIL}", 443)),
    attempt(lambda: connect(("169.254.1.1", 80))),
    attempt(lambda: connect(("169.254.1.1", 80))),
]
print(json.dumps({{"result": {{
    "errors": errors,
    "denied": [denied("host", "report"), denied("link_local", "report")],
}}}}))
""",
    )

    assert "PermissionError" not in answer["errors"]
    assert answer["denied"] == [2.0, 2.0]
    assert [(log["kind"], log["destination"]) for log in logs] == [
        ("host", EXFIL),
        ("link_local", "169.254.1.1"),
    ]


def test_a_second_install_adds_no_second_hook() -> None:
    answer, logs = _child(
        "report",
        f"""
egress_guard.install(settings)
egress_guard.install(CommunitySettings(SHIM_EGRESS_GUARD="enforce", _env_file=None))
error = attempt(lambda: socket.getaddrinfo("{EXFIL}", 80))
print(json.dumps({{"result": [error, denied("host", "report"), denied("host", "enforce")]}}))
""",
    )

    assert answer == ["gaierror", 1.0, 0]
    assert len(logs) == 1


def test_off_installs_nothing() -> None:
    answer, logs = _child(
        "off",
        f"""
egress_guard.install(settings)
print(json.dumps({{"result": [
    egress_guard.installed_mode,
    attempt(lambda: socket.getaddrinfo("{EXFIL}", 80)),
]}}))
""",
    )

    assert answer == ["off", "gaierror"]
    assert logs == []


def test_a_log_handler_that_resolves_a_host_does_not_reenter_the_hook() -> None:
    answer, _ = _child(
        "report",
        f"""
import logging.handlers
logging.getLogger().addHandler(logging.handlers.SocketHandler("{EXFIL}", 9))
logging.raiseExceptions = False
egress_guard.install(settings)
attempt(lambda: socket.getaddrinfo("{EXFIL}", 80))
print(json.dumps({{"result": denied("host", "report")}}))
""",
    )

    # Re-entered, the hook would count the handler's own lookup, again and again.
    assert answer == 1.0


def test_a_fault_in_the_guard_never_reaches_the_caller() -> None:
    answer, logs = _child(
        "enforce",
        """
egress_guard.install(settings)
def broken(*args):
    raise RuntimeError("guard bug")
egress_guard.decide = broken
print(json.dumps({"result": [
    attempt(lambda: socket.getaddrinfo("localhost", 80)),
    denied("guard_error", "enforce"),
]}))
""",
    )

    assert answer == [None, 1.0]
    assert logs == []


def test_isolation_workers_refuse_all_network_under_enforce() -> None:
    answer, _ = _child(
        "enforce",
        """
import os, socket
from shim.core import isolation
egress_guard.install(settings)
deadline = isolation.request_deadline()
def isolated(*args):
    try:
        isolation.run(*args, deadline=deadline)
        return None
    except BaseException as error:
        return type(error).__name__
print(json.dumps({"result": [
    isolated(socket.getaddrinfo, "localhost", 80),
    isolated(socket.gethostbyname, "localhost"),
    isolated(os.getpid) is None,
]}))
""",
    )

    assert answer == ["PermissionError", "PermissionError", True]


def test_isolation_workers_keep_their_network_under_report() -> None:
    answer, _ = _child(
        "report",
        """
import socket
from shim.core import isolation
egress_guard.install(settings)
info = isolation.run(socket.getaddrinfo, "localhost", 80, deadline=isolation.request_deadline())
print(json.dumps({"result": bool(info)}))
""",
    )

    assert answer is True
