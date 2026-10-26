"""The enterprise guards. An audit hook cannot be removed, so every test that installs
one runs it in a child process; this process only builds the allowlist."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from shim_enterprise.core.config import Settings
from shim_enterprise.guards import allowed_hosts, needs_metadata

ROOT = Path(__file__).resolve().parents[2]
# .invalid never resolves (RFC 2606): a guard that fails here sends no real query.
EXFIL = "exfil.shim-test.invalid"
DATABASE = "postgresql+asyncpg://shim:shim@db.shim-test.invalid:5432/shim"
# The child's own settings: what the test does not set, it does not inherit.
QUIET = {
    "SECRET_BACKEND": "fernet",
    "AWS_GATEWAY_IDENTITY": "none",
    "WORM_ARCHIVE_ENABLED": "false",
    "SHIM_STARTUP_GUARD": "off",
}


def _settings(**overrides: object) -> Settings:
    return Settings(  # ty: ignore[unknown-argument]
        _env_file=None,
        DATABASE_URL=DATABASE,
        REDIS_URL="redis://cache.shim-test.invalid:6379/0",
        SUPABASE_URL="https://project.supabase.co",
        **overrides,
    )


def test_the_allowlist_holds_what_the_settings_name() -> None:
    hosts = allowed_hosts(
        _settings(
            MODEL_DEPLOYMENT_ALLOWED_ORIGINS=["https://models.example.com"],
            MODEL_DEPLOYMENT_ALLOWED_ORIGIN_SUFFIXES=[".openai.azure.com"],
            MODEL_DEPLOYMENT_INTERNAL_ORIGINS=["http://vllm.internal:8000"],
            ALERT_ALLOWED_ORIGINS=["https://alerts.example.com"],
            RESEND_API_KEY="re_test",
        )
    )

    assert {
        "db.shim-test.invalid",
        "cache.shim-test.invalid",
        "project.supabase.co",
        "login.microsoftonline.com",
        "api.chatgpt.com",
        "api.resend.com",
        "models.example.com",
        "*.openai.azure.com",
        "vllm.internal",
        "alerts.example.com",
        # Bedrock and STS, from the default region templates.
        "*.amazonaws.com",
    } <= hosts
    assert "metadata.google.internal" not in hosts
    assert "api.resend.com" not in allowed_hosts(_settings())


def test_aws_templates_name_their_own_hosts() -> None:
    endpoints = {
        "AWS_BEDROCK_RUNTIME_URL_TEMPLATE": (
            "https://vpce-1.bedrock-runtime.{region}.vpce.amazonaws.com"
        ),
        "AWS_BEDROCK_CONTROL_URL_TEMPLATE": "http://aws-double.internal:9000",
        "AWS_STS_URL_TEMPLATE": "http://aws-double.internal:9000",
    }

    hosts = allowed_hosts(_settings(**endpoints))
    assert {"*.vpce.amazonaws.com", "aws-double.internal"} <= hosts
    assert "*.amazonaws.com" not in hosts
    # Secrets Manager and S3 are reached at AWS's own names, whatever the templates say.
    assert "*.amazonaws.com" in allowed_hosts(
        _settings(**endpoints, SECRET_BACKEND="aws_secrets_manager")
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"SECRET_BACKEND": "gcp_secret_manager"},
        {"SECRET_BACKEND": "aws_secrets_manager"},
        {"SECRET_BACKEND": "azure_key_vault"},
        {"AWS_GATEWAY_IDENTITY": "imds"},
        {
            "AWS_GATEWAY_IDENTITY": "gcp_metadata",
            "AWS_GCP_SERVICE_ACCOUNT_ID": "123",
        },
        {"WORM_ARCHIVE_ENABLED": True, "WORM_ARCHIVE_BUCKET": "audit"},
    ],
)
def test_metadata_is_reachable_only_where_credentials_come_from_it(
    overrides: dict[str, object],
) -> None:
    assert not needs_metadata(_settings())
    config = _settings(**overrides)
    assert needs_metadata(config)
    assert {"metadata.google.internal", "oauth2.googleapis.com"} <= allowed_hosts(
        config
    )


def test_azure_key_vault_is_listed_from_its_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AZURE_KEY_VAULT_URL", "https://shim.vault.azure.net/")

    assert "shim.vault.azure.net" in allowed_hosts(
        _settings(SECRET_BACKEND="azure_key_vault")
    )
    assert "shim.vault.azure.net" not in allowed_hosts(_settings())


_ATTEMPT = """
import json, socket
from shim.core import egress_guard
from shim_enterprise.guards import start_guards

def attempt(host):
    try:
        socket.getaddrinfo(host, 443)
        return None
    except BaseException as error:
        return type(error).__name__
"""


def _child(script: str, **environment: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env={**os.environ, **QUIET, "DATABASE_URL": DATABASE, **environment},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _result(script: str, **environment: str) -> object:
    result = _child(script, **environment)
    assert result.returncode == 0, result.stderr
    (answer,) = [
        json.loads(line)["result"]
        for line in result.stdout.splitlines()
        if line.startswith('{"result"')
    ]
    return answer


def test_the_gateway_refuses_what_its_settings_do_not_name() -> None:
    answer = _result(
        _ATTEMPT
        + f"""
start_guards()
learned = [attempt("idp.shim-test.invalid")]
egress_guard.allow("idp.shim-test.invalid")
learned.append(attempt("idp.shim-test.invalid"))
print(json.dumps({{"result": {{
    "exfil": attempt("{EXFIL}"),
    "database": attempt("db.shim-test.invalid"),
    "metadata": attempt("169.254.169.254"),
    "link_local": attempt("169.254.1.1"),
    "learned": learned,
}}}}))
""",
        SHIM_EGRESS_GUARD="enforce",
    )

    # gaierror: the lookup passed the guard and reached the resolver.
    assert answer == {
        "exfil": "PermissionError",
        "database": "gaierror",
        "metadata": "PermissionError",
        "link_local": "PermissionError",
        "learned": ["PermissionError", "gaierror"],
    }


def test_the_gateway_refuses_an_unlisted_forward_target_as_unsafe() -> None:
    answer = _result(
        _ATTEMPT
        + """
import asyncio
from shim_enterprise.compliance.url_guard import assert_safe_forward_url
start_guards()
try:
    asyncio.run(assert_safe_forward_url("https://hooks.shim-test.invalid/alert"))
    outcome = None
except BaseException as error:
    outcome = [type(error).__name__, type(error.__cause__).__name__]
print(json.dumps({"result": outcome}))
""",
        SHIM_EGRESS_GUARD="enforce",
    )

    # Saving the target answers 422, as for a host that does not resolve.
    assert answer == ["UnsafeForwardURL", "PermissionError"]


def test_a_delivering_worker_checks_addresses_but_not_names() -> None:
    answer = _result(
        _ATTEMPT
        + f"""
start_guards(check_names=False)
print(json.dumps({{"result": [
    attempt("{EXFIL}"), attempt("169.254.169.254"), attempt("169.254.1.1"),
]}}))
""",
        SHIM_EGRESS_GUARD="enforce",
    )

    assert answer == ["gaierror", "PermissionError", "PermissionError"]


def test_a_metadata_backend_reaches_metadata_and_nothing_else_new() -> None:
    answer = _result(
        _ATTEMPT
        + f"""
start_guards()
print(json.dumps({{"result": [
    attempt("{EXFIL}"), attempt("169.254.169.254"), attempt("169.254.1.1"),
]}}))
""",
        SHIM_EGRESS_GUARD="enforce",
        SECRET_BACKEND="gcp_secret_manager",
    )

    assert answer == ["PermissionError", None, "PermissionError"]


def test_without_egress_only_the_startup_scan_runs(tmp_path: Path) -> None:
    (tmp_path / "sitecustomize.py").write_text("")
    script = _ATTEMPT + "start_guards(egress=False)\n"

    answer = _result(
        script
        + f'print(json.dumps({{"result": [egress_guard.installed_mode, attempt("{EXFIL}")]}}))',
        SHIM_EGRESS_GUARD="enforce",
    )
    assert answer == ["off", "gaierror"]
    refused = _child(script, SHIM_STARTUP_GUARD="enforce", PYTHONPATH=str(tmp_path))
    assert refused.returncode == 78
    assert str(tmp_path / "sitecustomize.py") in refused.stdout


def test_the_guarded_gateway_starts_behind_the_guards(tmp_path: Path) -> None:
    script = """
import json
from shim.core import egress_guard
from shim_enterprise.guards import guarded_app
app = guarded_app()
print(json.dumps({"result": [type(app).__name__, egress_guard.installed_mode]}))
"""

    answer = _result(script, SHIM_EGRESS_GUARD="enforce")
    assert answer == ["FastAPI", "enforce"]
    (tmp_path / "sitecustomize.py").write_text("")
    refused = _child(script, SHIM_STARTUP_GUARD="enforce", PYTHONPATH=str(tmp_path))
    # The scan refuses before the application is built.
    assert refused.returncode == 78
    assert '"result"' not in refused.stdout
