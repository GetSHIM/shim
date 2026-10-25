"""The LiteLLM 1.107.0 delivery against shim: a `.pth` startup hook in site-packages
that starts a thread, which later resolves its collection host.

The environment is a real virtual environment, so the hook runs at interpreter start,
before any shim code, as it would in a poisoned image."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import sysconfig

import pytest

# .invalid never resolves (RFC 2606): a guard that fails here sends no real query.
EXFIL = "exfil.shim-test.invalid"
EVIL = f"""
import socket, threading, time
error = None
def _collect():
    global error
    # Long enough for the child to import shim and start its guards first.
    time.sleep(2)
    try:
        socket.getaddrinfo("{EXFIL}", 80)
    except BaseException as exc:
        error = exc
thread = threading.Thread(target=_collect, daemon=True)
thread.start()
"""


@pytest.fixture(scope="module")
def poisoned(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """A virtual environment whose site-packages carries evil.pth and evil.py."""

    root = tmp_path_factory.mktemp("poisoned")
    subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(root / "venv")],
        check=True,
        capture_output=True,
    )
    python = root / "venv" / "bin" / "python"
    site = Path(
        subprocess.run(
            [python, "-c", "import site; print(site.getsitepackages()[0])"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    # shim and its dependencies come from this environment, as path lines (no hooks).
    stdlib = Path(sysconfig.get_path("stdlib"))
    paths = [
        entry
        for entry in sys.path
        if entry and Path(entry).is_dir() and not Path(entry).is_relative_to(stdlib)
    ]
    (site / "shim-test-paths.pth").write_text("\n".join(paths) + "\n")
    (site / "evil.pth").write_text("import evil\n")
    (site / "evil.py").write_text(EVIL)
    return python, site


def _clean_environment() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("SHIM_", "OPENAI_", "ANTHROPIC_", "GOOGLE_"))
    }


_DEMO = """
import json
import evil
from shim.cli import start_guards
from shim.core.community_config import CommunitySettings
from shim.observability.logging import configure_logging

configure_logging("INFO")
settings = CommunitySettings(
    SHIM_STARTUP_GUARD="enforce", SHIM_EGRESS_GUARD="enforce", _env_file=None
)
try:
    start_guards(settings)
    code = None
except SystemExit as exit:
    code = exit.code
evil.thread.join(10)
print(json.dumps({"result": {"code": code, "error": type(evil.error).__name__}}))
"""


def test_the_guards_report_the_hook_and_stop_its_exfiltration(
    poisoned: tuple[Path, Path], tmp_path: Path
) -> None:
    python, site = poisoned

    result = subprocess.run(
        [python, "-c", _DEMO],
        cwd=tmp_path,
        env=_clean_environment(),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    lines = [json.loads(line) for line in result.stdout.splitlines()]
    (answer,) = [line["result"] for line in lines if "result" in line]
    # gaierror would mean the lookup reached the resolver.
    assert answer == {"code": 78, "error": "PermissionError"}
    hooks = {
        (line["path"], line["kind"])
        for line in lines
        if line.get("message") == "startup_hook_unexpected"
    }
    assert {
        (str(site / "evil.pth"), "pth_import"),
        (str(site / "evil.py"), "pth_target"),
    } <= hooks
    assert [
        (line["kind"], line["destination"], line["mode"])
        for line in lines
        if line.get("message") == "egress_denied"
    ] == [("host", EXFIL, "enforce")]


def test_shim_serve_refuses_to_start_with_an_unknown_hook_under_enforce(
    poisoned: tuple[Path, Path], tmp_path: Path
) -> None:
    python, site = poisoned
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    # Were the guard to let it through, uvicorn would serve until the timeout.
    result = subprocess.run(
        [
            python,
            "-c",
            f"from shim.cli import main; main(['serve', '--port', '{port}'])",
        ],
        cwd=tmp_path,
        env=_clean_environment()
        | {"SHIM_STARTUP_GUARD": "enforce", "SHIM_EGRESS_GUARD": "off"},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 78, result.stderr
    assert "Uvicorn running" not in result.stderr + result.stdout
    assert str(site / "evil.pth") in result.stdout
