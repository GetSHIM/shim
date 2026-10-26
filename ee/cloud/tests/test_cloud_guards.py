"""The cloud entry points behind the enterprise guards, each run in a child process:
an audit hook cannot be removed."""

import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]


def _child(
    arguments: list[str], tmp_path: Path, **environment: str
) -> subprocess.CompletedProcess[str]:
    (tmp_path / "sitecustomize.py").write_text("")
    return subprocess.run(
        [sys.executable, *arguments],
        cwd=ROOT,
        env={**os.environ, "SHIM_STARTUP_GUARD": "off", **environment},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_the_cloud_gateway_starts_behind_the_guards(tmp_path: Path) -> None:
    script = """
import json
from shim.core import egress_guard
from shim_cloud.guards import guarded_app
app = guarded_app()
print(json.dumps({"result": [type(app).__name__, egress_guard.installed_mode]}))
"""

    started = _child(["-c", script], tmp_path, SHIM_EGRESS_GUARD="enforce")
    assert started.returncode == 0, started.stderr
    assert json.loads(started.stdout.splitlines()[-1]) == {
        "result": ["FastAPI", "enforce"]
    }
    refused = _child(
        ["-c", script],
        tmp_path,
        SHIM_STARTUP_GUARD="enforce",
        PYTHONPATH=str(tmp_path),
    )
    assert refused.returncode == 78
    assert '"result"' not in refused.stdout


def test_migrations_do_not_start_after_an_unexpected_startup_hook(
    tmp_path: Path,
) -> None:
    refused = _child(
        ["-m", "shim_cloud.migrate"],
        tmp_path,
        SHIM_STARTUP_GUARD="enforce",
        PYTHONPATH=str(tmp_path),
    )

    assert refused.returncode == 78
    assert str(tmp_path / "sitecustomize.py") in refused.stdout
    assert "alembic" not in refused.stderr.lower()
