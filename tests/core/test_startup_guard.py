from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from shim.core import startup_guard
from shim.core.startup_guard import ALLOWLIST, Finding, scan

ROOT = Path(__file__).resolve().parents[2]


def _sha(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


@pytest.fixture
def site_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # On sys.path, as a site directory is, so hook targets resolve from it.
    monkeypatch.syspath_prepend(str(tmp_path))
    return tmp_path


def _ours(findings: tuple[Finding, ...], root: Path) -> list[tuple[str, str]]:
    # The interpreter running the tests may ship hooks of its own (conda: sitecustomize).
    return sorted(
        (Path(finding.path).relative_to(root).as_posix(), finding.kind)
        for finding in findings
        if Path(finding.path).is_relative_to(root)
    )


def test_path_lines_comments_and_blank_lines_are_not_hooks(site_dir: Path) -> None:
    (site_dir / "paths.pth").write_text("# a comment\n\n/opt/lib\nimportlib-foo\n")

    assert _ours(scan([site_dir]), site_dir) == []


def test_an_import_line_is_a_hook_with_its_hash(site_dir: Path) -> None:
    text = "import evil\n"
    (site_dir / "evil.pth").write_text(text)

    assert Finding(str(site_dir / "evil.pth"), "pth_import", _sha(text)) in scan(
        [site_dir]
    )


def test_an_import_after_a_tab_is_a_hook(site_dir: Path) -> None:
    (site_dir / "tab.pth").write_text("import\tos\n")

    assert _ours(scan([site_dir]), site_dir) == [("tab.pth", "pth_import")]


def test_a_hook_target_is_reported_with_its_hash(site_dir: Path) -> None:
    (site_dir / "evil.pth").write_text("import evil\n")
    (site_dir / "evil.py").write_text("STOLEN = True\n")

    findings = scan([site_dir])

    assert _ours(findings, site_dir) == [
        ("evil.pth", "pth_import"),
        ("evil.py", "pth_target"),
    ]
    assert Finding(
        str(site_dir / "evil.py"), "pth_target", _sha("STOLEN = True\n")
    ) in (findings)


def test_targets_named_by_from_imports_and_literal_dunder_import(
    site_dir: Path,
) -> None:
    (site_dir / "a.pth").write_text(
        "import os; from evil_a.sub import x; __import__('evil_b').run()\n"
    )
    (site_dir / "evil_a").mkdir()
    (site_dir / "evil_a" / "__init__.py").write_text("")
    (site_dir / "evil_b.py").write_text("")

    # os is the standard library's own.
    assert _ours(scan([site_dir]), site_dir) == [
        ("a.pth", "pth_import"),
        ("evil_a/__init__.py", "pth_target"),
        ("evil_b.py", "pth_target"),
    ]


def test_an_allowlisted_hook_and_target_are_not_reported(
    site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        startup_guard,
        "ALLOWLIST",
        {"vendor.pth": _sha("import vendor_hook\n"), "vendor_hook.py": _sha("")},
    )
    (site_dir / "vendor.pth").write_text("import vendor_hook\n")
    (site_dir / "vendor_hook.py").write_text("")

    assert _ours(scan([site_dir]), site_dir) == []


def test_an_allowlisted_name_with_other_bytes_is_a_hook(site_dir: Path) -> None:
    (site_dir / "_virtualenv.pth").write_text("import _virtualenv, evil\n")

    assert ("_virtualenv.pth", "pth_import") in _ours(scan([site_dir]), site_dir)


def test_an_allowlisted_hook_whose_target_is_not_allowlisted_is_reported(
    site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        startup_guard, "ALLOWLIST", {"vendor.pth": _sha("import vendor_hook\n")}
    )
    (site_dir / "vendor.pth").write_text("import vendor_hook\n")
    (site_dir / "vendor_hook.py").write_text("import os; os.system('curl ...')\n")

    assert _ours(scan([site_dir]), site_dir) == [("vendor_hook.py", "pth_target")]


def test_the_allowlist_is_the_published_image_set() -> None:
    # The image's own hooks, amd64 and arm64; nothing else belongs here.
    assert set(ALLOWLIST) == {
        "_virtualenv.pth",
        "_virtualenv.py",
        "distutils-precedence.pth",
        "_distutils_hack/__init__.py",
    }


def test_a_sitecustomize_on_the_path_is_a_hook(
    site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The interpreter's own, when it has one, already ran and would be found first.
    monkeypatch.delitem(sys.modules, "sitecustomize", raising=False)
    (site_dir / "sitecustomize.py").write_text("print('hi')\n")
    (site_dir / "usercustomize.py").write_text("")

    assert _ours(scan([site_dir]), site_dir) == [
        ("sitecustomize.py", "sitecustomize"),
        ("usercustomize.py", "usercustomize"),
    ]


def test_an_unreadable_hook_file_is_skipped_as_python_skips_it(
    site_dir: Path,
) -> None:
    # A directory cannot be read as a file, even by root.
    (site_dir / "odd.pth").mkdir()

    assert _ours(scan([site_dir]), site_dir) == []


def test_a_missing_directory_is_skipped(tmp_path: Path) -> None:
    assert _ours(scan([tmp_path / "absent"]), tmp_path) == []


# check() sets a process gauge and logs; run it where nothing else is measured.
_CHECK = """
import builtins, json, sys
from pathlib import Path
from prometheus_client import REGISTRY
from shim.core import startup_guard

site = Path(sys.argv[2])
sys.path.insert(0, str(site))
startup_guard._site_directories = lambda: [site]
opened = []
sys.addaudithook(lambda event, args: opened.append(str(args[0])) if event == "open" else None)
findings = startup_guard.check(sys.argv[1])
reads = [path for path in opened if path.startswith(str(site))]
print(json.dumps({
    "findings": [finding.kind for finding in findings if finding.path.startswith(str(site))],
    "gauge": REGISTRY.get_sample_value("shim_startup_hooks_unexpected"),
    "reads": len(reads),
}))
"""


@pytest.mark.parametrize("mode", ["off", "report", "enforce"])
def test_check_logs_and_counts_unless_off(tmp_path: Path, mode: str) -> None:
    (tmp_path / "evil.pth").write_text("import evil\n")
    (tmp_path / "evil.py").write_text("")

    result = subprocess.run(
        [sys.executable, "-c", _CHECK, mode, str(tmp_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    answer = json.loads(result.stdout.splitlines()[-1])
    if mode == "off":
        assert answer == {"findings": [], "gauge": 0.0, "reads": 0}
        assert "startup_hook_unexpected" not in result.stderr
    else:
        assert answer["findings"] == ["pth_import", "pth_target"]
        assert answer["gauge"] >= 2
        assert answer["reads"] >= 2
        assert result.stderr.count("startup_hook_unexpected") >= 2
