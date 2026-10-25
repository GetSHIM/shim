"""Find Python startup hooks the published image does not ship.

A `.pth` line that starts with `import` and a `sitecustomize` or `usercustomize`
module run at interpreter start, before shim. The scan only reads files: it never
imports, runs or removes what it finds.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Sequence
import hashlib
import importlib.util
import logging
from pathlib import Path
import site
import sys
import sysconfig
from types import MappingProxyType
from typing import Final, Literal, NamedTuple

from shim.observability.metrics import STARTUP_HOOKS_UNEXPECTED

# The hooks of ghcr.io/getshim/shim, identical on amd64 and arm64: path relative to
# site-packages, sha256 of its bytes. A change here is a reviewed change.
ALLOWLIST: Final = MappingProxyType(
    {
        # uv's virtual environment.
        "_virtualenv.pth": "69ac3d8f27e679c81b94ab30b3b56e9cd138219b1ba94a1fa3606d5a76a1433d",
        "_virtualenv.py": "cfb3db86aaa53bb62b5ff764970bec2d71c9228590a0ebec57f6ec926cc0bf1a",
        # setuptools 84.2.1, a runtime dependency of spacy and thinc.
        "distutils-precedence.pth": "2638ce9e2500e572a5e0de7faed6661eb569d1b696fcba07b0dd223da5f5d224",
        "_distutils_hack/__init__.py": "ced72e54431ecf2d8d7dbd8a1e27724f1b171af3ca1503c304bf11c59a7fe861",
    }
)
EX_CONFIG: Final = 78

Mode = Literal["off", "report", "enforce"]
Kind = Literal["pth_import", "pth_target", "sitecustomize", "usercustomize"]

_logger = logging.getLogger(__name__)


class Finding(NamedTuple):
    path: str
    kind: Kind
    sha256: str


def check(mode: Mode) -> tuple[Finding, ...]:
    """Scan unless `off`; log each finding and set the gauge to their number."""

    if mode == "off":
        return ()
    findings = scan()
    for finding in findings:
        _logger.warning("startup_hook_unexpected", extra=finding._asdict())
    STARTUP_HOOKS_UNEXPECTED.set(len(findings))
    return findings


def scan(directories: Sequence[Path] | None = None) -> tuple[Finding, ...]:
    """Every startup hook in the site directories that the allowlist does not hold."""

    roots = list(_site_directories() if directories is None else directories)
    findings: list[Finding] = []
    targets: set[str] = set()
    for root in roots:
        for path in sorted(root.glob("*.pth")) if root.is_dir() else ():
            try:
                data = path.read_bytes()
            except OSError:
                # Python's site cannot read it either, so it runs nothing.
                continue
            # The rule in CPython's site.addpackage.
            hooks = [
                line
                for line in data.decode("utf-8-sig", "replace").splitlines()
                if line.startswith(("import ", "import\t"))
            ]
            if not hooks:
                continue
            if ALLOWLIST.get(path.name) != _sha256(data):
                findings.append(Finding(str(path), "pth_import", _sha256(data)))
            targets.update(_imported(hooks))
    for module in sorted(targets):
        if finding := _unexpected(module, "pth_target", roots):
            findings.append(finding)
    for module in ("sitecustomize", "usercustomize"):
        if finding := _unexpected(module, module, roots, always=True):
            findings.append(finding)
    return tuple(findings)


def _site_directories() -> list[Path]:
    directories = list(site.getsitepackages())
    if site.ENABLE_USER_SITE:
        directories.append(site.getusersitepackages())
    return [Path(directory) for directory in directories]


def _imported(lines: Iterable[str]) -> set[str]:
    """Top-level modules a hook line imports, by statement or literal `__import__`."""

    names: set[str] = set()
    for line in lines:
        try:
            tree = ast.parse(line)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                names.add(node.module)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "__import__"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                names.add(node.args[0].value)
    return {name.split(".", 1)[0] for name in names}


def _unexpected(
    module: str, kind: Kind, roots: Sequence[Path], *, always: bool = False
) -> Finding | None:
    """A finding for `module` unless it is absent, in the standard library or allowed.

    `always`: the module is a hook wherever it lives, even loaded with no file.
    """

    try:
        spec = importlib.util.find_spec(module)
    except (ImportError, ValueError):
        spec = None
    if spec is None:
        return Finding(module, kind, "") if always and module in sys.modules else None
    if not spec.has_location or spec.origin is None:
        return Finding(module, kind, "") if always else None
    origin = Path(spec.origin)
    # A system Python keeps site-packages inside its stdlib directory, and a virtual
    # environment's platstdlib is its own lib directory, so a site root is never stdlib.
    if (
        not always
        and not any(origin.is_relative_to(root) for root in roots)
        and origin.is_relative_to(sysconfig.get_path("stdlib"))
    ):
        return None
    try:
        digest = _sha256(origin.read_bytes())
    except OSError:
        return Finding(str(origin), kind, "")
    for root in roots:
        if origin.is_relative_to(root) and (
            ALLOWLIST.get(origin.relative_to(root).as_posix()) == digest
        ):
            return None
    return Finding(str(origin), kind, digest)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
