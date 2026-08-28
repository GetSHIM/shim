from __future__ import annotations

import ast
from collections import Counter
from importlib.util import resolve_name
from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "architecture/module_ownership.toml"
OWNERS = ("public", "enterprise", "split")
PYTHON_ROOTS = (
    "ee/alembic",
    "ee/scripts",
    "ee/src/shim_enterprise",
    "ee/tests",
    "scripts",
    "src/shim",
    "tests",
)
ENTERPRISE_RUNTIME_ROOTS = (
    "ee/alembic",
    "ee/scripts",
    "ee/src/shim_enterprise",
)
# Enterprise tests may white-box community behavior without expanding the
# supported runtime API recorded in enterprise_public_api.


def _forbidden_public_import_roots() -> set[str]:
    document = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    roots = document.get("forbidden_public_import_roots")
    assert isinstance(roots, list)
    assert all(isinstance(root, str) and root for root in roots)
    typed_roots = [root for root in roots if isinstance(root, str)]
    assert typed_roots == sorted(set(typed_roots))
    return set(typed_roots)


def _enterprise_public_api() -> set[tuple[str, str]]:
    document = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    api = document.get("enterprise_public_api")
    assert isinstance(api, dict)
    assert list(api) == sorted(api)

    entries: set[tuple[str, str]] = set()
    for module, symbols in api.items():
        assert isinstance(module, str) and module.startswith("shim.")
        assert isinstance(symbols, list) and symbols
        assert all(
            isinstance(symbol, str) and symbol and symbol != "*" for symbol in symbols
        )
        typed_symbols = [symbol for symbol in symbols if isinstance(symbol, str)]
        assert typed_symbols == sorted(set(typed_symbols)), (
            f"unsorted public API symbols for {module}"
        )
        entries.update((module, symbol) for symbol in typed_symbols)
    return entries


def _manifest_ownership() -> dict[str, str]:
    document = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    assert document.get("version") == 1
    modules = document.get("modules")
    assert isinstance(modules, dict)
    assert set(modules) == set(OWNERS)

    owned_paths: dict[str, list[str]] = {}
    for owner in OWNERS:
        paths = modules[owner]
        assert isinstance(paths, list)
        assert all(isinstance(path, str) and path.endswith(".py") for path in paths)
        typed_paths = [path for path in paths if isinstance(path, str)]
        assert typed_paths == sorted(typed_paths), f"unsorted {owner} paths"
        owned_paths[owner] = typed_paths

    entries = [path for owner in OWNERS for path in owned_paths[owner]]
    duplicates = sorted(path for path, count in Counter(entries).items() if count > 1)
    current = {
        path.relative_to(ROOT).as_posix()
        for directory in PYTHON_ROOTS
        for path in (ROOT / directory).rglob("*.py")
    }
    recorded = set(entries)

    assert duplicates == [], f"duplicate ownership paths: {duplicates}"
    assert current - recorded == set(), (
        f"missing ownership paths: {sorted(current - recorded)}"
    )
    assert recorded - current == set(), (
        f"stale ownership paths: {sorted(recorded - current)}"
    )
    return {path: owner for owner in OWNERS for path in owned_paths[owner]}


def _module_name(path: str) -> str:
    parts = Path(path).with_suffix("").parts
    if parts[:3] == ("ee", "src", "shim_enterprise"):
        parts = parts[2:]
    elif parts[:2] == ("src", "shim"):
        parts = parts[1:]
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _add_known_import(name: str, known: set[str], imported: set[str]) -> None:
    parts = name.split(".")
    imported.update(
        candidate
        for index in range(1, len(parts) + 1)
        if (candidate := ".".join(parts[:index])) in known
    )


def _literal_string(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _dynamic_import_name(
    node: ast.Call,
    package: str,
    importlib_names: set[str],
    import_module_names: set[str],
    builtins_names: set[str],
    builtin_import_names: set[str],
) -> str | None:
    is_import_module = (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in importlib_names
        and node.func.attr == "import_module"
    ) or (isinstance(node.func, ast.Name) and node.func.id in import_module_names)
    is_builtin_import = (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in builtins_names
        and node.func.attr == "__import__"
    ) or (isinstance(node.func, ast.Name) and node.func.id in builtin_import_names)
    if not is_import_module and not is_builtin_import:
        return None

    loader = "importlib.import_module" if is_import_module else "__import__"
    if not node.args or (name := _literal_string(node.args[0])) is None:
        return f"<unresolved dynamic import via {loader}: non-literal module name>"
    if is_builtin_import or not name.startswith("."):
        return name

    package_node = node.args[1] if len(node.args) > 1 else None
    if package_node is None:
        package_node = next(
            (keyword.value for keyword in node.keywords if keyword.arg == "package"),
            None,
        )
    if isinstance(package_node, ast.Name) and package_node.id == "__package__":
        dynamic_package = package
    elif package_node is not None and (
        dynamic_package := _literal_string(package_node)
    ):
        pass
    else:
        return (
            "<unresolved dynamic import via importlib.import_module: "
            "relative module has non-literal package>"
        )
    return resolve_name(name, dynamic_package)


def _dynamic_import_aliases(
    tree: ast.AST,
) -> tuple[set[str], set[str], set[str], set[str]]:
    importlib_names = {"importlib"}
    import_module_names: set[str] = set()
    builtins_names = {"builtins"}
    builtin_import_names = {"__import__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            importlib_names.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name == "importlib"
            )
            builtins_names.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name == "builtins"
            )
        elif (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module == "importlib"
        ):
            import_module_names.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name == "import_module"
            )
        elif (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module == "builtins"
        ):
            builtin_import_names.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name == "__import__"
            )
    return (
        importlib_names,
        import_module_names,
        builtins_names,
        builtin_import_names,
    )


def _scan_imports(source: str, *, package: str, known: set[str]) -> set[str]:
    tree = ast.parse(source)
    aliases = _dynamic_import_aliases(tree)

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _add_known_import(alias.name, known, imported)
        elif isinstance(node, ast.ImportFrom):
            specifier = f"{'.' * node.level}{node.module or ''}"
            base = resolve_name(specifier, package) if node.level else specifier
            _add_known_import(base, known, imported)
            for alias in node.names:
                _add_known_import(f"{base}.{alias.name}", known, imported)
        elif isinstance(node, ast.Call):
            if name := _dynamic_import_name(
                node,
                package,
                *aliases,
            ):
                _add_known_import(name, known, imported)
                if name.startswith("<unresolved dynamic import"):
                    imported.add(name)
    return imported


def _scan_public_api_imports(
    source: str,
    *,
    package: str,
) -> tuple[set[tuple[str, str]], set[str]]:
    tree = ast.parse(source)
    aliases = _dynamic_import_aliases(tree)
    imported: set[tuple[str, str]] = set()
    errors: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            errors.update(
                f"line {node.lineno}: bare public module import {alias.name}"
                for alias in node.names
                if alias.name == "shim" or alias.name.startswith("shim.")
            )
        elif isinstance(node, ast.ImportFrom):
            specifier = f"{'.' * node.level}{node.module or ''}"
            module = resolve_name(specifier, package) if node.level else specifier
            if module == "shim" or module.startswith("shim."):
                for alias in node.names:
                    if alias.name == "*":
                        errors.add(f"line {node.lineno}: public API star import")
                    else:
                        imported.add((module, alias.name))
        elif isinstance(node, ast.Call):
            name = _dynamic_import_name(
                node,
                package,
                *aliases,
            )
            if name is None:
                continue
            if name.startswith("<unresolved dynamic import"):
                errors.add(f"line {node.lineno}: {name}")
            elif name == "shim" or name.startswith("shim."):
                errors.add(f"line {node.lineno}: dynamic public module import {name}")
    return imported, errors


def _imported_module_names(path: str, known: set[str]) -> set[str]:
    source = ROOT / path
    current = _module_name(path)
    package = current if source.name == "__init__.py" else current.rpartition(".")[0]
    return _scan_imports(
        source.read_text(encoding="utf-8"),
        package=package,
        known=known,
    )


def _internal_import_graph(ownership: dict[str, str]) -> dict[str, set[str]]:
    paths_by_module = {_module_name(path): path for path in ownership}
    assert len(paths_by_module) == len(ownership), "duplicate Python module names"
    known = set(paths_by_module)
    return {
        path: {
            paths_by_module[name]
            for name in _imported_module_names(path, known)
            if name in paths_by_module
        }
        for path in ownership
    }


def _reachable_paths(graph: dict[str, set[str]], start: str) -> set[str]:
    reachable: set[str] = set()
    pending = list(graph[start])
    while pending:
        path = pending.pop()
        if path in reachable:
            continue
        reachable.add(path)
        pending.extend(graph[path] - reachable)
    return reachable


def test_python_files_have_exactly_one_current_owner() -> None:
    _manifest_ownership()


def test_python_ownership_regions_are_canonical() -> None:
    ownership = _manifest_ownership()
    prefixes = {
        "public": ("scripts/", "src/shim/", "tests/"),
        "enterprise": (
            "ee/alembic/",
            "ee/scripts/",
            "ee/src/shim_enterprise/",
            "ee/tests/",
        ),
        "split": ("scripts/export_openapi.py", "tests/architecture/"),
    }
    violations = {
        path: owner
        for path, owner in ownership.items()
        if not path.startswith(prefixes[owner])
    }

    assert violations == {}
    assert all(
        not (ROOT / retired).exists()
        for retired in ("alembic", "app", "app.py", "src/shim_enterprise")
    )
    retired_imports = {
        path: sorted(imports)
        for path in ownership
        if (imports := _imported_module_names(path, {"app"}))
    }
    assert retired_imports == {}


def test_public_files_cannot_reach_enterprise_files() -> None:
    ownership = _manifest_ownership()
    graph = _internal_import_graph(ownership)
    enterprise = {path for path, owner in ownership.items() if owner == "enterprise"}
    violations = {
        path: sorted(_reachable_paths(graph, path) & enterprise)
        for path, owner in ownership.items()
        if owner == "public"
    }
    assert {path: imports for path, imports in violations.items() if imports} == {}


def test_public_files_cannot_reach_forbidden_or_unresolved_dependencies() -> None:
    ownership = _manifest_ownership()
    graph = _internal_import_graph(ownership)
    forbidden = _forbidden_public_import_roots()
    violations: dict[str, list[str]] = {}
    for path, owner in ownership.items():
        if owner != "public":
            continue
        reachable = {path, *_reachable_paths(graph, path)}
        imports = {
            name
            for dependency_path in reachable
            for name in _imported_module_names(dependency_path, forbidden)
        }
        if imports:
            violations[path] = sorted(imports)
    assert violations == {}


def test_enterprise_runtime_uses_exact_declared_public_api() -> None:
    ownership = _manifest_ownership()
    public_modules = {
        _module_name(path)
        for path, owner in ownership.items()
        if owner == "public" and path.startswith("src/shim/")
    }
    allowed = _enterprise_public_api()
    assert {module for module, _ in allowed} <= public_modules

    imported: set[tuple[str, str]] = set()
    errors: dict[str, list[str]] = {}
    for directory in ENTERPRISE_RUNTIME_ROOTS:
        for path in sorted((ROOT / directory).rglob("*.py")):
            relative_path = path.relative_to(ROOT).as_posix()
            module = _module_name(relative_path)
            package = (
                module if path.name == "__init__.py" else module.rpartition(".")[0]
            )
            file_imports, file_errors = _scan_public_api_imports(
                path.read_text(encoding="utf-8"),
                package=package,
            )
            imported.update(file_imports)
            if file_errors:
                errors[relative_path] = sorted(file_errors)

    assert errors == {}
    assert imported == allowed, (
        f"undeclared public API: {sorted(imported - allowed)}; "
        f"stale public API: {sorted(allowed - imported)}"
    )


def test_import_scanner_covers_static_and_dynamic_forms() -> None:
    known = {
        "shim_enterprise.absolute",
        "shim_enterprise.builtin_dynamic",
        "shim_enterprise.dynamic",
        "shim_enterprise.lazy",
        "shim_enterprise.optional",
        "shim_enterprise.package.dynamic_relative",
        "shim_enterprise.package.relative",
        "shim_enterprise.type_checked",
    }
    source = """
import shim_enterprise.absolute
from . import relative

def load_lazily():
    import shim_enterprise.lazy

try:
    import shim_enterprise.optional
except ImportError:
    pass

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from shim_enterprise import type_checked

import importlib
importlib.import_module("shim_enterprise.dynamic")
importlib.import_module(".dynamic_relative", __package__)
__import__("shim_enterprise.builtin_dynamic")
"""
    assert (
        _scan_imports(source, package="shim_enterprise.package", known=known) == known
    )


def test_public_api_scanner_fails_closed_across_import_forms() -> None:
    source = """
from shim.public import Direct

def load_lazily():
    from shim.public import Lazy

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from shim.public import TypeChecked

from shim.star import *
import shim.bare

import importlib as il
il.import_module("shim.dynamic")
il.import_module(module_name)
"""
    imported, errors = _scan_public_api_imports(
        source,
        package="shim_enterprise.package",
    )

    assert imported == {
        ("shim.public", "Direct"),
        ("shim.public", "Lazy"),
        ("shim.public", "TypeChecked"),
    }
    assert errors == {
        "line 11: public API star import",
        "line 12: bare public module import shim.bare",
        "line 15: dynamic public module import shim.dynamic",
        "line 16: <unresolved dynamic import via "
        "importlib.import_module: non-literal module name>",
    }


def test_dynamic_import_scanner_tracks_aliases_and_fails_closed() -> None:
    module_error = (
        "<unresolved dynamic import via importlib.import_module: "
        "non-literal module name>"
    )
    builtin_error = (
        "<unresolved dynamic import via __import__: non-literal module name>"
    )
    package_error = (
        "<unresolved dynamic import via importlib.import_module: "
        "relative module has non-literal package>"
    )
    cases = (
        (
            'import importlib as il\nil.import_module("shim_enterprise.loaded")',
            {"shim_enterprise.loaded"},
        ),
        (
            'from importlib import import_module as load\nload("shim_enterprise.loaded")',
            {"shim_enterprise.loaded"},
        ),
        ("import importlib\nimportlib.import_module(module_name)", {module_error}),
        ("import importlib as il\nil.import_module(module_name)", {module_error}),
        (
            "from importlib import import_module\nimport_module(module_name)",
            {module_error},
        ),
        (
            "from importlib import import_module as load\nload(module_name)",
            {module_error},
        ),
        ("__import__(module_name)", {builtin_error}),
        (
            'import builtins as bi\nbi.__import__("shim_enterprise.loaded")',
            {"shim_enterprise.loaded"},
        ),
        (
            "from builtins import __import__ as load\nload(module_name)",
            {builtin_error},
        ),
        (
            'importlib.import_module(".relative", package_name)',
            {package_error},
        ),
        (
            'importlib.import_module(".relative", __package__)',
            {"shim_enterprise.package.relative"},
        ),
    )
    known = {"shim_enterprise.loaded", "shim_enterprise.package.relative"}
    for source, expected in cases:
        assert (
            _scan_imports(source, package="shim_enterprise.package", known=known)
            == expected
        )


def test_reachability_follows_transitive_imports() -> None:
    graph = {
        "public.py": {"split.py"},
        "split.py": {"enterprise.py"},
        "enterprise.py": set(),
    }
    assert _reachable_paths(graph, "public.py") == {
        "enterprise.py",
        "split.py",
    }
