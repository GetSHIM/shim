from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import posixpath
import tomllib

import pytest


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "architecture/route_profiles.toml"
PROFILE_NAMES = ("community", "enterprise")
PROFILE_SCHEMAS = {
    "community": ROOT / "openapi/community.json",
    "enterprise": ROOT / "ee/openapi/enterprise.json",
}
OPENAPI_METHODS = frozenset(
    {"delete", "get", "head", "options", "patch", "post", "put", "trace"}
)
Route = tuple[str, str]


def _normalize_path(path: str) -> str:
    return posixpath.normpath(f"/{path.lstrip('/')}")


def _route_profiles() -> dict[str, list[Route]]:
    document = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    assert document.get("version") == 1
    raw_profiles = document.get("profiles")
    assert isinstance(raw_profiles, dict)
    assert set(raw_profiles) == set(PROFILE_NAMES)

    profiles: dict[str, list[Route]] = {}
    for profile in PROFILE_NAMES:
        raw_routes = raw_profiles[profile]
        assert isinstance(raw_routes, list)
        routes: list[Route] = []
        for raw_route in raw_routes:
            assert isinstance(raw_route, dict)
            assert set(raw_route) == {"method", "path"}
            method = raw_route["method"]
            path = raw_route["path"]
            assert isinstance(method, str)
            assert isinstance(path, str)
            assert method == method.upper() and method.lower() in OPENAPI_METHODS
            assert path == _normalize_path(path)
            routes.append((method, path))

        duplicates = sorted(
            route for route, count in Counter(routes).items() if count > 1
        )
        assert duplicates == [], f"duplicate {profile} routes: {duplicates}"
        profiles[profile] = routes
    return profiles


def _openapi_routes(schema_path: Path) -> set[Route]:
    document = json.loads(schema_path.read_text(encoding="utf-8"))
    paths = document.get("paths")
    assert isinstance(paths, dict)

    routes: set[Route] = set()
    for path, path_item in paths.items():
        assert isinstance(path, str)
        assert path == _normalize_path(path)
        assert isinstance(path_item, dict)
        for method in path_item:
            if method in OPENAPI_METHODS:
                routes.add((method.upper(), path))
    return routes


def test_route_profiles_are_normalized_and_unique() -> None:
    _route_profiles()


def test_community_profile_is_a_strict_enterprise_subset() -> None:
    profiles = _route_profiles()

    assert set(profiles["community"]) < set(profiles["enterprise"])


@pytest.mark.parametrize("profile", PROFILE_NAMES)
def test_generated_profile_openapi_is_exact(profile: str) -> None:
    schema_path = PROFILE_SCHEMAS[profile]

    assert schema_path.is_file()
    assert _openapi_routes(schema_path) == set(_route_profiles()[profile])
