"""Export the FastAPI contract as a deterministic JSON artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUTS = {
    "community": REPOSITORY_ROOT / "openapi" / "community.json",
    "enterprise": REPOSITORY_ROOT / "ee" / "openapi" / "enterprise.json",
}


def render_openapi(profile: str) -> str:
    """Return the canonical OpenAPI document with stable formatting."""
    if profile == "community":
        from shim.application import create_community_app
        from shim.core.community_config import CommunitySettings

        application = create_community_app(CommunitySettings(_env_file=None))
    elif profile == "enterprise":
        from shim_enterprise.application import create_enterprise_app

        application = create_enterprise_app()
    else:
        raise ValueError(f"unknown OpenAPI profile: {profile}")
    return json.dumps(application.openapi(), indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        choices=tuple(DEFAULT_OUTPUTS),
        required=True,
        help="Application profile to export",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output path (default: the selected profile's canonical artifact)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail instead of writing when the committed artifact is stale",
    )
    args = parser.parse_args()

    output = (args.output or DEFAULT_OUTPUTS[args.profile]).resolve()
    rendered = render_openapi(args.profile)
    if args.check:
        if not output.exists() or output.read_text(encoding="utf-8") != rendered:
            parser.error(f"{output} is stale; rerun this command without --check")
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
