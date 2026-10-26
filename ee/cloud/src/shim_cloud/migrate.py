"""Apply enterprise migrations before the independent cloud schema."""

from pathlib import Path
import subprocess
import sys

from shim_enterprise.guards import start_guards


def main() -> None:
    for path in (Path("ee/alembic.ini"), Path("ee/cloud/alembic.ini")):
        subprocess.run(
            [sys.executable, "-m", "alembic", "-c", str(path), "upgrade", "head"],
            check=True,
        )


if __name__ == "__main__":
    # Alembic runs in a child, which an audit hook does not reach.
    start_guards(egress=False)
    main()
