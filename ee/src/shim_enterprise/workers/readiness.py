"""Local successful-pass heartbeat; independent of application configuration."""

import argparse
import json
import logging
import math
import os
from pathlib import Path
import tempfile
import time

logger = logging.getLogger(__name__)


def write_heartbeat(path: Path | None, worker: str) -> None:
    if path is None:
        return
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", dir=path.parent, delete=False
        ) as file:
            temporary = Path(file.name)
            json.dump({"worker": worker, "monotonic_success": time.monotonic()}, file)
        os.replace(temporary, path)
    except (OSError, ValueError) as exc:
        logger.error("Worker heartbeat write failed type=%s", type(exc).__name__)
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except (OSError, ValueError) as exc:
                logger.error(
                    "Worker heartbeat cleanup failed type=%s", type(exc).__name__
                )


def is_ready(path: Path, worker: str, max_age_seconds: float) -> bool:
    if (
        not path.is_absolute()
        or not math.isfinite(max_age_seconds)
        or max_age_seconds <= 0
    ):
        return False
    try:
        payload = json.loads(path.read_text())
        if not isinstance(payload, dict) or payload.get("worker") != worker:
            return False
        timestamp = payload.get("monotonic_success")
        if type(timestamp) not in (int, float):
            return False
        age = time.monotonic() - timestamp
        return math.isfinite(age) and 0 <= age <= max_age_seconds
    except (OSError, ValueError, OverflowError):
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument(
        "--worker",
        choices=("outbox", "reconciliation", "compliance", "ai_act"),
        required=True,
    )
    parser.add_argument("--max-age-seconds", type=float, required=True)
    args = parser.parse_args()
    raise SystemExit(0 if is_ready(args.path, args.worker, args.max_age_seconds) else 1)


if __name__ == "__main__":
    main()
