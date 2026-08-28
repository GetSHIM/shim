"""Enterprise scan accounting errors."""

from __future__ import annotations

from .enterprise_scan import ScanUsageStatus


class ScanLimitExceeded(RuntimeError):
    code = "SCAN_LIMIT_EXCEEDED"

    def __init__(self, usage: ScanUsageStatus) -> None:
        super().__init__("Monthly scan limit exceeded.")
        self.usage = usage


class ScanPersistenceError(RuntimeError):
    code = "INTERNAL_ERROR"

    def __init__(self) -> None:
        super().__init__("Scan state could not be persisted.")
