from __future__ import annotations


class ScanAnalysisError(RuntimeError):
    code = "INTERNAL_ERROR"

    def __init__(self) -> None:
        super().__init__("PII analysis could not be completed.")
