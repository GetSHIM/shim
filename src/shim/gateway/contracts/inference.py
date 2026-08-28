"""Provider-free scan contracts."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from . import FrozenContractModel


ScanVerdict = Literal["clean", "warn", "block"]
ScanPolicy = Literal["warn", "block"]


class ScanInput(FrozenContractModel):
    text: str = Field(max_length=50_000)
    source: Literal["chatgpt", "gemini", "unknown"] = "unknown"


class ScanEntity(FrozenContractModel):
    type: str = Field(min_length=1)
    score: float = Field(ge=0, le=1)
    start: int = Field(ge=0)
    end: int = Field(ge=0)
