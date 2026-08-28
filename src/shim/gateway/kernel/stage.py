"""Narrow protocol implemented by gateway pipeline stages."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, TypeVar


InputT = TypeVar("InputT", contravariant=True)
OutputT = TypeVar("OutputT", covariant=True)
TraceValue = str | int | float | bool | None


class Stage(Protocol[InputT, OutputT]):
    """A typed, independently testable kernel transition."""

    name: str

    async def run(self, value: InputT) -> OutputT:
        """Execute one transition and return its typed output."""

    def trace_metadata(self, output: OutputT) -> Mapping[str, TraceValue]:
        """Return bounded, non-sensitive metadata for the stage span."""
