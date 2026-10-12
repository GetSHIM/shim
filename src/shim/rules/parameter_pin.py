"""Parameter pins: a provider parameter every request in scope carries at one value."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, StrictFloat, StrictInt, model_validator

PinParameter = Literal["temperature", "top_p", "top_k", "seed", "reasoning_effort"]

# Where each parameter lives, by protocol; a protocol not listed has no such parameter.
PIN_PATHS: dict[str, dict[str, tuple[str, ...]]] = {
    "temperature": {
        "chat": ("temperature",),
        "responses": ("temperature",),
        "messages": ("temperature",),
        "generate_content": ("generationConfig", "temperature"),
    },
    "top_p": {
        "chat": ("top_p",),
        "responses": ("top_p",),
        "messages": ("top_p",),
        "generate_content": ("generationConfig", "topP"),
    },
    "top_k": {
        "messages": ("top_k",),
        "generate_content": ("generationConfig", "topK"),
    },
    "seed": {"chat": ("seed",), "generate_content": ("generationConfig", "seed")},
    "reasoning_effort": {
        "chat": ("reasoning_effort",),
        "responses": ("reasoning", "effort"),
    },
}
# (lowest, highest, integer only)
_BOUNDS = {
    "temperature": (0, 2, False),
    "top_p": (0, 1, False),
    "top_k": (1, 500, True),
    "seed": (0, 2_147_483_647, True),
}
EFFORTS = ("none", "minimal", "low", "medium", "high", "xhigh")


class ParameterPinMatch(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    parameter: PinParameter
    value: StrictInt | StrictFloat | str

    @model_validator(mode="after")
    def in_range(self) -> ParameterPinMatch:
        if self.parameter == "reasoning_effort":
            if self.value not in EFFORTS:
                raise ValueError(f"reasoning_effort is one of {', '.join(EFFORTS)}")
            return self
        low, high, integer = _BOUNDS[self.parameter]
        value = self.value
        if (
            isinstance(value, str)
            or (integer and not isinstance(value, int))
            or not low <= value <= high
        ):
            kind = "an integer" if integer else "a number"
            raise ValueError(f"{self.parameter} takes {kind} from {low} to {high:,}")
        return self
