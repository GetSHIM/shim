"""Lossless JSON request boundary for native provider payloads."""

from __future__ import annotations

from typing import TypeVar, cast

from pydantic import JsonValue, RootModel

RequestValue = TypeVar("RequestValue")


class ProviderRequest(RootModel[dict[str, JsonValue]]):
    """Preserve provider JSON while subclasses validate gateway routing fields."""

    def require(self, name: str, expected: type[RequestValue]) -> RequestValue:
        value = self.root.get(name)
        if name not in self.root or not isinstance(value, expected):
            raise ValueError(f"{name} must be {expected.__name__}")
        return cast(RequestValue, value)

    def optional(self, name: str, expected: type[RequestValue]) -> RequestValue | None:
        if name not in self.root:
            return None
        return self.require(name, expected)

    def require_nonempty_string(self, name: str) -> str:
        value = self.require(name, str)
        assert isinstance(value, str)
        if not value.strip():
            raise ValueError(f"{name} cannot be empty")
        if value != value.strip():
            raise ValueError(f"{name} cannot have surrounding whitespace")
        return value

    def optional_nonempty_string(self, name: str) -> str | None:
        if name not in self.root:
            return None
        return self.require_nonempty_string(name)

    def provider_payload(self, *exclude: str) -> dict[str, JsonValue]:
        return {key: value for key, value in self.root.items() if key not in exclude}
