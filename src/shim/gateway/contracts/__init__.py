"""Immutable contracts shared across gateway boundaries."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NoReturn, Self

from pydantic import BaseModel, ConfigDict


def _immutable(*_args: Any, **_kwargs: Any) -> NoReturn:
    raise TypeError("canonical contract collections are immutable")


class FrozenDict(dict):
    """JSON-serializable mapping that rejects mutation."""

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable

    def __ior__(self, _other: object) -> NoReturn:
        return _immutable()

    def __copy__(self) -> FrozenDict:
        return self

    def __deepcopy__(self, _memo: dict[int, Any]) -> FrozenDict:
        return self


class FrozenList(list):
    """JSON-serializable sequence that rejects mutation."""

    __setitem__ = _immutable
    __delitem__ = _immutable
    __iadd__ = _immutable
    __imul__ = _immutable
    append = _immutable
    clear = _immutable
    extend = _immutable
    insert = _immutable
    pop = _immutable
    remove = _immutable
    reverse = _immutable
    sort = _immutable

    def __copy__(self) -> FrozenList:
        return self

    def __deepcopy__(self, _memo: dict[int, Any]) -> FrozenList:
        return self


def deep_freeze(value: Any) -> Any:
    """Recursively freeze JSON-like containers without changing serialization."""

    if isinstance(value, dict):
        return FrozenDict({key: deep_freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return FrozenList(deep_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(deep_freeze(item) for item in value)
    if isinstance(value, set):
        return frozenset(deep_freeze(item) for item in value)
    return value


class FrozenContractModel(BaseModel):
    """Frozen Pydantic base whose copies remain validated and immutable."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    def model_post_init(self, __context: Any) -> None:
        for field_name in type(self).model_fields:
            object.__setattr__(self, field_name, deep_freeze(getattr(self, field_name)))

    def model_copy(
        self, *, update: Mapping[str, Any] | None = None, deep: bool = False
    ) -> Self:
        values = {name: getattr(self, name) for name in type(self).model_fields}
        if update:
            values.update(update)
        copied = type(self).model_validate(values)
        fields_set = set(self.model_fields_set)
        if update:
            fields_set.update(update)
        object.__setattr__(copied, "__pydantic_fields_set__", fields_set)
        return copied
