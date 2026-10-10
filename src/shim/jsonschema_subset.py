"""A bounded check of a JSON value against the JSON Schema subset structured output uses.

Stdlib only. Evaluated: `type`, `enum`, `const`, `properties`, `required`,
`additionalProperties`, `minProperties`, `maxProperties`, `items` (the Draft 7 list form as
`prefixItems`), `prefixItems`, `minItems`, `maxItems`, `uniqueItems`, `minLength`, `maxLength`
(code points), `minimum`, `maximum`, numeric `exclusiveMinimum` and `exclusiveMaximum`,
`multipleOf` (exact), `allOf`, `anyOf`, `oneOf`, and `$ref` within the document. Annotations are
ignored. Anything else is reported in `unsupported` and never guessed; `pattern` is never run.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import math
from typing import Any, Literal

Reason = Literal["depth", "nodes", "too_large", "bad_schema"]

_ANNOTATIONS = frozenset(
    {
        "title",
        "description",
        "default",
        "examples",
        "$comment",
        "deprecated",
        "readOnly",
        "writeOnly",
        "format",
        "contentEncoding",
        "contentMediaType",
        "$schema",
        "$defs",
        "definitions",
    }
)
_OPENAPI_ANNOTATIONS = frozenset({"propertyOrdering", "example", "nullable"})
_MAX_UNSUPPORTED = 16
_MAX_SEGMENT = 64
_MAX_PATH = 512


@dataclass(frozen=True, slots=True)
class SchemaCheck:
    valid: bool | None
    error_path: str | None
    error_keyword: str | None
    unsupported: tuple[str, ...]
    reason: Reason | None


class _Stop(Exception):
    def __init__(self, reason: Reason) -> None:
        self.reason = reason


# (state, (path, keyword) of the first failure)
_Result = tuple[bool | None, tuple[tuple[str, ...], str] | None]
_TRUE: _Result = (True, None)


def _types(value: Any) -> set[str]:
    if value is None:
        return {"null"}
    if isinstance(value, bool):
        return {"boolean"}
    if isinstance(value, int):
        return {"integer", "number"}
    if isinstance(value, float):
        whole = math.isfinite(value) and value.is_integer()
        return {"number", "integer"} if whole else {"number"}
    if isinstance(value, str):
        return {"string"}
    if isinstance(value, list):
        return {"array"}
    if isinstance(value, dict):
        return {"object"}
    return set()


def _number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _equal(left: Any, right: Any) -> bool:
    """JSON equality: 1 equals 1.0, true never equals 1."""

    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if _number(left) and _number(right):
        return left == right
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(map(_equal, left, right))
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(
            _equal(value, right[key]) for key, value in left.items()
        )
    return type(left) is type(right) and left == right


class _Run:
    def __init__(self, root: Any, dialect: str, max_depth: int, max_nodes: int) -> None:
        self.root = root
        self.openapi = dialect == "openapi"
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.nodes = 0
        self.unsupported: set[str] = set()

    def resolve(self, reference: Any) -> Any:
        if not isinstance(reference, str):
            raise _Stop("bad_schema")
        if not reference.startswith("#"):
            return None
        node = self.root
        for part in reference[1:].split("/")[1:] if reference != "#" else []:
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(node, dict) and part in node:
                node = node[part]
            elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
                node = node[int(part)]
            else:
                raise _Stop("bad_schema")
        return node

    def unknown(self, keyword: str) -> bool | None:
        self.unsupported.add(keyword[:_MAX_SEGMENT])
        return None

    def evaluate(
        self, value: Any, schema: Any, path: tuple[str, ...], depth: int
    ) -> _Result:
        if depth > self.max_depth:
            raise _Stop("depth")
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise _Stop("nodes")
        if schema is True:
            return _TRUE
        if schema is False:
            return False, (path, "false")
        if not isinstance(schema, dict):
            raise _Stop("bad_schema")
        unknown = False
        for keyword, argument in schema.items():
            try:
                state, failure = self.keyword(
                    value, schema, keyword, argument, path, depth
                )
            except (
                TypeError,
                ValueError,
                InvalidOperation,
                AttributeError,
                LookupError,
            ):
                raise _Stop("bad_schema") from None
            if state is False:
                return False, failure or (path, keyword)
            unknown = unknown or state is None
        return (None, None) if unknown else _TRUE

    def keyword(
        self,
        value: Any,
        schema: dict[str, Any],
        keyword: str,
        argument: Any,
        path: tuple[str, ...],
        depth: int,
    ) -> _Result:
        if keyword in _ANNOTATIONS or (keyword == "$id" and schema is self.root):
            return _TRUE
        if self.openapi and keyword in _OPENAPI_ANNOTATIONS:
            return _TRUE
        if keyword == "type":
            allowed = {argument} if isinstance(argument, str) else set(argument)
            if self.openapi:
                allowed = {name.lower() for name in allowed}
                if schema.get("nullable") is True:
                    allowed.add("null")
            return (True, None) if _types(value) & allowed else (False, None)
        if keyword in {"enum", "const"}:
            options = argument if keyword == "enum" else [argument]
            return (any(_equal(value, option) for option in options), None)
        if keyword == "$ref":
            target = self.resolve(argument)
            if target is None:
                return self.unknown("$ref"), None
            return self.evaluate(value, target, path, depth + 1)
        if keyword in {"allOf", "anyOf", "oneOf"}:
            return self.combine(value, keyword, argument, path, depth)
        if isinstance(value, dict):
            return self.object_keyword(value, schema, keyword, argument, path, depth)
        if isinstance(value, list):
            return self.array_keyword(value, schema, keyword, argument, path, depth)
        if isinstance(value, str) and keyword in {"minLength", "maxLength"}:
            ok = (
                len(value) >= argument
                if keyword == "minLength"
                else len(value) <= argument
            )
            return ok, None
        if _number(value) and keyword in {
            "minimum",
            "maximum",
            "exclusiveMinimum",
            "exclusiveMaximum",
            "multipleOf",
        }:
            return self.number_keyword(value, keyword, argument)
        if keyword in _APPLIES_TO:
            # A keyword for another type says nothing about this value.
            return _TRUE
        return self.unknown(keyword), None

    def number_keyword(self, value: Any, keyword: str, argument: Any) -> _Result:
        if isinstance(argument, bool):
            return self.unknown(keyword), None
        if keyword == "minimum":
            return value >= argument, None
        if keyword == "maximum":
            return value <= argument, None
        if keyword == "exclusiveMinimum":
            return value > argument, None
        if keyword == "exclusiveMaximum":
            return value < argument, None
        if not math.isfinite(value) or argument <= 0:
            return self.unknown(keyword), None
        try:
            return Decimal(repr(value)) % Decimal(repr(argument)) == 0, None
        except InvalidOperation:
            # A quotient too large for the context: undecided, not invalid.
            return self.unknown(keyword), None

    def object_keyword(
        self,
        value: dict[str, Any],
        schema: dict[str, Any],
        keyword: str,
        argument: Any,
        path: tuple[str, ...],
        depth: int,
    ) -> _Result:
        if keyword == "properties":
            unknown = False
            for name, child in argument.items():
                if name in value:
                    state, failure = self.evaluate(
                        value[name], child, (*path, name), depth + 1
                    )
                    if state is False:
                        return False, failure
                    unknown = unknown or state is None
            return (None, None) if unknown else _TRUE
        if keyword == "required":
            missing = next((name for name in argument if name not in value), None)
            return _TRUE if missing is None else (False, ((*path, missing), keyword))
        if keyword == "additionalProperties":
            if "patternProperties" in schema:
                return None, None
            extra = [key for key in value if key not in schema.get("properties", {})]
            unknown = False
            for key in extra:
                state, failure = self.evaluate(
                    value[key], argument, (*path, "*"), depth + 1
                )
                if state is False:
                    return False, ((*path, "*"), keyword)
                unknown = unknown or state is None
            return (None, None) if unknown else _TRUE
        if keyword == "minProperties":
            return len(value) >= argument, None
        if keyword == "maxProperties":
            return len(value) <= argument, None
        if keyword in _APPLIES_TO:
            return _TRUE
        return self.unknown(keyword), None

    def array_keyword(
        self,
        value: list[Any],
        schema: dict[str, Any],
        keyword: str,
        argument: Any,
        path: tuple[str, ...],
        depth: int,
    ) -> _Result:
        if keyword == "prefixItems" or (
            keyword == "items" and isinstance(argument, list)
        ):
            # Draft 7's list form of items is what 2020-12 calls prefixItems.
            pairs = list(enumerate(argument[: len(value)]))
        elif keyword == "items":
            prefix = schema.get("prefixItems")
            start = len(prefix) if isinstance(prefix, list) else 0
            pairs = [(index, argument) for index in range(start, len(value))]
        else:
            pairs = None
        if pairs is not None:
            unknown = False
            for index, child in pairs:
                state, failure = self.evaluate(
                    value[index], child, (*path, str(index)), depth + 1
                )
                if state is False:
                    return False, failure
                unknown = unknown or state is None
            return (None, None) if unknown else _TRUE
        if keyword == "minItems":
            return len(value) >= argument, None
        if keyword == "maxItems":
            return len(value) <= argument, None
        if keyword == "uniqueItems":
            if not argument:
                return _TRUE
            # ponytail: O(n²) pairs, bounded by max_nodes; hashing JSON equality would cost more code.
            for index, item in enumerate(value):
                self.nodes += len(value) - index
                if self.nodes > self.max_nodes:
                    raise _Stop("nodes")
                if any(_equal(item, other) for other in value[index + 1 :]):
                    return False, None
            return _TRUE
        if keyword in _APPLIES_TO:
            return _TRUE
        return self.unknown(keyword), None

    def combine(
        self,
        value: Any,
        keyword: str,
        branches: list[Any],
        path: tuple[str, ...],
        depth: int,
    ) -> _Result:
        results = []
        for branch in branches:
            state, failure = self.evaluate(value, branch, path, depth)
            if keyword == "allOf" and state is False:
                return False, failure
            results.append(state)
        trues, unknowns = results.count(True), results.count(None)
        if keyword == "allOf":
            return (None, None) if unknowns else _TRUE
        if keyword == "anyOf":
            return (
                (True, None) if trues else (None, None) if unknowns else (False, None)
            )
        if trues >= 2:
            return False, None
        if trues == 1 and not unknowns:
            return _TRUE
        return (None, None) if unknowns else (False, None)


# Keywords this module evaluates for some type; on a value of another type they pass.
_APPLIES_TO = frozenset(
    {
        "properties",
        "required",
        "additionalProperties",
        "minProperties",
        "maxProperties",
        "items",
        "prefixItems",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
    }
)


def _pointer(path: tuple[str, ...]) -> str:
    pointer = "".join(
        "/" + segment[:_MAX_SEGMENT].replace("~", "~0").replace("/", "~1")
        for segment in path
    )
    return pointer[:_MAX_PATH]


def check(
    instance: Any,
    schema: Any,
    *,
    dialect: Literal["json_schema", "openapi"] = "json_schema",
    max_depth: int = 32,
    max_nodes: int = 10_000,
) -> SchemaCheck:
    """Never raises for any JSON value and schema; records no value."""

    run = _Run(schema, dialect, max_depth, max_nodes)
    try:
        state, failure = run.evaluate(instance, schema, (), 0)
    except _Stop as stop:
        return SchemaCheck(None, None, None, _listed(run), stop.reason)
    except RecursionError:
        return SchemaCheck(None, None, None, _listed(run), "depth")
    if state is False and failure is not None:
        return SchemaCheck(False, _pointer(failure[0]), failure[1], _listed(run), None)
    return SchemaCheck(None if state is None else True, None, None, _listed(run), None)


def _listed(run: _Run) -> tuple[str, ...]:
    return tuple(sorted(run.unsupported)[:_MAX_UNSUPPORTED])
