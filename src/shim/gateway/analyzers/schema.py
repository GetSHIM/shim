"""The `schema` analyzer: does the answer, or each tool call, match the schema the app asked for."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Literal

from shim.gateway.pipeline.analysis import TOOL_NAME, AnalysisContext
from shim.jsonschema_subset import SchemaCheck, check

Dialect = Literal["json_schema", "openapi"]

MAX_SCHEMA_CHARACTERS = 100_000
MAX_TOOL_CALLS = 64
_JSON_FORMATS = frozenset({"json_object", "json_schema"})
# Maps of name to subschema; their names are keys, never values.
_SCHEMA_MAPS = frozenset({"properties", "patternProperties", "$defs", "definitions"})


@dataclass(frozen=True, slots=True)
class RequestedOutput:
    kind: Literal["json_schema", "json_object"]
    schema: Any
    dialect: Dialect
    # Whether the provider was asked to enforce the schema itself.
    strict: bool


@dataclass(frozen=True, slots=True)
class _ToolSchema:
    schema: Any
    dialect: Dialect
    strict: bool


def _at(value: Any, *keys: str) -> Any:
    for key in keys:
        value = value.get(key) if isinstance(value, dict) else None
    return value


def requested_output(payload: dict[str, Any], protocol: str) -> RequestedOutput | None:
    if protocol in {"chat", "responses"}:
        found = (
            payload.get("response_format")
            if protocol == "chat"
            else _at(payload, "text", "format")
        )
        kind = _at(found, "type")
        if kind not in _JSON_FORMATS:
            return None
        spec = _at(found, "json_schema") if protocol == "chat" else found
        return RequestedOutput(
            kind, _at(spec, "schema"), "json_schema", _at(spec, "strict") is True
        )
    if protocol == "messages":
        found = _at(payload, "output_config", "format") or payload.get("output_format")
        if _at(found, "type") != "json_schema":
            return None
        # Anthropic's structured output always constrains decoding to the schema.
        return RequestedOutput("json_schema", _at(found, "schema"), "json_schema", True)
    if protocol == "generate_content":
        config = payload.get("generationConfig")
        # An enum or text answer (text/x.enum) is not JSON, whatever its schema.
        if not isinstance(config, dict) or config.get("responseMimeType") not in (
            None,
            "application/json",
        ):
            return None
        if "responseJsonSchema" in config:
            return RequestedOutput(
                "json_schema", config["responseJsonSchema"], "json_schema", True
            )
        if "responseSchema" in config:
            return RequestedOutput(
                "json_schema", config["responseSchema"], "openapi", True
            )
        if config.get("responseMimeType") == "application/json":
            return RequestedOutput("json_object", None, "json_schema", False)
    return None


def _tool_schemas(
    payload: dict[str, Any], protocol: str
) -> dict[str, _ToolSchema | None]:
    """Offered tool name to its argument schema; None for a tool without one (a built-in)."""

    tools = payload.get("tools")
    found: dict[str, _ToolSchema | None] = {}
    legacy = payload.get("functions")
    functions = (
        [
            *(
                _at(tool, "function")
                for tool in (tools if isinstance(tools, list) else [])
            ),
            # Chat's legacy `functions`, called with `function_call`.
            *(legacy if isinstance(legacy, list) else []),
        ]
        if protocol == "chat"
        else []
    )
    for function in functions:
        if isinstance(function, dict) and isinstance(function.get("name"), str):
            found[function["name"]] = _ToolSchema(
                _parameters(function), "json_schema", function.get("strict") is True
            )
    for tool in tools if isinstance(tools, list) and protocol != "chat" else []:
        if not isinstance(tool, dict):
            continue
        if protocol == "generate_content":
            for declaration in tool.get("functionDeclarations") or []:
                if isinstance(declaration, dict) and isinstance(
                    declaration.get("name"), str
                ):
                    if "parametersJsonSchema" in declaration:
                        schema = _ToolSchema(
                            declaration["parametersJsonSchema"], "json_schema", False
                        )
                    elif "parameters" in declaration:
                        schema = _ToolSchema(
                            declaration["parameters"], "openapi", False
                        )
                    else:
                        schema = None
                    found[declaration["name"]] = schema
            continue
        # A built-in has only a type; its calls are not the app's to check.
        name = tool.get("name", tool.get("type"))
        if not isinstance(name, str):
            continue
        if protocol == "responses":
            found[name] = (
                _ToolSchema(
                    _parameters(tool), "json_schema", tool.get("strict") is True
                )
                if tool.get("type") == "function"
                else None
            )
        else:
            found[name] = (
                _ToolSchema(
                    tool["input_schema"], "json_schema", tool.get("strict") is True
                )
                if "input_schema" in tool
                else None
            )
    return found


def _parameters(tool: dict[str, Any]) -> Any:
    # Absent or null parameters: a function that takes no arguments.
    parameters = tool.get("parameters")
    return {} if parameters is None else parameters


def _restored(schema: Any, restore) -> Any:
    """A copy whose enum and const strings are turned back from placeholders, as the answer was.

    Property names and `required` entries stay masked, so no restored value can reach
    an error path.
    """

    if isinstance(schema, list):
        return [_restored(item, restore) for item in schema]
    if not isinstance(schema, dict):
        return schema
    return {
        key: _restored_value(value, restore)
        if key in ("enum", "const")
        else {name: _restored(item, restore) for name, item in value.items()}
        if key in _SCHEMA_MAPS and isinstance(value, dict)
        else _restored(value, restore)
        for key, value in schema.items()
    }


def _restored_value(value: Any, restore) -> Any:
    if isinstance(value, str):
        return restore(value)
    if isinstance(value, list):
        return [_restored_value(item, restore) for item in value]
    if isinstance(value, dict):
        return {key: _restored_value(item, restore) for key, item in value.items()}
    return value


def _parse(text: str) -> tuple[bool, Any]:
    try:
        return True, json.loads(text.strip() or "null")
    except (ValueError, RecursionError):
        return False, None


def _prepared(schema: Any, restore) -> tuple[Any, str | None]:
    """The schema ready to check, or why it cannot be."""

    try:
        if (
            len(json.dumps(schema, separators=(",", ":"), default=str))
            > MAX_SCHEMA_CHARACTERS
        ):
            return None, "too_large"
        return _restored(schema, restore), None
    except RecursionError:
        return None, "depth"


class SchemaAnalyzer:
    """Checks the answer or each tool call against the request's schema, after delivery."""

    name = "schema"
    version = "1"
    reads_answer = True

    def analyze(self, ctx: AnalysisContext) -> dict[str, Any]:
        requested = requested_output(ctx.payload, ctx.protocol)
        tools = _tool_schemas(ctx.payload, ctx.protocol)
        expected = (
            "tool_args" if ctx.tool_calls else requested.kind if requested else "none"
        )
        result: dict[str, Any] = {
            "expected": expected,
            "valid": None,
            "error_path": None,
            "error_keyword": None,
            "error_tool": None,
            "unsupported": False,
            "unsupported_keywords": [],
            "strict": False,
            "reason": None,
        }
        if expected == "none":
            return result
        outcome = ctx.completion_outcome
        if outcome == "truncated":
            return {**result, "reason": "truncated"}
        if outcome in {"refused", "filtered", "empty"}:
            return {**result, "reason": outcome}
        if ctx.answer_truncated:
            return {**result, "reason": "too_large"}
        if expected == "tool_args":
            return self._tool_args(ctx, tools, result)
        assert requested is not None
        result["strict"] = requested.strict
        parsed, instance = _parse(ctx.answer_text)
        if not parsed:
            return {**result, "valid": False, "error_keyword": "parse"}
        if requested.kind == "json_object":
            if not isinstance(instance, dict):
                return {**result, "valid": False, "error_keyword": "type"}
            return {**result, "valid": True}
        schema, reason = _prepared(requested.schema, ctx.restore)
        if reason:
            return {**result, "reason": reason}
        return _merged(result, check(instance, schema, dialect=requested.dialect), "")

    def _tool_args(
        self,
        ctx: AnalysisContext,
        tools: dict[str, _ToolSchema | None],
        result: dict[str, Any],
    ) -> dict[str, Any]:
        unknown = False
        checked: list[bool] = []
        unsupported: set[str] = set()
        reason = None
        prepared: dict[str, tuple[Any, str | None]] = {}
        for index, call in enumerate(ctx.tool_calls[:MAX_TOOL_CALLS]):
            if not call.name:
                # A chat stream's custom tool call carries no function name.
                continue
            prefix = f"/tool_calls/{index}"
            tool = tools.get(call.name)
            if call.name not in tools:
                return {
                    **result,
                    "valid": False,
                    "error_path": prefix,
                    "error_keyword": "unknown_tool",
                    # The name is the model's text: recorded only as providers allow it.
                    "error_tool": call.name if TOOL_NAME.fullmatch(call.name) else None,
                }
            if tool is None:
                continue
            checked.append(tool.strict)
            failure = {"valid": False, "error_tool": call.name, "strict": tool.strict}
            parsed, arguments = _parse(call.arguments or "{}")
            if not parsed:
                return {
                    **result,
                    **failure,
                    "error_path": prefix,
                    "error_keyword": "parse",
                }
            if call.name not in prepared:
                prepared[call.name] = _prepared(tool.schema, ctx.restore)
            schema, unusable = prepared[call.name]
            if unusable:
                unknown, reason = True, reason or unusable
                continue
            found = check(arguments, schema, dialect=tool.dialect)
            unsupported.update(found.unsupported)
            if found.valid is False:
                return {
                    **_merged(result, found, prefix),
                    **failure,
                    "unsupported_keywords": sorted(unsupported)[:16],
                    "unsupported": bool(unsupported),
                }
            if found.valid is None:
                unknown, reason = True, reason or found.reason
        return {
            **result,
            "valid": None if unknown or not checked else True,
            "unsupported": bool(unsupported),
            "unsupported_keywords": sorted(unsupported)[:16],
            "strict": bool(checked) and all(checked),
            "reason": reason,
        }


def _merged(result: dict[str, Any], found: SchemaCheck, prefix: str) -> dict[str, Any]:
    return {
        **result,
        "valid": found.valid,
        "error_path": None
        if found.error_path is None
        else (prefix + found.error_path)[:512],
        "error_keyword": found.error_keyword,
        "unsupported": bool(found.unsupported),
        "unsupported_keywords": list(found.unsupported),
        "reason": found.reason,
    }
