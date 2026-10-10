"""The `schema` analyzer: does the answer, or each tool call, match the schema the app asked for."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Literal

from shim.gateway.pipeline.analysis import AnalysisContext
from shim.jsonschema_subset import SchemaCheck, check

Dialect = Literal["json_schema", "openapi"]

MAX_SCHEMA_CHARACTERS = 100_000
MAX_TOOL_CALLS = 64
_JSON_FORMATS = frozenset({"json_object", "json_schema"})


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
        if not isinstance(config, dict):
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
    for tool in tools if isinstance(tools, list) else []:
        if not isinstance(tool, dict):
            continue
        if protocol == "generate_content":
            found.update(dict.fromkeys(set(tool) - {"functionDeclarations"}))
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
        if protocol == "chat":
            function = tool.get("function")
            if isinstance(function, dict) and isinstance(function.get("name"), str):
                found[function["name"]] = _ToolSchema(
                    function.get("parameters", {}),
                    "json_schema",
                    function.get("strict") is True,
                )
            elif isinstance(_at(tool, "custom", "name"), str):
                found[tool["custom"]["name"]] = None
            continue
        # A built-in has only a type; its calls are not the app's to check.
        name = tool.get("name", tool.get("type"))
        if not isinstance(name, str):
            continue
        if protocol == "responses":
            found[name] = (
                _ToolSchema(
                    tool.get("parameters", {}),
                    "json_schema",
                    tool.get("strict") is True,
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


def _restored(schema: Any, restore) -> Any:
    """A copy with every string turned back from its placeholder, as the answer was."""

    if isinstance(schema, str):
        return restore(schema)
    if isinstance(schema, list):
        return [_restored(item, restore) for item in schema]
    if isinstance(schema, dict):
        return {key: _restored(value, restore) for key, value in schema.items()}
    return schema


def _parse(text: str) -> tuple[bool, Any]:
    try:
        return True, json.loads(text.strip() or "null")
    except ValueError:
        return False, None


def _too_large(schema: Any) -> bool:
    return (
        len(json.dumps(schema, separators=(",", ":"), default=str))
        > MAX_SCHEMA_CHARACTERS
    )


class SchemaAnalyzer:
    """Checks the answer or each tool call against the request's schema, after delivery."""

    name = "schema"
    version = "1"

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
        if _too_large(requested.schema):
            return {**result, "reason": "too_large"}
        found = check(
            instance,
            _restored(requested.schema, ctx.restore),
            dialect=requested.dialect,
        )
        return _merged(result, found, "")

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
        for index, call in enumerate(ctx.tool_calls[:MAX_TOOL_CALLS]):
            prefix = f"/tool_calls/{index}"
            failure = {"valid": False, "error_tool": call.name[:64]}
            if call.name not in tools:
                return {
                    **result,
                    **failure,
                    "error_path": prefix,
                    "error_keyword": "unknown_tool",
                }
            tool = tools[call.name]
            if tool is None:
                continue
            checked.append(tool.strict)
            parsed, arguments = _parse(call.arguments or "{}")
            if not parsed:
                return {
                    **result,
                    **failure,
                    "error_path": prefix,
                    "error_keyword": "parse",
                }
            if _too_large(tool.schema):
                unknown, reason = True, reason or "too_large"
                continue
            found = check(
                arguments, _restored(tool.schema, ctx.restore), dialect=tool.dialect
            )
            unsupported.update(found.unsupported)
            if found.valid is False:
                merged = _merged(result, found, prefix)
                return {
                    **merged,
                    "error_tool": call.name[:64],
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
