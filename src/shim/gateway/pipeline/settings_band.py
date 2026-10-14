"""The settings band: provider parameters the tenant sets; content is never changed."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from hashlib import sha256
import json
import re
from typing import Any

from shim.gateway.image_rules import DETAIL_LOWERS_V1, gemini3, openai_family
from shim.gateway.kernel.result import PreparedInference
from shim.gateway.kernel.stage import TraceValue
from shim.gateway.media import classify_media, value_at
from shim.gateway.pipeline.postprocess import has_cache_control
from shim.rules.evaluate import in_scope, settle_pins
from shim.rules.model import Rule
from shim.rules.parameter_pin import PIN_PATHS

_ABSENT = object()


def pins_in_scope(prepared: PreparedInference) -> list[Rule]:
    """The request's parameter pins whose parameter its protocol has, by rule id."""

    if prepared.rules is None or prepared.protocol == "count_tokens":
        return []
    tags = prepared.admission.tags if prepared.admission is not None else ()
    return sorted(
        (
            rule
            for rule in prepared.rules.rules
            if rule.kind == "parameter_pin"
            and prepared.protocol in PIN_PATHS[rule.match["parameter"]]
            and in_scope(rule, prepared, tags)
        ),
        key=lambda rule: rule.id,
    )


class SettingsBandStage:
    """Applies the pins, then STEPS, on the masked payload.

    Returns it with the id of a blocking pin.
    """

    name = "settings_band"

    def __init__(self, pins: Sequence[Rule]) -> None:
        self.pins = pins

    async def run(
        self, value: PreparedInference
    ) -> tuple[PreparedInference, str | None]:
        payload, applied, betas = value.payload, [], []
        if self.pins:
            value, payload, applied, blocked = _apply_pins(value, self.pins)
            if blocked is not None:
                return replace(value, settings_applied=()), blocked
        for step_id, version, protocols, apply, step_betas in STEPS:
            if value.protocol in protocols:
                changed = apply(value, payload)
                if changed is not None:
                    payload = changed
                    applied.append({"id": step_id, "version": version})
                    betas += [beta for beta in step_betas if beta not in betas]
        return replace(
            value,
            payload=payload,
            settings_applied=tuple(applied),
            provider_betas=tuple(betas),
        ), None

    def trace_metadata(
        self, output: tuple[PreparedInference, str | None]
    ) -> Mapping[str, TraceValue]:
        return {"settings_applied": len(output[0].settings_applied or ())}


def _apply_pins(
    value: PreparedInference, pins: Sequence[Rule]
) -> tuple[PreparedInference, dict[str, Any], list[dict[str, object]], str | None]:
    assert value.rules is not None
    revision = value.rules.revision
    value = replace(value, rules_evaluated=True)
    payload = value.payload
    thinking_on = value.protocol == "messages" and _thinking_on(payload)
    winners: dict[str, str] = {}
    for rule in pins:
        if rule.state == "enforced":
            winners.setdefault(rule.match["parameter"], rule.id)
    skipped: dict[str, str] = {}
    sets: list[Rule] = []
    for rule in pins:
        parameter, pinned = rule.match["parameter"], rule.match["value"]
        current = _read(payload, PIN_PATHS[parameter][value.protocol])
        # JSON equality: 0 equals 0.0, true is not 1.
        if not isinstance(current, bool) and current == pinned:
            continue
        # Anthropic refuses these with thinking on: top_p takes 0.95 to 1 only.
        if thinking_on and (
            parameter in {"temperature", "top_k"}
            or (parameter == "top_p" and pinned < 0.95)
        ):
            skipped[rule.id] = "RULE_PIN_INCOMPATIBLE"
        elif rule.state == "enforced" and winners[parameter] != rule.id:
            skipped[rule.id] = "RULE_PIN_SHADOWED"
        else:
            value.record_rule_match(rule, 1)
            if (rule.state, rule.action) == ("enforced", "set"):
                sets.append(rule)
    ids = {rule.id for rule in pins}
    blocked = settle_pins(
        value, [match for match in value.rule_matches if match.rule_id in ids], skipped
    )
    if blocked:
        return value, payload, [], blocked[0]
    applied: list[dict[str, object]] = []
    for rule in sets:
        path = PIN_PATHS[rule.match["parameter"]][value.protocol]
        payload = _write(payload, path, rule.match["value"])
        applied.append({"id": f"parameter_pin.{rule.id}", "version": revision})
    return value, payload, applied, None


def _provider_target(prepared: PreparedInference) -> bool:
    # An on-prem server behind a provider-compatible API may refuse a parameter it
    # does not know, so only listed deployments are touched.
    return (
        prepared.target is None
        or prepared.model in prepared.band.provider_cache_deployments
    )


def _anthropic_auto_cache(
    prepared: PreparedInference, payload: dict[str, Any]
) -> dict[str, Any] | None:
    ttl = prepared.band.anthropic_auto_cache
    if ttl == "off" or not _provider_target(prepared) or has_cache_control(payload):
        return None
    # A random placeholder changes the prompt on every request: a write, never a read.
    if (
        prepared.placeholder_key is None
        and prepared.privacy is not None
        and prepared.privacy.verification_map
    ):
        return None
    marker = (
        {"type": "ephemeral"} if ttl == "5m" else {"type": "ephemeral", "ttl": "1h"}
    )
    return {**payload, "cache_control": marker}


def _leading_instructions(items: object) -> list[object]:
    leading = []
    for item in _list(items):
        if not (
            isinstance(item, Mapping) and item.get("role") in {"system", "developer"}
        ):
            break
        leading.append(item)
    return leading


def _openai_prompt_cache_key(
    prepared: PreparedInference, payload: dict[str, Any]
) -> dict[str, Any] | None:
    scope = prepared.band.openai_prompt_cache_key
    if (
        scope == "off"
        or not _provider_target(prepared)
        or payload.get("prompt_cache_key") is not None
    ):
        return None
    if prepared.protocol == "chat":
        prefix = {
            "messages": _leading_instructions(payload.get("messages")),
            "tools": payload.get("tools"),
        }
    else:
        prefix = {
            "instructions": payload.get("instructions"),
            "input": _leading_instructions(payload.get("input")),
            "tools": payload.get("tools"),
        }
    prefix_digest = sha256(
        json.dumps(prefix, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    material = "\x1f".join(
        (
            "shim.prompt_cache_key.v1",
            str(prepared.tenant_id),
            str(prepared.api_key_id) if scope == "key" else "",
            prepared.model,
            prefix_digest,
        )
    )
    return {
        **payload,
        "prompt_cache_key": "shim-" + sha256(material.encode()).hexdigest()[:32],
    }


def _skip(prepared: PreparedInference, step_id: str, reason: str) -> None:
    prepared.record_verdict(
        f"settings.{step_id}",
        stage="settings",
        outcome="skip",
        reason_code=reason,
        policy=prepared.band.model_dump(mode="json"),
    )


def _thinking_on(payload: Mapping[str, Any]) -> bool:
    thinking = payload.get("thinking")
    return isinstance(thinking, Mapping) and thinking.get("type") in {
        "enabled",
        "adaptive",
    }


# Version 1 of each model gate: the families the provider documents the feature for.
TOOL_SEARCH_MODELS_V1 = {
    "messages": re.compile(
        r"^claude-((opus|sonnet|haiku)-4-[5-9]|(opus|sonnet|haiku)-[5-9]|fable-|mythos-)"
    ),
    "responses": re.compile(r"^gpt-(5\.([4-9]|[1-9][0-9])|[6-9])([.-]|$)"),
}
REASONING_CONTEXT_MODELS_V1 = re.compile(r"^gpt-(5\.([6-9]|[1-9][0-9])|[6-9])([.-]|$)")
_SEARCH_TOOLS = {
    "regex": {
        "type": "tool_search_tool_regex_20251119",
        "name": "tool_search_tool_regex",
    },
    "bm25": {"type": "tool_search_tool_bm25_20251119", "name": "tool_search_tool_bm25"},
}


def thinking_bound(payload: Mapping[str, Any]) -> bool:
    """An Anthropic request with thinking on, or thinking blocks in its history."""
    return _thinking_on(payload) or any(
        isinstance(block, Mapping)
        and block.get("type") in {"thinking", "redacted_thinking"}
        for message in _list(payload.get("messages"))
        if isinstance(message, Mapping)
        for block in _list(message.get("content"))
    )


def _eligible(protocol: str, tool: object) -> bool:
    if not isinstance(tool, Mapping):
        return False
    if protocol == "messages":
        return tool.get("type") in {None, "custom"}
    return tool.get("type") == "function"


def _client_defers(tools: list[Any]) -> bool:
    for tool in tools:
        if not isinstance(tool, Mapping):
            continue
        if (
            str(tool.get("type", "")).startswith("tool_search")
            or "defer_loading" in tool
        ):
            return True
        configs = tool.get("configs")
        nested = [
            tool.get("default_config"),
            *(configs.values() if isinstance(configs, Mapping) else ()),
        ]
        if any(
            isinstance(config, Mapping) and "defer_loading" in config
            for config in nested
        ):
            return True
    return False


def _forced_names(choice: object) -> set[str]:
    if not isinstance(choice, Mapping):
        return set()
    if choice.get("type") in {"tool", "function"} and isinstance(
        choice.get("name"), str
    ):
        return {choice["name"]}
    if choice.get("type") == "allowed_tools":
        return {
            tool["name"]
            for tool in _list(choice.get("tools"))
            if isinstance(tool, Mapping) and isinstance(tool.get("name"), str)
        }
    return set()


def _tool_search(
    prepared: PreparedInference, payload: dict[str, Any]
) -> dict[str, Any] | None:
    band = prepared.band
    if (
        band.tool_search == "off"
        or not _provider_target(prepared)
        or (
            band.tool_search_api_key_ids
            and str(prepared.api_key_id) not in band.tool_search_api_key_ids
        )
    ):
        return None
    tools = _list(payload.get("tools"))
    eligible = [
        index for index, tool in enumerate(tools) if _eligible(prepared.protocol, tool)
    ]
    if len(eligible) < band.tool_search_min_tools:
        return None
    if not TOOL_SEARCH_MODELS_V1[prepared.protocol].match(prepared.pricing_model):
        _skip(prepared, "tool_search", "SETTING_MODEL_UNSUPPORTED")
        return None
    if _client_defers(tools):
        _skip(prepared, "tool_search", "SETTING_CLIENT_OWNED")
        return None
    # Changing tools mid-conversation invalidates every earlier thinking block.
    if prepared.protocol == "messages" and thinking_bound(payload):
        _skip(prepared, "tool_search", "SETTING_THINKING_BOUND")
        return None
    kept = set(band.tool_search_keep_loaded) | _forced_names(payload.get("tool_choice"))
    deferred = {
        index
        for index in eligible
        if not (isinstance(name := tools[index].get("name"), str) and name in kept)
        and not (prepared.protocol == "messages" and "cache_control" in tools[index])
    }
    # The provider refuses a request whose every tool is deferred.
    if len(deferred) == len(eligible):
        deferred.discard(eligible[0])
    # Nothing left to search: the search tool would only cost tokens.
    if not deferred:
        return None
    search = (
        _SEARCH_TOOLS[band.tool_search]
        if prepared.protocol == "messages"
        else {"type": "tool_search"}
    )
    return {
        **payload,
        "tools": [
            {**tool, "defer_loading": True} if index in deferred else tool
            for index, tool in enumerate(tools)
        ]
        + [search],
    }


def _anthropic_clear_thinking(
    prepared: PreparedInference, payload: dict[str, Any]
) -> dict[str, Any] | None:
    turns = prepared.band.anthropic_keep_thinking_turns
    if not turns or not _provider_target(prepared) or not _thinking_on(payload):
        return None
    if "context_management" in payload:
        _skip(prepared, "anthropic_clear_thinking", "SETTING_CLIENT_OWNED")
        return None
    # Never clear_tool_uses: dropping tool results is history trimming.
    edit = {
        "type": "clear_thinking_20251015",
        "keep": {"type": "thinking_turns", "value": turns},
    }
    return {**payload, "context_management": {"edits": [edit]}}


def _openai_reasoning_context(
    prepared: PreparedInference, payload: dict[str, Any]
) -> dict[str, Any] | None:
    if (
        prepared.band.openai_reasoning_context == "off"
        or not _provider_target(prepared)
        # Earlier models already default to the current turn.
        or not REASONING_CONTEXT_MODELS_V1.match(prepared.pricing_model)
    ):
        return None
    reasoning = payload.get("reasoning")
    if isinstance(reasoning, Mapping) and "context" in reasoning:
        _skip(prepared, "openai_reasoning_context", "SETTING_CLIENT_OWNED")
        return None
    return _write(payload, ("reasoning", "context"), "current_turn")


_GEMINI_LEVELS = {"low": "MEDIA_RESOLUTION_LOW", "medium": "MEDIA_RESOLUTION_MEDIUM"}


def _image_detail(
    prepared: PreparedInference, payload: dict[str, Any]
) -> dict[str, Any] | None:
    setting = prepared.band.image_detail
    google = prepared.protocol == "generate_content"
    level = setting.gemini if google else setting.openai
    if (
        level == "off"
        or not prepared.media
        or not _provider_target(prepared)
        or (setting.models and prepared.model not in setting.models)
    ):
        return None
    # Field paths, relative to each image part, that carry the level.
    images: list[tuple[tuple[str | int, ...], object]] = []
    for part in classify_media(payload):
        node = value_at(payload, part.path)
        if part.kind != "image":
            continue
        if google:
            images.append(
                ((*part.path, "mediaResolution"), node.get("mediaResolution"))
            )
        elif node.get("type") == "image_url" and isinstance(
            node.get("image_url"), Mapping
        ):
            detail = node["image_url"].get("detail")
            images.append(((*part.path, "image_url", "detail"), detail))
        elif node.get("type") == "input_image" and not _computer_use(
            payload, part.path
        ):
            images.append(((*part.path, "detail"), node.get("detail")))
    if not images:
        return None
    if not (
        gemini3(prepared.pricing_model)
        if google
        else level
        in DETAIL_LOWERS_V1.get(openai_family(prepared.pricing_model) or "", ())
    ):
        _skip(prepared, "image_detail", "SETTING_MODEL_UNSUPPORTED")
        return None
    config = payload.get("generationConfig")
    unset = [
        path
        for path, current in images
        if (current is None if google else current in {None, "auto"})
    ]
    if not unset or (
        google and isinstance(config, Mapping) and "mediaResolution" in config
    ):
        _skip(prepared, "image_detail", "SETTING_CLIENT_OWNED")
        return None
    # Changing an earlier turn invalidates the encrypted reasoning replayed with it.
    if any(
        isinstance(item, Mapping) and item.get("type") == "reasoning"
        for item in _list(payload.get("input"))
    ):
        _skip(prepared, "image_detail", "SETTING_THINKING_BOUND")
        return None
    value = {"level": _GEMINI_LEVELS[level]} if google else level
    for path in unset:
        payload = _write_at(payload, path, value)
    return payload


def _computer_use(payload: Mapping[str, Any], path: tuple[str | int, ...]) -> bool:
    # Computer use needs its screenshots in the original frame.
    item = value_at(payload, path[:2]) if path[0] == "input" and len(path) > 1 else None
    return isinstance(item, Mapping) and item.get("type") == "computer_call_output"


# (id, version, protocols, apply, Anthropic beta flags), in order after the pins. A
# step adds, changes or removes provider parameters and structural markers only,
# never a content string.
STEPS: tuple[
    tuple[
        str,
        int,
        frozenset[str],
        Callable[[PreparedInference, dict[str, Any]], dict[str, Any] | None],
        tuple[str, ...],
    ],
    ...,
] = (
    ("anthropic_auto_cache", 1, frozenset({"messages"}), _anthropic_auto_cache, ()),
    (
        "openai_prompt_cache_key",
        1,
        frozenset({"chat", "responses"}),
        _openai_prompt_cache_key,
        (),
    ),
    ("tool_search", 1, frozenset({"messages", "responses"}), _tool_search, ()),
    (
        "anthropic_clear_thinking",
        1,
        frozenset({"messages"}),
        _anthropic_clear_thinking,
        ("context-management-2025-06-27",),
    ),
    (
        "openai_reasoning_context",
        1,
        frozenset({"responses"}),
        _openai_reasoning_context,
        (),
    ),
    (
        "image_detail",
        1,
        frozenset({"chat", "responses", "generate_content"}),
        _image_detail,
        (),
    ),
)


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _read(payload: Mapping[str, Any], path: tuple[str, ...]) -> object:
    value: object = payload
    for key in path:
        value = value.get(key, _ABSENT) if isinstance(value, Mapping) else _ABSENT
    return value


def _write_at(payload: Any, path: tuple[str | int, ...], value: object) -> Any:
    """`_write` through lists too: copies only the containers on the path."""
    head, *rest = path
    copied: Any = list(payload) if isinstance(payload, list) else dict(payload)
    copied[head] = _write_at(payload[head], tuple(rest), value) if rest else value
    return copied


# Copies only the objects on the path: the masked payload may be shared.
def _write(payload: Mapping[str, Any], path: tuple[str, ...], value: object) -> dict:
    head, *rest = path
    if not rest:
        return {**payload, head: value}
    inner = payload.get(head)
    return {
        **payload,
        head: _write(inner if isinstance(inner, Mapping) else {}, tuple(rest), value),
    }
