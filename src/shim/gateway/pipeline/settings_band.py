"""The settings band: provider parameters the tenant sets; content is never changed."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from shim.gateway.kernel.result import PreparedInference
from shim.gateway.kernel.stage import TraceValue
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
    """Applies the pins on the masked payload; returns it with the id of a blocking pin."""

    name = "settings_band"

    def __init__(self, pins: Sequence[Rule]) -> None:
        self.pins = pins

    async def run(
        self, value: PreparedInference
    ) -> tuple[PreparedInference, str | None]:
        assert value.rules is not None
        revision = value.rules.revision
        value = replace(value, rules_evaluated=True)
        payload = value.payload
        thinking = payload.get("thinking") if value.protocol == "messages" else None
        thinking_on = isinstance(thinking, Mapping) and thinking.get("type") in {
            "enabled",
            "adaptive",
        }
        winners: dict[str, str] = {}
        for rule in self.pins:
            if rule.state == "enforced":
                winners.setdefault(rule.match["parameter"], rule.id)
        skipped: dict[str, str] = {}
        sets: list[Rule] = []
        for rule in self.pins:
            parameter, pinned = rule.match["parameter"], rule.match["value"]
            current = _read(payload, PIN_PATHS[parameter][value.protocol])
            # JSON equality: 0 equals 0.0, true is not 1.
            if not isinstance(current, bool) and current == pinned:
                continue
            if thinking_on and parameter in {"temperature", "top_k"}:
                skipped[rule.id] = "RULE_PIN_INCOMPATIBLE"
            elif rule.state == "enforced" and winners[parameter] != rule.id:
                skipped[rule.id] = "RULE_PIN_SHADOWED"
            else:
                value.record_rule_match(rule, 1)
                if (rule.state, rule.action) == ("enforced", "set"):
                    sets.append(rule)
        pins = {rule.id for rule in self.pins}
        blocked = settle_pins(
            value,
            [match for match in value.rule_matches if match.rule_id in pins],
            skipped,
        )
        if blocked:
            return replace(value, settings_applied=()), blocked[0]
        applied = []
        for rule in sets:
            path = PIN_PATHS[rule.match["parameter"]][value.protocol]
            payload = _write(payload, path, rule.match["value"])
            applied.append({"id": f"parameter_pin.{rule.id}", "version": revision})
        return replace(value, payload=payload, settings_applied=tuple(applied)), None

    def trace_metadata(
        self, output: tuple[PreparedInference, str | None]
    ) -> Mapping[str, TraceValue]:
        return {"settings_applied": len(output[0].settings_applied or ())}


def _read(payload: Mapping[str, Any], path: tuple[str, ...]) -> object:
    value: object = payload
    for key in path:
        value = value.get(key, _ABSENT) if isinstance(value, Mapping) else _ABSENT
    return value


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
