"""Timing wrapper shared by typed inference stages."""

from __future__ import annotations

from typing import TypeVar

from opentelemetry.trace.status import Status, StatusCode

from shim.gateway.kernel.stage import Stage
from shim.observability.tracing import safe_attributes, start_span


InputT = TypeVar("InputT")
OutputT = TypeVar("OutputT")
_STAGE_SPANS = {
    "resolve_principal": "gateway.auth",
    "admission": "gateway.admission",
    "privacy": "gateway.privacy",
    "provider_spend": "gateway.quota_reservation",
    "provider_execution": "gateway.provider_call",
    "postprocess": "gateway.postprocess",
}


async def run_stage(stage: Stage[InputT, OutputT], value: InputT) -> OutputT:
    with start_span(_STAGE_SPANS[stage.name]) as span:
        try:
            output = await stage.run(value)
            metadata = dict(stage.trace_metadata(output))
        except BaseException as exc:
            span.set_attribute("status", "failed")
            span.set_status(Status(StatusCode.ERROR, type(exc).__name__))
            raise
        span.set_attributes(safe_attributes(metadata))
        span.set_attribute("status", "success")
        return output
