import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from starlette.responses import Response

import shim.gateway.kernel.gateway_kernel as kernel_module
from shim.gateway.kernel.gateway_kernel import GatewayKernel
from shim.gateway.pipeline.authenticate import GatewayRequestMetadata
from shim.gateway.pipeline.provider_execution import ProviderCallError
from shim.services.gateway.service import GatewayService


def _kernel(usage) -> GatewayKernel:
    execution = SimpleNamespace(pii_scrubber=object())
    return GatewayKernel(
        {
            "openai": execution,
            "anthropic": execution,
            "google": execution,
        },
        chain_store=object(),
        policy_resolver=object(),
        rate_limiter=object(),
        loop_detector=object(),
        loop_repeat_limit=3,
        loop_window_seconds=60,
        cost_tag_max_length=64,
        usage=usage,
    )


@pytest.mark.asyncio
async def test_kernel_runs_the_authoritative_stage_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []
    prepared = SimpleNamespace(stream=False)
    provider_output = object()
    response = Response("ok")

    def stage(name: str):
        return lambda *_args, **_kwargs: SimpleNamespace(name=name, reserved=False)

    for class_name, stage_name in (
        ("AuthenticateStage", "resolve_principal"),
        ("AdmissionStage", "admission"),
        ("PrivacyStage", "privacy"),
        ("ProviderSpendStage", "provider_spend"),
        ("ProviderExecutionStage", "provider_execution"),
        ("PostprocessStage", "postprocess"),
    ):
        monkeypatch.setattr(kernel_module, class_name, stage(stage_name))

    async def run_stage(stage, _value):
        order.append(stage.name)
        if stage.name == "provider_execution":
            return provider_output
        if stage.name == "postprocess":
            return response
        return prepared

    async def record_privacy(*_args):
        order.append("record_privacy")

    monkeypatch.setattr(kernel_module, "run_stage", run_stage)
    provider_execution = SimpleNamespace(pii_scrubber=object())
    kernel = GatewayKernel(
        {
            "openai": provider_execution,
            "anthropic": provider_execution,
            "google": provider_execution,
        },
        chain_store=object(),
        policy_resolver=object(),
        rate_limiter=object(),
        loop_detector=object(),
        loop_repeat_limit=3,
        loop_window_seconds=60,
        cost_tag_max_length=64,
        usage=SimpleNamespace(
            record_privacy=record_privacy,
            fail=AsyncMock(),
        ),
    )

    result = await kernel._execute(SimpleNamespace(provider="google"))

    assert result is response
    assert order == [
        "resolve_principal",
        "admission",
        "privacy",
        "record_privacy",
        "provider_spend",
        "provider_execution",
        "postprocess",
    ]


def test_kernel_accepts_a_supported_provider_subset() -> None:
    kernel = GatewayKernel(
        {"openai": SimpleNamespace(pii_scrubber=object())},
        chain_store=object(),
        policy_resolver=object(),
        rate_limiter=object(),
        loop_detector=object(),
        loop_repeat_limit=3,
        loop_window_seconds=60,
        cost_tag_max_length=64,
        usage=object(),
    )

    assert set(kernel.executions) == {"openai"}


@pytest.mark.parametrize("executions", [{}, {"unsupported": object()}])
def test_kernel_rejects_empty_or_unsupported_execution_sets(
    executions: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="supported native providers"):
        GatewayKernel(
            executions,
            chain_store=object(),
            policy_resolver=object(),
            rate_limiter=object(),
            loop_detector=object(),
            loop_repeat_limit=3,
            loop_window_seconds=60,
            cost_tag_max_length=64,
            usage=object(),
        )


@pytest.mark.asyncio
async def test_kernel_sanitizes_an_unconfigured_provider() -> None:
    usage = SimpleNamespace(fail=AsyncMock())
    kernel = GatewayKernel(
        {"openai": SimpleNamespace(pii_scrubber=object())},
        chain_store=object(),
        policy_resolver=object(),
        rate_limiter=object(),
        loop_detector=object(),
        loop_repeat_limit=3,
        loop_window_seconds=60,
        cost_tag_max_length=64,
        usage=usage,
    )

    response = await GatewayService(kernel).dispatch_inference(
        payload={},
        provider="google",
        protocol="generate_content",
        model="gemini-test",
        stream=False,
        headers={},
        provider_credential=None,
        principal=SimpleNamespace(),  # type: ignore[arg-type]
        request_metadata=GatewayRequestMetadata(
            endpoint="/v1beta/models/gemini-test:generateContent"
        ),
    )

    # A Gemini request surfaces a native google.rpc.Status body, not FastAPI's
    # {"detail": ...}, and keeps the 503 the kernel raised.
    assert response.status_code == 503
    payload = json.loads(bytes(response.body))
    assert "detail" not in payload
    assert payload == {
        "error": {
            "code": 503,
            "message": "The Google request failed.",
            "status": "UNAVAILABLE",
        }
    }
    usage.fail.assert_not_awaited()


@pytest.mark.parametrize(
    ("status_code", "expected_reason"),
    [
        (404, "provider_rejected_without_usage"),
        (503, "request_aborted"),
    ],
)
@pytest.mark.asyncio
async def test_kernel_maps_provider_failures_to_usage_reason(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
    expected_reason: str,
) -> None:
    prepared = SimpleNamespace(stream=False)
    failure = ProviderCallError(
        status_code=status_code,
        error_code="PROVIDER_UNAVAILABLE",
        retryable=status_code >= 500,
        provider="openai",
    )

    async def run_stage(stage, _value):
        if stage.name == "provider_execution":
            raise failure
        return prepared

    monkeypatch.setattr(kernel_module, "run_stage", run_stage)
    usage = SimpleNamespace(record_privacy=AsyncMock(), fail=AsyncMock())

    with pytest.raises(ProviderCallError) as error:
        await _kernel(usage)._execute(SimpleNamespace(provider="openai"))

    assert error.value is failure
    usage.fail.assert_awaited_once_with(prepared, reason=expected_reason)


@pytest.mark.asyncio
async def test_kernel_maps_post_reservation_admission_abort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = SimpleNamespace(stream=False)
    failure = RuntimeError("admission interrupted")

    async def run_stage(stage, _value):
        if stage.name == "admission":
            stage.reserved = True
            raise failure
        return prepared

    monkeypatch.setattr(kernel_module, "run_stage", run_stage)
    usage = SimpleNamespace(fail=AsyncMock())

    with pytest.raises(RuntimeError) as error:
        await _kernel(usage)._execute(SimpleNamespace(provider="openai"))

    assert error.value is failure
    usage.fail.assert_awaited_once_with(prepared, reason="admission_aborted")


@pytest.mark.asyncio
async def test_recovery_session_failure_does_not_mask_original_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = SimpleNamespace(stream=False)
    failure = RuntimeError("admission interrupted")

    async def run_stage(stage, _value):
        if stage.name == "admission":
            stage.reserved = True
            raise failure
        return prepared

    monkeypatch.setattr(kernel_module, "run_stage", run_stage)
    usage = SimpleNamespace(fail=AsyncMock(side_effect=RuntimeError("I/O failed")))

    with pytest.raises(RuntimeError) as error:
        await _kernel(usage)._execute(SimpleNamespace(provider="openai"))

    assert error.value is failure
