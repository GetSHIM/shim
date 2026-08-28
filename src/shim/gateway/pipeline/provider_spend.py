"""Provider-spend stage backed by the public usage lifecycle."""

from __future__ import annotations

from shim.gateway.kernel.result import PreparedInference
from shim.gateway.kernel.stage import TraceValue
from shim.gateway.pipeline.authenticate import GatewayInvocation
from shim.gateway.usage import UsageLifecycle


class ProviderSpendStage:
    name = "provider_spend"

    def __init__(
        self,
        invocation: GatewayInvocation,
        usage: UsageLifecycle,
    ) -> None:
        self.invocation = invocation
        self.usage = usage

    async def run(self, value: PreparedInference) -> PreparedInference:
        credential = self.invocation.provider_credential
        await self.usage.reserve_provider_spend(
            value,
            ephemeral_byok=credential is not None and credential.available(),
        )
        return value

    def trace_metadata(self, output: PreparedInference) -> dict[str, TraceValue]:
        return {
            "provider": str(output.provider),
            "reserved": True,
        }
