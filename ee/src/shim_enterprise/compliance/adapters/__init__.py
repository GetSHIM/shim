"""Public connector-adapter port and deterministic provider registry."""

from collections.abc import Mapping
from typing import Any

from shim_enterprise.compliance.adapters.anthropic import AnthropicComplianceAdapter
from shim_enterprise.compliance.adapters.base import (
    ComplianceAdapter,
    ProviderConfigError,
    UnknownProviderError,
)
from shim_enterprise.compliance.adapters.openai import OpenAIComplianceAdapter


_ADAPTERS: dict[str, type[ComplianceAdapter]] = {
    "anthropic": AnthropicComplianceAdapter,
    "openai": OpenAIComplianceAdapter,
}


def get_adapter(
    provider: str,
    api_key: str,
    config: Mapping[str, Any] | None = None,
) -> ComplianceAdapter:
    adapter = _ADAPTERS.get(provider)
    if adapter is None:
        raise UnknownProviderError(f"unsupported compliance provider: {provider}")
    return adapter(api_key, config=config)


__all__ = (
    "ComplianceAdapter",
    "ProviderConfigError",
    "UnknownProviderError",
    "get_adapter",
)
