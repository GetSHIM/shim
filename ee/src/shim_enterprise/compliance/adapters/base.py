"""Typed compliance-adapter contract and explicit provider registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

from shim_enterprise.compliance.normalized import ContentRef, NormalizedContent


class UnknownProviderError(ValueError):
    """The requested compliance provider is not registered."""


class ProviderConfigError(ValueError):
    """Provider configuration is incomplete or invalid."""


class ComplianceAdapter(ABC):
    provider = ""

    def __init__(
        self,
        api_key: str,
        config: Mapping[str, Any] | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("compliance provider credential is required")
        self.api_key = api_key
        self.config = dict(config or {})

    @abstractmethod
    async def verify_key(self) -> bool:
        """Validate the credential against a bounded provider probe."""

    @abstractmethod
    async def fetch_content(self, ref: ContentRef) -> NormalizedContent:
        """Fetch ephemeral content for immediate scanning."""

    async def close(self) -> None:
        return None
