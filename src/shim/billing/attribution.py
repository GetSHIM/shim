"""Provider-neutral cost attribution."""

from __future__ import annotations

from dataclasses import dataclass
import re


UNTAGGED = "untagged"
_ATTRIBUTION_PATTERN = re.compile(r"^[a-z0-9_.:-]+$")


def normalize_attribution(value: str, *, maximum_length: int) -> str:
    if maximum_length < 1:
        raise ValueError("maximum attribution length must be positive")
    normalized = value.strip().casefold()
    if (
        not normalized
        or len(normalized) > maximum_length
        or _ATTRIBUTION_PATTERN.fullmatch(normalized) is None
    ):
        raise ValueError(
            "cost attribution must contain only lowercase letters, digits, '.', "
            "'_', ':', or '-' within the configured length"
        )
    return normalized


@dataclass(frozen=True, slots=True)
class CostAttribution:
    cost_center: str
    tags: tuple[str, ...]

    @classmethod
    def resolve(
        cls,
        raw_tags: str | None,
        *,
        api_key_cost_center: str | None,
        maximum_length: int,
    ) -> CostAttribution:
        if maximum_length < 1:
            raise ValueError("maximum attribution length must be positive")
        tags: list[str] = []
        for candidate in (raw_tags or "").split(","):
            if not candidate.strip():
                continue
            try:
                tag = normalize_attribution(
                    candidate,
                    maximum_length=maximum_length,
                )
            except ValueError:
                continue
            if tag not in tags:
                tags.append(tag)
        if tags:
            return cls(cost_center=tags[0], tags=tuple(tags))
        if api_key_cost_center:
            return cls(
                cost_center=normalize_attribution(
                    api_key_cost_center,
                    maximum_length=maximum_length,
                ),
                tags=(),
            )
        return cls(cost_center=UNTAGGED, tags=())
