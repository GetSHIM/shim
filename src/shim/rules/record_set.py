"""The record_set rule kind's match model: a set of hashed records or document fingerprints."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RecordSetMatch(BaseModel):
    """`min_fields` for a records set (default 2), `min_shared` for a fingerprints set (6).

    Which one applies, and whether the set exists, is checked where sets live.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    set_id: UUID
    min_fields: int | None = Field(default=None, ge=1, le=6)
    min_shared: int | None = Field(default=None, ge=2, le=200)

    @model_validator(mode="after")
    def one_threshold(self) -> RecordSetMatch:
        if self.min_fields is not None and self.min_shared is not None:
            raise ValueError(
                "give min_fields for records or min_shared for fingerprints"
            )
        return self
