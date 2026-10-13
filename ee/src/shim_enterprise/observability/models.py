"""Hourly aggregates of model servers' own load metrics."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    PrimaryKeyConstraint,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from shim_enterprise.core.database import Base


class InferenceMetricsHourly(Base):
    """One deployment's server samples in one UTC hour: counts, sums and maxima only."""

    __tablename__ = "inference_metrics_hourly"
    __table_args__ = (
        PrimaryKeyConstraint(
            "organization_id",
            "deployment_id",
            "hour",
            name="pk_inference_metrics_hourly",
        ),
        CheckConstraint(
            "server IN ('vllm', 'tgi', 'ollama')",
            name="ck_inference_metrics_hourly_server",
        ),
        CheckConstraint(
            "samples >= 0 AND busy_samples >= 0 AND queued_samples >= 0 "
            "AND loaded_samples >= 0 AND errors >= 0",
            name="ck_inference_metrics_hourly_counts",
        ),
        CheckConstraint(
            "cache_usage_max IS NULL OR cache_usage_max BETWEEN 0 AND 1",
            name="ck_inference_metrics_hourly_cache",
        ),
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "organizations.id",
            name="fk_inference_metrics_hourly_organization",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    deployment_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "model_deployments.id",
            name="fk_inference_metrics_hourly_deployment",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    hour: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    server: Mapped[str] = mapped_column(String(16), nullable=False)
    samples: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    busy_samples: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )
    queued_samples: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )
    loaded_samples: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )
    errors: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    running_sum: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default="0"
    )
    waiting_sum: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default="0"
    )
    running_max: Mapped[int | None] = mapped_column(Integer)
    waiting_max: Mapped[int | None] = mapped_column(Integer)
    cache_usage_sum: Mapped[float] = mapped_column(
        Float, nullable=False, server_default="0"
    )
    cache_usage_max: Mapped[float | None] = mapped_column(Float)
    vram_bytes_max: Mapped[int | None] = mapped_column(BigInteger)
    last_error: Mapped[str | None] = mapped_column(String(32))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
