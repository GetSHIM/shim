"""One archived request: the masked payload and the edit, both encrypted."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy import UUID as SqlUUID
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from shim_enterprise.core.database import Base


class RequestArchive(Base):
    __tablename__ = "request_archive"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "request_id", name="uq_request_archive_request"
        ),
        Index("ix_request_archive_tenant_created", "organization_id", "created_at"),
        Index("ix_request_archive_expires", "expires_at"),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "organizations.id",
            name="fk_request_archive_organization",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    request_id: Mapped[str] = mapped_column(String(255), nullable=False)
    api_key_id: Mapped[UUID | None] = mapped_column(SqlUUID(as_uuid=True))
    protocol: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(255), nullable=False)
    # Entity types and rule ids with their action and count; never a value.
    matched: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    masked_payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    edit_map: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
