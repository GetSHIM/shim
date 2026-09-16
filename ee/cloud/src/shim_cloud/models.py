"""Cloud-owned, short-lived checkout/portal results; entitlements stay in tenants."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from shim_enterprise.tenants.models import Organization, User


class CloudBase(DeclarativeBase):
    pass


class BillingOperation(CloudBase):
    __tablename__ = "billing_operation"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "request_id", name="uq_billing_operation_request"
        ),
        CheckConstraint(
            "kind IN ('checkout', 'portal')", name="ck_billing_operation_kind"
        ),
        CheckConstraint(
            "status IN ('pending', 'processing', 'complete', 'failed', 'expired')",
            name="ck_billing_operation_status",
        ),
        Index("ix_billing_operation_expiry", "expires_at"),
        {"schema": "shim_cloud"},
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey(Organization.id), nullable=False
    )
    created_by: Mapped[UUID] = mapped_column(ForeignKey(User.id), nullable=False)
    request_id: Mapped[UUID] = mapped_column(nullable=False)
    kind: Mapped[str] = mapped_column(Text)
    product_id: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(
        Text, default="pending", server_default="pending"
    )
    result_ciphertext: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
