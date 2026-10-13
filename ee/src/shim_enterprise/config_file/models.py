"""Where a tenant's policy comes from, and the keys that may sign its file."""

from __future__ import annotations

from collections.abc import Collection
from datetime import datetime
from typing import Literal
from uuid import UUID, uuid4

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    String,
    Text,
    UniqueConstraint,
    UUID as SqlUUID,
    func,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from shim_enterprise.config_file import FILE_MANAGEABLE
from shim_enterprise.core.database import Base, TimestampMixin
from shim_enterprise.policy.plans import (
    Impact,
    Risk,
    State,
    no_impact,
    version_detail,
)
from shim_enterprise.tenants.audit import change_details, record_management_action
from shim_enterprise.tenants.models import User
from shim_enterprise.tenants.permissions import Permission


class OrganizationConfigMode(Base, TimestampMixin):
    """No row means `api`: the panel and the API manage every resource."""

    __tablename__ = "organization_config_modes"
    __table_args__ = (
        CheckConstraint(
            "mode IN ('api', 'file')", name="ck_organization_config_modes_mode"
        ),
    )

    organization_id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True),
        ForeignKey(
            "organizations.id",
            name="fk_organization_config_modes_organization",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )
    mode: Mapped[str] = mapped_column(
        String(8), nullable=False, default="api", server_default=text("'api'")
    )
    resources: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    last_serial: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )
    last_file_sha256: Mapped[str | None] = mapped_column(String(64))
    last_applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_by: Mapped[str | None] = mapped_column(String(64))


class ConfigSigningKey(Base):
    """An Ed25519 public key a human of the tenant signs its file with."""

    __tablename__ = "config_signing_keys"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "user_id"],
            ["users.organization_id", "users.id"],
            name="fk_config_signing_keys_tenant_user",
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "organization_id", "key_id", name="uq_config_signing_keys_tenant_key"
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True),
        ForeignKey(
            "organizations.id",
            name="fk_config_signing_keys_organization",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    key_id: Mapped[str] = mapped_column(String(32), nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[UUID] = mapped_column(SqlUUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[str | None] = mapped_column(String(64))


async def file_managed(session: AsyncSession, organization_id: UUID) -> list[str]:
    """The resources the tenant's signed file manages; [] in api mode."""
    row = await session.get(OrganizationConfigMode, organization_id)
    return list(row.resources) if row is not None and row.mode == "file" else []


async def active_signing_keys(session: AsyncSession, organization_id: UUID) -> int:
    return int(
        await session.scalar(
            select(func.count()).where(
                ConfigSigningKey.organization_id == organization_id,
                ConfigSigningKey.revoked_at.is_(None),
            )
        )
        or 0
    )


class ConfigMode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["api", "file"]
    resources: list[Literal["privacy", "gateway_settings", "rules"]] = Field(
        max_length=len(FILE_MANAGEABLE)
    )

    @model_validator(mode="after")
    def matches_mode(self) -> ConfigMode:
        if self.mode == "file" and not self.resources:
            raise ValueError("file mode manages at least one resource")
        if self.mode == "api" and self.resources:
            raise ValueError("api mode manages no resource from a file")
        if len(set(self.resources)) != len(self.resources):
            raise ValueError("a resource is listed once")
        return self


class _ConfigModeResource:
    """Where changes come from, not what they allow: every change is neutral."""

    name = "config_mode"
    permission: Permission = "config.manage"
    creatable = False
    deletable = False

    async def snapshot(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_ids: Collection[str] | None,
    ) -> dict[str, State]:
        row = await session.get(OrganizationConfigMode, organization_id)
        return {
            "_": {
                "mode": row.mode if row is not None else "api",
                "resources": list(row.resources) if row is not None else [],
            }
        }

    async def validate(
        self,
        session: AsyncSession,
        actor: User,
        item_id: str | None,
        before: State | None,
        proposed: State,
    ) -> State:
        try:
            mode = ConfigMode.model_validate({**(before or {}), **proposed})
        except ValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail=exc.errors(include_url=False, include_context=False),
            ) from None
        if mode.mode == "file" and not await active_signing_keys(
            session, actor.organization_id
        ):
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "CONFIG_NO_SIGNING_KEY",
                    "message": "File mode needs an active signing key.",
                    "hint": "Register a public signing key first.",
                },
            )
        return {
            "mode": mode.mode,
            "resources": [name for name in FILE_MANAGEABLE if name in mode.resources],
        }

    async def apply(
        self,
        session: AsyncSession,
        actor: User,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        *,
        policy_version: int | None,
    ) -> None:
        assert after is not None
        await session.execute(
            insert(OrganizationConfigMode)
            .values(organization_id=organization_id)
            .on_conflict_do_nothing()
        )
        row = await session.get(
            OrganizationConfigMode, organization_id, populate_existing=True
        )
        assert row is not None
        row.mode, row.resources, row.updated_by = (
            after["mode"],
            after["resources"],
            str(actor.id),
        )
        await record_management_action(
            session,
            actor,
            "tenant.config_mode_changed",
            str(organization_id),
            details={
                **change_details(before, after),
                **version_detail(policy_version),
            },
        )

    def classify(self, before: State | None, after: State | None) -> Risk:
        return "neutral"

    async def impact(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        window_days: int,
    ) -> Impact:
        return no_impact(
            window_days, "changes where policy comes from, not what it allows"
        )


CONFIG_MODE = _ConfigModeResource()
