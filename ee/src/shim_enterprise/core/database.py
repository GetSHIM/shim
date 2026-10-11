"""SQLAlchemy metadata, engine, sessions, and FastAPI session dependency."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, cast

from fastapi import HTTPException
from sqlalchemy import DateTime, delete, func, select, text
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from shim_enterprise.core.config import settings


class Base(DeclarativeBase):
    """Single metadata authority for every persistent domain model."""


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


engine = create_async_engine(
    str(settings.DATABASE_URL),
    echo=settings.LOG_LEVEL == "DEBUG",
    pool_pre_ping=True,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    # Unnamed statements; server-side cursors (session.stream) are unsafe here.
    connect_args={"statement_cache_size": 0},
)
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with AsyncSessionLocal() as session:
        yield session


# What one statement of a read, a preview or a findings pass may take.
STATEMENT_TIMEOUT = "10s"
# PostgreSQL's query_canceled, which a statement timeout raises.
QUERY_CANCELED = "57014"


async def bound_statements(session: AsyncSession) -> None:
    """Every later statement of this transaction stops after STATEMENT_TIMEOUT."""
    await session.execute(text(f"SET LOCAL statement_timeout = '{STATEMENT_TIMEOUT}'"))


@asynccontextmanager
async def bounded_read(session: AsyncSession) -> AsyncIterator[None]:
    """A read whose statements are bounded; one that runs out answers 503."""
    await bound_statements(session)
    try:
        yield
    except DBAPIError as error:
        if getattr(error.orig, "pgcode", None) != QUERY_CANCELED:
            raise
        raise HTTPException(
            status_code=503,
            detail={
                "code": "QUERY_TIMEOUT",
                "message": "The read took too long; ask for a shorter window.",
            },
        ) from None


DELETE_BATCH = 1_000
DELETE_BATCHES = 50


async def delete_in_batches(
    session_factory: async_sessionmaker[AsyncSession],
    model: Any,
    *where: Any,
    order_by: Any,
) -> int:
    """Delete the matching rows, oldest first, in bounded batches of one transaction each."""
    deleted = 0
    for _ in range(DELETE_BATCHES):
        async with session_factory.begin() as session:
            batch = cast(
                CursorResult[Any],
                await session.execute(
                    delete(model).where(
                        model.id.in_(
                            select(model.id)
                            .where(*where)
                            .order_by(order_by)
                            .limit(DELETE_BATCH)
                        )
                    )
                ),
            ).rowcount
        deleted += batch
        if batch < DELETE_BATCH:
            break
    return deleted
