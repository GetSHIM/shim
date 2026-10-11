"""SQLAlchemy metadata, engine, sessions, and FastAPI session dependency."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import DateTime, func, text
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
