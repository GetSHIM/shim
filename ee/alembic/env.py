"""Alembic environment for the standalone shim architecture baseline."""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

import shim_enterprise.ai_act.models  # noqa: F401
import shim_enterprise.billing.models  # noqa: F401
import shim_enterprise.compliance.models  # noqa: F401
import shim_enterprise.observability.analytics_projection  # noqa: F401
import shim_enterprise.outbox.models  # noqa: F401
import shim_enterprise.shared_results.models  # noqa: F401
import shim_enterprise.tenants.models  # noqa: F401
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import Base


config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

database_url = str(settings.DATABASE_URL)
config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
target_metadata = Base.metadata


def _configure(connection: object | None = None) -> None:
    options = {
        "target_metadata": target_metadata,
        "compare_type": True,
        "compare_server_default": True,
    }
    if connection is None:
        context.configure(
            url=config.get_main_option("sqlalchemy.url"),
            literal_binds=True,
            dialect_opts={"paramstyle": "named"},
            **options,
        )
    else:
        context.configure(connection=connection, **options)


def run_migrations_offline() -> None:
    _configure()
    with context.begin_transaction():
        context.run_migrations()


async def _run_migrations_online() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_run_migrations)
    await connectable.dispose()


def _run_migrations(connection: object) -> None:
    _configure(connection)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    asyncio.run(_run_migrations_online())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
