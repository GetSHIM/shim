"""Cloud schema only; enterprise owns the public schema and its migration history."""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection, pool, text
from sqlalchemy.ext.asyncio import async_engine_from_config

from shim_cloud.models import CloudBase
from shim_enterprise.core.config import settings

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)
config.set_main_option("sqlalchemy.url", str(settings.DATABASE_URL).replace("%", "%%"))


def include_name(
    name: str | None, type_: str, parent_names: dict[str, str | None]
) -> bool:
    if type_ == "schema":
        return name == "shim_cloud"
    return True


def run(connection: Connection) -> None:
    connection.execute(text("CREATE SCHEMA IF NOT EXISTS shim_cloud"))
    connection.commit()
    context.configure(
        connection=connection,
        target_metadata=CloudBase.metadata,
        version_table_schema="shim_cloud",
        include_schemas=True,
        include_name=include_name,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def online() -> None:
    engine = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with engine.connect() as connection:
        await connection.run_sync(run)
    await engine.dispose()


if context.is_offline_mode():
    context.configure(
        url=str(settings.DATABASE_URL),
        target_metadata=CloudBase.metadata,
        version_table_schema="shim_cloud",
        literal_binds=True,
    )
    context.execute("CREATE SCHEMA IF NOT EXISTS shim_cloud")
    with context.begin_transaction():
        context.run_migrations()
else:
    asyncio.run(online())
