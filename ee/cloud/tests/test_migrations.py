"""Opt-in rehearsal against a disposable, operator-provisioned PostgreSQL DB."""

import os
import subprocess
import sys

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine


@pytest.mark.asyncio
async def test_cloud_migration_resolves_enterprise_schema_and_runtime_grants():
    database_url = os.environ.get("CLOUD_MIGRATION_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("Requires a disposable non-public enterprise schema database.")
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as connection:
            assert not await connection.scalar(
                text(
                    "SELECT has_database_privilege(current_user, current_database(), 'CREATE')"
                )
            )
            assert await connection.scalar(
                text("SELECT current_schema() NOT IN ('public', 'shim_cloud')")
            )
            assert await connection.scalar(
                text("SELECT to_regnamespace('shim_cloud') IS NOT NULL")
            )
    finally:
        await engine.dispose()
    environment = {
        **os.environ,
        "DATABASE_URL": database_url,
        "REDIS_URL": "redis://localhost:6379/0",
        "SECRET_KEY": "local-migration-test-only",
        "ENVIRONMENT": "test",
        "AUTH_MODE": "supabase",
        "SUPABASE_URL": "https://migration-test.supabase.co",
    }
    subprocess.run(
        [sys.executable, "-m", "shim_cloud.migrate"],
        env=environment,
        check=True,
        timeout=60,
    )
    for config in ("ee/alembic.ini", "ee/cloud/alembic.ini"):
        subprocess.run(
            [sys.executable, "-m", "alembic", "-c", config, "check"],
            env=environment,
            check=True,
            timeout=60,
        )

    try:
        async with engine.connect() as connection:
            enterprise_schema = await connection.scalar(text("SELECT current_schema()"))
            assert enterprise_schema not in (None, "public", "shim_cloud")
            targets = (
                await connection.execute(
                    text(
                        "SELECT n.nspname, t.relname FROM pg_constraint c "
                        "JOIN pg_class t ON t.oid = c.confrelid "
                        "JOIN pg_namespace n ON n.oid = t.relnamespace "
                        "WHERE c.conrelid = 'shim_cloud.billing_operation'::regclass "
                        "AND c.contype = 'f'"
                    )
                )
            ).all()
            assert set(targets) == {
                (enterprise_schema, "organizations"),
                (enterprise_schema, "users"),
            }
            assert await connection.scalar(
                text("SELECT to_regclass('public.organizations') IS NULL")
            )
            assert await connection.scalar(
                text("SELECT to_regclass('shim_cloud.alembic_version') IS NOT NULL")
            )
            assert await connection.scalar(
                text("SELECT to_regclass('alembic_version') IS NOT NULL")
            )
            assert await connection.scalar(
                text(
                    "SELECT has_schema_privilege('shim_runtime', 'shim_cloud', 'USAGE')"
                )
            )
            for table in ("billing_activation", "billing_operation"):
                for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                    assert await connection.scalar(
                        text(
                            "SELECT has_table_privilege('shim_runtime', :table, :privilege)"
                        ),
                        {"table": f"shim_cloud.{table}", "privilege": privilege},
                    )
    finally:
        await engine.dispose()
