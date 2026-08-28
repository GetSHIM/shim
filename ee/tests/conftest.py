from __future__ import annotations

import asyncio
from collections.abc import Callable
import hashlib
import signal
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio


class WorkerShutdownProbe:
    def __init__(self) -> None:
        self.handlers: dict[signal.Signals, Callable[[], None]] = {}
        self.removed_signals: list[signal.Signals] = []
        self.loop = SimpleNamespace(
            add_signal_handler=self.add_signal_handler,
            remove_signal_handler=self.remove_signal_handler,
        )

    def add_signal_handler(
        self,
        shutdown_signal: signal.Signals,
        callback: Callable[[], None],
    ) -> None:
        self.handlers[shutdown_signal] = callback

    def remove_signal_handler(self, shutdown_signal: signal.Signals) -> bool:
        self.removed_signals.append(shutdown_signal)
        return self.handlers.pop(shutdown_signal, None) is not None

    async def run(self, stop_event: asyncio.Event) -> None:
        assert set(self.handlers) == {signal.SIGINT, signal.SIGTERM}
        for shutdown_signal in (signal.SIGINT, signal.SIGTERM):
            stop_event.clear()
            self.handlers[shutdown_signal]()
            assert stop_event.is_set()
        raise asyncio.CancelledError

    def assert_cleaned_up(self) -> None:
        assert self.handlers == {}
        assert self.removed_signals == [signal.SIGINT, signal.SIGTERM]


@pytest.fixture
def worker_shutdown_probe() -> WorkerShutdownProbe:
    return WorkerShutdownProbe()


@pytest_asyncio.fixture
async def async_engine():
    from sqlalchemy.ext.asyncio import create_async_engine

    from shim_enterprise.core.config import settings

    engine = create_async_engine(
        settings.DATABASE_URL,
        echo=False,
        connect_args={"statement_cache_size": 0},
    )
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db(async_engine):
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm import sessionmaker

    connection = await async_engine.connect()
    transaction = await connection.begin()
    factory = sessionmaker(
        connection,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    async with factory() as session:
        yield session
    if transaction.is_active:
        await transaction.rollback()
    await connection.close()


@pytest_asyncio.fixture
async def test_org(db):
    from shim_enterprise.tenants.models import Organization

    organization = Organization(
        id=uuid4(),
        name="Architecture Test Tenant",
        slug=f"architecture-test-{uuid4().hex}",
    )
    db.add(organization)
    await db.flush()
    return organization


@pytest_asyncio.fixture
async def test_user_with_org(db, test_org):
    from shim_enterprise.tenants.models import User

    user = User(
        id=uuid4(),
        email=f"architecture-{uuid4().hex}@example.com",
        full_name="Architecture Test User",
        is_active=True,
        is_verified=True,
        organization_id=test_org.id,
    )
    db.add(user)
    await db.flush()
    return user


@pytest_asyncio.fixture
async def test_tier(db):
    from sqlalchemy import text

    await db.execute(
        text(
            "INSERT INTO tier_definitions "
            "(slug, name, rate_limit_rpm, rate_limit_tpm, "
            "monthly_request_limit, monthly_token_limit, features) "
            "VALUES ('free', 'Free', 60, 15000, 1000, 1000000, '{}') "
            "ON CONFLICT (slug) DO NOTHING"
        )
    )
    await db.flush()
    return "free"


@pytest_asyncio.fixture
async def test_api_key(db, test_user_with_org, test_tier):
    from shim_enterprise.tenants.models import ApiKey

    api_key = ApiKey(
        id=uuid4(),
        user_id=test_user_with_org.id,
        organization_id=test_user_with_org.organization_id,
        key_hash=hashlib.sha256(b"sk-shim-architecture-test").hexdigest(),
        prefix="sk-shim-arch",
        name="Architecture Test Key",
        tier=test_tier,
        is_active=True,
    )
    db.add(api_key)
    await db.flush()
    return api_key
