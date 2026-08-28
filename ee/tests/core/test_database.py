from typing import cast

from sqlalchemy.pool import AsyncAdaptedQueuePool

from shim_enterprise.core.config import settings
from shim_enterprise.core.database import engine


def test_database_engine_uses_bounded_pool_defaults() -> None:
    pool = cast(AsyncAdaptedQueuePool, engine.pool)

    assert settings.DATABASE_POOL_SIZE == 2
    assert settings.DATABASE_MAX_OVERFLOW == 1
    assert pool.size() == settings.DATABASE_POOL_SIZE
    assert pool._max_overflow == settings.DATABASE_MAX_OVERFLOW
