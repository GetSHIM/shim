"""Cloud composition adds commerce to the licensed enterprise application."""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, Security
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import bearer_scheme, get_current_user
from shim_enterprise.application import create_enterprise_app
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import AsyncSessionLocal, get_db
from shim_enterprise.tenants.models import User
from shim_enterprise.tenants.plans import configure_organization_quota
from shim_cloud.api import router
from shim_cloud.config import CloudSettings
from shim_cloud.activate import require_activation


async def cloud_user(
    request: Request,
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    session: AsyncSession = Depends(get_db),
) -> User:
    user = await get_current_user(request, bearer, session)
    if request.app.state.cloud_settings.CLOUD_BILLING_ENABLED:
        await configure_organization_quota(session, user.organization_id)
        await session.commit()
    return user


def create_cloud_app(config: CloudSettings | None = None) -> FastAPI:
    application = create_enterprise_app()
    application.state.cloud_settings = config or CloudSettings()
    enterprise_lifespan = application.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if app.state.cloud_settings.CLOUD_BILLING_ENABLED:
            async with AsyncSessionLocal() as session:
                await require_activation(session)
        async with enterprise_lifespan(app):
            yield

    application.router.lifespan_context = lifespan
    application.dependency_overrides[get_current_user] = cloud_user
    application.include_router(router, prefix=settings.API_PREFIX)
    return application
