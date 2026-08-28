from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker

from shim_enterprise.tenants.models import BillingWebhookReceipt, Organization, User
from shim_enterprise.tenants.service import (
    authenticate_api_key,
    create_api_key,
    ensure_privacy_defaults,
    get_or_create_organization,
    move_user_from_bootstrap,
)


@pytest.mark.asyncio
async def test_tenant_bootstrap_creates_idempotent_owned_slug(db) -> None:
    owner_id = uuid4()

    first = await get_or_create_organization(
        db,
        name="Research & Safety",
        creator_user_id=owner_id,
    )
    second = await get_or_create_organization(
        db,
        name="Research & Safety",
        creator_user_id=owner_id,
    )

    assert first.id == second.id
    assert first.slug == f"research-safety-{str(owner_id)[:8]}"


@pytest.mark.asyncio
async def test_tenant_bootstrap_is_idempotent_under_concurrency(async_engine) -> None:
    session_factory = async_sessionmaker(async_engine, expire_on_commit=False)
    owner_id = uuid4()
    slug = f"concurrent-research-{str(owner_id)[:8]}"

    async def bootstrap() -> tuple[UUID, UUID]:
        async with session_factory.begin() as session:
            organization = await get_or_create_organization(
                session,
                name="Concurrent Research",
                creator_user_id=owner_id,
            )
            config = await ensure_privacy_defaults(session, organization.id)
            return organization.id, config.id

    try:
        results = await asyncio.gather(*(bootstrap() for _ in range(8)))
        assert len({organization_id for organization_id, _ in results}) == 1
        assert len({config_id for _, config_id in results}) == 1
    finally:
        async with session_factory.begin() as cleanup:
            await cleanup.execute(delete(Organization).where(Organization.slug == slug))


@pytest.mark.asyncio
async def test_api_key_creation_requires_mandatory_tenant_ownership(db) -> None:
    with pytest.raises(ValueError, match="tenant"):
        await create_api_key(
            db,
            user_id=uuid4(),
            name="forbidden",
        )


@pytest.mark.asyncio
async def test_api_key_creation_serializes_with_owner_deactivation(
    async_engine,
) -> None:
    session_factory = async_sessionmaker(async_engine, expire_on_commit=False)
    organization_id = uuid4()
    user_id = uuid4()
    async with session_factory.begin() as setup:
        setup.add(
            Organization(
                id=organization_id,
                name="API key race",
                slug=f"api-key-race-{organization_id}",
            )
        )
        setup.add(
            User(
                id=user_id,
                organization_id=organization_id,
                email=f"api-key-race-{user_id}@example.com",
                role="member",
                is_active=True,
                is_verified=True,
            )
        )

    try:
        async with session_factory() as removal:
            owner = await removal.scalar(
                select(User).where(User.id == user_id).with_for_update(of=User)
            )
            assert owner is not None
            owner.is_active = False
            await removal.flush()

            async with session_factory() as creation:
                await creation.execute(text("SET LOCAL lock_timeout = '100ms'"))
                with pytest.raises(DBAPIError) as exc_info:
                    await create_api_key(
                        creation,
                        user_id=user_id,
                        name="must wait",
                    )
                assert "lock timeout" in str(exc_info.value).lower()
                await creation.rollback()

            await removal.commit()

        async with session_factory.begin() as verification:
            with pytest.raises(ValueError, match="active"):
                await create_api_key(
                    verification,
                    user_id=user_id,
                    name="must reject",
                )
    finally:
        async with session_factory.begin() as cleanup:
            await cleanup.execute(
                delete(Organization).where(Organization.id == organization_id)
            )


@pytest.mark.asyncio
async def test_bootstrap_move_waits_for_tenant_child_and_rechecks_emptiness(
    async_engine,
) -> None:
    session_factory = async_sessionmaker(async_engine, expire_on_commit=False)
    source_id = uuid4()
    destination_id = uuid4()
    user_id = uuid4()
    async with session_factory.begin() as setup:
        setup.add_all(
            [
                Organization(
                    id=source_id,
                    name="Bootstrap source",
                    slug=f"bootstrap-source-{source_id}",
                ),
                Organization(
                    id=destination_id,
                    name="Destination",
                    slug=f"bootstrap-destination-{destination_id}",
                ),
                User(
                    id=user_id,
                    organization_id=source_id,
                    email=f"bootstrap-move-{user_id}@example.com",
                    role="owner",
                    is_active=True,
                    is_verified=True,
                ),
            ]
        )
        await setup.flush()
        await ensure_privacy_defaults(setup, source_id)

    try:
        async with session_factory() as writer:
            writer.add(
                BillingWebhookReceipt(
                    organization_id=source_id,
                    payload_digest=uuid4().hex,
                    event_name="subscription_created",
                    event_at=datetime.now(timezone.utc),
                )
            )
            await writer.flush()

            async with session_factory() as mover:
                await mover.execute(text("SET LOCAL lock_timeout = '100ms'"))
                with pytest.raises(DBAPIError) as exc_info:
                    await move_user_from_bootstrap(
                        mover,
                        user_id=user_id,
                        source_organization_id=source_id,
                        destination_organization_id=destination_id,
                        role="member",
                    )
                assert "lock timeout" in str(exc_info.value).lower()
                await mover.rollback()

            await writer.commit()

        async with session_factory.begin() as mover:
            moved = await move_user_from_bootstrap(
                mover,
                user_id=user_id,
                source_organization_id=source_id,
                destination_organization_id=destination_id,
                role="member",
            )
            assert moved is None

        async with session_factory() as verification:
            user = await verification.get(User, user_id)
            assert user is not None
            assert user.organization_id == source_id
            assert await verification.get(Organization, source_id) is not None
    finally:
        async with session_factory.begin() as cleanup:
            await cleanup.execute(
                delete(Organization).where(
                    Organization.id.in_([source_id, destination_id])
                )
            )


@pytest.mark.asyncio
async def test_api_key_authentication_uses_only_digest(db, test_api_key) -> None:
    authenticated = await authenticate_api_key(db, "sk-shim-architecture-test")

    assert authenticated is not None
    assert authenticated.id == test_api_key.id
    assert await authenticate_api_key(db, "wrong-prefix") is None
