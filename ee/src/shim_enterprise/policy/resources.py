"""The managed resources: what a version records, a plan changes and a restore puts back."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Collection, Mapping
from typing import Protocol
from uuid import UUID

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act.api import OVERSIGHT_POLICIES
from shim_enterprise.api.v1.management import (
    API_KEYS,
    BUDGETS,
    DEPLOYMENTS,
    PRIVACY,
    TEAMS,
)
from shim_enterprise.policy.plans import Impact, Risk, State
from shim_enterprise.tenants.models import User

PostCommit = Callable[[], Awaitable[None]]


class ManagedResource(Protocol):
    name: str
    creatable: bool
    deletable: bool

    async def snapshot(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_ids: Collection[str] | None,
    ) -> dict[str, State]: ...

    def validate(
        self, item_id: str | None, before: State | None, proposed: State
    ) -> State: ...

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
    ) -> PostCommit | None: ...

    def classify(self, before: State | None, after: State | None) -> Risk: ...

    async def impact(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        window_days: int,
    ) -> Impact: ...

    async def after_commit(self, request: Request, organization_id: UUID) -> None: ...


REGISTRY: Mapping[str, ManagedResource] = {
    resource.name: resource
    for resource in (PRIVACY, TEAMS, API_KEYS, DEPLOYMENTS, BUDGETS, OVERSIGHT_POLICIES)
}
