"""Bind a verified external subject to an existing local account by explicit IDs."""

import argparse
import asyncio
from uuid import UUID

from sqlalchemy import select

from shim_enterprise.core.config import settings
from shim_enterprise.core.database import AsyncSessionLocal
from shim_enterprise.tenants.audit import record_management_action
from shim_enterprise.tenants.models import Organization, User


async def link(
    organization_id: UUID, user_id: UUID, subject: str, operator: str
) -> None:
    if settings.AUTH_MODE != "keycloak" or not settings.OIDC_ISSUER_URL:
        raise ValueError("Select keycloak mode and its exact issuer before linking")
    if (
        not subject
        or len(subject) > 255
        or not subject.isascii()
        or not operator.strip()
    ):
        raise ValueError("A valid subject and operator identity are required")
    async with AsyncSessionLocal() as session:
        async with session.begin():
            if not await session.scalar(
                select(Organization.id)
                .where(Organization.id == organization_id)
                .with_for_update()
            ):
                raise ValueError("Workspace does not exist")
            user = await session.scalar(
                select(User)
                .where(
                    User.id == user_id,
                    User.organization_id == organization_id,
                    User.is_active.is_(True),
                )
                .with_for_update()
            )
            if user is None:
                raise ValueError("Active local workspace member does not exist")
            binding = (settings.OIDC_ISSUER_URL, subject)
            existing = (user.oidc_issuer, user.oidc_subject)
            if existing != (None, None) and existing != binding:
                raise ValueError(
                    "Account already has an external identity; review and unlink explicitly first"
                )
            collision = await session.scalar(
                select(User.id).where(
                    User.oidc_issuer == binding[0],
                    User.oidc_subject == binding[1],
                    User.id != user.id,
                )
            )
            if collision is not None:
                raise ValueError("External identity is already linked")
            user.oidc_issuer, user.oidc_subject = binding
            await record_management_action(
                session,
                user,
                "tenant.external_identity_linked",
                str(user.id),
                details={
                    "issuer": binding[0],
                    "subject": binding[1],
                    "operator": operator,
                },
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("organization_id", type=UUID)
    parser.add_argument("user_id", type=UUID)
    parser.add_argument("subject")
    parser.add_argument("--operator", required=True)
    args = parser.parse_args()
    asyncio.run(link(args.organization_id, args.user_id, args.subject, args.operator))


if __name__ == "__main__":
    main()
