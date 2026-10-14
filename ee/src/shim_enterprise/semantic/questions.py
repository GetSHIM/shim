"""The tenant's semantic questions: one versioned set, a managed policy resource.

The questions are the tenant's own confidential text, like rule terms: never in Redis,
a log, a metric or an audit event; audits carry ids only.
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import require
from shim_enterprise.api.v1.management._common import _managed_write, _tenant_id
from shim_enterprise.core.database import get_db
from shim_enterprise.policy.plans import Impact, Risk, State, lock_tenant, no_impact
from shim_enterprise.semantic.models import OrganizationSemanticQuestions
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim_enterprise.tenants.models import User
from shim_enterprise.tenants.permissions import Permission

router = APIRouter(prefix="/management/semantic-questions", tags=["rules"])
MAX_QUESTIONS = 20


class SemanticQuestion(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,47}$")
    text: str = Field(min_length=10, max_length=500)
    examples: list[Annotated[str, StringConstraints(min_length=5, max_length=300)]] = (
        Field(default=[], max_length=5)
    )


class QuestionSetPut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision: int = Field(ge=0)
    questions: list[SemanticQuestion] = Field(max_length=MAX_QUESTIONS)

    @field_validator("questions")
    @classmethod
    def unique_ids(cls, value: list[SemanticQuestion]) -> list[SemanticQuestion]:
        ids = [question.id for question in value]
        if len(set(ids)) != len(ids):
            raise ValueError("question ids repeat")
        return value


class QuestionSetView(BaseModel):
    revision: int
    questions: list[SemanticQuestion]


def _by_id(state: State | None) -> dict[str, Any]:
    return {question["id"]: question for question in (state or {}).get("questions", [])}


class _SemanticQuestionsResource:
    name = "semantic_questions"
    permission: Permission = "rules.write"
    creatable = False
    deletable = False

    async def snapshot(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_ids: Collection[str] | None,
    ) -> dict[str, State]:
        row = await session.get(OrganizationSemanticQuestions, organization_id)
        return {"_": {"questions": list(row.questions) if row is not None else []}}

    async def validate(
        self,
        session: AsyncSession,
        actor: User,
        item_id: str | None,
        before: State | None,
        proposed: State,
    ) -> State:
        try:
            questions = QuestionSetPut.model_validate(
                {"revision": 0, "questions": proposed.get("questions", [])}
            ).questions
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None
        return {"questions": [question.model_dump() for question in questions]}

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
    ) -> None:
        assert after is not None
        await session.execute(
            insert(OrganizationSemanticQuestions)
            .values(organization_id=organization_id)
            .on_conflict_do_nothing()
        )
        row = await session.get(
            OrganizationSemanticQuestions,
            organization_id,
            with_for_update=True,
            populate_existing=True,
        )
        assert row is not None
        row.questions = after["questions"]
        row.revision += 1
        row.updated_by = actor.id if actor.kind != "system" else None
        old, new = _by_id(before), _by_id(after)
        await _audit(
            session,
            actor,
            "tenant.semantic_questions_updated",
            str(organization_id),
            details={
                "revision": row.revision,
                "added": sorted(new.keys() - old.keys()),
                "removed": sorted(old.keys() - new.keys()),
                "changed": sorted(
                    key for key in old.keys() & new.keys() if old[key] != new[key]
                ),
                **(
                    {} if policy_version is None else {"policy_version": policy_version}
                ),
            },
        )

    def classify(self, before: State | None, after: State | None) -> Risk:
        old, new = _by_id(before), _by_id(after)
        # A question removed or rewritten finds less; one added finds more.
        if old.keys() - new.keys() or any(
            old[key] != new[key] for key in old.keys() & new.keys()
        ):
            return "relaxing"
        return "tightening" if new.keys() - old.keys() else "neutral"

    async def impact(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        window_days: int,
    ) -> Impact:
        return no_impact(
            window_days, "questions are read against archived requests only"
        )


SEMANTIC_QUESTIONS = _SemanticQuestionsResource()


@router.get("", response_model=QuestionSetView)
async def get_semantic_questions(
    user: User = Depends(require("rules.read")),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    row = await session.get(OrganizationSemanticQuestions, _tenant_id(user))
    return {
        "revision": row.revision if row is not None else 0,
        "questions": row.questions if row is not None else [],
    }


@router.put("", response_model=QuestionSetView)
async def replace_semantic_questions(
    payload: QuestionSetPut,
    user: User = Depends(require("rules.write")),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tenant_id = _tenant_id(user)
    await lock_tenant(session, tenant_id)
    row = await session.get(
        OrganizationSemanticQuestions, tenant_id, populate_existing=True
    )
    current = row.revision if row is not None else 0
    if payload.revision != current:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "REVISION_CONFLICT",
                "message": "The questions changed since they were read.",
                "revision": current,
            },
        )
    before = (await SEMANTIC_QUESTIONS.snapshot(session, tenant_id, None))["_"]
    after = {"questions": [question.model_dump() for question in payload.questions]}
    await _managed_write(session, user, SEMANTIC_QUESTIONS, "_", before, after)
    await session.commit()
    row = await session.get(
        OrganizationSemanticQuestions, tenant_id, populate_existing=True
    )
    return {
        "revision": row.revision if row is not None else 0,
        "questions": row.questions if row is not None else [],
    }
