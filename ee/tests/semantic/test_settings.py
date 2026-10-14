from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from ee.tests.rules.test_rules_resource import (
    MANAGEMENT,
    _aliases,
    _call,
    _organization,
)
from shim_enterprise.core.config import settings
from shim_enterprise.tenants.gateway_settings import (
    SETTING_AVAILABILITY,
    SETTING_DIRECTIONS,
    SemanticReviewSettings,
)
from shim_enterprise.tenants.models import ApiKey

SETTINGS = f"{MANAGEMENT}/gateway-settings"


async def _tenant(db, allowed=None):
    owner = (await _organization(db))["owner"]
    await _aliases(db, owner.organization_id, {"denetci": "openai"})
    key = ApiKey(
        id=uuid4(),
        organization_id=owner.organization_id,
        user_id=owner.id,
        key_hash=uuid4().hex,
        prefix="sk-shim-rev",
        name="review",
        tier="enterprise",
        is_active=True,
        allowed_models=allowed,
    )
    db.add(key)
    await db.flush()
    return owner, key


@pytest.mark.asyncio
async def test_the_review_is_turned_on_with_a_registered_alias_and_an_active_key(
    db,
) -> None:
    owner, key = await _tenant(db)

    patched = await _call(
        db,
        owner,
        "PATCH",
        SETTINGS,
        json={
            "semantic_review": {
                "enabled": True,
                "model": "denetci",
                "api_key_id": str(key.id),
                "max_items_per_hour": 10,
            }
        },
    )

    assert patched.status_code == 200, patched.text
    review = patched.json()["settings"]["semantic_review"]
    assert (review["enabled"], review["model"], review["max_items_per_hour"]) == (
        True,
        "denetci",
        10,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("review", "allowed"),
    [
        ({"enabled": True, "model": "denetci"}, None),
        ({"enabled": True, "api_key_id": "key"}, None),
        ({"enabled": True, "model": "unregistered", "api_key_id": "key"}, None),
        ({"enabled": True, "model": "denetci", "api_key_id": str(uuid4())}, None),
        ({"enabled": True, "model": "denetci", "api_key_id": "key"}, ["other"]),
        ({"max_items_per_hour": 0}, None),
        ({"max_items_per_hour": 1_001}, None),
        ({"max_cost_usd_per_day": "0.001"}, None),
        ({"max_cost_usd_per_day": "1000.01"}, None),
    ],
)
async def test_an_incomplete_or_foreign_review_setting_is_refused(
    db, review, allowed
) -> None:
    owner, key = await _tenant(db, allowed)
    if review.get("api_key_id") == "key":
        review = {**review, "api_key_id": str(key.id)}

    refused = await _call(
        db, owner, "PATCH", SETTINGS, json={"semantic_review": review}
    )

    assert refused.status_code == 422, refused.text


@pytest.mark.parametrize(
    ("before", "after", "direction"),
    [
        ({}, {"enabled": True}, "relaxing"),
        ({"enabled": True}, {"enabled": True, "model": "other"}, "relaxing"),
        ({"enabled": True}, {}, "tightening"),
        ({"enabled": True}, {"enabled": True, "max_items_per_hour": 5}, "neutral"),
        ({}, {"max_cost_usd_per_day": "9"}, "neutral"),
    ],
)
def test_turning_it_on_or_changing_the_model_relaxes(before, after, direction) -> None:
    def review(values):
        enabled = values.get("enabled", False)
        return SemanticReviewSettings.model_validate(
            {
                "model": "denetci" if enabled else None,
                "api_key_id": uuid4() if enabled else None,
                **values,
            }
        )

    assert SETTING_DIRECTIONS["semantic_review"](review(before), review(after)) == (
        direction
    )


def test_an_enabled_review_needs_its_model_and_key() -> None:
    with pytest.raises(ValidationError):
        SemanticReviewSettings(enabled=True, model="denetci")


def test_it_is_unavailable_without_the_archive_switch(monkeypatch) -> None:
    monkeypatch.setattr(settings, "REQUEST_ARCHIVE_ENABLED", False)
    assert SETTING_AVAILABILITY["semantic_review"]() == (
        "off, needs REQUEST_ARCHIVE_ENABLED in this installation (self-hosted only)"
    )
    monkeypatch.setattr(settings, "REQUEST_ARCHIVE_ENABLED", True)
    assert SETTING_AVAILABILITY["semantic_review"]() is None
