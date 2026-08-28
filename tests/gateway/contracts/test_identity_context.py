from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from shim.gateway.contracts.context import (
    AuditPolicy,
    GatewayContext,
    PrivacyPolicy,
    TenantPolicy,
    TierPolicy,
)
from shim.gateway.contracts.ids import (
    ApiKeyId,
    ModelId,
    ProviderId,
    RequestId,
    SecretRef,
    TenantId,
    UserId,
)
from shim.gateway.contracts.principal import AuthenticatedPrincipal


TENANT_UUID = UUID("11111111-1111-1111-1111-111111111111")
API_KEY_UUID = UUID("22222222-2222-2222-2222-222222222222")
USER_UUID = UUID("33333333-3333-3333-3333-333333333333")
NOW = datetime(2026, 7, 12, 9, 30, tzinfo=UTC)
NAIVE_NOW = NOW.replace(tzinfo=None)


def policies() -> dict[str, object]:
    return {
        "tier_policy": TierPolicy(
            rate_limit_rpm=120,
            rate_limit_tpm=50_000,
            daily_request_limit=None,
            monthly_request_limit=25_000,
            monthly_token_limit=1_000_000,
        ),
        "privacy_policy": PrivacyPolicy(
            pii_mode="scrub",
        ),
        "audit_policy": AuditPolicy(mode="strict"),
    }


def api_key_context_payload() -> dict[str, object]:
    return {
        "request_id": RequestId("req_golden"),
        "tenant_id": TenantId(TENANT_UUID),
        "actor_type": "api_key",
        "api_key_id": ApiKeyId(API_KEY_UUID),
        "user_id": None,
        "endpoint": "/v1/chat/completions",
        "started_at": NOW,
        **policies(),
    }


def test_id_newtypes_preserve_uuid_and_string_backing_types():
    assert TenantId(TENANT_UUID) == TENANT_UUID
    assert UserId(USER_UUID) == USER_UUID
    assert ApiKeyId(API_KEY_UUID) == API_KEY_UUID
    assert RequestId("req_1") == "req_1"
    assert ProviderId("openai") == "openai"
    assert ModelId("gpt-5.6-luna") == "gpt-5.6-luna"
    assert SecretRef("secret://provider/key") == "secret://provider/key"


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (
            {
                "actor_type": "api_key",
                "api_key_id": API_KEY_UUID,
                "user_id": USER_UUID,
                "authenticated_at": NOW,
            },
            {"api_key_id": str(API_KEY_UUID), "user_id": str(USER_UUID)},
        ),
        (
            {
                "actor_type": "user_jwt",
                "user_id": USER_UUID,
                "authenticated_at": NOW,
            },
            {"api_key_id": None, "user_id": str(USER_UUID)},
        ),
        (
            {"actor_type": "internal", "authenticated_at": NOW},
            {"api_key_id": None, "user_id": None},
        ),
    ],
)
def test_authenticated_principal_serializes_valid_actor_shapes(payload, expected):
    principal = AuthenticatedPrincipal.model_validate(payload)
    serialized = principal.model_dump(mode="json")

    assert serialized["actor_type"] == payload["actor_type"]
    assert serialized["authenticated_at"] == "2026-07-12T09:30:00Z"
    assert serialized["api_key_id"] == expected["api_key_id"]
    assert serialized["user_id"] == expected["user_id"]


@pytest.mark.parametrize(
    "payload",
    [
        {"actor_type": "api_key", "authenticated_at": NOW},
        {"actor_type": "user_jwt", "authenticated_at": NOW},
        {
            "actor_type": "user_jwt",
            "api_key_id": API_KEY_UUID,
            "user_id": USER_UUID,
            "authenticated_at": NOW,
        },
        {
            "actor_type": "internal",
            "api_key_id": API_KEY_UUID,
            "authenticated_at": NOW,
        },
    ],
)
def test_authenticated_principal_rejects_invalid_actor_shapes(payload):
    with pytest.raises(ValidationError, match="invalid identity fields"):
        AuthenticatedPrincipal.model_validate(payload)


def test_authenticated_principal_requires_timezone_aware_timestamp():
    with pytest.raises(ValidationError, match="timezone"):
        AuthenticatedPrincipal(
            actor_type="internal",
            authenticated_at=NAIVE_NOW,
        )


def test_gateway_context_serializes_exact_identity_and_policy_contract():
    context = GatewayContext.model_validate(api_key_context_payload())

    assert context.model_dump(mode="json") == {
        "request_id": "req_golden",
        "tenant_id": str(TENANT_UUID),
        "actor_type": "api_key",
        "api_key_id": str(API_KEY_UUID),
        "user_id": None,
        "endpoint": "/v1/chat/completions",
        "started_at": "2026-07-12T09:30:00Z",
        "tier_policy": {
            "rate_limit_rpm": 120,
            "rate_limit_tpm": 50_000,
            "daily_request_limit": None,
            "monthly_request_limit": 25_000,
            "monthly_token_limit": 1_000_000,
        },
        "privacy_policy": {
            "pii_mode": "scrub",
        },
        "audit_policy": {"mode": "strict"},
    }

    with pytest.raises(ValidationError, match="frozen"):
        context.endpoint = "changed"


@pytest.mark.parametrize("tenant_value", [None])
def test_gateway_context_requires_nonoptional_tenant(tenant_value):
    payload = api_key_context_payload()
    payload["tenant_id"] = tenant_value

    with pytest.raises(ValidationError):
        GatewayContext.model_validate(payload)

    payload.pop("tenant_id")
    with pytest.raises(ValidationError):
        GatewayContext.model_validate(payload)


@pytest.mark.parametrize(
    "updates",
    [
        {"api_key_id": None},
        {"actor_type": "user_jwt", "api_key_id": None, "user_id": None},
        {"actor_type": "internal", "api_key_id": API_KEY_UUID},
    ],
)
def test_gateway_context_rejects_invalid_actor_shapes(updates):
    payload = api_key_context_payload()
    payload.update(updates)

    with pytest.raises(ValidationError, match="invalid identity fields"):
        GatewayContext.model_validate(payload)


def test_gateway_context_requires_timezone_aware_started_at():
    payload = api_key_context_payload()
    payload["started_at"] = NAIVE_NOW

    with pytest.raises(ValidationError, match="timezone"):
        GatewayContext.model_validate(payload)


def test_policy_models_reject_unknown_or_invalid_values():
    with pytest.raises(ValidationError):
        TierPolicy(
            rate_limit_rpm=-1,
            rate_limit_tpm=100,
            daily_request_limit=None,
            monthly_request_limit=None,
            monthly_token_limit=1000,
        )
    with pytest.raises(ValidationError):
        AuditPolicy(mode="optional")
    with pytest.raises(ValidationError):
        TenantPolicy(raw_provider_key="secret")


def test_tier_policy_uses_none_for_unlimited_dimensions():
    policy = TierPolicy()

    assert policy.model_dump() == {
        "rate_limit_rpm": None,
        "rate_limit_tpm": None,
        "daily_request_limit": None,
        "monthly_request_limit": None,
        "monthly_token_limit": None,
    }


def test_context_policy_collections_are_immutable_and_still_serialize():
    tenant_policy = TenantPolicy(
        allowed_providers=["openai"],
        allowed_regions=["eu"],
    )
    with pytest.raises(TypeError):
        tenant_policy.allowed_regions[0] = "us"
    assert tenant_policy.model_dump(mode="json") == {
        "allowed_providers": ["openai"],
        "allowed_regions": ["eu"],
        "require_zero_retention": False,
    }


def test_identity_and_context_copies_revalidate_invariants():
    principal = AuthenticatedPrincipal(
        actor_type="internal",
        authenticated_at=NOW,
    )
    context = GatewayContext.model_validate(api_key_context_payload())

    with pytest.raises(ValidationError, match="invalid identity fields"):
        principal.model_copy(update={"api_key_id": API_KEY_UUID})
    with pytest.raises(ValidationError):
        context.model_copy(update={"tenant_id": None})
