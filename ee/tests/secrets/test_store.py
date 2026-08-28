from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from pydantic import ValidationError

import shim_enterprise.secrets.store as store_module
from shim_enterprise.api.v1 import management
from shim_enterprise.core.config import Settings
from shim.gateway.contracts.ids import SecretRef, TenantId
from shim_enterprise.secrets.migration import assign_secret_reference
from shim_enterprise.secrets.aws_secrets_manager import AWSSecretsManagerStore
from shim_enterprise.secrets.azure_key_vault import AzureKeyVaultStore
from shim.secrets.credentials import EphemeralProviderCredential
from shim_enterprise.secrets.fernet_store import FernetSecretStore
from shim_enterprise.secrets.gcp_secret_manager import GCPSecretManagerStore
from shim_enterprise.secrets.store import (
    ManagedProviderCredentialResolver,
    parse_secret_ref,
    validate_write,
)
from shim_enterprise.tenants.models import ProviderSecret


@pytest.mark.asyncio
async def test_fernet_v2_round_trip_rotation_and_tenant_binding() -> None:
    store = FernetSecretStore()
    tenant_id = TenantId(uuid4())
    foreign_tenant_id = TenantId(uuid4())

    secret_ref = await store.put_secret(
        tenant_id,
        "provider:openai",
        "sk-original",
        {"provider": "openai"},
    )

    parsed = parse_secret_ref(secret_ref)
    assert parsed.backend == "fernet"
    assert parsed.version == "v2"
    assert "sk-original" not in str(secret_ref)
    assert await store.get_secret(tenant_id, secret_ref) == "sk-original"
    with pytest.raises(ValueError, match="does not belong"):
        await store.get_secret(foreign_tenant_id, secret_ref)
    with pytest.raises(ValueError, match="wrong purpose"):
        await store.get_secret(
            tenant_id,
            secret_ref,
            expected_purpose="compliance-connector-api-key",
        )

    rotated_ref = await store.rotate_secret(tenant_id, secret_ref, "sk-rotated")
    assert rotated_ref != secret_ref
    assert await store.get_secret(tenant_id, rotated_ref) == "sk-rotated"
    assert await store.delete_secret(tenant_id, rotated_ref) is None


@pytest.mark.asyncio
async def test_long_fernet_provider_reference_persists(db, test_org) -> None:
    store = FernetSecretStore()
    tenant_id = TenantId(test_org.id)
    plaintext = "sk-proj-" + "x" * 256
    secret_ref = await store.put_secret(
        tenant_id,
        "provider:openai:api-key",
        plaintext,
        {"provider": "openai"},
    )
    assert len(secret_ref) > 512

    provider = ProviderSecret(
        organization_id=test_org.id,
        provider="openai",
        name="long-reference-regression",
        masked_key="sk-...xxxx",
    )
    assign_secret_reference(provider, secret_ref)
    db.add(provider)
    await db.flush()

    assert provider.secret_ref == secret_ref
    assert (
        await store.get_secret(
            tenant_id,
            SecretRef(provider.secret_ref),
            expected_purpose="provider:openai:api-key",
        )
        == plaintext
    )


class FakeSecretManagerClient:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}
        self.deleted: list[str] = []
        self.version = 0

    def create_secret(self, *, request: dict) -> SimpleNamespace:
        name = f"{request['parent']}/secrets/{request['secret_id']}"
        return SimpleNamespace(name=name)

    def add_secret_version(self, *, request: dict) -> SimpleNamespace:
        self.version += 1
        self.values[request["parent"]] = request["payload"]["data"]
        return SimpleNamespace(name=f"{request['parent']}/versions/{self.version}")

    def access_secret_version(self, *, request: dict) -> SimpleNamespace:
        name = request["name"].split("/versions/", 1)[0]
        return SimpleNamespace(payload=SimpleNamespace(data=self.values[name]))

    def delete_secret(self, *, request: dict) -> None:
        self.deleted.append(request["name"])
        self.values.pop(request["name"], None)


@pytest.mark.asyncio
async def test_gcp_secret_manager_uses_injected_client_for_real_operations() -> None:
    client = FakeSecretManagerClient()
    store = GCPSecretManagerStore(project_id="test-project", client=client)
    tenant_id = TenantId(uuid4())
    foreign_tenant_id = TenantId(uuid4())

    secret_ref = await store.put_secret(
        tenant_id,
        "compliance-webhook",
        "signing-secret",
        {"connector": "webhook"},
    )

    parsed = parse_secret_ref(secret_ref)
    assert parsed.backend == "gcp"
    assert parsed.version == "1"
    assert parsed.format_version == "v1"
    assert parsed.locator.startswith("projects/test-project/secrets/shim-tenant-")
    assert "/versions/latest" not in parsed.locator
    assert parsed.locator.endswith("/versions/1")
    assert await store.get_secret(tenant_id, secret_ref) == "signing-secret"
    with pytest.raises(ValueError, match="does not belong"):
        await store.get_secret(foreign_tenant_id, secret_ref)

    rotated_ref = await store.rotate_secret(tenant_id, secret_ref, "new-secret")
    assert GCPSecretManagerStore._secret_name(
        parse_secret_ref(rotated_ref).locator
    ) != GCPSecretManagerStore._secret_name(parse_secret_ref(secret_ref).locator)
    assert str(rotated_ref).endswith("/versions/2")
    assert await store.get_secret(tenant_id, rotated_ref) == "new-secret"
    await store.delete_secret(tenant_id, rotated_ref)
    assert len(client.deleted) == 1


def test_gcp_ref_parser_rejects_latest_alias() -> None:
    with pytest.raises(ValueError, match="pin a numeric version"):
        parse_secret_ref("gcpsm:v1:projects/test-project/secrets/a/versions/latest")


def test_secret_reference_and_write_validation_reject_empty_structure() -> None:
    with pytest.raises(ValueError, match="no encrypted payload"):
        parse_secret_ref("fernet:v2:")
    with pytest.raises(ValueError, match="purpose is required"):
        validate_write(TenantId(uuid4()), "  ", "secret")


@pytest.mark.asyncio
async def test_gcp_store_rejects_refs_from_another_project() -> None:
    store = GCPSecretManagerStore(
        project_id="test-project", client=FakeSecretManagerClient()
    )
    with pytest.raises(ValueError, match="Not a GCP"):
        await store.get_secret(
            TenantId(uuid4()),
            SecretRef("gcpsm:v1:projects/other/secrets/a/versions/1"),
        )


@pytest.mark.asyncio
async def test_gcp_store_accepts_canonical_numeric_project_reference() -> None:
    client = FakeSecretManagerClient()
    store = GCPSecretManagerStore(project_id="test-project", client=client)
    tenant_id = TenantId(uuid4())
    reference = await store.put_secret(
        tenant_id,
        "provider:openai:api-key",
        "sk-test",
    )
    canonical = SecretRef(
        str(reference).replace("projects/test-project/", "projects/582658327194/")
    )

    assert await store.get_secret(tenant_id, canonical) == "sk-test"


@pytest.mark.asyncio
async def test_aws_rotation_creates_an_independent_secret() -> None:
    client = SimpleNamespace(
        create_secret=Mock(return_value={"ARN": "new-secret", "VersionId": "2"})
    )
    store = AWSSecretsManagerStore(client=client)
    store._read = AsyncMock(
        return_value=({"purpose": "provider:openai", "metadata": {}}, "old-secret")
    )
    tenant_id = TenantId(uuid4())

    rotated = await store.rotate_secret(
        tenant_id,
        SecretRef("awssm:v1:old-secret@1"),
        "sk-rotated",
    )

    assert parse_secret_ref(rotated).locator == "new-secret"
    client.create_secret.assert_called_once()


@pytest.mark.asyncio
async def test_azure_rotation_creates_an_independent_secret() -> None:
    vault_url = "https://test.vault.azure.net"
    client = SimpleNamespace(
        set_secret=Mock(
            side_effect=lambda name, _value: SimpleNamespace(
                id=f"{vault_url}/secrets/{name}/2"
            )
        )
    )
    store = AzureKeyVaultStore(vault_url=vault_url, client=client)
    store._read = AsyncMock(
        return_value=({"purpose": "provider:openai", "metadata": {}}, "old-secret")
    )

    rotated = await store.rotate_secret(
        TenantId(uuid4()),
        SecretRef(f"azurekv:v1:{vault_url}/secrets/old-secret/1"),
        "sk-rotated",
    )

    assert "/secrets/old-secret/" not in parse_secret_ref(rotated).locator
    client.set_secret.assert_called_once()


def test_configured_singleton_uses_canonical_backend_setting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(store_module, "_store_singleton", None)
    monkeypatch.setattr(
        store_module.settings,
        "SECRET_BACKEND",
        "gcp_secret_manager",
    )
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "test-project")

    store = store_module.get_secret_store()

    assert store.backend == "gcp"
    assert store_module.get_secret_store() is store


class SessionScope:
    def __init__(self, session: object) -> None:
        self.session = session
        self.entered = False

    async def __aenter__(self) -> object:
        self.entered = True
        return self.session

    async def __aexit__(self, *args: object) -> None:
        return None


@pytest.mark.asyncio
async def test_explicit_provider_credential_bypasses_managed_storage() -> None:
    tenant_id = TenantId(uuid4())
    credential = EphemeralProviderCredential("openai", "invocation-provider-key")
    store = Mock(get_secret=AsyncMock())
    session_factory = Mock()
    resolver = ManagedProviderCredentialResolver(
        "openai",
        store,
        session_factory,
    )

    assert await resolver.resolve(tenant_id, credential) == "invocation-provider-key"
    assert credential.available() is False
    session_factory.assert_not_called()
    store.get_secret.assert_not_awaited()


@pytest.mark.asyncio
async def test_managed_provider_resolution_uses_a_fresh_session_per_lookup() -> None:
    tenant_id = TenantId(uuid4())
    row = SimpleNamespace(secret_ref="fernet:v2:encrypted-provider-key")
    results = [row, None]
    sessions = [
        SimpleNamespace(
            execute=AsyncMock(
                return_value=SimpleNamespace(
                    scalars=lambda current=current: SimpleNamespace(
                        first=lambda: current
                    )
                )
            )
        )
        for current in results
    ]
    scopes = [SessionScope(session) for session in sessions]
    session_factory = Mock(side_effect=scopes)
    store = Mock(get_secret=AsyncMock(return_value="managed-provider-key"))
    resolver = ManagedProviderCredentialResolver(
        "openai",
        store,
        session_factory,
    )

    assert await resolver.resolve(tenant_id, None) == "managed-provider-key"
    assert await resolver.resolve(tenant_id, None) is None
    assert session_factory.call_count == 2
    assert all(scope.entered for scope in scopes)
    assert all(session.execute.await_count == 1 for session in sessions)
    store.get_secret.assert_awaited_once_with(
        tenant_id,
        SecretRef(row.secret_ref),
        expected_purpose="provider:openai:api-key",
    )


@pytest.mark.asyncio
async def test_managed_provider_mismatch_does_not_consume_or_query() -> None:
    tenant_id = TenantId(uuid4())
    credential = EphemeralProviderCredential("google", "google-provider-key")
    session_factory = Mock()
    resolver = ManagedProviderCredentialResolver(
        "openai",
        Mock(),
        session_factory,
    )

    with pytest.raises(ValueError, match="does not match"):
        await resolver.resolve(tenant_id, credential)
    assert credential.available() is True
    session_factory.assert_not_called()


def test_production_rejects_local_secret_backend() -> None:
    with pytest.raises(ValidationError, match="managed secret backend"):
        Settings(
            DATABASE_URL="postgresql+asyncpg://test:test@localhost/test",
            REDIS_URL="redis://localhost:6379/0",
            SECRET_KEY="test-secret-key-value",
            SUPABASE_URL="https://example.supabase.co",
            ENVIRONMENT="production",
            SECRET_BACKEND="fernet",
            _env_file=None,
        )


def test_production_rejects_manual_test_dashboard() -> None:
    with pytest.raises(ValidationError, match="manual test dashboard"):
        Settings(
            DATABASE_URL="postgresql+asyncpg://test:test@localhost/test",
            REDIS_URL="redis://localhost:6379/0",
            SECRET_KEY="test-secret-key-value",
            SUPABASE_URL="https://example.supabase.co",
            ENVIRONMENT="production",
            SECRET_BACKEND="gcp_secret_manager",
            MANUAL_TEST_DASHBOARD_ENABLED=True,
            _env_file=None,
        )


def test_reconciliation_interval_cannot_outlive_stream_heartbeat_grace() -> None:
    with pytest.raises(ValidationError, match="cannot exceed its grace period"):
        Settings(
            DATABASE_URL="postgresql+asyncpg://test:test@localhost/test",
            REDIS_URL="redis://localhost:6379/0",
            SECRET_KEY="test-secret-key-value",
            SUPABASE_URL="https://example.supabase.co",
            GATEWAY_RECONCILIATION_GRACE_SECONDS=30,
            GATEWAY_RECONCILIATION_INTERVAL_SECONDS=31,
            _env_file=None,
        )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "https://one.example, https://two.example",
            ["https://one.example", "https://two.example"],
        ),
        ('["https://one.example"]', ["https://one.example"]),
    ],
)
def test_settings_accept_csv_or_json_lists(value: str, expected: list[str]) -> None:
    configured = Settings(
        DATABASE_URL="postgresql+asyncpg://test:test@localhost/test",
        REDIS_URL="redis://localhost:6379/0",
        SECRET_KEY="test-secret-key-value",
        SUPABASE_URL="https://example.supabase.co",
        BACKEND_CORS_ORIGINS=value,
        _env_file=None,
    )

    assert configured.BACKEND_CORS_ORIGINS == expected


@pytest.mark.parametrize(
    "url",
    ["http://store.lemonsqueezy.com/buy/variant", "/buy/variant", "https:///buy"],
)
def test_checkout_urls_require_absolute_https(url: str) -> None:
    with pytest.raises(ValidationError, match="absolute HTTPS URL"):
        Settings(
            DATABASE_URL="postgresql+asyncpg://test:test@localhost/test",
            REDIS_URL="redis://localhost:6379/0",
            SECRET_KEY="test-secret-key-value",
            SUPABASE_URL="https://example.supabase.co",
            LEMON_SQUEEZY_SOLO_PRO_MONTHLY_CHECKOUT_URL=url,
            _env_file=None,
        )


class RotationStore:
    def __init__(self, rotated_reference: SecretRef) -> None:
        self.rotated_reference = rotated_reference
        self.deleted: list[SecretRef] = []

    async def rotate_secret(self, *args, **kwargs) -> SecretRef:
        return self.rotated_reference

    async def delete_secret(
        self,
        tenant_id: TenantId,
        secret_ref: SecretRef,
        *,
        expected_purpose: str | None = None,
    ) -> None:
        del tenant_id, expected_purpose
        self.deleted.append(secret_ref)


class RotationSession:
    def __init__(self, *, fail_commit: bool) -> None:
        self.fail_commit = fail_commit
        self.rolled_back = False
        self.refreshed = False

    async def commit(self) -> None:
        if self.fail_commit:
            raise RuntimeError("commit failed")

    async def rollback(self) -> None:
        self.rolled_back = True

    async def refresh(self, row: ProviderSecret) -> None:
        del row
        self.refreshed = True


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_commit", [False, True])
async def test_provider_rotation_cleans_the_unreferenced_managed_secret(
    monkeypatch: pytest.MonkeyPatch,
    fail_commit: bool,
) -> None:
    tenant_id = uuid4()
    previous = SecretRef("gcpsm:v1:projects/test/secrets/provider-old/versions/1")
    rotated = SecretRef("gcpsm:v1:projects/test/secrets/provider-new/versions/2")
    row = ProviderSecret(
        id=uuid4(),
        organization_id=tenant_id,
        provider="openai",
        name="OpenAI",
        secret_ref=str(previous),
        secret_backend="gcp",
        secret_version="1",
        masked_key="sk-...old",
    )
    user = SimpleNamespace(organization_id=tenant_id)
    store = RotationStore(rotated)
    session = RotationSession(fail_commit=fail_commit)

    async def owned_provider_secret(*args, **kwargs) -> ProviderSecret:
        return row

    async def audit(*args, **kwargs) -> None:
        return None

    monkeypatch.setattr(management, "_owned_provider_secret", owned_provider_secret)
    monkeypatch.setattr(management, "_audit", audit)
    monkeypatch.setattr(management, "get_secret_store", lambda: store)

    operation = management.update_provider_secret(
        row.id,
        management.ProviderSecretPatch(key="sk-provider-rotated"),
        user,
        session,
    )
    if fail_commit:
        with pytest.raises(RuntimeError, match="commit failed"):
            await operation
        assert session.rolled_back is True
        assert store.deleted == [rotated]
        assert session.refreshed is False
    else:
        assert await operation is row
        assert store.deleted == [previous]
        assert session.refreshed is True
