from __future__ import annotations

import json
from uuid import uuid4

import httpx
import pytest

from shim.gateway.contracts.ids import TenantId
from shim_enterprise.core.config import settings
from shim_enterprise.secrets.store import parse_secret_ref
from shim_enterprise.secrets.vault import VaultSecretStore


@pytest.mark.asyncio
async def test_vault_pinned_rotation_tenant_purpose_and_agent_token_reload(
    tmp_path, monkeypatch
):
    token_file = tmp_path / "vault-token"
    token_file.write_text("first-token")
    monkeypatch.setattr(settings, "VAULT_ADDR", "https://vault.internal")
    monkeypatch.setattr(settings, "VAULT_TOKEN_FILE", str(token_file))
    secrets = {}
    seen_tokens = []

    def vault(request):
        seen_tokens.append(request.headers["X-Vault-Token"])
        path = request.url.path
        if request.method == "POST":
            body = json.loads(request.content)
            assert body["options"] == {"cas": 0}
            secrets[path] = body["data"]
            return httpx.Response(200, json={"data": {"version": 1}})
        if request.method == "GET":
            assert request.url.params["version"] == "1"
            if path not in secrets:
                return httpx.Response(404)
            return httpx.Response(200, json={"data": {"data": secrets[path]}})
        assert request.method == "PUT" and json.loads(request.content) == {
            "versions": [1]
        }
        del secrets[path.replace("/destroy/", "/data/")]
        return httpx.Response(204)

    store = VaultSecretStore(transport=httpx.MockTransport(vault))
    tenant = TenantId(uuid4())
    original = await store.put_secret(tenant, "provider:openai", "sk-one")
    assert parse_secret_ref(original).version == "1"
    assert "sk-one" not in original
    token_file.write_text("renewed-token")
    rotated = await store.rotate_secret(
        tenant, original, "sk-two", expected_purpose="provider:openai"
    )
    assert original != rotated
    assert await store.get_secret(tenant, original) == "sk-one"
    assert await store.get_secret(tenant, rotated) == "sk-two"
    calls = len(seen_tokens)
    with pytest.raises(ValueError, match="tenant"):
        await store.get_secret(TenantId(uuid4()), original)
    assert len(seen_tokens) == calls
    with pytest.raises(ValueError, match="purpose"):
        await store.get_secret(tenant, original, expected_purpose="wrong")
    await store.delete_secret(tenant, original)
    with pytest.raises(httpx.HTTPStatusError):
        await store.get_secret(tenant, original)
    assert seen_tokens[0] == "first-token"
    assert set(seen_tokens[1:]) == {"renewed-token"}
