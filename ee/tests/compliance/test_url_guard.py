import asyncio
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
import ssl
from unittest.mock import AsyncMock, Mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
import httpx
from pydantic import ValidationError
import pytest

import shim_enterprise.api.enterprise_deps as enterprise_deps
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.compliance import url_guard
from shim_enterprise.compliance.url_guard import (
    UnsafeForwardURL,
    assert_safe_forward_url,
)
from shim_enterprise.core.config import Settings, settings
from shim_enterprise.core.database import get_db
from shim_enterprise.outbox import handlers


INTERNAL = "https://siem.corp.example:8443"


def _resolve_to(monkeypatch: pytest.MonkeyPatch, address: str) -> AsyncMock:
    resolver = AsyncMock(return_value=[(0, 0, 0, "", (address, 8443))])
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolver)
    return resolver


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    ["https://10.0.0.5:8443/hook", "https://siem.corp.example:8443/hook"],
)
async def test_private_destination_needs_an_operator_approved_origin(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    _resolve_to(monkeypatch, "10.0.0.5")
    monkeypatch.setattr(settings, "ALERT_ALLOWED_ORIGINS", [])

    with pytest.raises(UnsafeForwardURL):
        await assert_safe_forward_url(url)

    origin = url.removesuffix("/hook")
    monkeypatch.setattr(settings, "ALERT_ALLOWED_ORIGINS", [origin.upper()])
    assert await assert_safe_forward_url(url) == ip_address("10.0.0.5")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "https://siem.corp.example/hook",
        "https://siem.corp.example:9443/hook",
        "https://other.corp.example:8443/hook",
    ],
)
async def test_approval_is_for_the_exact_origin(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    _resolve_to(monkeypatch, "10.0.0.5")
    monkeypatch.setattr(settings, "ALERT_ALLOWED_ORIGINS", [INTERNAL])

    with pytest.raises(UnsafeForwardURL):
        await assert_safe_forward_url(url)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "address",
    [
        "169.254.169.254",
        "169.254.10.1",
        "fd00:ec2::254",
        "::ffff:169.254.169.254",
        "fe80::1",
        "224.0.0.1",
        "ff02::1",
        "0.0.0.0",
        "::",
    ],
)
async def test_metadata_link_local_and_non_unicast_stay_rejected_when_approved(
    monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    _resolve_to(monkeypatch, address)
    literal = f"[{address}]" if ":" in address else address
    monkeypatch.setattr(
        settings,
        "ALERT_ALLOWED_ORIGINS",
        [INTERNAL, f"https://{literal}:8443"],
    )

    for url in (f"{INTERNAL}/hook", f"https://{literal}:8443/hook"):
        with pytest.raises(UnsafeForwardURL):
            await assert_safe_forward_url(url)


@pytest.mark.asyncio
async def test_approved_origin_still_requires_https(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _resolve_to(monkeypatch, "10.0.0.5")
    monkeypatch.setattr(settings, "ALERT_ALLOWED_ORIGINS", [INTERNAL])

    with pytest.raises(UnsafeForwardURL):
        await assert_safe_forward_url("http://siem.corp.example:8443/hook")


@pytest.mark.parametrize(
    "origin",
    [
        "http://siem.corp.example",
        "https://siem.corp.example/path",
        "https://siem.corp.example?x=1",
        "https://user@siem.corp.example",
        "https://10.0.0.0/8",
        "siem.corp.example",
        "https://siem.corp.example:99999",
    ],
)
def test_alert_allowed_origins_accept_exact_https_origins_only(origin: str) -> None:
    with pytest.raises(ValidationError, match="ALERT_ALLOWED_ORIGINS"):
        Settings(_env_file=None, ALERT_ALLOWED_ORIGINS=[origin])

    assert Settings(
        _env_file=None, ALERT_ALLOWED_ORIGINS=[INTERNAL, "https://siem.corp.example/"]
    ).ALERT_ALLOWED_ORIGINS == [INTERNAL, "https://siem.corp.example/"]


def test_outbound_ca_bundle_keeps_the_released_model_deployment_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MODEL_DEPLOYMENT_CA_BUNDLE", "/etc/shim/legacy.pem")
    assert Settings(_env_file=None).OUTBOUND_CA_BUNDLE == "/etc/shim/legacy.pem"

    monkeypatch.setenv("OUTBOUND_CA_BUNDLE", "/etc/shim/outbound.pem")
    assert Settings(_env_file=None).OUTBOUND_CA_BUNDLE == "/etc/shim/outbound.pem"


def _private_ca(path) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "shim test ca")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return str(path)


@pytest.mark.asyncio
async def test_alert_delivery_trusts_the_outbound_ca_bundle(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(
        settings, "OUTBOUND_CA_BUNDLE", _private_ca(tmp_path / "internal-ca.pem")
    )
    monkeypatch.setattr(
        handlers, "assert_safe_forward_url", AsyncMock(return_value="10.0.0.5")
    )
    client = AsyncMock()
    client.__aenter__.return_value = client
    response_context = AsyncMock()
    response_context.__aenter__.return_value = Mock()
    client.stream = Mock(return_value=response_context)
    client_factory = Mock(return_value=client)
    monkeypatch.setattr(handlers.httpx, "AsyncClient", client_factory)

    await handlers._post_forward_url(
        f"{INTERNAL}/hook", content=b"{}", headers={"content-type": "application/json"}
    )

    verify = client_factory.call_args.kwargs["verify"]
    assert isinstance(verify, ssl.SSLContext)
    assert verify.verify_mode == ssl.CERT_REQUIRED
    assert [
        dict(item[0] for item in certificate["subject"])["commonName"]
        for certificate in verify.get_ca_certs()
    ] == ["shim test ca"]


@pytest.mark.asyncio
async def test_create_routes_accept_private_destinations_only_when_approved(
    monkeypatch: pytest.MonkeyPatch, db, test_user_with_org
) -> None:
    test_user_with_org.role = "admin"
    _resolve_to(monkeypatch, "10.0.0.5")
    application = FastAPI()
    application.include_router(management_router, prefix="/api/v1")
    application.dependency_overrides[enterprise_deps.get_current_user] = lambda: (
        test_user_with_org
    )
    application.dependency_overrides[get_db] = lambda: db
    target = {"kind": "siem_webhook", "endpoint": f"{INTERNAL}/hook"}
    budget = {
        "scope_type": "org",
        "limit_usd": "10",
        "notify_targets": [{"kind": "webhook", "endpoint": f"{INTERNAL}/hook"}],
    }

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        statuses = []
        for allowed in ([], [INTERNAL]):
            monkeypatch.setattr(url_guard.settings, "ALERT_ALLOWED_ORIGINS", allowed)
            statuses.append(
                (
                    (
                        await client.post(
                            "/api/v1/compliance/forward-targets", json=target
                        )
                    ).status_code,
                    (
                        await client.post(
                            "/api/v1/management/cost/budgets", json=budget
                        )
                    ).status_code,
                )
            )

    assert statuses == [(422, 422), (201, 200)]
