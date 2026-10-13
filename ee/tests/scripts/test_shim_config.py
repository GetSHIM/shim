from __future__ import annotations

import json
from pathlib import Path
import runpy
import stat
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from shim_enterprise.config_file.models import ConfigSigningKey
from shim_enterprise.config_file.signing import key_id, verify_config_signature
from shim_enterprise.tenants.models import Organization, User

_TOOL = runpy.run_path(str(Path(__file__).parents[2] / "scripts" / "shim_config.py"))
main = _TOOL["main"]
TOKEN = "shim-management-token-for-tests"


def _file(path: Path, organization_id) -> Path:
    path.write_bytes(
        (
            "format: shim.config\nversion: 1\n"
            f"organization_id: {organization_id}\nserial: 2\n"
            "resources:\n  privacy: {response_scan: 'off'}\r\n"
        ).encode()
    )
    return path


def test_keygen_writes_a_private_key_only_its_owner_reads_and_never_overwrites(
    tmp_path, capsys
) -> None:
    assert main(["keygen", "--out-dir", str(tmp_path)]) == 0
    printed = capsys.readouterr().out.strip()
    private, public = (
        tmp_path / "shim-config-signing.key",
        tmp_path / "shim-config-signing.pub",
    )

    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert printed == key_id(load_pem_public_key(public.read_bytes()))
    before = private.read_bytes()
    assert main(["keygen", "--out-dir", str(tmp_path)]) == 2
    assert private.read_bytes() == before
    assert "already exists" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_a_signature_from_the_script_verifies_on_the_exact_bytes(
    db, tmp_path, capsys
) -> None:
    organization = Organization(
        id=uuid4(), name="Script", slug=f"script-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    holder = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"script-{uuid4().hex}@example.com",
        role="owner",
        is_active=True,
        is_verified=True,
    )
    db.add(holder)
    await db.flush()
    assert main(["keygen", "--out-dir", str(tmp_path)]) == 0
    signer = capsys.readouterr().out.strip()
    db.add(
        ConfigSigningKey(
            organization_id=organization.id,
            key_id=signer,
            public_key=(tmp_path / "shim-config-signing.pub").read_text(),
            user_id=holder.id,
            name="ci",
        )
    )
    await db.flush()
    file = _file(tmp_path / "shim.yaml", organization.id)
    out = tmp_path / "shim.sig"

    assert (
        main(
            [
                "sign",
                "--private-key",
                str(tmp_path / "shim-config-signing.key"),
                "--file",
                str(file),
                "--out",
                str(out),
            ]
        )
        == 0
    )
    signature = out.read_text().strip()

    key = await verify_config_signature(
        db, organization.id, file.read_bytes(), signature
    )
    assert key.key_id == signer
    assert signature.startswith(f"{signer}.")


def _server(statuses: dict[str, int], seen: list[httpx.Request]) -> httpx.MockTransport:
    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        status = statuses[request.url.path.rsplit("/", 1)[-1]]
        return httpx.Response(status, json={"status": status})

    return httpx.MockTransport(answer)


@pytest.mark.parametrize(
    ("route", "status", "exit_code"),
    [
        ("plan", 200, 0),
        ("apply", 200, 0),
        ("apply", 202, 3),
        ("apply", 409, 1),
        ("apply", 403, 1),
    ],
)
def test_push_exit_codes_and_the_token_stays_secret(
    tmp_path, capsys, monkeypatch, route, status, exit_code
) -> None:
    assert main(["keygen", "--out-dir", str(tmp_path)]) == 0
    capsys.readouterr()
    file = _file(tmp_path / "shim.yaml", uuid4())
    seen: list[httpx.Request] = []
    real = httpx.Client
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **options: real(transport=_server({route: status}, seen), **options),
    )
    monkeypatch.setenv("SHIM_MANAGEMENT_TOKEN", TOKEN)
    key_path = str(tmp_path / "shim-config-signing.key")

    code = main(
        [
            "push",
            "--url",
            "https://shim.example.test/",
            "--file",
            str(file),
            "--private-key",
            key_path,
            *(["--plan-only"] if route == "plan" else []),
        ]
    )
    captured = capsys.readouterr()

    assert code == exit_code
    [request] = seen
    assert request.url.path == f"/api/v1/management/config/{route}"
    assert request.headers["authorization"] == f"Bearer {TOKEN}"
    body = json.loads(request.content)
    # The exact bytes, CRLF included, as they were signed.
    assert body["file"].encode() == file.read_bytes()
    assert TOKEN not in captured.out + captured.err
    assert key_path not in captured.out + captured.err


def test_push_without_a_token_is_a_usage_error(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.delenv("SHIM_MANAGEMENT_TOKEN", raising=False)
    file = _file(tmp_path / "shim.yaml", uuid4())

    code = main(
        [
            "push",
            "--url",
            "https://shim.example.test",
            "--file",
            str(file),
            "--signature",
            "x.y",
        ]
    )

    assert code == 2
    assert "SHIM_MANAGEMENT_TOKEN" in capsys.readouterr().err


def test_export_writes_the_file(tmp_path, monkeypatch) -> None:
    real = httpx.Client
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **options: real(
            transport=httpx.MockTransport(
                lambda request: (
                    httpx.Response(200, content=b"format: shim.config\n")
                    if request.url.params.get("version") == "4"
                    else httpx.Response(404)
                )
            ),
            **options,
        ),
    )
    monkeypatch.setenv("SHIM_MANAGEMENT_TOKEN", TOKEN)
    out = tmp_path / "out.yaml"

    assert (
        main(
            [
                "export",
                "--url",
                "https://shim.example.test",
                "--version",
                "4",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    assert out.read_bytes() == b"format: shim.config\n"
    assert (
        main(["export", "--url", "https://shim.example.test", "--out", str(out)]) == 1
    )
