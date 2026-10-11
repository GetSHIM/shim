from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from cryptography.fernet import Fernet
from pydantic import ValidationError
import pytest
import pytest_asyncio
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim.gateway.contracts.context import (
    AuditPolicy,
    GatewayContext,
    PrivacyPolicy,
    TierPolicy,
)
from shim.gateway.contracts.ids import ProviderId
from shim.gateway.kernel.result import PreparedInference
from shim.gateway.pipeline.privacy import PrivacyStage
from shim.gateway.request_policy import RequestPolicyContext
from shim.privacy.continuation import InMemoryPrivacyContinuationStore
from shim.privacy.pii_scrubber import PIIScrubberService
from shim.privacy.policies import (
    PrivacyAction,
    PrivacyOutcome,
    effective_entity_actions,
)
from shim.rules.model import RuleMatch
from shim_enterprise.archive import service
from shim_enterprise.core import database
from shim_enterprise.archive.models import RequestArchive
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.core.config import Settings, settings
from shim_enterprise.observability.enterprise_metrics import (
    REQUEST_ARCHIVE_WRITES_TOTAL,
)
from shim_enterprise.tenants.gateway_settings import (
    GatewaySettings,
    RequestArchiveSettings,
    classify_change,
)

TCKN = "10000000146"
EMAIL = "ayse.yilmaz@example.com"
ON = GatewaySettings(request_archive=RequestArchiveSettings(enabled=True))


@pytest.fixture
def installed(monkeypatch) -> None:
    monkeypatch.setattr(settings, "REQUEST_ARCHIVE_ENABLED", True)
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", Fernet.generate_key().decode())


@pytest_asyncio.fixture
async def factory(db) -> async_sessionmaker[AsyncSession]:
    # Savepoints keep the fixture's rolled-back transaction across commits.
    return async_sessionmaker(
        bind=await db.connection(),
        join_transaction_mode="create_savepoint",
        expire_on_commit=False,
    )


def _prepared(
    key,
    payload: dict[str, Any] | None = None,
    *,
    protocol: str = "chat",
    provider: str = "openai",
    gateway: object = ON,
    **privacy: Any,
) -> PreparedInference:
    return PreparedInference(
        context=GatewayContext(
            request_id=f"req_arc_{uuid4().hex}",
            tenant_id=key.organization_id,
            actor_type="api_key",
            api_key_id=key.id,
            user_id=None,
            endpoint="/v1/chat/completions",
            started_at=datetime.now(timezone.utc),
            tier_policy=TierPolicy(),
            privacy_policy=PrivacyPolicy(pii_mode="scrub"),
            audit_policy=AuditPolicy(mode="best_effort"),
        ),
        payload=payload
        or {"model": "gpt-5-nano", "messages": [{"role": "user", "content": "<P_1>"}]},
        provider=ProviderId(provider),
        protocol=protocol,  # ty: ignore[invalid-argument-type]
        model="gpt-5-nano",
        stream=False,
        policy=RequestPolicyContext(rate_limit_key_hash="key-hash", tier="free"),
        pii_config=None,
        entity_actions=effective_entity_actions(),
        tenant_gateway_settings=gateway,
        privacy=PrivacyOutcome(
            action=PrivacyAction.SCRUBBED,
            pii_detected=bool(privacy),
            verification_map={"<P_1>": EMAIL},
            **privacy,
        ),
    )


async def _lifecycle(db, prepared: PreparedInference) -> None:
    db.add(
        RequestLifecycle(
            request_id=str(prepared.request_id),
            organization_id=prepared.tenant_id,
            actor_type="api_key",
            api_key_id=prepared.api_key_id,
            source_endpoint="chat.completions",
            status="accepted",
            requested_model=prepared.model,
            stream=False,
            started_at=prepared.context.started_at,
            lifecycle_metadata={},
        )
    )
    await db.flush()


async def _archived(
    db, prepared: PreparedInference
) -> tuple[RequestArchive | None, Any]:
    row = await db.scalar(
        select(RequestArchive).where(
            RequestArchive.request_id == str(prepared.request_id)
        )
    )
    metadata = await db.scalar(
        select(RequestLifecycle.lifecycle_metadata).where(
            RequestLifecycle.request_id == str(prepared.request_id)
        )
    )
    return row, (metadata or {}).get("request_archive")


@pytest.mark.parametrize(
    ("installation", "tenant", "stored"),
    [(True, True, True), (False, True, False), (True, False, False)],
)
@pytest.mark.asyncio
async def test_both_switches_must_be_on(
    db, factory, test_api_key, monkeypatch, installation, tenant, stored
) -> None:
    monkeypatch.setattr(settings, "REQUEST_ARCHIVE_ENABLED", installation)
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", Fernet.generate_key().decode())
    prepared = _prepared(
        test_api_key,
        gateway=ON if tenant else GatewaySettings(),
        pii_entities={"EMAIL_ADDRESS": 1},
    )
    await _lifecycle(db, prepared)

    await service.archive_request(factory, prepared)

    row, marker = await _archived(db, prepared)
    assert (row is not None, marker) == (stored, "stored" if stored else None)


def test_the_installation_switch_needs_an_encryption_key() -> None:
    with pytest.raises(
        ValidationError, match="REQUEST_ARCHIVE_ENABLED requires ENCRYPTION_KEY"
    ):
        Settings(_env_file=None, REQUEST_ARCHIVE_ENABLED=True, ENCRYPTION_KEY="")  # ty: ignore[unknown-argument]


@pytest.mark.parametrize(
    "privacy",
    [
        {"pii_entities": {"EMAIL_ADDRESS": 1}},
        {"monitored_entities": {"PERSON": 2}},
        {"blocked_entities": {"SECRET": 1}},
        {},
    ],
    ids=["masked", "monitored", "blocked", "rule"],
)
@pytest.mark.asyncio
async def test_each_kind_of_match_qualifies(
    db, factory, test_api_key, installed, privacy
) -> None:
    prepared = _prepared(test_api_key, **privacy)
    if not privacy:
        prepared.rule_matches.append(
            RuleMatch(
                rule_id="kasa", kind="term", action="block", state="monitor", count=1
            )
        )
    await _lifecycle(db, prepared)

    await service.archive_request(factory, prepared)

    row, marker = await _archived(db, prepared)
    assert row is not None and marker == "stored"
    if not privacy:
        # A rule in monitor state only watched.
        assert row.matched == [
            {"kind": "rule", "id": "kasa", "action": "monitor", "count": 1}
        ]


@pytest.mark.parametrize("protocol", ["chat", "count_tokens"])
@pytest.mark.asyncio
async def test_clean_requests_and_token_counts_are_never_kept(
    db, factory, test_api_key, installed, protocol
) -> None:
    clean = _prepared(test_api_key)
    counted = _prepared(
        test_api_key, protocol="count_tokens", pii_entities={"EMAIL_ADDRESS": 1}
    )
    prepared = clean if protocol == "chat" else counted
    await _lifecycle(db, prepared)

    await service.archive_request(factory, prepared)

    assert await _archived(db, prepared) == (None, None)


@pytest.mark.asyncio
async def test_the_row_holds_ciphertext_and_ids_only(
    db, factory, test_api_key, installed
) -> None:
    payload = {
        "model": "gpt-5-nano",
        "messages": [{"role": "user", "content": f"<P_1> ve {TCKN}"}],
    }
    prepared = _prepared(test_api_key, payload, pii_entities={"EMAIL_ADDRESS": 1})
    await _lifecycle(db, prepared)

    await service.archive_request(factory, prepared)

    stored = await db.scalar(
        text(
            "SELECT row_to_json(r)::text FROM request_archive r WHERE request_id = :id"
        ),
        {"id": str(prepared.request_id)},
    )
    for secret in (EMAIL, TCKN, "<P_1>", "P_1"):
        assert secret not in stored
        assert secret.encode().hex() not in stored


def _payloads() -> list[tuple[str, str, dict[str, Any]]]:
    text_ = f"Müşteri {EMAIL}, kimlik {TCKN}"
    return [
        (
            "chat",
            "openai",
            {"model": "gpt-5-nano", "messages": [{"role": "user", "content": text_}]},
        ),
        (
            "responses",
            "openai",
            {"model": "gpt-5-nano", "input": [{"role": "user", "content": text_}]},
        ),
        (
            "messages",
            "anthropic",
            {
                "model": "claude-haiku-5-5",
                "max_tokens": 16,
                "messages": [
                    {"role": "user", "content": [{"type": "text", "text": text_}]}
                ],
            },
        ),
        (
            "generate_content",
            "google",
            {"contents": [{"role": "user", "parts": [{"text": text_}]}]},
        ),
    ]


@pytest.mark.parametrize(("protocol", "provider", "payload"), _payloads())
@pytest.mark.asyncio
async def test_opening_restores_what_was_sent_for_each_protocol(
    db, factory, test_api_key, installed, protocol, provider, payload
) -> None:
    sent = {**payload}
    before = _prepared(test_api_key, sent, protocol=protocol, provider=provider)
    before = replace(before, privacy=None)
    masked = await PrivacyStage(
        PIIScrubberService(),
        InMemoryPrivacyContinuationStore(ttl_seconds=60, max_entries=8),
    ).run(before)
    await _lifecycle(db, masked)

    await service.archive_request(factory, masked)

    row, _ = await _archived(db, masked)
    assert row is not None
    opened = service.opened(row)
    assert opened["masked_payload"] == masked.payload
    assert TCKN not in str(opened["masked_payload"])
    assert opened["original_payload"] == payload
    assert TCKN in str(opened["original_payload"])
    assert {item["original"] for item in opened["replacements"]} >= {TCKN}


@pytest.mark.parametrize("failure", ["encryption", "insert"])
@pytest.mark.asyncio
async def test_a_failed_write_is_counted_and_never_marked_stored(
    db, factory, test_api_key, installed, monkeypatch, failure
) -> None:
    prepared = _prepared(test_api_key, pii_entities={"EMAIL_ADDRESS": 1})
    await _lifecycle(db, prepared)
    if failure == "encryption":

        def broken(*_args):
            raise ValueError("no key")

        monkeypatch.setattr(service, "_sealed", broken)
    else:
        # A row already there for the request makes the insert fail.
        await service.archive_request(factory, prepared)
        await db.execute(
            update(RequestLifecycle)
            .where(RequestLifecycle.request_id == str(prepared.request_id))
            .values(lifecycle_metadata={})
        )
    failed = REQUEST_ARCHIVE_WRITES_TOTAL.labels(result="failed")._value.get()

    await service.archive_request(factory, prepared)

    assert (
        REQUEST_ARCHIVE_WRITES_TOTAL.labels(result="failed")._value.get() == failed + 1
    )
    assert (await _archived(db, prepared))[1] is None


@pytest.mark.asyncio
async def test_a_payload_over_the_limit_is_skipped_and_marked(
    db, factory, test_api_key, installed, monkeypatch
) -> None:
    monkeypatch.setattr(service, "MAX_ARCHIVED_BYTES", 10)
    prepared = _prepared(test_api_key, pii_entities={"EMAIL_ADDRESS": 1})
    await _lifecycle(db, prepared)

    await service.archive_request(factory, prepared)

    assert await _archived(db, prepared) == (None, "skipped_size")


@pytest.mark.asyncio
async def test_a_key_that_cannot_decrypt_is_reported(
    db, factory, test_api_key, installed, monkeypatch
) -> None:
    prepared = _prepared(test_api_key, pii_entities={"EMAIL_ADDRESS": 1})
    await _lifecycle(db, prepared)
    await service.archive_request(factory, prepared)
    row, _ = await _archived(db, prepared)
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", Fernet.generate_key().decode())

    with pytest.raises(service.ArchiveUndecryptable):
        service.opened(row)


async def _row(db, organization_id, *, expires_in: timedelta) -> RequestArchive:
    row = RequestArchive(
        organization_id=organization_id,
        request_id=f"req_{uuid4().hex}",
        protocol="chat",
        model="gpt-5-nano",
        matched=[],
        masked_payload=b"x",
        edit_map=b"x",
        size_bytes=1,
        created_at=datetime.now(timezone.utc) - timedelta(days=10),
        expires_at=datetime.now(timezone.utc) + expires_in,
    )
    db.add(row)
    await db.flush()
    return row


@pytest.mark.asyncio
async def test_only_expired_rows_go_in_bounded_batches_whatever_the_switches(
    db, factory, test_org, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "REQUEST_ARCHIVE_ENABLED", False)
    monkeypatch.setattr(database, "DELETE_BATCH", 2)
    monkeypatch.setattr(database, "DELETE_BATCHES", 2)
    expired = [
        await _row(db, test_org.id, expires_in=-timedelta(days=1)) for _ in range(5)
    ]
    kept = await _row(db, test_org.id, expires_in=timedelta(days=1))

    deleted = await service.delete_expired(factory)

    left = set(
        await db.scalars(
            select(RequestArchive.id).where(
                RequestArchive.organization_id == test_org.id
            )
        )
    )
    # Two batches of two: one expired row waits for the next pass.
    assert deleted == 4
    assert kept.id in left and len(left & {row.id for row in expired}) == 1


@pytest.mark.asyncio
async def test_a_shorter_retention_moves_expiry_forward_only(db, test_org) -> None:
    fresh = await _row(db, test_org.id, expires_in=timedelta(days=80))
    soon = await _row(db, test_org.id, expires_in=timedelta(days=1))
    soon_expiry = soon.expires_at

    await service.shorten_retention(db, test_org.id, 30)

    await db.refresh(fresh)
    await db.refresh(soon)
    assert fresh.expires_at == fresh.created_at + timedelta(days=30)
    assert soon.expires_at == soon_expiry


@pytest.mark.parametrize(
    ("before", "after", "direction"),
    [
        ({}, {"enabled": True}, "relaxing"),
        ({"enabled": True}, {}, "tightening"),
        (
            {"enabled": True, "retention_days": 30},
            {"enabled": True, "retention_days": 60},
            "relaxing",
        ),
        ({"enabled": True}, {"enabled": True, "retention_days": 30}, "tightening"),
    ],
)
def test_more_content_kept_is_relaxing(before, after, direction) -> None:
    assert (
        classify_change(
            GatewaySettings(request_archive=RequestArchiveSettings(**before)),
            GatewaySettings(request_archive=RequestArchiveSettings(**after)),
        )[0]
        == direction
    )
