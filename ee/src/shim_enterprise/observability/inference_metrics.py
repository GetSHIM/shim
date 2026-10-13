"""Read the load of tenants' own model servers from their metrics routes.

vLLM and TGI publish Prometheus text on `/metrics`; Ollama lists its loaded models on
`/api/ps`. Only a fixed set of numbers is kept, as hourly aggregates. A model name,
a label value or any other text of a page is never stored or logged. The URL is the
deployment's approved origin plus a fixed path, never tenant input.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import logging
import re
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from sqlalchemy import delete, select, text, tuple_
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim.gateway.contracts.ids import SecretRef, TenantId
from shim_enterprise.observability.enterprise_metrics import INFERENCE_SCRAPES_TOTAL
from shim_enterprise.observability.models import InferenceMetricsHourly
from shim_enterprise.secrets.store import get_secret_store, provider_secret_purpose
from shim_enterprise.tenants.deployments import validate_deployment_url
from shim_enterprise.tenants.gateway_settings import InferenceMetricsSource
from shim_enterprise.tenants.models import (
    ModelDeployment,
    OrganizationGatewaySettings,
    ProviderSecret,
)

logger = logging.getLogger(__name__)
Server = Literal["vllm", "tgi", "ollama"]
PATHS: dict[str, str] = {"vllm": "/metrics", "tgi": "/metrics", "ollama": "/api/ps"}
MAX_BODY_BYTES = 1_048_576
SCRAPE_SECONDS = 5
MAX_IN_FLIGHT = 8
RETENTION_DAYS = 90
DELETE_BATCH = 10_000
# Metric name -> (field, how label sets combine). Nothing else of a page is read.
_NAMES: dict[str, dict[str, tuple[str, Literal["sum", "max"]]]] = {
    "vllm": {
        "vllm:num_requests_running": ("running", "sum"),
        "vllm:num_requests_waiting": ("waiting", "sum"),
        "vllm:kv_cache_usage_perc": ("cache_usage", "max"),
        "vllm:gpu_cache_usage_perc": ("cache_usage_legacy", "max"),
    },
    "tgi": {
        "tgi_batch_current_size": ("running", "sum"),
        "tgi_queue_size": ("waiting", "sum"),
    },
}
_LINE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)")


class ScrapeError(Exception):
    """A failed read: `code` is what the hourly row records."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Sample:
    running: int | None = None
    waiting: int | None = None
    cache_usage: float | None = None
    loaded: bool | None = None
    vram_bytes: int | None = None


def parse_prometheus(server: Server, body: str) -> Sample:
    """The allow-listed gauges of a Prometheus text page, summed or maxed over labels."""
    names = _NAMES[server]
    found: dict[str, float] = {}
    for line in body.splitlines():
        match = _LINE.match(line)
        if match is None or match.group(1) not in names:
            continue
        try:
            value = float(match.group(3))
        except ValueError:
            continue
        if value != value:  # NaN
            continue
        field, combine = names[match.group(1)]
        found[field] = (
            value
            if field not in found
            else (
                found[field] + value if combine == "sum" else max(found[field], value)
            )
        )
    if not found:
        raise ScrapeError("unrecognized")
    cache = found.get("cache_usage", found.get("cache_usage_legacy"))
    return Sample(
        running=None if "running" not in found else int(found["running"]),
        waiting=None if "waiting" not in found else int(found["waiting"]),
        cache_usage=None if cache is None else min(1.0, max(0.0, cache)),
    )


def parse_ollama(body: str, upstream_model: str) -> Sample:
    """Whether the deployment's model is loaded, and its VRAM; Ollama counts no requests."""
    try:
        models = json.loads(body)["models"]
        entry = next(
            (
                item
                for item in models
                if upstream_model in (item.get("model"), item.get("name"))
            ),
            None,
        )
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ScrapeError("unrecognized") from None
    if entry is None:
        return Sample(loaded=False)
    vram = entry.get("size_vram")
    return Sample(loaded=True, vram_bytes=vram if isinstance(vram, int) else None)


def metrics_url(base_url: str, server: Server) -> str:
    """The approved origin of the deployment plus the server's fixed path."""
    try:
        approved = validate_deployment_url(base_url)
    except ValueError:
        raise ScrapeError("origin_not_approved") from None
    parts = urlsplit(approved)
    return f"{parts.scheme}://{parts.netloc}{PATHS[server]}"


async def read_sample(
    client: httpx.AsyncClient,
    server: Server,
    base_url: str,
    upstream_model: str,
    credential: str | None,
) -> Sample:
    url = metrics_url(base_url, server)
    headers = {"Authorization": f"Bearer {credential}"} if credential else {}
    try:
        async with asyncio.timeout(SCRAPE_SECONDS):
            async with client.stream(
                "GET", url, headers=headers, follow_redirects=False
            ) as response:
                if response.status_code in {401, 403}:
                    raise ScrapeError("unauthorized")
                if response.status_code != 200:
                    raise ScrapeError(f"http_{response.status_code}")
                body = b""
                async for chunk in response.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_BODY_BYTES:
                        raise ScrapeError("too_large")
    except TimeoutError:
        raise ScrapeError("timeout") from None
    except httpx.HTTPError:
        raise ScrapeError("connection") from None
    page = body.decode("utf-8", errors="replace")
    if server == "ollama":
        return parse_ollama(page, upstream_model)
    return parse_prometheus(server, page)


@dataclass(frozen=True)
class Target:
    organization_id: UUID
    deployment_id: UUID
    server: Server
    base_url: str
    upstream_model: str
    provider: str
    secret: ProviderSecret | None


async def _targets(session: AsyncSession) -> list[Target]:
    """Every listed internal deployment of every tenant, in one statement."""
    rows = await session.execute(
        select(
            OrganizationGatewaySettings.organization_id,
            OrganizationGatewaySettings.settings,
        ).where(OrganizationGatewaySettings.settings.has_key("inference_metrics"))
    )
    sources: dict[tuple[UUID, UUID], InferenceMetricsSource] = {}
    for organization_id, stored in rows:
        for entry in stored.get("inference_metrics") or ():
            try:
                source = InferenceMetricsSource.model_validate(entry)
            except ValueError:
                continue
            sources[(organization_id, source.deployment_id)] = source
    if not sources:
        return []
    deployments = await session.execute(
        select(ModelDeployment, ProviderSecret)
        .join(ProviderSecret, ProviderSecret.id == ModelDeployment.provider_secret_id)
        .where(
            ModelDeployment.id.in_([key[1] for key in sources]),
            ModelDeployment.deployment_kind == "internal",
        )
    )
    targets = []
    for deployment, secret in deployments:
        # A deleted or foreign deployment simply drops out.
        source = sources.get((deployment.organization_id, deployment.id))
        if source is None:
            continue
        targets.append(
            Target(
                organization_id=deployment.organization_id,
                deployment_id=deployment.id,
                server=source.server,
                base_url=deployment.base_url,
                upstream_model=deployment.upstream_model,
                provider=deployment.provider,
                secret=secret if source.send_credential else None,
            )
        )
    return targets


async def _credential(target: Target) -> str | None:
    secret = target.secret
    if secret is None or secret.secret_ref is None:
        return None
    try:
        return await get_secret_store().get_secret(
            TenantId(target.organization_id),
            SecretRef(secret.secret_ref),
            expected_purpose=provider_secret_purpose(
                secret.provider, secret.credential_kind
            ),
        )
    except Exception:
        # Fail closed: the server is not read without the credential it was listed with.
        raise ScrapeError("credential_unavailable") from None


async def record_sample(
    session: AsyncSession,
    target: Target,
    hour: datetime,
    sample: Sample | None,
    error: str | None,
) -> None:
    """One sample (or one failure) added to its hour, in one upsert."""
    table = InferenceMetricsHourly.__table__
    values: dict[str, Any] = {
        "organization_id": target.organization_id,
        "deployment_id": target.deployment_id,
        "hour": hour,
        "server": target.server,
    }
    if sample is None:
        values |= {"errors": 1, "last_error": error}
        statement = insert(InferenceMetricsHourly).values(**values)
        statement = statement.on_conflict_do_update(
            constraint="pk_inference_metrics_hourly",
            set_={
                "errors": table.c.errors + 1,
                "last_error": error,
                "updated_at": text("now()"),
            },
        )
    else:
        running, waiting = sample.running or 0, sample.waiting or 0
        values |= {
            "samples": 1,
            "busy_samples": int(running > 0),
            "queued_samples": int(waiting > 0),
            "loaded_samples": int(bool(sample.loaded)),
            "running_sum": running,
            "waiting_sum": waiting,
            "running_max": sample.running,
            "waiting_max": sample.waiting,
            "cache_usage_sum": sample.cache_usage or 0.0,
            "cache_usage_max": sample.cache_usage,
            "vram_bytes_max": sample.vram_bytes,
            "last_error": None,
        }
        excluded = insert(InferenceMetricsHourly).excluded
        statement = insert(InferenceMetricsHourly).values(**values)
        statement = statement.on_conflict_do_update(
            constraint="pk_inference_metrics_hourly",
            set_={
                **{
                    name: table.c[name] + excluded[name]
                    for name in (
                        "samples",
                        "busy_samples",
                        "queued_samples",
                        "loaded_samples",
                        "running_sum",
                        "waiting_sum",
                        "cache_usage_sum",
                    )
                },
                **{
                    name: text(
                        f"GREATEST(inference_metrics_hourly.{name}, excluded.{name})"
                    )
                    for name in (
                        "running_max",
                        "waiting_max",
                        "cache_usage_max",
                        "vram_bytes_max",
                    )
                },
                "last_error": None,
                "updated_at": text("now()"),
            },
        )
    await session.execute(statement)


async def scrape_inference_metrics(
    session_factory: Callable[[], Any],
    http_client: httpx.AsyncClient,
    *,
    now: datetime,
    interval_seconds: int,
) -> int:
    """One pass: read every listed server, at most 8 at once, within the pass deadline.

    No transaction is open during an HTTP call. Returns the targets sampled.
    """
    async with session_factory() as session:
        targets = await _targets(session)
    if not targets:
        return 0
    hour = now.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
    gate = asyncio.Semaphore(MAX_IN_FLIGHT)
    results: list[tuple[Target, Sample | None, str | None]] = []

    async def one(target: Target) -> None:
        async with gate:
            try:
                sample = await read_sample(
                    http_client,
                    target.server,
                    target.base_url,
                    target.upstream_model,
                    await _credential(target),
                )
            except ScrapeError as error:
                results.append((target, None, error.code))
                INFERENCE_SCRAPES_TOTAL.labels(
                    server=target.server, outcome="error"
                ).inc()
                return
            results.append((target, sample, None))
            INFERENCE_SCRAPES_TOTAL.labels(server=target.server, outcome="ok").inc()

    pending = [asyncio.ensure_future(one(target)) for target in targets]
    deadline = max(1, min(50, interval_seconds - 5))
    _, late = await asyncio.wait(pending, timeout=deadline)
    for task in late:
        task.cancel()
    finished = {id(target) for target, _, _ in results}
    for target in targets:
        if id(target) not in finished:
            INFERENCE_SCRAPES_TOTAL.labels(
                server=target.server, outcome="skipped"
            ).inc()
    async with session_factory() as session:
        for target, sample, error in results:
            await record_sample(session, target, hour, sample, error)
        key = tuple_(
            InferenceMetricsHourly.organization_id,
            InferenceMetricsHourly.deployment_id,
            InferenceMetricsHourly.hour,
        )
        await session.execute(
            delete(InferenceMetricsHourly).where(
                key.in_(
                    select(
                        InferenceMetricsHourly.organization_id,
                        InferenceMetricsHourly.deployment_id,
                        InferenceMetricsHourly.hour,
                    )
                    .where(
                        InferenceMetricsHourly.hour
                        < now - timedelta(days=RETENTION_DAYS)
                    )
                    .limit(DELETE_BATCH)
                )
            )
        )
        await session.commit()
    return len(results)
