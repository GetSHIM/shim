"""The community startup-hook and egress guards for the enterprise gateway and workers.

The gateway starts through `guarded_app`, which installs the guards before the
application's own imports; each worker's `__main__` calls `start_guards` before its
loop. Tests call the factories and `main()` directly, so they never install a hook.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from shim.cli import start_guards as start_community_guards
from shim.core.egress_guard import Kind
from shim.observability.logging import configure_logging
from shim_enterprise.core.config import Settings, settings

if TYPE_CHECKING:
    from fastapi import FastAPI

# Backends and identities whose credentials come from a cloud metadata service.
METADATA_BACKENDS = frozenset(
    {"gcp_secret_manager", "aws_secrets_manager", "azure_key_vault"}
)
METADATA_IDENTITIES = frozenset({"container", "imds", "gcp_metadata"})


def allowed_hosts(config: Settings) -> frozenset[str]:
    """The hosts the enterprise processes reach beyond the community gateway's own."""

    urls = [
        config.DATABASE_URL,
        str(config.REDIS_URL),
        config.SUPABASE_URL,
        config.OIDC_ISSUER_URL,
        config.VAULT_ADDR,
        # Any tenant may store Entra credentials, whatever the gateway's own are.
        config.SHIM_AZURE_AUTHORITY_HOST,
        config.WORM_ARCHIVE_ENDPOINT_URL,
        "https://api.resend.com" if config.RESEND_API_KEY else None,
        "https://api.chatgpt.com",
        *config.MODEL_DEPLOYMENT_ALLOWED_ORIGINS,
        *config.MODEL_DEPLOYMENT_INTERNAL_ORIGINS,
        *config.ALERT_ALLOWED_ORIGINS,
    ]
    if config.SECRET_BACKEND == "azure_key_vault":
        urls.append(os.getenv("AZURE_KEY_VAULT_URL"))
    if needs_metadata(config):
        urls += [
            "http://metadata.google.internal",
            # A service-account key file refreshes its token here, not at metadata.
            "https://oauth2.googleapis.com",
            config.AWS_GCP_METADATA_URL,
            config.AWS_IMDS_URL,
            os.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"),
        ]
    hosts = {urlsplit(url).hostname for url in urls if url}
    # A `{region}` label stands for every region: the rest of the name is the suffix.
    for template in (
        config.AWS_BEDROCK_RUNTIME_URL_TEMPLATE,
        config.AWS_BEDROCK_CONTROL_URL_TEMPLATE,
        config.AWS_STS_URL_TEMPLATE,
    ):
        host = urlsplit(template).hostname or ""
        hosts.add("*" + host.split("{region}", 1)[1] if "{region}" in host else host)
    if config.SECRET_BACKEND == "aws_secrets_manager" or config.WORM_ARCHIVE_ENABLED:
        hosts.add("*.amazonaws.com")
    hosts.update(
        "*" + suffix for suffix in config.MODEL_DEPLOYMENT_ALLOWED_ORIGIN_SUFFIXES
    )
    return frozenset(host.rstrip(".") for host in hosts if host)


def needs_metadata(config: Settings) -> bool:
    return (
        config.SECRET_BACKEND in METADATA_BACKENDS
        or config.AWS_GATEWAY_IDENTITY in METADATA_IDENTITIES
        or config.WORM_ARCHIVE_ENABLED
    )


def start_guards(*, check_names: bool = True, egress: bool = True) -> None:
    """Both guards, configured from the enterprise settings; exits 78 as `shim serve` does.

    `check_names=False` is for a process that delivers to tenants' own public hosts:
    it still refuses metadata and link-local addresses. `egress=False` runs the
    startup scan alone, for a process whose network work happens in a child.
    """

    configure_logging(settings.LOG_LEVEL)
    allow_kinds: set[Kind] = set()
    if not check_names:
        allow_kinds.add("host")
    if needs_metadata(settings):
        allow_kinds.add("metadata")
    start_community_guards(
        settings
        if egress
        else settings.model_copy(update={"SHIM_EGRESS_GUARD": "off"}),
        allowed_hosts(settings),
        allow_kinds=allow_kinds,
    )


def guarded_app() -> FastAPI:
    """The enterprise application, behind the guards; uvicorn calls it with --factory."""

    start_guards()
    from shim_enterprise.application import create_enterprise_app

    return create_enterprise_app()
