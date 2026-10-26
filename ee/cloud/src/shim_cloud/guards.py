"""The cloud application behind the enterprise guards; uvicorn calls it with --factory."""

from __future__ import annotations

from typing import TYPE_CHECKING

from shim_enterprise.guards import start_guards

if TYPE_CHECKING:
    from fastapi import FastAPI


def guarded_app() -> FastAPI:
    start_guards()
    from shim_cloud.application import create_cloud_app

    return create_cloud_app()
