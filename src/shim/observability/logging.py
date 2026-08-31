"""Process-wide structured logging configuration."""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

from pythonjsonlogger.json import JsonFormatter
import sentry_sdk
from sentry_sdk.types import Event, Hint

_HANDLER_NAME = "shim-structured-stdout"
_SECRET_FIELD = re.compile(
    r"authorization|api[_-]?key|token|secret|password|cookie|credential|decrypted",
    re.IGNORECASE,
)


def configure_logging(log_level: str) -> None:
    root = logging.getLogger()
    root.setLevel(log_level.upper())
    if not any(handler.get_name() == _HANDLER_NAME for handler in root.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler.set_name(_HANDLER_NAME)
        handler.setFormatter(
            JsonFormatter(
                "%(asctime)s %(levelname)s %(name)s %(message)s",
                rename_fields={"levelname": "level", "asctime": "timestamp"},
            )
        )
        root.addHandler(handler)
    for logger_name in ("httpx", "sqlalchemy.engine", "uvicorn.access"):
        logging.getLogger(logger_name).setLevel(logging.WARNING)


def configure_error_reporting(
    *,
    sentry_dsn: str | None,
    environment: str,
) -> None:
    """Configure metadata-only error reporting when a DSN is present."""

    if not sentry_dsn:
        return
    sentry_sdk.init(
        dsn=sentry_dsn,
        send_default_pii=False,
        include_local_variables=False,
        before_send=_sanitize_error_event,
        traces_sample_rate=0.0,
        profiles_sample_rate=0.0,
        environment=environment,
    )


def _sanitize_error_event(
    event: Event,
    _hint: Hint,
) -> Event:
    request = event.get("request")
    if isinstance(request, dict):
        for field in ("cookies", "data", "env", "query_string", "url"):
            request.pop(field, None)
        headers = request.get("headers")
        request["headers"] = (
            _sanitize_mapping(headers) if isinstance(headers, dict) else {}
        )

    exception = event.get("exception")
    if isinstance(exception, dict):
        for item in exception.get("values", ()):
            if not isinstance(item, dict):
                continue
            item["value"] = "[redacted]"
            stacktrace = item.get("stacktrace")
            if not isinstance(stacktrace, dict):
                continue
            for frame in stacktrace.get("frames", ()):
                if isinstance(frame, dict):
                    frame.pop("vars", None)
    for field in ("breadcrumbs", "contexts", "extra", "logentry", "message", "user"):
        event.pop(field, None)
    return event


def _sanitize_mapping(value: dict[Any, Any]) -> dict[str, Any]:
    return {
        str(key): "[redacted]" if _SECRET_FIELD.search(str(key)) else "[omitted]"
        for key in value
    }
