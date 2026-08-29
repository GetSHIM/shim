FROM python:3.14-slim@sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5 AS builder

COPY --from=ghcr.io/astral-sh/uv:0.12.5@sha256:e85be844203885286c60ffad8a858d48afb6c5a5c237ca0e67f12e74b8f174b1 /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
COPY ee/pyproject.toml ee/LICENSE ee/NOTICE ./ee/
COPY src ./src
COPY ee/src ./ee/src
RUN uv sync --locked --no-dev --all-packages --no-editable

FROM builder AS test

RUN uv sync --locked --all-packages --no-editable

FROM python:3.14-slim@sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5 AS runtime

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN addgroup --system shim \
    && adduser --system --ingroup shim shim

COPY --from=builder --chown=shim:shim /app/.venv ./.venv
COPY --chown=shim:shim ee/alembic.ini ./ee/alembic.ini
COPY --chown=shim:shim ee/alembic ./ee/alembic
COPY --chown=shim:shim ee/scripts ./ee/scripts

USER shim
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"

CMD ["uvicorn", "shim_enterprise.application:create_enterprise_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
