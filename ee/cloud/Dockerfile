FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS builder

COPY --from=ghcr.io/astral-sh/uv:0.12.5@sha256:e85be844203885286c60ffad8a858d48afb6c5a5c237ca0e67f12e74b8f174b1 /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1 \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
COPY ee/pyproject.toml ee/LICENSE ee/NOTICE ./ee/
COPY ee/cloud/pyproject.toml ee/cloud/LICENSE ee/cloud/NOTICE ./ee/cloud/
COPY src ./src
COPY ee/src ./ee/src
COPY ee/cloud/src ./ee/cloud/src
RUN uv sync --locked --no-dev --package shim-cloud --no-editable

FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS runtime

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN python -m pip uninstall --yes pip \
    && addgroup --system shim \
    && adduser --system --ingroup shim shim

COPY --from=builder /app/.venv ./.venv
COPY ee/alembic.ini ./ee/alembic.ini
COPY ee/alembic ./ee/alembic
COPY ee/cloud/alembic.ini ./ee/cloud/alembic.ini
COPY ee/cloud/alembic ./ee/cloud/alembic

USER shim
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"

CMD ["uvicorn", "shim_cloud.application:create_cloud_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
