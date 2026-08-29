# shim

shim is a provider-native AI trust-boundary gateway. It applies authentication,
privacy, admission, usage, and error-sanitization policy without translating
OpenAI, Anthropic, or Gemini payloads into a shared wire format.

The backend is one package-modular monorepo with two products:

```text
src/shim                              ee/src/shim_enterprise
community gateway  <----------------  enterprise composition
no enterprise imports                 tenancy, billing, audit, workers
```

The `shim-gateway` distribution installs the `shim` package. The
`shim-enterprise` distribution installs `shim_enterprise` and depends on the
exact same version of `shim-gateway`.

## Community quick start

Requires Python 3.13 and uv 0.12.x (0.12.5 or newer).

```bash
cp .env.example .env
uv sync --locked --package shim-gateway
uv run --locked --package shim-gateway shim serve
```

The default bind is `127.0.0.1:8000`. Set a `SHIM_API_KEY` of at least 16
characters before binding to a non-loopback address:

```bash
uv run --locked --package shim-gateway shim serve --host 0.0.0.0 --port 8000
```

Provider credentials may be configured as `OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, or `GOOGLE_API_KEY`, or supplied per request with
`x-provider-key`. The gateway key authenticates the caller; it is not forwarded
to a provider.

Community mode needs no PostgreSQL, Redis, Supabase, enterprise settings, or
workers. Its rate, circuit, privacy-continuation, and usage state is bounded and
process-local.

The root `Dockerfile` builds the same community-only runtime:

```bash
docker build -t shim-community .
docker run --rm -p 8000:8000 -e SHIM_API_KEY=replace-with-a-long-key shim-community
```

## Enterprise quick start

Enterprise composes the community gateway with tenant authentication, durable
accounting, managed secrets, audit, compliance, and workers. Copy and complete
the enterprise environment before startup:

```bash
cp ee/.env.example ee/.env
docker compose up --build
```

Canonical source commands are:

```bash
uv sync --locked --all-packages
uv run --locked --package shim-enterprise alembic -c ee/alembic.ini upgrade head
uv run --locked --package shim-enterprise uvicorn \
  shim_enterprise.application:create_enterprise_app --factory
```

Workers run as `python -m shim_enterprise.workers.outbox`,
`reconciliation`, `compliance`, and `ai_act`.

## API profiles

Community exposes provider-native inference routes, model discovery,
`POST /v1/scan`, `/health`, and `/metrics`. Enterprise exposes the same provider
contracts plus tenant management, durable scan usage, shared results,
subscriptions, compliance, and AI Act controls.

The checked-in contracts are:

- `openapi/community.json`
- `ee/openapi/enterprise.json`

OpenAI and Anthropic SDK compatibility is pinned to `openai==2.53.0` and
`anthropic==0.121.0`. Outbound SDK retries are disabled so one admitted request
causes at most one billable provider attempt. Use `/v1/models` to inspect the
models admitted by the checked-in price catalog.

## Verification

```bash
uv lock --check
uv sync --locked --all-packages
uv run --locked ruff format --check src ee/src tests ee/tests scripts ee/scripts ee/alembic
uv run --locked ruff check src ee/src tests ee/tests scripts ee/scripts ee/alembic
uv run --locked ty check
uv run --locked python -m pytest -q
uv run --locked --package shim-gateway python scripts/export_openapi.py --profile community --check
uv run --locked --package shim-enterprise python scripts/export_openapi.py --profile enterprise --check
```

See [the developer guide](DEVELOPER_GUIDE.md),
[current architecture](docs/CURRENT_ARCHITECTURE.md), and
[target architecture](docs/TARGET_ARCHITECTURE.md) before changing a public
contract or a cross-package dependency.

## Licensing

Files outside `ee/` are licensed under the Apache License 2.0 in
[`LICENSE`](LICENSE), with scope recorded in [`NOTICE`](NOTICE). Files under
`ee/` are source-available under the Elastic License 2.0 in
[`ee/LICENSE`](ee/LICENSE), with the licensor named in
[`ee/NOTICE`](ee/NOTICE). `shim-enterprise` depends on the separately licensed
`shim-gateway` distribution.

No CLA, runtime licence check, or enterprise bootstrap validator is implied by
this split. Add one only when an approved contribution or commercial policy
requires it.
