# Supply chain

This page describes how a shim gateway image is built and published, how to
check an image before you run it, where provider keys live, and what these
controls do not cover. It applies to the community image
`ghcr.io/getshim/shim`. The enterprise image has its own release workflow,
`.github/workflows/enterprise-release.yml`.

## What these controls do not cover

Read this first.

- shim is a Python application. Python runs `.pth` import lines and
  `sitecustomize` before any shim code. A malicious dependency that ships a
  startup hook runs before shim can check anything. The guards below detect it
  and can refuse to serve traffic. They cannot undo what the hook did first.
- A provenance attestation proves which workflow signed an image. Someone who
  holds an admin token for this repository can change that workflow, and the
  image it then builds still carries a valid attestation. Rebuilding from the
  tag and comparing digests is the check that catches this case. shim's image
  builds are not reproducible today: the build sets no `SOURCE_DATE_EPOCH`, so
  rebuilding the same tag gives a different digest.
- shim has had no third-party penetration test and holds no SOC 2 or ISO 27001
  certification.
- Network egress control belongs at the network layer (Kubernetes
  `NetworkPolicy`, Cloud Run egress settings, a proxy). The egress guard inside
  the process is a second layer, not a replacement.

## How a release is built

| Step | What happens | Where |
| --- | --- | --- |
| Trigger | A pushed tag that starts with `v`. There is no manual dispatch and no workflow input. A merge to `main` publishes nothing. | `.github/workflows/release.yml` |
| Credentials | The workflow publishes and signs with its own short-lived `github.token` and the OIDC identity of the run. No personal access token is used to publish. | `release.yml` |
| Checkout | The tagged commit of `GetSHIM/shim`, with `persist-credentials: false`. | `release.yml` |
| Actions | Every `uses:` is pinned to a full commit SHA. A test fails when one is not. | `tests/architecture/` |
| Base image | `python:3.13-slim` and `uv` are pinned by digest. | `Dockerfile` |
| Dependencies | `uv sync --locked --no-dev --package shim-gateway`. The lockfile carries a hash for every package downloaded from PyPI. `pip` is removed from the runtime image. The process runs as the non-root user `shim`. | `Dockerfile`, `uv.lock` |
| Provider SDKs | Pinned to exact versions (`openai==2.53.0`, `anthropic==0.121.0`, `google-genai==2.16.0`). Dependabot does not update them; they move by a reviewed change. | `pyproject.toml`, `.github/dependabot.yml` |
| Build | `linux/amd64` and `linux/arm64`, with BuildKit provenance (`mode=max`) and an SBOM. | `release.yml` |
| Attestation | `actions/attest-build-provenance` signs a provenance statement for the image digest and pushes it to the registry. | `release.yml` |
| Startup-hook check | The image smoke steps run with `SHIM_STARTUP_GUARD=enforce` and `SHIM_EGRESS_GUARD=enforce`. An image that carries a Python startup hook outside the allowlist exits with code 78 and never answers `/health`. In pull-request CI the change fails. In a release the GitHub release is not created, but the image tags are already pushed (see "Tags" below). | `release.yml`, `test.yml` |
| Smoke | The image starts by digest and must answer `/health`. | `release.yml` |
| SBOM | An SPDX SBOM of the published digest. | `release.yml` |
| GitHub release | The SBOM and the provenance bundle are attached to the release. | `release.yml` |

Tags: `vX.Y.Z` publishes `ghcr.io/getshim/shim:X.Y.Z` and moves `latest`. A
tag with a suffix, such as `v0.4.5-rc.1`, publishes the version tag only.
`latest` moves when the image is pushed, before the smoke step runs. Install
by digest, not by `latest`.

## Verify an image

1. Resolve the digest of the version you want:

   ```
   docker buildx imagetools inspect ghcr.io/getshim/shim:0.4.5
   ```

2. Verify the attestation against this repository, its release workflow and
   the tag:

   ```
   gh attestation verify oci://ghcr.io/getshim/shim@sha256:<digest> \
     --repo GetSHIM/shim \
     --signer-workflow GetSHIM/shim/.github/workflows/release.yml \
     --source-ref refs/tags/v0.4.5
   ```

   `--repo` and `--signer-workflow` check who signed the image.
   `--source-ref` checks the tag the workflow ran on. None of them shows what
   the workflow checked out. In shim the two are the same by construction:
   `release.yml` takes no input and checks out the tagged commit of this
   repository. A release pipeline that takes its source as an input can sign
   an image built from somewhere else, and the signature stays valid.

3. Check the build provenance itself. It records the source repository and
   commit that BuildKit saw:

   ```
   docker buildx imagetools inspect ghcr.io/getshim/shim@sha256:<digest> \
     --format '{{json .Provenance}}'
   ```

   The source must be `https://github.com/GetSHIM/shim` at the commit of the
   tag you expect.

4. Run the image by the digest you verified:

   ```
   docker run --rm -p 8000:8000 -e SHIM_API_KEY=a-key-of-at-least-16-chars \
     ghcr.io/getshim/shim@sha256:<digest>
   ```

A failed verification means the image did not come from this repository's
release workflow. Report it through the advisory link in `SECURITY.md`.

## Where provider keys live

**Community.** A provider key comes from the `x-provider-key` header of the
request, or else from the provider's environment variable
(`docs/CURRENT_ARCHITECTURE.md`). Community has no
database, no Redis and no response cache, and keeps no request history. Its
usage events are local JSONL lines with counts, costs, timings and entity
counts, plus the tag, cost-center, task and trace values the caller sends in its
`X-Shim-*` and `traceparent` headers, as sent. No prompt or answer text is written.
Credential-bearing headers are removed before request metadata is recorded.

**Enterprise.** Provider keys are stored in a Fernet-encrypted store in
PostgreSQL, or are read from an external secret manager: GCP Secret Manager,
AWS Secrets Manager, Azure Key Vault or HashiCorp Vault
(`ee/src/shim_enterprise/secrets/`).

In both, a header-supplied provider credential is scoped to one invocation. Report a key that appears in a log, an error body or a
trace as a vulnerability (`SECURITY.md`).

## Process guards

`shim serve` installs both guards after it reads its settings and before the
server starts: the egress guard first, so that a thread a startup hook started is
covered while the scan runs, then the startup scan. `create_community_app` installs
neither, so tests and applications that embed the gateway get no hook they cannot
remove.

**Startup-hook guard** (`SHIM_STARTUP_GUARD`: `off`, `report`, `enforce`;
default `report`; `src/shim/core/startup_guard.py`). It reads every `.pth` file in
the site-packages directories (and the user site, when Python enables it). A file
with a line that starts with `import` is a hook, by the rule in CPython's
`site.py`. The modules such a line imports, by `import`, `from … import` or a
literal `__import__("…")`, are checked too, as are `sitecustomize` and
`usercustomize` wherever Python finds them. Each one is compared with an allowlist
of path and sha256: the four files the published image ships on amd64 and arm64
(uv's `_virtualenv.pth` and `_virtualenv.py`, setuptools'
`distutils-precedence.pth` and `_distutils_hack/__init__.py`). Anything else is a
finding with its path, its kind (`pth_import`, `pth_target`, `sitecustomize`,
`usercustomize`) and its sha256. `report` logs each one as
`startup_hook_unexpected` and sets `shim_startup_hooks_unexpected` to their
number. `enforce` also stops the process with exit code 78 (`EX_CONFIG`) before it
serves traffic. The scan reads files only; it imports, runs and removes nothing.
Changing the allowlist is a reviewed change to that file, and so is a uv or
setuptools update that changes those four files.

A local Python can carry hooks of its own: conda's and Homebrew's Pythons each ship a
`sitecustomize.py`. `report` then logs it at every start, and `enforce` refuses to
start. For local development, set `SHIM_STARTUP_GUARD=off`, or build the environment
on uv's managed Python, which ships none (`uv python install 3.13`, then
`UV_PYTHON=$(uv python find --managed-python 3.13) uv sync`).

**Egress guard** (`SHIM_EGRESS_GUARD`: `off`, `report`, `enforce`; default
`report`; `src/shim/core/egress_guard.py`). A Python audit hook (PEP 578) checks
name lookups (`socket.getaddrinfo`, `gethostbyname`, `gethostbyname_ex`,
`gethostbyaddr`) and connections (`socket.connect`, `connect_ex`). A name may be
resolved when it is:

- the host of `OPENAI_BASE_URL` (default `api.openai.com`), `ANTHROPIC_BASE_URL`
  (default `api.anthropic.com`) and `GOOGLE_BASE_URL`;
- the host of `SHIM_AZURE_OPENAI_ENDPOINT` when set, and of
  `SHIM_AZURE_AUTHORITY_HOST` when Entra ID credentials are set;
- the host of `OTEL_EXPORTER_OTLP_ENDPOINT` and of `SENTRY_DSN` when set;
- `localhost`;
- an entry of `SHIM_EGRESS_ALLOW_HOSTS`: comma-separated, each an exact host or
  `*.` and a suffix, with no scheme, path or port.

A literal address is allowed unless it is cloud instance metadata
(`169.254.169.254`, `fd00:ec2::254`, `169.254.170.2`, and EKS Pod Identity's
`169.254.170.23` and `fd00:ec2::23`, also written as an IPv4-mapped IPv6 address) or another link-local address (`169.254.0.0/16`,
`fe80::/10`). A connection to a name is held to the name rule. `report` logs each
destination once as `egress_denied` (at most 256 destinations per process) and
counts every denial in `shim_egress_denied_total` by `kind` (`host`, `metadata`,
`link_local`) and `mode`. `enforce` also makes the call fail with
`PermissionError`, before any DNS query. A fault inside the guard is counted as
`kind="guard_error"` and never reaches the caller.

Before you turn on `enforce` behind a corporate proxy, list the proxy host in
`SHIM_EGRESS_ALLOW_HOSTS`; in `report` the missing entry only logs.

The PDF and image parsers run in spawned worker processes, which run Python's
startup hooks again. Under `enforce` those workers refuse every name lookup and
every network connection: they need none. Under `report` they record nothing,
because a worker writes no log.

What the egress guard does not cover: code that ran before the hook was
installed (a `.pth` runs first, so it can read files before shim starts), a
process forked or started before `shim serve` began, native code that opens
sockets without the audited Python calls, a process started with `subprocess`,
and a connection to a literal public IP address.

**Enterprise and cloud.** The enterprise and cloud images start the gateway
through `shim_enterprise.guards:guarded_app` and `shim_cloud.guards:guarded_app`,
which install both guards before the application is imported. Each worker's
`python -m` entry calls `start_guards` before its loop. The settings, the
`report` default and exit code 78 are the community ones. A name may also be
resolved when it is the host of:

- `DATABASE_URL`, `REDIS_URL`, `SUPABASE_URL` and `OIDC_ISSUER_URL`, and, once
  discovery has returned the configured issuer, the token, JWKS and userinfo
  endpoints it names;
- `VAULT_ADDR`, `AZURE_KEY_VAULT_URL` with `SECRET_BACKEND=azure_key_vault`, and
  `WORM_ARCHIVE_ENDPOINT_URL`;
- `SHIM_AZURE_AUTHORITY_HOST`, because any tenant can store Entra ID credentials;
  `api.chatgpt.com`, for OpenAI's compliance API; `api.resend.com` when
  `RESEND_API_KEY` is set;
- an entry of `MODEL_DEPLOYMENT_ALLOWED_ORIGINS`, `MODEL_DEPLOYMENT_INTERNAL_ORIGINS`
  or `ALERT_ALLOWED_ORIGINS`, or `*` followed by an entry of
  `MODEL_DEPLOYMENT_ALLOWED_ORIGIN_SUFFIXES`;
- the three AWS URL templates, where a `{region}` label stands for any region
  (`*.amazonaws.com` by default), and `*.amazonaws.com` itself with
  `SECRET_BACKEND=aws_secrets_manager` or the WORM archive on.

Metadata is reachable only where credentials come from it: with `SECRET_BACKEND`
set to `gcp_secret_manager`, `aws_secrets_manager` or `azure_key_vault`, with
`AWS_GATEWAY_IDENTITY` set to `container`, `imds` or `gcp_metadata`, or with the WORM
archive on. Those settings also list `metadata.google.internal`,
`oauth2.googleapis.com` and the hosts of `AWS_GCP_METADATA_URL`, `AWS_IMDS_URL` and
`AWS_CONTAINER_CREDENTIALS_FULL_URI`. Other link-local addresses stay refused.

The outbox, compliance and cloud workers deliver webhooks and alerts to tenants'
own public hosts. They skip the name rule and still refuse metadata and link-local
addresses. `python -m shim_cloud.migrate` runs the startup scan only, because
Alembic runs in a child process that an audit hook does not reach. Alembic started
directly, as the Helm and Compose migration jobs do, runs neither guard.

Tenants' model deployments need no entry: their base URLs must already match the
deployment origin lists above. A webhook or alert target does: the gateway resolves
its host when a tenant saves it, and under `enforce` refuses an unlisted host with
422, as for a host that does not resolve. The outbox then delivers without the name
rule. Before you turn on `enforce` in an enterprise install, list any proxy and the
webhook hosts tenants may use in `SHIM_EGRESS_ALLOW_HOSTS`; `report` logs each
missing entry. GCP Secret Manager's
client speaks gRPC from native code, so its traffic is outside the guard; the token
it sends is fetched in Python and is checked.

The guards add about 90 ns to each audited event, about 0.1 ms on a 32 KB
request, below what the latency benchmark can measure.

## Dependency updates

Dependabot opens weekly pull requests for Python packages, actions and base
images. Minor and patch Python updates come as one group; a major update comes on
its own. The provider SDKs are not updated by Dependabot. Every update passes the full CI gate, including the image smoke
with the startup-hook guard in `enforce`. Dependabot has no cooldown period
configured today.
