# Contributing to shim

## What is open, and what is not

Everything outside `ee/` is Apache-2.0 and open to contributions. The gateway
itself, the privacy detectors, the provider transports, the tests and the
documentation all live there.

Files under `ee/` are source-available under the Elastic License 2.0. They are
public so that a customer can read what runs in their own deployment, but they
are not open to outside contributions and a pull request touching `ee/` will be
declined. Taking an outside contribution into a commercially licensed layer
would need a rights assignment we deliberately do not ask for.

There is no CLA. Apache-2.0 already grants the patent licence a project this
size needs, and a CLA would add friction without adding protection.

## Sign your commits off

Every commit carries a `Signed-off-by` line, the
[Developer Certificate of Origin](https://developercertificate.org/). Git writes
it for you:

```console
git commit --signoff
```

It states that you wrote the change, or have the right to submit it. Commit
signing with a key is required of maintainers only.

## Getting set up

shim needs Python 3.13 exactly and uv 0.12.5 or newer.

```console
git clone https://github.com/GetSHIM/shim && cd shim
uv sync --locked --all-packages
```

## Verification

Run this before opening a pull request. Continuous integration runs the same
commands, plus the container builds.

```console
uv lock --check
uv sync --locked --all-packages
uv run --locked ruff format --check src ee/src tests ee/tests scripts ee/scripts ee/alembic
uv run --locked ruff check src ee/src tests ee/tests scripts ee/scripts ee/alembic
uv run --locked ty check
uv run --locked python -m pytest -q
uv run --locked --package shim-gateway python scripts/export_openapi.py --profile community --check
uv run --locked --package shim-enterprise python scripts/export_openapi.py --profile enterprise --check
```

The enterprise tests need PostgreSQL and a Redis with the search and JSON
modules. `docker compose up` brings both up.

Read [the developer guide](DEVELOPER_GUIDE.md) and
[the current architecture](docs/CURRENT_ARCHITECTURE.md) before you change a
public contract or a dependency that crosses the package boundary. Both are
enforced by tests under `tests/architecture`, so a boundary violation fails the
build rather than reaching review.

## The name

The name is `shim`, lowercase, everywhere including the start of a sentence. It
is a word, not an acronym. Environment variables such as `SHIM_API_KEY` and
headers such as `X-Shim-Tag` keep their own casing, and the licence files keep
the licensor's registered name.

## Where things go

- **A question, or an idea you want to talk through:** Discussions.
- **A bug or a piece of work:** Issues.
- **A security problem:** do not open an issue. Use
  [the security policy](https://github.com/GetSHIM/shim/security/policy), which
  routes to a private advisory.

## A note on the Cyber Resilience Act

The Cyber Resilience Act places its obligations on the manufacturer who puts a
product on the European market. It does not place them on a person who
contributes to someone else's open-source project. Contributing here does not
make you answerable for shim's compliance, and we are not asking you to take on
any part of it.

## Tests come with the change

New functionality arrives with tests for it in the same pull request, and a
bug fix arrives with a test that fails without the fix. This is the rule, not
a preference: a change that cannot be tested is a design question to raise in
the pull request rather than something to skip.
