# Signed releases and offline bundles

Enterprise tags are `enterprise-v<version>` and dashboard tags are
`dashboard-v<version>`. These publish artifacts only; they do not match the
production `v<major>.<minor>.<patch>` deployment trigger. Each repository builds
its own image with its own GitHub package token. The dashboard repository and
its packages remain private. Give the release operator explicit read access;
no public workflow checks out the dashboard repository.

The workflows deliver one archive per `linux/amd64` and `linux/arm64` platform:
image archive, immutable source reference, component version, commit, SPDX
SBOM, BuildKit provenance, public key, signed checksums. They also sign the
registry image digest. Backend **0.1.3** and dashboard **0.1.0** are separate
component versions; a bundle ID such as `example-release-1` identifies their
combination. Publishing requires tag versions to match package metadata.
Workflows are not proof that an unpublished image has been built or tested.

## Trust and release keys

Use cosign **3.1.3**. Provision `RELEASE_COSIGN_PRIVATE_KEY` (encrypted PEM) and
`RELEASE_COSIGN_PASSWORD` in each repository's release secrets. Restrict tag
creation and changes to release workflows using repository rules. Release
signing authorization is separate from production deployment authorization.

Distribute the public key and its SHA-256 file fingerprint over an authenticated
channel before delivery. The operator maintains a local approved key file; a
public key delivered beside artifacts is informational, never a new trust root.
A release signer can approve artifacts, so protect that key accordingly.

This scheme uses explicit keys, without Fulcio identity, online Rekor lookup,
or timestamp-based trust. `--use-signing-config=false --tlog-upload=false`
disables online signing services in this pinned cosign version. Verification
uses `--insecure-ignore-tlog` intentionally: the trusted local key and signature
remain mandatory. No transparency or signing-time guarantee is claimed.

Before rotation, authenticate the new key fingerprint through the same operator
channel, document its first approved release, and retain the previous key only
for approved rollback releases. After compromise, revoke the old key in operator
policy and reissue affected deliveries; do not accept whichever key accompanies
a bundle. Pin the expected bundle ID to avoid silently accepting an older valid
release. The current offline startup licence key and release key are independent.

## Verify a component delivery without internet

After extracting the delivery into a fresh staging directory, use the approved
key, not `release.pub` from the delivery:

```sh
cosign verify-blob --key /etc/shim/trust/release.pub --insecure-ignore-tlog \
  --bundle SHA256SUMS.sigstore.json SHA256SUMS
sha256sum --check SHA256SUMS
```

Both commands must succeed before reading metadata as trusted or importing the
image. Check `image.json` for the approved component version and platform.
The signed checksums bind the archive, SBOM and provenance to that exact source
reference. BuildKit provenance is covered by the delivery signature. Its builder and source
claims are evidence from the authorized release workflow, not a separate
keyless identity attestation.
On macOS the equivalent checksum command is `shasum -a 256 --check SHA256SUMS`.

## Assemble a complete installation bundle

Use Python 3.13, Docker 28+ and cosign 3.1.3 on a connected release workstation.
The assembler is `ee/scripts/offline_bundle.py`, provisioned from reviewed source.
Verify component deliveries first. Resolve images to immutable references; use
only reviewed releases. Package the Helm chart with `helm package` before adding
it to the bundle. Its dependencies must be vendored; no dependency update is run
at install time.

Create a JSON specification beside the local files (replace every placeholder):

```json
{
  "bundle_id": "example-release-1",
  "platform": "linux/amd64",
  "images": [
    {"name": "backend", "version": "0.1.3", "source": "ghcr.io/getshim/shim-enterprise@sha256:<64-hex-digest>"},
    {"name": "dashboard", "version": "0.1.0", "source": "ghcr.io/getshim/shim-dashboard@sha256:<64-hex-digest>"}
  ],
  "files": ["shim-enterprise-0.1.0.tgz", "OFFLINE_RELEASES.md", "OPERATIONS.md", "backend.spdx.json", "dashboard.spdx.json", "backend.provenance.json", "dashboard.provenance.json"]
}
```

Also list **every** additional runtime image required by the selected topology:
PostgreSQL, Redis, internal IdP, Vault, internal model server, and any test or
migration image distinct from the backend. Services supplied by the customer
must instead be explicitly recorded in the operator inventory with their local
endpoints. Include their SBOMs, provenance, licences, installation instructions,
CA material and chart dependencies in `files`. No secret credentials belong in
the bundle. Backend/dashboard licences and notices must accompany delivery;
keep Apache-2.0 and Elastic-2.0 materials distinguishable. Include approved
Python/cosign/Helm/Docker installation media if the isolated workstation does not
already have them. Provision the verifier and trusted key independently.

The explicit inventory is a release-operator responsibility: the assembler does
not discover hidden dependencies or certify that the inventory is complete.
It refuses tag-only image references and existing output directories.

```sh
python ee/scripts/offline_bundle.py create --spec bundle-spec.json \
  --directory example-release-1 --key /secure/release.key
```

Transfer the resulting directory. Its signed manifest contains file SHA-256s,
source registry digests, archive-derived configuration digests, versions and
platform. Manifest schema 2 replaces the pre-release schema 1 `image_id` field;
rebuild older bundles rather than trusting a source daemon's image ID.
No image download occurs during verification or import:

```sh
python /opt/shim/offline_bundle.py verify --directory example-release-1 \
  --key /etc/shim/trust/release.pub --expected-id example-release-1
python /opt/shim/offline_bundle.py import --directory example-release-1 \
  --key /etc/shim/trust/release.pub --expected-id example-release-1
```

Import rechecks **all** files before the first Docker load. Use a staging directory
writable only by the operator and do not modify it during verification/import.
Import uses the ID actually returned by Docker, re-exports that object to a
temporary archive, and checks its configuration digest and platform against the
original. The configuration digest includes root filesystem layer IDs. Keep
enough temporary disk space for one image archive. Classic Docker and containerd
can use different local identities, including a newly synthesized manifest ID.
Docker save/load does **not** promise to retain registry RepoDigests; neither the
source image ID nor a config digest is a portable lookup reference. To seed an
internal registry, tag the verified ID printed by import, push it, record the new
registry digest, and configure Helm with that internal immutable reference.
Preserve the original signed manifest and import output as mapping evidence.
For example:

```sh
docker tag sha256:<verified-loaded-id> registry.internal/shim/backend:0.1.3
docker push registry.internal/shim/backend:0.1.3
# Record the digest returned by push; use registry.internal/shim/backend@sha256:...
```

Install the local chart with `imagePullPolicy: IfNotPresent` and internal digest
references. Configure local PostgreSQL/Redis, OIDC, Vault, model origins and TLS
using the chart's operator instructions. No public service may remain mandatory.
Use the backend image for migrations; back up PostgreSQL before upgrading.
Roll back only to a schema-compatible image; never downgrade the production
schema. Retain the previous verified bundle and internal digest inventory for
recovery. A clean recovery also needs database backups and separately protected
operator secrets; the release bundle contains neither.

## Evidence and remaining acceptance

`uv run --locked python -m pytest -q ee/tests/scripts/test_offline_bundle.py`
uses real local cosign keys and rejects archive tampering, manifest tampering,
an unexpected signer, wrong bundle ID, extra files and symlinks. HTTP(S) requests
are directed to a refused local proxy; Docker is replaced with a small archive
fixture. The existing `ee/tests/core/test_license.py` covers missing, invalid,
valid and expiry/grace boundaries. Capacity reporting is explicitly deferred;
current licence terms and startup verification are unchanged.

These checks are not the full air-gap rehearsal. Before declaring offline
readiness, an independent operator must use a clean environment with internet
egress blocked, verify and import the full inventory, install, log in through
the internal IdP, call an internal model, inspect usage/audit records, and restart
services. Record platform, bundle ID, internal digests, exact commands and results.
Real customer TLS/IdP, offline tool provisioning, backup/restore and schema-safe
upgrade/rollback remain deployment acceptance checks.

BuildKit provenance extraction follows the [Docker CLI reference](https://docs.docker.com/reference/cli/docker/buildx/imagetools/inspect/).
