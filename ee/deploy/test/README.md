# Isolated chart acceptance

Run from the backend repository after building the final enterprise runtime and
an OIDC dashboard runtime. The dashboard can come from its private repository;
this harness and its manually dispatched CI workflow never check out that repo
or request its token.

```sh
uv run --locked --all-packages python ee/deploy/test/run.py \
  --gateway-image shim-enterprise:phase01 \
  --dashboard-image shim-dashboard:phase01
```

Requires Docker, kind 0.33.0, Helm 4.2.4, kubectl compatible with Kubernetes 1.37,
and the locked Python environment. Images are pulled before isolation. Allow
roughly 8 GB of free Docker storage. Use immutable digest references for supplied
images in CI. `--chart` selects a chart checkout; `--cluster` names a new disposable
cluster. Existing clusters are refused, never replaced implicitly. `--keep`
retains the failed/successful cluster for diagnosis; the default destroys only
the cluster/network created by the harness.

The harness installs the real chart with its gateway, dashboard, four workers,
migration job, and disposable PostgreSQL/Redis. Real Keycloak and Vault run beside
two small native OpenAI/Anthropic HTTP fixtures. A generated two-day CA signs the
IdP and fixture certificates. Vault and the dashboard are exposed through the
fixture's TLS proxy. The gateway uses its actual custom-CA configuration, OIDC
code/PKCE callback, Vault secret storage, registry routing, usage, and audit APIs.
It checks all six chart deployments' readiness and creates/revokes a workload key.
The login client follows Keycloak's real HTML form and secure session cookies;
it does not replace browser accessibility/UI tests.

A Docker `--internal` network encloses the kind node. A positive public-IP
connectivity control runs before isolation, then two public-IP probes must fail
from the gateway pod while internal calls succeed. This verifies an external
network boundary. It does **not** claim kind's default CNI enforces the chart's
NetworkPolicy, nor prove a particular customer's firewall configuration.

The production licence verifier remains enabled. A separately tagged and labelled
**test-only** image overlays only a newly generated public key. Its short-lived
licence is asserted invalid against the original image's packaged public key;
the original image identity is checked unchanged. Neither private signing keys
nor test public keys enter source control. Never publish or release the test-only
image. This is not an alternate customer licence mechanism.

Temporary material is private to the local OS user and includes disposable test
secrets/kubeconfig; do not upload it wholesale. Only `result.json` and
`resources.txt` are CI artifacts. After review, use `trash` on the printed
temporary directory. Remove the printed test-only Docker image with Docker's
image removal command when no longer needed. Real Entra, customer TLS PKI, and
operator restore/rollback remain separate acceptance scenarios.
