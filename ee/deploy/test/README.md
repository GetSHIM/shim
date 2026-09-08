# Isolated chart acceptance

Run from the backend repository after building the final enterprise runtime and
an OIDC dashboard runtime. The dashboard can come from its private repository;
this harness and its manually dispatched CI workflow never check out that repo
or request a source checkout token. For a private GHCR dashboard image, explicitly
configure repository secret `ON_PREM_DASHBOARD_GHCR_TOKEN` with read access only
to that package and repository variable `ON_PREM_DASHBOARD_GHCR_USER` with its
service-account username. The workflow logs in only to GHCR for image pulling;
public images need no credential. The token must not have source write/admin
permissions. Local runs use the operator's existing Docker registry login.

```sh
uv run --locked --all-packages python ee/deploy/test/run.py \
  --gateway-image shim-enterprise:local \
  --dashboard-image shim-dashboard:local
```

Requires Docker, kind 0.33.0, Helm 4.2.4, kubectl compatible with Kubernetes 1.37,
and the locked Python environment. Images are pulled before isolation. Allow
roughly 8 GB of free Docker storage. Use immutable digest references for supplied
images in CI. `--chart` selects a chart checkout; `--cluster` names a new disposable
cluster. Existing clusters are refused, never replaced implicitly. `--keep`
retains the failed/successful cluster for diagnosis; the default destroys only
the named disposable cluster/network. `--reuse-empty-cluster` resumes a failed
image preload and refuses a cluster with application deployments, StatefulSets,
or Jobs. It is only for a cluster created by this harness before isolation.

The harness installs the real chart with its gateway, dashboard, four workers,
migration job, and disposable PostgreSQL/Redis. Real Keycloak and Vault run beside
two small native OpenAI/Anthropic HTTP fixtures. A generated two-day CA signs the
IdP and fixture certificates. Vault and the dashboard are exposed through the
fixture's TLS proxy. The gateway uses its actual custom-CA configuration, OIDC
code/PKCE callback, Vault secret storage, registry routing, usage, and audit APIs.
It checks all six chart deployments' readiness and creates/revokes a workload key.
The login client follows Keycloak's real HTML form and secure session cookies;
it does not replace browser accessibility/UI tests.

The disposable kind node has explicit IPv4/IPv6 OUTPUT and FORWARD firewall
chains. Only established traffic, loopback, and the node/pod/service CIDRs pass;
other destinations are rejected. CoreDNS upstream forwarding is removed.
A positive node public-IP connectivity control runs before isolation, then two
public-IP probes must fail from the gateway pod while internal calls succeed.
This verifies a real external network boundary. It does **not** claim kind's
default CNI enforces the chart's NetworkPolicy, nor prove a customer's firewall.
Docker `--internal` is deliberately avoided: it suppresses kind's published
control-plane API port. Static HTML/CSS/JS/font fetches record the declared asset
hosts separately; this evidence is not JavaScript/browser execution.

The production licence verifier remains enabled. A separately tagged and labelled
**test-only** image overlays only a newly generated public key. Its short-lived
licence is asserted invalid against the original image's packaged public key;
the original image identity is checked unchanged. Neither private signing keys
nor test public keys enter source control. Never publish or release the test-only
image. This is not an alternate customer licence mechanism.

Temporary material is private to the local OS user and includes disposable test
secrets/kubeconfig; do not upload it wholesale. Only `result.json`, `asset-audit.json`, and
`resources.txt` are CI artifacts. After review, use `trash` on the printed
temporary directory. Remove the printed test-only Docker image with Docker's
image removal command when no longer needed. Real Entra, customer TLS PKI, and
operator restore/rollback remain separate acceptance scenarios.
