# Model deployments

Workspace owners and admins register models at **Gateway → Model deployments**
or `/api/v1/management/model-deployments`. Create a stored provider credential
first. The registry stores its tenant-scoped identifier, never credential text.
A deployment has a stable UUID, gateway alias, upstream model, protocol, base
URL, timeout, internal/external classification, owner and declared version.
Updates and health checks produce management audit events.

Set `MODEL_DEPLOYMENT_REQUIRED=true` for registry-only inference. With `false`,
registered aliases override public-catalog routing. Disabled aliases remain
denied. Gateway-key model allowlists use tenant aliases; unknown aliases cannot
be assigned. Restrict each key to the models its workload needs. Registry
checks cover requests passing through shim, not direct access to other servers.

The platform operator sets `MODEL_DEPLOYMENT_ALLOWED_ORIGINS` to a JSON list of
exact scheme/host/port origins, for example `["https://models.internal:8443"]`.
API users cannot expand this policy. URL credentials, queries, fragments,
metadata addresses and redirects are rejected. Internal HTTP origins require
explicit approval; use HTTPS in production. Add private certificate authorities
with `MODEL_DEPLOYMENT_CA_BUNDLE`; certificate verification stays enabled.
Enforce DNS and outbound network policy at the deployment boundary as well.

For OpenAI-compatible deployments, use the API base including `/v1`; for
Anthropic use the server root. shim uses its existing native transports, masks
configured sensitive content before forwarding, and makes one provider attempt.
There is no retry or failover. A five-second model-list health probe records
only HTTP success/failure and never reads an unbounded response body. Health is
an observation, not a request-routing or version-verification guarantee.

The declared version/hash/digest is operator supplied and included in the
registry policy evidence. Pin the actual serving image and model revision at
the model server; shim does not independently attest which weights it serves.

Public catalog prices apply to recognized upstream model names. Custom models
are explicitly unpriced: ledger arithmetic uses a zero placeholder with
`pricing_resolution=unknown`, and usage reports carry completeness counters.
A monetary provider limit rejects unpriced inference instead of treating it as
free. Token and request quotas still apply.

## Verified compatibility

`uv run --locked python -m pytest -q ee/tests/tenants/test_deployments.py`
uses the actual provider SDK over a mock HTTP transport, two distinct endpoint
origins and PostgreSQL accounting. It verifies OpenAI Chat Completions and
Responses JSON/SSE, upstream model selection, tenant-scoped credentials,
privacy, one-attempt errors, isolated endpoint circuits, model restrictions and
unpriced spending limits. Health tests exercise the bounded model-list probe.

These checks establish shim's wire behavior. They do not certify every vLLM,
NIM, TGI or Ollama version. Run the same request families against each selected
serving version before enabling it; unsupported protocol capabilities return
native errors rather than an emulated result.
