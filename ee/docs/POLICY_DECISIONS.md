# Gateway decision evidence

Gateway audit events include `policy_verdicts` for the checks actually evaluated.
Each verdict contains `schema_version`, `rule_id`, `rule_version`,
`policy_version`, `stage`, `outcome`, `reason_code`, and `effective_at` (UTC).
`effective_at` is the evaluation time, not a claim about when a configuration
first became effective. Configuration digests or the locked accounting policy
version identify the evaluated snapshot; rule version 1 identifies the shipped
check semantics. No policy document, prompt, response, credential, or raw error
message is included.

The event envelope binds all verdicts to the request, tenant, actor type and
API key or authenticated user. An API key identifies the key, including when
shared: it does not identify its owner as the person making the request.
Unrecognized credentials and policy-resolution failures without a verified
tenant remain sanitized authentication/error telemetry; they are never assigned
to a guessed tenant or user. HTTP/body validation before the gateway invocation
also remains outside tenant decision evidence.

| Rule | Evidence |
| --- | --- |
| `tenant.allowed_providers` | Provider passed or failed the tenant allowlist. |
| `tenant.zero_retention_request` | Required request flags/options passed or failed the gateway's check, or the check was not required. This does not attest to the provider's wider retention practices. |
| `gateway.model_catalog` | Model is supported by the catalog snapshot, or was rejected. Unsupported caller-supplied model text is omitted from rejected enterprise events. |
| `rate.requests`, `rate.tokens`, `rate.repeated_requests` | Configured burst/repeat checks passed, were unlimited, or denied admission. Repeated content does not establish an automatic retry. |
| `quota.requests_and_tokens` | Atomic request/token reservation passed or was rejected, using the policy loaded under the accounting lock. The combined limit is not attributed to a particular counter when the atomic check cannot distinguish it. |
| `privacy.input` | Scrubbing masked data, found no enabled entity, was disabled, blocked unsupported content, or failed closed. |
| `spend.provider_monthly` | Provider spending reservation passed, was unlimited, was rejected, or could not be evaluated. Invocation-scoped BYOK remains outside the stored-provider cap. |
| `gateway.admission` | Other admission validation failed or admission infrastructure was unavailable. |

`allow` means that individual check passed; it does not imply that the entire
request completed. `mask`, `deny`, `error`, and `skip` are distinct outcomes.
Later stages are absent when an earlier stage stopped execution. Terminal
lifecycle status remains separate from policy results and provider behavior.

## Durability and failures

Existing short quota, privacy, and spend transactions retain decision snapshots
in lifecycle metadata. Terminal settlement/refund builds the existing audit
completion/outbox event from those snapshots. Failures before a quota lifecycle
exists create an audit completion and committed outbox intent directly, without
usage charges or provider execution. The identity remains
`request:<request_id>:outbox:audit.completion`. Outbox redelivery uses the existing
tenant/request/event deduplication and hash-chain writer.

For pre-admission denials, audit mode `off` writes no audit intent. `best_effort`
attempts the transaction and emits a content-free error log if it cannot commit,
preserving the original rejection. `strict` returns `AUDIT_INTENT_FAILED` (503)
when required evidence cannot commit; no provider attempt occurs.

Admitted accounting retains its existing atomic audit behavior: a required
preflight failure prevents provider execution, and an audit completion failure
rolls back settlement for reconciliation. Accounting truth is never discarded to
make evidence delivery appear successful. A strict failure while finalizing a
denial is surfaced instead of swallowed; best-effort failure retains recovery
and a sanitized error log. Database unavailability cannot guarantee new durable
evidence, and best-effort mode must not be described as lossless.

The audit worker and existing chain verifier remain the inspection path.
Decision evidence does not create a configurable policy engine, a
content archive, signatures, or an independent trust anchor.

Verification: `uv run --locked python -m pytest -q
 ee/tests/gateway/pipeline/test_decisions.py` covers real quota/spend transactions,
pre-admission denials, masking and privacy rejection, audit failure modes,
redelivery, and chain verification. The repository-wide gate is in `AGENTS.md`.
