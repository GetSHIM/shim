# Security policy

## Supported versions

Only the latest released version receives security fixes. Every 0.x release is
alpha, and an interface can change between releases.

The enterprise layer under `ee/` is covered by this policy as well. It is
source-available under the Elastic License 2.0 rather than open source, but a
vulnerability in it is reported the same way and fixed on the same timeline.

## Reporting a vulnerability

Report a suspected vulnerability through a private
[GitHub Security Advisory](https://github.com/GetSHIM/shim/security/advisories/new)
for this repository. Do not put exploit details in a public issue.

Please include the affected version, how it was deployed (container or source),
which provider path was involved, the steps to reproduce, the impact you see,
and any relevant logs with sensitive values removed. Do not send real
credentials or real personal data: an API key or a customer prompt inside a
report is a second incident, not evidence.

We acknowledge a report within three working days, tell you what we found
within ten, and coordinate disclosure through the advisory. If the report turns
out to describe expected behaviour, you get that answer with the reasoning
behind it.

## What is in scope

shim sits between a client and a model provider, so a report is in scope when a
request crosses a boundary it should not have crossed:

- a prompt or a response reaching a provider that policy excluded
- a redaction path that fails open rather than closed
- credentials appearing in logs, error bodies or traces
- an audit row that can be written, altered or dropped without detection
- admission, quota or accounting bypassed by a crafted request
- privilege escalation between tenants or between keys

## What is out of scope

A provider's own behaviour once a request has legitimately left shim. Detector
coverage on data it never claimed to cover: a name it did not catch is a bug
report, not a vulnerability report, and the limits are written in the README.
Findings from an automated scanner with no demonstrated impact.

## Release integrity

Every tagged release publishes an SPDX SBOM and a signed build provenance
attestation. Verify the image before you trust it:

```
gh attestation verify oci://ghcr.io/getshim/shim:0.1.2 --owner GetSHIM
```

A failed verification means the image did not come from this repository's
release workflow. Treat that as a security report and use the advisory link
above.
