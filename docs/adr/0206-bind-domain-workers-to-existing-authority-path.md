# ADR-0206: Bind Domain Workers to the Existing Authority Path

## Status

Accepted

## Context

Web, Network, System, Application, Mobile, Cloud, AI, Cryptography, and Forensics operations need
different isolation, credential, filesystem, device, protocol, and evidence constraints. Running
all Capabilities with one generic Worker privilege set would either over-privilege safe analysis or
make high-risk operations impossible to review accurately.

PAJIN already has Capability releases, deployment-pinned Worker identities, direct mTLS, Tool
Gateway policy re-entry, trusted execution receipts, secret leases, Docker isolation, and
single-use Permit dispatch. A parallel domain execution engine would duplicate and weaken those
boundaries.

## Decision

DOMAIN-004 will add code-owned, content-addressed Worker trust-boundary profiles. An exact profile
must be bound by deployment to a reviewed Capability release and Worker identity. Security Domain
classification alone cannot select or widen a Worker profile.

Every domain operation continues through the existing path:

```text
Capability release + Campaign authority + Graph Decision
-> Proposal + Policy / Approval
-> single-use ActionPermit
-> Tool Gateway
-> deployment-bound Worker
-> trusted receipt + normalized Observation/Evidence
```

The first profiles will encode the minimum boundaries listed by ARCH-002: egress-only Web,
host/port-scoped Network, authenticated non-root System, read-only sandboxed Application,
device-bound Mobile, ephemeral-credential Cloud, provider/model/cost-bound AI, offline-preferred
Cryptography, and immutable read-only Forensics.

Dynamic execution, filesystem mutation, credential use, device instrumentation, cloud writes,
privilege changes, and cleanup each require separate explicit Capability and approval semantics.
Forensics defaults to provenance-preserving read-only analysis and cannot mutate evidence.

## Consequences

- Existing Permit, Gateway, retry, evidence, and audit contracts remain the only execution path.
- A Capability cannot run when the deployment lacks its exact Worker boundary, even if the domain
  or Tool category appears compatible.
- Different Capabilities in one domain may require different Worker profiles.
- Worker-boundary conformance and negative tests become prerequisites for each domain vertical
  slice.
- Cross-host fencing and production provider isolation remain explicit later operational work.

## Rejected alternatives

### One universal security Worker

Rejected because its maximum privilege would become ambient authority for every lower-risk action.

### Select a Worker from the Security Domain label

Rejected because classification is not an exact deployment or Capability authority.

### Add a separate execution engine per domain

Rejected because it would duplicate Policy, approval, Permit, Gateway, retry, and evidence logic.

## Compatibility and rollback

Existing Workers and PENTEST/REDTEAM deployments remain unchanged. New domain Worker profiles are
opt-in and additive. Rollback disables their deployment bindings without rewriting prior Permits,
receipts, evidence, or Run records.

## Related documents

- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [CAP-002](../capability/CAP-002-metadata-code-backed-authority-interfaces.md)
- [GRAPH-006](../graph/GRAPH-006-atomic-action-permit-authority.md)
- [ADR-0187](0187-bind-replay-worker-credential-to-executor-profiles.md)
