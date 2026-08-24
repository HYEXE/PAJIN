# ADR-0226: Admit Cloud API Observations without Credential-use Authority

## Status

Accepted

## Context

CLOUD-001B produces a secret-free, content-addressed preparation for one exact read-only Cloud
provider `GET`. It deliberately has no provider runtime, Worker job, credential materialization,
network request, result, or Graph-admission authority. A preparation, provider label, route, or
lease fingerprint therefore cannot prove that a request ran or that a resource or policy exists.

PAJIN has durable approval-consumption receipts, consumed ActionPermits, the DOMAIN-004 minimum
Cloud Worker profile, direct-mTLS identity contracts, and one Canonical Graph writer. It does not
have a repository-owned Cloud provider client or a Cloud entry in the existing DOMAIN-004
deployment registry. Treating CLOUD-001B as an executable adapter would fabricate runtime support;
adding a second Graph writer or storing provider responses in Graph nodes would weaken existing
authority and data-minimization boundaries.

## Decision

Add a CLOUD-001C source-verification and admission boundary. Do not add a provider client or
execute a request in this repository. Require a deployment-owned external runtime to provide two
detached JSON artifacts:

1. an Ed25519-signed `CloudProviderExecutionBundle`; and
2. a neutral `CloudProviderResponseReceipt` that records response status, media type, byte count,
   and body digest without embedding the provider body, response headers, credentials, resource
   fields, policy fields, or effective-permission conclusions.

The deployment configures an out-of-band trust anchor when constructing the admission gate; the
source input cannot supply or override it. The anchor binds exactly one deployment, the current
CLOUD-001B code-backed Capability and release, the DOMAIN-004 minimum Cloud Worker profile, a
Worker mTLS policy and subject/SPKI, the explicit provider adapter, credential audience, and a
uniquely sorted Ed25519 keyring with exactly one active key. The trust anchor and Worker binding are
verification inputs only: they do not select a Worker, invoke a provider, use a credential, issue a
Permit, or admit Graph data.

The signed statement must bind the current Campaign, exact CLOUD-001B preparation and provider
request, Run and request identities, one already consumed ActionPermit, its durable approval
receipt, the deployment/Worker binding and signed direct-mTLS admission, and the detached response
receipt's path, file digest, and content-addressed identity. It also carries a credential-use audit
receipt asserting that the deployment rechecked the broker, materialized the exact fingerprint-only
single-use lease, consumed it once, used no ambient credential, embedded neither bearer lease ID nor
credential material, and discarded the material. These are signed provenance claims from the
external execution boundary; CLOUD-001C cannot materialize or reuse the lease and does not grant a
new credential use.

Revalidate the current signed Cloud activation and current Campaign Scope. Join the statement to
exactly one consumed Permit and exactly one approval-consumption receipt in the existing SQLite
Graph authority store. Require all Capability, release, Campaign, Decision, Proposal, Grant,
request, target, normalized-parameter, adapter, Worker, mTLS, execution, lease, timing, one-request, zero-write,
response budget, artifact hash, and signature identities to agree.

Only then construct one Observation proposal containing one succeeded Action, one target-derived
`cloud.api-observation`, two Evidence nodes for the signed bundle and detached response receipt,
one `produces` edge, and two `supported-by` edges. Submit it at the caller-bound current Graph head
through the existing `GraphAdmissionAuthority`. The fixed Observation summary states only that a
separately authorized read-only provider request produced sealed API response evidence for the
exact bound Cloud Surface.

Do not create a Cloud Hypothesis, Surface, CampaignFact, Finding, Replay, or policy-evaluation node.
Keep the raw provider body and all provider-derived resource or policy fields outside the Graph.
Fix resource existence and ownership, policy effect, effective permission, Scope expansion,
credential use, provider/Worker selection, network access, mutation, Replay, Finding, and execution
authority to false in the candidate and admission contracts.

## Consequences

- CLOUD-001C can prove that one separately authorized bounded request produced a sealed response
  receipt without claiming what the provider body means.
- Provider execution remains deployment-owned and is not fabricated by a non-executable Tool
  adapter.
- The signed credential-use receipt is historical provenance, not a bearer credential or a fresh
  broker authorization.
- Raw provider responses, headers, credentials, resource records, policies, and effective-access
  conclusions do not enter Graph nodes or prose.
- Exact retries reuse the existing semantic event and perform no provider, broker, Worker, or
  network operation.
- CLOUD-001D remains responsible for deterministic policy re-evaluation, independent execution or
  controls where required, disposable provider/emulator Ground Truth, and measurements.

## Rejected alternatives

### Invoke the provider from the CLOUD-001B Tool

Rejected because that Tool explicitly has no Worker materializer or result normalizer. Adding a
placeholder client would claim support without a deployment-owned runtime, current broker bearer
handle, Gateway integration, or sealed result contract.

### Trust a preparation or lease fingerprint as execution evidence

Rejected because neither value proves approval, Permit consumption, credential materialization,
network execution, response receipt, or successful completion.

### Embed the provider response in the Graph

Rejected because provider-controlled bodies may contain credentials, tenant data, high-cardinality
inventory, or misleading policy claims. The neutral receipt records only bounded metadata and the
body digest; custody of the raw response remains external.

### Infer resource existence or effective permissions from HTTP success

Rejected because a successful API status does not establish durable existence, ownership,
authorization reachability, policy effect, or effective access. Those require separate bounded
interpretation and validation contracts.

### Add a Cloud-specific Graph writer or execution ledger

Rejected because the existing approval/Permit store and Graph single writer already provide the
required authority, stale-head, lineage, idempotency, and append-only semantics.

## Compatibility and rollback

CLOUD-001C is additive and explicitly imported. It changes no CLOUD-001A/B, Campaign, Scope,
Capability, ToolRequest, approval, ActionPermit, SecretBroker, Worker, Graph, Replay, Finding, or
benchmark wire. Rollback removes the specialized workflow, tests, contract, and this ADR. Existing
external artifacts and already admitted immutable Graph events require no migration.

## Related documents

- [CLOUD-001C contract](../graph/CLOUD-001C-sealed-cloud-provider-observation-admission.md)
- [CLOUD-001B](../capability/CLOUD-001B-read-only-inventory-policy-capability.md)
- [CLOUD-001A](../discovery/CLOUD-001A-account-project-resource-iam-container-surface-model.md)
- [DOMAIN-002](../graph/DOMAIN-002-common-multi-domain-graph-semantics.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0225](0225-bind-cloud-read-only-preparation-without-credential-use-authority.md)
