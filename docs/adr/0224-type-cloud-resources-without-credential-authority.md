# ADR-0224: Type Cloud Resources without Credential Authority

## Status

Accepted

## Context

DOMAIN-002 reserves `cloud.account-resource` and
`pajin.locator.cloud.account-resource.v1` as semantic identifiers but intentionally does not
implement their locator schema. PAJIN already has strict AWS S3, STS, and KMS production-selection
contracts, a disposable MinIO conformance provider, Docker Target Factory lifecycle evidence, and a
DOMAIN-004 Cloud Worker profile. Those contracts govern particular runtime or custody boundaries;
none is a provider-neutral Cloud Surface model.

CLOUD-001A must represent account, project, resource, IAM, and container knowledge before a Cloud
inventory Capability or ephemeral credential lease exists. Reusing an STS selection, provider
adapter, tenant identifier, endpoint, or Docker operation as the Surface would import credential,
activation, transport, Campaign, or lifecycle semantics into the representation layer. Mutable
resource aliases and image tags would also make canonical identity time-dependent.

## Decision

Add a content-addressed Cloud account/resource locator registry with five code-owned classes:

- `cloud-account`: provider ID, provider partition, and provider-local account ID;
- `cloud-project`: one exact parent account and provider-local project ID;
- `cloud-resource`: one account-or-project parent plus service, location, resource type, and
  provider-local resource ID;
- `cloud-iam`: one account-or-project parent plus a bounded IAM object kind and provider-local IAM
  ID; and
- `cloud-container`: one account-or-project parent plus orchestrator, runtime scope, namespace,
  immutable container ID, and exact `sha256` image digest.

Canonicalize provider, partition, service, location, resource-type, orchestrator, and namespace
coordinates locally. Preserve case-sensitive provider-local IDs while rejecting surrounding or
control whitespace, mutable aliases, URL/query/fragment syntax, wildcards, and unknown fields.
Nest parent locators rather than duplicating provider or account fields so cross-parent
substitution cannot pass as the same identity.

Add an inert `CloudAccountResourceSurface` wrapper that binds one locator to the exact Cloud Domain
and DOMAIN-002 type-set and starts as `registered-not-authorized`. Do not add these locators to the
existing evidence-bound discovery `SurfaceLocator` union. Do not change `AttackSurface`, Scope,
Graph, Capability, Worker, provider, object-storage, container-runtime, or artifact wires.

The registry and typed Surface explicitly deny provider selection, inventory or policy reads,
policy evaluation, credential lease or ambient credential access, tenant authority, container
access, resource or IAM mutation, Scope expansion, Capability activation, approval satisfaction,
Permit issuance, Tool or Worker selection, network access, Graph admission, runtime-support
assertion, and execution authority.

## Consequences

- CLOUD-001B can bind an exact account, project, resource, IAM, or container identity to a separately
  reviewed read-only Capability and ephemeral credential lease without deriving authority from the
  locator.
- Existing AWS account, S3 bucket, STS role, KMS key, MinIO, or Docker coordinates may be projected
  into provider-local locator components only by a later explicit adapter. Their provider
  selections, credentials, endpoints, tenant metadata, and live evidence are not copied or
  activated by CLOUD-001A.
- IAM object identity does not include policy content and makes no effective-permission claim.
- Container identity requires an image digest rather than a mutable tag but does not assert that
  the container exists, is running, is healthy, or is accessible.
- Provider IDs are canonical vocabulary, not a registry of supported providers.

## Rejected alternatives

### Reuse object-storage provider selections as generic Cloud Surfaces

Rejected because those models are deliberately bound to deployment, tenant, endpoint, credential
custody, encryption, and activation requirements that do not belong in a generic Surface.

### Treat account or tenant metadata as a credential lease

Rejected because identity and custody are separate authorities. An account ID, tenant ID, IAM role
name, or provider registration does not prove current Scope, approval, credentials, or access.

### Store provider URLs, full request coordinates, or policy documents in locators

Rejected because active endpoints and policy content require bounded Observation/Evidence and can
contain sensitive or mutable data. CLOUD-001A stores only provider-local identity components.

### Accept container image tags as canonical identity

Rejected because tags can move between images. The v1 container locator requires an exact lowercase
SHA-256 image digest.

### Extend the established discovery locator union immediately

Rejected because Cloud discovery has no sealed Observation/Evidence admission contract in this
slice. An additive typed wrapper preserves existing readers and artifact identities.

## Compatibility and rollback

CLOUD-001A is additive and requires no migration. Existing public wires, canonical digests,
readers, provider contracts, and runtime behavior remain unchanged. Rollback removes the new
module, exports, tests, contract, ADR, and consumers. New locator membership, IAM object kinds, or
image digest algorithms require an explicit versioned change rather than silent expansion.

## Related documents

- [CLOUD-001A contract](../discovery/CLOUD-001A-account-project-resource-iam-container-surface-model.md)
- [DOMAIN-002](../graph/DOMAIN-002-common-multi-domain-graph-semantics.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0195](0195-select-aws-s3-seoul-production-custody-boundary.md)
- [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)
- [ADR-0205](0205-admit-cross-domain-knowledge-without-scope-expansion.md)
