# ADR-0195: Select AWS S3 Seoul without Granting Production Activation

## Status

Accepted

## Context

ADR-0193 selected disposable local MinIO only for provider-common conformance. ADR-0194 allowed its
exact fresh evidence to start local transport for one bounded window, but explicitly granted no
production provider, credential, KMS/HSM, tenant-isolation, retention, backup, cost, or operations
authority.

The repository contains no deployment-owned cloud account, bucket, IAM role, KMS key, VPC endpoint,
backup inventory, restore evidence, or cost approval. Treating test fixture identifiers or an
environment variable as those facts would turn configuration into authority and could expose
cross-tenant data or create billable resources without approval.

## Decision

### Select the provider family and primary region

Select Amazon S3 in AWS partition `aws`, region `ap-northeast-2`, through the regional endpoint
`https://s3.ap-northeast-2.amazonaws.com`. Fix boto3/botocore `1.43.73`, SigV4, and virtual-hosted
addressing to match the pinned local SDK while replacing the MinIO-specific endpoint, root
credential, SSE-C key, and path addressing.

The selection is a versioned desired-state contract. It does not assert that any named resource
exists and cannot activate a provider.

### Isolate each tenant at bucket, role, key, prefix, and network policy

Require one exact bucket, STS role, customer-managed symmetric KMS key, and
`pajin/tenants/{tenantId}` prefix per tenant. Bind one AWS account across all three resources and
require one exact VPC gateway endpoint plus bucket, endpoint, organization, trust, permission,
session, key, and grant policy digests.

Require Bucket-owner-enforced ownership, ACLs disabled, all four Block Public Access settings,
SSE-KMS, and no public-network eligibility. Credential and KMS custodians must be distinct.

### Use minimum-duration runtime-only STS credentials

Require `AssumeRole` with a 900-second session, an external-ID digest, deterministic source
identity, exact tenant session tag, and a narrowing session-policy digest. Prohibit static and
persisted credential values. The selection stores no returned access key, secret key, or token.

### Use per-tenant customer-managed KMS keys

Require a fully qualified KMS key ARN, AWS_KMS-origin symmetric key material, enabled state, no
pending deletion, no cross-tenant grants, and 365-day automatic rotation. Revocation disables the
key before any separately reviewed deletion; a selected deletion policy uses the maximum 30-day
waiting period.

Disable S3 Bucket Keys in v1 so object-level encryption-context restrictions are not silently
reduced to a bucket-level context. This accepts higher KMS request cost until measured production
usage and an explicitly approved policy justify a change.

### Keep ephemeral transport and retained backups separate

The tenant transport bucket remains unversioned and without Object Lock because UX-007O cleanup
must actually remove staged bytes. Versioned objects or locked versions would survive visible-key
cleanup.

Require separate policy digests and owners for off-host immutable authority-state backup, external
anti-rollback retention, new-path restore drills, expired-upload cleanup, and cost approval. The
actual backup inventory and live restore evidence belong to UX-007R2.

### Make the selection non-executable

Fix production activation, transport admission, public network, Artifact admission, finalization,
and external resource creation false. Require fresh live inventory, issuer evidence, KMS evidence,
tenant-isolation probes, and restore evidence before a later authority may change any ceiling.

## Consequences

- PAJIN now has one provider-specific production target instead of an unconstrained S3-compatible
  placeholder.
- Deployment, tenant, account, bucket, prefix, role, key, policy, custody, operations, and cost
  identities become content-addressed and cross-bound.
- Fixture values can exercise the contract but cannot become deployment evidence.
- AWS account provisioning and live reads remain required; no resource has been created.
- KMS request cost is higher with Bucket Keys disabled and must be measured before R2 approval.
- The ephemeral transport bucket does not provide retained Artifact or authority backup storage.
- Public routes, Distributed Workers, cross-host fences, Artifact admission, and finalization remain
  separate trust boundaries.

## Rejected alternatives

### Reuse the local MinIO inventory

Rejected because its disposable root credential, SSE-C key, local CA, path-style endpoint, and
destroyed target are test-only and no longer live.

### Allow arbitrary S3-compatible production providers

Rejected because credential issuance, encryption receipts, policy observation, cleanup, and
tenant isolation are provider-specific security boundaries.

### Persist static IAM access keys

Rejected because long-lived values would expand credential theft and rotation risk and are not
needed for STS runtime sessions.

### Enable S3 Bucket Keys immediately

Rejected for v1 because they change the KMS encryption context to the bucket ARN and may invalidate
object-level policy assumptions. Cost optimization requires a separate measured decision.

### Enable Versioning or Object Lock on the transport bucket

Rejected because current cleanup observes the active prefix, not every historical object version.
Retention controls belong to a separate immutable backup inventory.

### Mark desired configuration as live evidence

Rejected because identifiers and booleans supplied by a caller do not prove AWS state, negative
cross-tenant behavior, backup publication, restore success, or cost approval.

## Compatibility and rollback

The decision is additive and non-executable. Existing MinIO conformance, selected-provider
admission, provider-neutral runtime, databases, public requests, and managed Artifact admission are
unchanged.

Before UX-007R2, rollback removes only the selection models and documents. After a future live
activation, rollback must preserve current authority, admission, provider-journal, and external
checkpoint heads and reconcile all pending attempts before disabling the adapter.

## Follow-up work

- UX-007R2 must consume deployment-owned AWS identifiers, implement a production adapter, collect
  signed fresh inventory and negative tenant-isolation evidence, perform an independent restore
  drill, and obtain security, operations, and cost approval.
- Cross-host fencing, external transparency anchoring, public routes, Distributed Workers, Artifact
  admission, and finalization remain separate slices.

## Related documents

- [UX-007R1 contract](../orchestration/UX-007R1-aws-s3-production-custody-selection.md)
- [ADR-0194 fresh selected-provider admission](0194-require-fresh-revocable-selected-provider-admission.md)
- [ADR-0188 transport and Artifact separation](0188-separate-object-storage-transport-from-artifact-admission.md)
