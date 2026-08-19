# ADR-0193: Select Disposable MinIO for Local Provider Conformance

## Status

Accepted

## Context

ADR-0192 defines a provider-common Object Storage conformance harness but deliberately leaves the
provider family, exact SDK, endpoint and bucket inventory, credential custody, signing, encryption,
and isolated environment unselected. UX-007P cannot close on an in-memory target because the common
runner must receive raw observations from actual SDK and HTTPS operations.

A production cloud provider has not been selected, and this work has no authority to create a
cloud account, external bucket, tenant credential, cost-bearing resource, or deployment. The first
concrete target therefore needs to be local, disposable, reproducible, and unable to acquire
production authority from a passing test.

## Decision

### Select one exact local target

Use single-node MinIO release `RELEASE.2025-09-07T16-13-09Z`, pinned by the multi-platform image
index digest `sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e`
and platform `linux/amd64`. Use `boto3==1.43.73` and require `botocore==1.43.73` at runtime. Bind the
exact loopback endpoint, redirect-probe endpoint, bucket, region, path-style addressing, SigV4 query
signer, runtime-only credential custody, SSE-C AES-256 policy, isolation profile, and TLS CA digest
in a content-addressed secret-free inventory.

The optional SDK dependency group does not activate the provider. A caller must construct the
inventory, runtime secrets, adapter, UX-007O activation, and common-harness target explicitly.

### Restrict the archived server to disposable single-node use

The MinIO community repository is archived and the selected tag is its final release. The published
path-traversal advisory identifies a multi-node-only route and states that standalone single-node
deployments do not register it. Permit this image only in a fresh single-node conformance container
with loopback ports, random credentials, a named disposable data volume, and no production data or
public network authority. This decision is not a production MinIO recommendation.

### Keep secrets and credentials runtime-only

Generate a random root access key, root secret, and 32-byte SSE-C key per run. Inject the root
credential only into the provider container and attached runner. Return presigned URL and required
SSE-C headers only in a redacted ephemeral credential object. Persist neither those values nor a
secret-derived digest. Require TLS verification for SDK and raw HTTPS requests.

### Run the black-box path where TLS is observable

Use Docker Desktop on the Windows host for the exact container and volume lifecycle. Execute the
actual SDK and raw HTTPS suite inside WSL Ubuntu, using a repository-ignored WSL virtual environment,
because endpoint security intercepts Windows loopback TLS on the current workstation. Do not disable
certificate verification, weaken hostname checks, or bypass endpoint security.

### Preserve the authority ceiling

The selected inventory, adapter, target, and report remain transport-only. All inventory and report
models fix public-network, Artifact-admission, and finalization eligibility false. A passing report
does not activate a provider or grant deployment authority. A later UX-007Q decision must define
report freshness and deployment admission before any selected adapter can enter a deployment.

## Consequences

- UX-007P has an actual SDK/TLS/S3 target for all eight common black-box cases.
- Exact SDK and image selection are reviewable and cannot drift through a floating tag.
- SSE-C allows the suite to prove signed encryption headers and encrypted object access without
  introducing an external KMS or persisting a customer key.
- Each run has a distinct CA digest and therefore a distinct provider inventory and report lineage.
- Docker and WSL are test-environment prerequisites; they are not runtime dependencies of existing
  PAJIN workflows.
- The adapter and target join the selected-provider trust base. They can still fabricate an
  observation if malicious, so implementation review remains necessary.
- The archived MinIO image must not be reused as a production default or multi-node target.

## Rejected alternatives

### Select a production cloud bucket

Rejected because no cloud provider, account, credential custodian, region, cost boundary, retention
policy, or deployment operator has been authorized.

### Use an in-memory or mocked S3 target

Rejected because UX-007P1 already covers orchestration with a fixture; it cannot prove native
signatures, redirects, TLS, encryption receipts, consistency, multipart state, or cleanup.

### Use a floating MinIO tag or unconstrained SDK

Rejected because a report could no longer identify the implementation that produced its
observations.

### Disable TLS verification on Windows

Rejected because it would invalidate the TLS and redirect boundary and bypass a security control.

### Treat SSE-C as production key management

Rejected because the per-run key exists only to exercise the signed encryption contract. It does
not supply KMS/HSM custody, rotation, tenant separation, backup, or recovery.

## Compatibility and rollback

The change is additive and internal. It adds an optional dependency group, selected-provider module,
runner, tests, and secret-free evidence. It changes no public route, Worker wire, database migration,
Artifact format, provider-neutral adapter protocol, or existing default workflow.

Rollback removes the optional target and its reports. The exact container and volume are already
disposable, but any UX-007O attempt that is not terminal must still be reconciled before its local
state is removed. A rollback cannot convert unknown remote state to absent.

## Follow-up work

- Define the maximum report age, exact inventory/report binding, revocation behavior, and deployment
  admission authority in UX-007Q.
- Select a production provider only through a separate decision with real credential custody,
  tenant isolation, KMS/HSM, retention, backup, and operational cleanup policies.
- Keep public routes, Distributed Workers, cross-host fencing, and automatic garbage collection in
  separate trust-boundary slices.

## Related documents

- [UX-007P2 selected-provider conformance](../orchestration/UX-007P2-minio-selected-provider-live-conformance.md)
- [ADR-0192 raw-observation conformance](0192-derive-provider-conformance-from-raw-observations.md)
- [UX-007P provider-common harness](../orchestration/UX-007P-provider-common-conformance-harness.md)
- [UX-007O durable provider recovery](../orchestration/UX-007O-durable-object-storage-provider-recovery.md)
