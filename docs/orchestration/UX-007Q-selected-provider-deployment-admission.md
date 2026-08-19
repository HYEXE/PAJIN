# UX-007Q Selected-provider Deployment Admission

## Status

Implemented and exercised on 2026-08-18. UX-007Q turns one exact selected-provider conformance
chain into a short-lived, revocable authority for starting local provider transport. It does not
select a production provider and grants no public-network, Artifact-admission, or finalization
authority.

## Purpose

UX-007P1 reports provider-common black-box observations, while UX-007P2 supplies the exact local
MinIO inventory and target that produced them. The report does not directly contain the selected
image, SDK, TLS CA, bucket, or full provider activation. Treating a report digest alone as
deployment authority would therefore permit inventory substitution and indefinite replay.

UX-007Q adds four distinct authorities:

1. selected-provider evidence binding the exact inventory, provider activation, and report;
2. an append-only deployment policy selecting that exact evidence or disabling admission;
3. a time-bounded deployment admission recorded under the current policy; and
4. an external checkpoint for the current policy and admission heads.

The authorities remain separate from the UX-007M deployment head and UX-007O attempt journal. Each
consumer revalidates all three current stores instead of promoting a filename, URL, request field,
or caller claim into authority.

## Selected-provider evidence

`ObjectStorageSelectedProviderEvidence` embeds the complete secret-free
`MinioS3ProviderInventory`, `ObjectStorageConcreteProviderActivation`, and
`ObjectStorageProviderConformanceReport`. It requires:

- exact inventory, activation, and report digests;
- the report's activation, authority checkpoint, adapter, deployment profile, and local
  conformance profile to match the embedded activation;
- the activation endpoint, provider family, encryption policy, and conformance profile to match
  the inventory; and
- the report to start no earlier than provider activation.

The envelope is content-addressed. It contains no runtime credential, signed URL, SSE-C customer
key, remote bytes, raw log, or provider exception.

## Fixed freshness policy

The v1 selected policy fixes `maxReportAgeSeconds=3600`. The report finish time is the clock origin;
the policy and admission accept `finishedAt <= now < finishedAt + 3600 seconds`. A future-dated
report and the exact expiry boundary fail closed. There is no clock-skew grace or caller-controlled
extension.

The one-hour value bounds exposure of a locally observed provider configuration while leaving time
for reviewed startup composition. A different duration is a new versioned decision, not a mutable
runtime setting.

## Append-only policy and revocation

`ObjectStorageProviderAdmissionPolicy` forms a contiguous digest chain. An enabled revision selects
the exact evidence, inventory, report, activation, authority checkpoint, adapter, and deployment
profile. It also binds the exact deployment and tenant.

`revoke_object_storage_provider_admission()` creates a deny-all successor. It clears every selected
digest, adds the previous inventory and report to uniquely sorted revocation sets, and fixes
`transportAdmissionEligible=false`. Store transitions require:

- exact predecessor and contiguous sequence;
- stable deployment and tenant;
- non-regressing issue time; and
- monotonic supersets of inventory and report revocations.

An old admission becomes unusable immediately when the policy head changes. A replacement image,
SDK, CA, bucket, endpoint, adapter, profile, activation, or report requires new conformance evidence,
a new enabled policy revision, and a new admission.

## Durable admission store and checkpoint

`ObjectStorageProviderAdmissionStore` is an explicitly bootstrapped SQLite store. `open()` never
creates missing state. Startup validates database integrity, exact schema inventory and metadata,
the immutable store identity, the complete policy chain, and the complete admission chain.

Every write requires the exact prior `ObjectStorageProviderAdmissionCheckpoint`. The checkpoint
binds store identity, current policy head, latest admission head, and whether that admission belongs
to the current enabled policy. A missing, corrupt, foreign, rolled-back, or stale checkpoint fails
closed. The deployment operator must retain the expected checkpoint outside the database to detect
a restored older local head.

Before appending an admission, the store requires:

- the current enabled policy to select every exact evidence digest;
- neither inventory nor report to be revoked;
- the report to be inside the fixed one-hour window;
- the UX-007M authority checkpoint to equal the evidence activation checkpoint;
- the UX-007O journal's latest provider activation to equal the evidence activation;
- the runtime MinIO inventory to equal the evidence inventory; and
- no pending provider attempt.

An exact retry returns the existing current admission while it remains fresh. A different report or
policy appends a new admission linked to its predecessor.

## Startup and pre-call gate

`DeploymentAdmittedObjectStorageProviderRuntime` is an opt-in wrapper around the existing
recoverable runtime. Construction requires the exact current admission and checkpoint. Starting an
attempt rechecks them, and `_AdmissionGatedProvider` rechecks immediately before credential issue,
completion, and every remote read.

Admission expiry, policy rotation, revocation, inventory substitution, authority-head change, or
provider-activation change rejects later remote work. The existing UX-007M current-head check and
UX-007O journal fence still run independently.

Cleanup and restart reconciliation deliberately do not require a fresh admission. Revocation must
stop new use without preventing idempotent removal or resolution of already-unknown provider state.
Those paths still require their existing authority head, activation, journal, and fence checks.

The admission, authority-head, and attempt-journal databases are separate local transactions. A
policy can rotate immediately after a pre-call check. The next provider call rechecks and fails;
cross-process or cross-host atomic revocation remains outside this local cooperative boundary.

## Live retained evidence

The latest disposable MinIO execution retained this chain:

- inventory `minio-inventory-3351ef2b8716a5efd9569ef2d6222658b038249132f427fe48998b0cd636610d.json`;
- report `minio-report-57da9bf2da7c96e396e2da3ba9462575a109633a78347fcaf91abf3f1ec9d8db.json`;
- evidence `minio-evidence-647337e25349a95b1cac880d68d2eb66e88fd610345603b111a5947db185833a.json`;
- policy `minio-admission-policy-3daca380bde4d57619960e3b5c571556355a6475a1a584d91e91e2bd4bb12b09.json`;
- admission `minio-admission-ab05ed89005f8101e253187bbd75b6c8542f0ff20c59e351aea2a29b80cb238d.json`;
  and
- checkpoint `minio-admission-checkpoint-c3bb8d01e5ef2b4155fc3ba37759056bc26a751707dc13e6827449c02f6dd8b4.json`.

The report observed all eight cases from `2026-08-18T13:56:14.644138Z` through
`2026-08-18T13:57:15.417767Z`. The historical admission was valid until
`2026-08-18T14:57:15.417767Z`, but the target container and all runtime stores were destroyed at the
end of the run. Retained JSON alone cannot recreate current admission because the live authority,
provider, admission-store heads, and expected checkpoint must all exist and match.

All six files were reparsed through their strict models and cross-checked. The report had eight
passing cases. The retained directory contained no matched access-key prefix, secret-access label,
SSE-C customer key, private-key block, or complete SigV4 credential query. The exact container,
named volume, and runtime temporary directory inventories were empty after execution.

## Authority ceiling

UX-007Q permits only opt-in local selected-provider transport startup while the exact admission is
current. It does not:

- permit public network access or select a production provider;
- admit remote bytes as an Artifact or finalize a Replay Run;
- issue deployment configuration, tenant credentials, KMS/HSM keys, or retention policy;
- make a conformance result permanent or transferable to another inventory;
- provide cross-host revocation, coordinated backup, or external anti-rollback anchoring; or
- authorize automatic expiry or historical garbage collection.

## Compatibility and rollback

The change is additive. Existing provider-neutral and recoverable runtimes remain available for
test and cleanup paths; only callers that explicitly construct the admitted wrapper receive the new
startup gate. No public route, Worker wire, Artifact schema, existing database, or default workflow
changes.

Rollback stops constructing the admitted wrapper and removes the admission store only after all
pending attempts are reconciled. Removing the gate does not authorize direct production provider
use. A revoked or expired admission cannot be restored by copying an older database without also
matching the externally retained checkpoint and the current UX-007M/UX-007O heads.

## Related documents

- [UX-007R1 AWS S3 production custody selection](UX-007R1-aws-s3-production-custody-selection.md)
- [ADR-0194 fresh and revocable selected-provider admission](../adr/0194-require-fresh-revocable-selected-provider-admission.md)
- [UX-007P2 selected MinIO conformance](UX-007P2-minio-selected-provider-live-conformance.md)
- [UX-007P provider-common harness](UX-007P-provider-common-conformance-harness.md)
- [UX-007O durable provider recovery](UX-007O-durable-object-storage-provider-recovery.md)
- [UX-007M durable authority head](UX-007M-object-storage-durable-authority-head.md)
