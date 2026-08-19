# ADR-0190: Revalidate Remote Object Storage before Managed Admission

## Status

Accepted

## Context

ADR-0188 separates Object Storage transport locators from Artifact authority. ADR-0189 then
persists a deployment authority head and requires an exact current-head check immediately before
provider use. Neither decision defines the executable provider seam. In particular, a pre-signed
URL, native multipart completion, ETag, object version, or successful HTTP response must not select
the Replay output or bypass the existing managed repository and finalization checks.

The current package includes the Control Plane HTTP stack but no selected Object Storage SDK,
signer, provider credential configuration, or deployment inventory. Choosing S3, MinIO, Azure, or
another provider in code would therefore create an unsupported deployment decision and secret
boundary.

## Decision

### Introduce a provider-neutral, deployment-supplied adapter

Add a content-addressed `ObjectStorageProviderAdapterDefinition` and an
`ObjectStorageProviderAdapter` protocol. Trusted deployment composition supplies the concrete
implementation. Its non-secret definition must exactly match the current UX-007L HTTPS origin and
transport profile. Native upload IDs and provider credentials remain private to that
implementation.

Every provider call receives a server-derived, content-addressed operation ID. Mutating operations
must be idempotent for that ID. The runtime calls `ObjectStorageAuthorityHeadStore.require_current()`
immediately before upload credential issuance, completion, every part read, and cleanup. A stale
authority or checkpoint stops before the provider call. This code-owned composition does not turn
the fixed false eligibility fields in UX-007L/M documents into request authority.

### Keep upload credentials ephemeral

Represent a pre-signed upload credential only as a runtime dataclass with a redacted representation
and no Pydantic or durable wire model. The runtime accepts only `PUT`, the exact server-derived part
key, the binding's exact expiry, and the pinned canonical HTTPS origin. It exposes no route or log
record for the URL. The concrete provider must bind the signed request to the same values and must
not follow redirects across origins.

### Re-read all bytes before touching managed staging

Provider completion returns no metadata. Any non-null result is rejected so an ETag or provider
receipt cannot become Artifact authority. After completion, the runtime reads every expected part
by its server-derived key with its exact byte bound. It reassembles each file in bounded memory,
recomputes every file SHA-256 and the canonical multipart manifest, and compares the complete
observed manifest with the existing executor-attested binding.

Only after the full remote tree matches does the runtime feed the verified bytes through
`ManagedArtifactRepository.begin_portable_multipart_upload()`, part publication, and
`materialize_portable_multipart_upload()`. Existing Replay finalization still performs managed
import, sealed Run inspection, executor attestation verification, gate evaluation, and database
admission. The external adapter adds no Artifact or finalization wire.

### Fail closed on expiry and uncertain mutation outcomes

Issue and completion paths reject use before issue time or at and after exact expiry. Explicit
cleanup remains available for a current-head expired or abandoned binding and accepts only typed
`cleaned` or `already-absent` results. It performs no automatic retries. A provider-declared or
unexpected uncertain mutation outcome is sanitized, classified as unknown, and requires explicit
cleanup or operator reconciliation before the runtime can claim success.

## Consequences

- Request, URL, response metadata, and provider-native locators cannot select Artifact bytes.
- A head change between parts stops the next remote read before it reaches the provider.
- Corrupt remote bytes are rejected before any multipart data is written into managed staging.
- Exact local multipart materialization remains the bridge into the pre-existing finalization path.
- The adapter implementation and its credential-to-key binding are deployment TCB.
- The direct-call runtime holds at most the existing 64 MiB transport bound while verifying the
  complete remote tree.

## Rejected alternatives

### Persist or return the full pre-signed URL in an authority model

Rejected because the credential is a bearer-like transport capability and would leak into durable
records, logs, equality, or finalization semantics.

### Admit provider completion, ETag, or version metadata

Rejected because those values do not prove the file digests, canonical tree, sealed Run, executor
statement, or Replay lineage.

### Stream unverified parts directly into authoritative staging

Rejected because a later file-digest failure would poison the opaque staging capability with
remote bytes that cannot be safely replaced by an exact retry.

### Select a cloud SDK without deployment authority

Rejected because the repository currently has no provider selection, signer configuration, or
credential contract. Provider-specific implementation remains an explicit deployment decision.

## Compatibility and rollback

The change is additive and internal. It adds no environment variable, database migration, public
route, Worker request, finalization field, or provider dependency. Existing inline and local
multipart transports are unchanged. Rollback disables new adapter calls but must preserve the
UX-007M head and must explicitly reconcile any provider state already created under this runtime.

The first runtime has no durable provider-attempt journal, automatic scheduler, provider-specific
implementation, or old-revision cleanup after a head advance. Those require a later deployment and
recovery contract; unknown state must not be treated as absent meanwhile.

## Related documents

- [UX-007N contract](../orchestration/UX-007N-object-storage-provider-revalidation.md)
- [ADR-0189 durable head](0189-activate-object-storage-authority-head-before-provider-use.md)
- [ADR-0188 transport/admission separation](0188-separate-object-storage-transport-from-artifact-admission.md)
- [ADR-0045 local multipart transport](0045-resumable-multipart-portable-artifact-transport.md)
