# UX-007L Object Storage Deployment Authority

## Status

Implemented as a non-executable Phase 9 contract. No external provider, public API, upload URL,
remote object read, garbage collector, or Artifact admission path is activated by this slice.

## Purpose

Separate a future external Object Storage transport from the existing managed Artifact admission
authority before provider-specific behavior is introduced. External locators and temporary upload
credentials may move bytes, but they must not decide which Replay output is admitted, finalized,
or accepted as sealed evidence.

## Existing authority

The current `pajin.control-plane.local-object-store/v1` multipart path accepts no Worker-selected
filesystem path, object key, upload URL, tenant, or expiry. Before the first byte, the Control Plane
verifies the live Replay lease and fence, exact issued Replay authority, canonical multipart
manifest, and executor attestation. Finalization reassembles and hashes every file, imports the
opaque `outputStagingId` through `ManagedArtifactRepository`, reopens the sealed Run, and rechecks
the complete ticket, permit, receipt, and projection lineage.

UX-007L does not replace that chain. It defines what a future external adapter must preserve.

## Versioned deployment authority

`pajin.control-plane.object-storage-deployment-authority/v1` binds:

- one immutable deployment and tenant identity;
- a canonical HTTPS endpoint origin and deployment-owned relative object-key prefix;
- the external pre-signed multipart transport profile;
- an upload TTL between 60 and 3,600 seconds;
- the current 64 MiB total, 16 MiB per file, 256-file, and fixed 1 MiB part bounds;
- the existing managed Artifact repository as the only admission profile; and
- `transportOnly=true`, `providerIntegrationEligible=false`,
  `artifactAdmissionEligible=false`, and `finalizationEligible=false`.

The authority is content-addressed and revisioned. Revision one has no predecessor. A later
revision must be exactly the remembered revision plus one, name the exact predecessor digest, use
a strictly later issue time, and retain deployment, tenant, transport, and Artifact-admission
identity. Exact replay of the remembered revision is idempotent; same-revision equivocation,
rollback, gaps, wrong predecessors, and cross-tenant substitution fail closed.

The selector is a reference transition verifier, not durable activation storage. A provider
integration must persist the remembered head outside request input and refuse bootstrap when that
state is unexpectedly lost. Repassing `None` is not an anti-rollback mechanism.

## Upload-only transport binding

`pajin.control-plane.object-storage-transport-binding/v1` binds the complete deployment authority
to the existing server-issued `outputStagingId`, canonical multipart manifest, executor-attestation
digest, issue and exact expiry time, and a server-derived object-key root. Per-part keys are derived
only from that root and checked manifest coordinates. Neither a request nor a provider response can
supply a replacement key.

The binding remains non-executable and fixes Artifact admission and finalization eligibility to
false. It is not accepted by `ReplayFinalizeRequest` and is not wired to a Control Plane route.

## Authority classification

| Value | Classification | Required rule |
| --- | --- | --- |
| Object key | Storage transport locator | Derive from deployment digest, opaque staging capability, manifest digest, and exact part coordinate; never accept it as Artifact identity |
| Pre-signed upload URL | Ephemeral transport credential | Keep outside durable authority and logs; require the pinned HTTPS origin and bounded expiry in a future adapter; never treat receipt or HTTP success as admission |
| Expiry | Transport failure boundary | Expiry closes upload use only; it cannot cancel, finalize, or admit a Replay Run |
| Tenant | Deployment identity | Pin in the contiguous deployment chain; request, token, URL, bucket, or prefix text cannot change it |
| Manifest and executor-attestation digest | Integrity input | Bind the bytes expected by the existing Replay authority, but do not replace server-side reassembly, hashing, seal, and lineage verification |
| External completion/ETag/version | Provider observation | May be checked by a future adapter; never serves as Artifact finalization authority |
| `ArtifactRef`, admission digest, finalization result | Artifact admission authority | Continue to derive only after managed import and complete server verification |

## Threat model and negative cases

An attacker may submit a different endpoint, path-like prefix, object key, signed URL, expiry,
tenant, manifest, attestation digest, part coordinate, authority revision, or predecessor. They may
also replay an exact transport binding after expiry or claim that provider success finalized the
Artifact.

The contract rejects non-canonical HTTP/origin/path input, unknown fields such as `uploadUrl`,
digest drift, bounds drift, expiry drift, key-root substitution, invalid part coordinates,
JSON number/boolean type coercion, authority-eligibility escalation, rollback, gaps, equivocation,
and cross-tenant transitions. The existing finalization wire continues to reject external
transport fields.

## Compatibility, migration, and rollback

This slice adds one internal module and two versioned models. It changes no database schema,
environment variable, public route, existing multipart wire, managed repository, or Worker
behavior. Inline and local multipart transports remain the only executable portable paths.

Removing this module and its tests is a behavior-preserving rollback while no provider consumes
it. After future activation, rollback must preserve the durable remembered authority head, disable
new URL issuance, let already admitted local Artifacts remain immutable, and never reinterpret
remote objects or transport receipts as finalized Artifacts.

## Audit and benchmark impact

The authority and binding expose secret-free content digests suitable for a future activation and
audit record. Full pre-signed URLs and credentials are deliberately absent. This contract creates
no Run event, Artifact, Finding, benchmark observation, comparison, execution, or activation
eligibility.

## Validation

- Authority round-trip, content digest, exact JSON scalar types, fixed false ceilings, and unknown
  URL-field rejection.
- Canonical HTTPS origin and relative prefix rejection cases.
- Bootstrap, exact replay, contiguous successor, rollback, gap, wrong-predecessor, equivocation,
  and cross-tenant transition cases.
- Server-derived key root, exact TTL, manifest-bound part keys, and invalid-coordinate cases.
- Key, expiry, URL, admission, finalization, and provider-eligibility substitution cases.
- Existing `ReplayFinalizeRequest` rejection of external key, URL, tenant, and expiry fields.

## Related documents

- [ADR-0188](../adr/0188-separate-object-storage-transport-from-artifact-admission.md)
- [ADR-0045 local multipart transport](../adr/0045-resumable-multipart-portable-artifact-transport.md)
- [ADR-0039 executor-attested portable transport](../adr/0039-executor-attested-portable-artifact-transport.md)
- [UX-007K deployment authority ceiling](UX-007K-phase9-deployment-authority-ceiling.md)
