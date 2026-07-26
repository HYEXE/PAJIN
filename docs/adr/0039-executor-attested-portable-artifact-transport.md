# ADR 0039: Executor-attested portable Replay Artifact transport

- Status: Accepted
- Date: 2026-07-24

## Context

ADR 0038 lets an off-host verifier validate the exact Claim receipt set issued by the Control
Plane, but the executor still has to write output into a staging volume shared with the Control
Plane. That public signature also covers Control Plane receipt authority. It does not prove that a
separately identified workload executor observed a particular compilation, permit set, and sealed
output.

Replacing the shared volume with a remote or caller-supplied filesystem path would bypass managed
Artifact admission through path substitution, TOCTOU, link traversal, or partial uploads. Adding
only an executor signature without binding the transferred bytes would permit replaying a valid
receipt over another output.

## Decision

1. B2.8a separates the executor workload key from the Control Plane key. Only the executor holds
   the Ed25519 private key. The Control Plane holds a separately distributed issuer/trust-domain
   public-key anchor with `active`, `retired`, and `revoked` lifecycle. Bundle-supplied key material
   is never trusted.
2. The portable `ReplayFinalizeRequest` form always requires `artifact_bundle` and
   `executor_attestation` together. The bundle contains canonically sorted relative regular-file
   paths, per-file size, SHA-256 and base64 bytes, plus a manifest SHA-256. The first vertical
   slice is bounded to 2 MiB raw total, 1 MiB per file, 256 files, and depth 24. Absolute, parent,
   dot, prefix-colliding, or duplicate paths and symbolic, hard, or special files fail closed.
3. The executor statement signs issuer, trust domain, profile, issue time, batch, item, Job,
   ticket, fence, Replay Run, source root, compilation, and execution-context digests. It also
   signs the canonically ordered permit digests and Replay request IDs, bundle manifest, file
   count and bytes, artifact-set digest, and both seal roots. Its signature domain is separate
   from the Control Plane Claim receipt signature.
4. The Control Plane verifies the external signature and issued authority before copying any
   caller-supplied Artifact bytes. Clocks on separate hosts receive at most 30 seconds of future
   skew, and the attestation cannot predate the execution context or any permit. The Control Plane
   then atomically materializes the bundle into an opaque server-owned staging reservation. The
   existing managed repository reverifies tree content, Run integrity, artifact set, receipt, and
   seals. The portable manifest digest must exactly equal the admitted
   `ArtifactRef.content_digest`.
5. The Control Plane transport receipt and executor attestation are retained with their digests
   and the verifying trust-anchor digest in the immutable Replay Job finalization result, and all
   three digests are bound into the finalization result digest. Projection input authority includes
   the transport and attestation digests, and the complete executor attestation is
   sealed at `validation/v1alpha1/executor-attestations/{item_id}.json`.
6. Existing shared-staging finalization remains a compatibility path. Portable and legacy retries
   cannot substitute for one another. A portable retry must reproduce the stored attestation and
   exact manifest.

## Security boundary

This decision proves that a workload key in a pinned executor trust domain signed the exact
Control Plane authority, permit set, and sealed output tree. It also enables bounded Artifact
transfer without a shared filesystem. The Control Plane does not possess the executor private key,
and signature failures are rejected before Artifact import.

The executor still relays target responses. This proof alone does not establish that the target
workload actually answered or that provider audit logs, KMS, HSM, or a transparency log recorded
the execution. The confirmation Gate therefore retains `needs-review` and
`independent-execution-attestation-missing`. B2.8b must bind a target-issued, challenge-bound
signed receipt to the host-observed proxy receipt before independent confirmation is considered.

## Consequences

- A Replay Worker and Control Plane can transfer a small sealed Run without sharing a filesystem.
- Signer, issued authority, permit set, and transferred bytes form one verification chain.
- The 2 MiB ceiling is a minimum slice that fits the current 4 MiB Control Plane request fence.
  Large Artifacts, resume, multipart, and object-store pre-signed upload remain follow-up adapters
  that reuse the content-addressed manifest contract.
- Operators must keep the executor private key outside the Control Plane and distribute and pin
  the trust anchor over a separate channel.
