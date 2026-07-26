# ADR 0045: Resumable multipart portable Artifact transport

- Status: Accepted
- Date: 2026-07-25

## Context

The first ADR 0039 slice transports a sealed Replay Run as a base64 inline bundle. To stay within
the Control Plane's 4 MiB request fence, that path limits raw content to 2 MiB total and 1 MiB per
file. Evidence beyond those limits therefore cannot cross from a separate executor host even when
its executor signature, Target proofs, and sealed Run are otherwise valid.

Reintroducing caller-selected filesystem paths or a shared volume would weaken the managed Artifact
admission boundary against path substitution, link traversal, and TOCTOU attacks. Large bytes must
instead be split into a server-owned bounded object namespace after the issued Replay authority and
executor signature have been verified, then reassembled against the final manifest and sealed Run.

## Decision

1. The existing `pajin.control-plane.portable-artifact-bundle/v1` inline path remains unchanged.
   Only a Run above 2 MiB total or 1 MiB per file selects
   `pajin.control-plane.portable-artifact-multipart-manifest/v1`.
2. This first multipart slice is bounded to 64 MiB total, 16 MiB per file, 256 files, and depth 24.
   Part size is fixed at 1 MiB. The manifest contains canonical relative paths, file sizes and
   SHA-256 digests, plus the existing canonical manifest SHA-256; it carries no file bytes.
3. The Replay Worker sends the exact lease, ticket, fence, output staging capability, manifest, and
   executor attestation when it begins an upload. The Control Plane accepts no part bytes before it
   verifies the live Replay authority, permit coverage, signer and trust anchor, and manifest
   metadata.
4. A verified upload is stored by output staging ID in the owner-private
   `pajin.control-plane.local-object-store/v1` repository namespace. Namespace operations are
   serialized by a process-shared directory lock, completed temporary upload authority is
   published atomically, and each part moves atomically from a fully written and synchronized
   temporary object. Begin and part PUT operations are idempotent for exact retries. Different
   bytes for the same file index and part number, or a part size, digest, or sequence outside the
   manifest, fail closed.
5. The Worker retries an identical begin or part with bounded backoff after a transient Control
   Plane transport error. Lease, fence, authentication, and protocol failures are not retried. Each
   base64 part request remains inside the existing 4 MiB request fence.
6. At finalization the Control Plane requires the complete ordered part set and recomputes every
   file size and SHA-256, the canonical manifest, and the tree content digest. It atomically
   publishes the tree into the owner-issued staging reservation, then reuses the existing managed
   Artifact import, Run integrity, artifact-set, receipt, and seal verification.
7. The multipart transport receipt binds the object-store profile, staging ID, manifest, file,
   byte, and part counts, and executor-attestation digest. Its digest and the executor-attestation
   digest remain in the existing finalization result and projection authority.

## Security boundary and limitations

This slice uses the Control Plane host's owner-private filesystem as the object-store adapter. It
does not yet provide an external S3-compatible store, pre-signed URLs, multi-tenant bucket policy,
server-side encryption, retention or garbage collection, or expiry of abandoned uploads. The
Worker snapshot is collected in memory within the 64 MiB bound, and durable materialization retains
the managed repository's POSIX directory `fsync` requirement.

The multipart receipt proves agreement between transferred bytes and executor authority. It does
not add independent Target or organizational trust. Target-attested Replay promotion still requires
the receipt, HTTPS, SPKI, and session checks from ADR 0040 through ADR 0044.

## Consequences

A sealed Replay Run larger than 2 MiB can now cross hosts without a shared filesystem, up to the
64 MiB boundary, and an exact part can be resent after a transient failure. Small Runs retain their
existing serialization and verification semantics.

Follow-up transport work includes an external object-store adapter with pre-signed multipart
uploads, upload expiry and garbage collection, encryption and tenant isolation, and larger
streaming snapshots. TLS 1.3 RFC 9266 exporter support and runtime registry refresh remain separate
follow-up boundaries.
