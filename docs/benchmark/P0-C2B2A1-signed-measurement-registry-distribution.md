# P0-C2B2A1: Signed Measurement Registry Distribution and Durable Activation

- Status: Implemented contract and local activation store
- Trust Anchor: `pajin.dev/benchmark-measurement-registry-distribution-trust-anchor/v1alpha1`
- Statement: `pajin.dev/benchmark-measurement-registry-distribution-statement/v1alpha1`
- Bundle: `pajin.dev/benchmark-measurement-registry-distribution-bundle/v1alpha1`
- Activation: `pajin.dev/benchmark-measurement-registry-activation/v1alpha1`
- Decision: [ADR-0084](../adr/0084-signed-measurement-registry-distribution.md)
- Predecessor: [P0-C2B1](P0-C2B1-benchmark-measurement-trust-registry.md)

## Scope

P0-C2B2A1 gives the P0-C2B1 measurement registry an origin and a durable local order. A separate
out-of-band Trust Anchor authorizes Ed25519 keys used only for registry distribution. It never
reuses Benchmark measurement keys or Replay Target registry keys, and no private key enters a
model, bundle, activation row, or Run artifact.

The signed statement contains one complete registry transition: exact trust domain and issuer,
sequence, previous bundle digest, bounded timestamps, current registry, and its exact predecessor.
The statement sequence must equal the registry revision. Revision one has no predecessor; later
revisions require both the previous signed-bundle digest and the P0-C2B1 predecessor registry.

## Signature and lifetime

`BenchmarkMeasurementRegistryDistributionSigner` is an offline helper and signs only with the one
active distribution key. Verification accepts a known active or retired key only when the statement
issue time lies inside its key window. A revoked distribution key invalidates every bundle signed by
that key. The Ed25519 signature is domain-separated from measurement attestations and Replay Target
registries.

Every statement satisfies `issuedAt <= notBefore < expiresAt`, may live for at most seven days, and
cannot predate the embedded registry. Current activation additionally requires
`notBefore <= now < expiresAt`.

## Durable activation checkpoint

`BenchmarkMeasurementRegistryActivationStore` uses a host-local SQLite file with
`synchronous=FULL`, `journal_mode=DELETE`, `BEGIN IMMEDIATE`, and an append-only activation table.
Update, delete, and replace triggers protect accepted rows. File, ancestor, sidecar, symlink,
junction, and hardlink checks mirror the P0-C2A local trust boundary.

The first accepted bundle must be revision one. Later activation is contiguous and requires the
durable head's exact bundle digest, registry digest, and complete predecessor registry. Repeating
the same bundle is idempotent and returns the original activation timestamp. A different bundle at
the same revision is equivocation; lower revisions are rollback; skipped revisions are gaps.

Each row stores a content-addressed activation containing the complete signed bundle and Trust
Anchor digest. Reads reconstruct the strict model and compare every indexed row identity to its
embedded content before returning it.

## Negative boundaries

Invalid signature, unknown or revoked signing key, expired/not-yet-valid bundle, cross-domain
issuer, unbounded lifetime, missing predecessor, rollback, gap, equivocation, wrong bundle or
registry predecessor, Trust Anchor substitution, update/delete/replace, row/content mismatch, and
unsafe linked database paths fail closed.

## Compatibility and remaining work

P0-C2B1 models, admission artifacts, and direct runners are unchanged. The distribution bundle and
activation store are additive. P0-C2B2A2 now binds the verified bundle and activation to the exact
target/admission outcome in a sealed Harness authority before exposing a registry-governed
Observation.

The activation store trusts the local host and filesystem. Deleting the entire database also
deletes its remembered head, so an external backup or independently anchored transparency log is
still required for recovery from host compromise. Distribution Trust Anchor rotation, remote HTTPS
fetch, transparency, and federation are not implemented. A live Docker/provider run remains
P0-C2B2B.

## Related documents

- [P0-C2B1 contract](P0-C2B1-benchmark-measurement-trust-registry.md)
- [P0-C2B2A2 contract](P0-C2B2A2-mandatory-registry-governed-harness.md)
- [ADR-0083](../adr/0083-benchmark-measurement-trust-registry.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
