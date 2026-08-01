# P0-C1: Provider-Neutral Target Factory Lifecycle and Measurement Attestation

- Status: Implemented contract and Harness
- Adapter contract: `pajin.dev/benchmark-target-factory-adapter/v1alpha1`
- Coordinate contract: `pajin.dev/benchmark-target-coordinate/v1alpha1`
- Trust Anchor contract: `pajin.dev/benchmark-measurement-trust-anchor/v1alpha1`
- Run authority: `pajin.dev/benchmark-target-run-authority/v1alpha1`
- Decision: [ADR-0081](../adr/0081-provider-neutral-benchmark-target-lifecycle.md)

## Scope

P0-C1 defines an async provider-neutral Target Factory adapter and a Runner for one exact
Manifest arm/seed/repetition coordinate. The Runner calls four ordered stages:

1. reset the Target environment;
2. establish a fresh per-coordinate isolation identity;
3. execute the arm and return raw BENCH-003B1 Observation facts; and
4. attempt cleanup.

Each stage returns a content-addressed receipt with the exact adapter and coordinate digests,
fresh provider operation ID, one stable environment ID, isolation ID where applicable, timestamps,
status, and an opaque provider evidence digest. Reset and isolation receipts are validated before
the next provider call. Execution failure or invalid execution evidence triggers mandatory cleanup
before the Runner fails.

## Measurement attestation

The adapter definition binds the Manifest Target Factory ID/version/digest to one measurement
authority ID/version and explicit Ed25519 Trust Anchor digest. After cleanup, the authority signs a
canonical statement containing the adapter, coordinate, four receipt digests, and final Observation
ID/digest. The Runner verifies that signature before any output is admitted.

Private key bytes are accepted only by the signer helper and are never serialized to a Run artifact.
The Trust Anchor contains only the raw public key and content digest. P0-C2B1 adds an out-of-band
measurement Trust Registry with validity windows, rotation, retirement, and revocation while
preserving this wire shape. P0-C2B2A1 adds signed durable local registry activation.

## Observation and BENCH-003B1 compatibility

The adapter supplies raw metric facts, but the Runner requires its original Manifest, arm,
configuration, Target, Campaign, Ground Truth, protocol, measurement authority, coordinate, and
execution timestamps to match before cleanup. It never rewrites a foreign identity onto those
values. Only the content ID/digest and final `cleanupSucceeded` value are rebuilt after the cleanup
receipt.

The sealed output includes `benchmark-manifest.json`, the standard
`walking-benchmark-run-observation.json`, the exact BENCH-003B1 publication event, all stage
receipts, the attestation, and the complete Run authority. `BenchmarkTargetRunOutcome` exposes the
same sealed Run as a `WalkingBenchmarkRunObservationOutcome`, so B1 can consume it without a wire
format fork.

## Negative boundaries

Foreign or out-of-range coordinate, adapter/Manifest/Trust Anchor mismatch, failed reset/isolation/
execution, reordered or overlapping stages, changed environment/isolation, reused operation or
evidence identity, foreign raw Observation, budget excess, forged statement or signature, missing
cleanup attempt, and output/event mutation fail closed. Cleanup failure is recorded as
`cleanupSucceeded=false`; it is not silently converted into success.

## Compatibility and next step

BENCH-001 and BENCH-003A/B wire formats are unchanged. The adapter Protocol has no implementation
side effects by itself. Tests use a deterministic contract adapter and fixed test key only. P0-C2
must implement and verify a real isolated Docker or external provider adapter, including provider
evidence retrieval and network policy. P0-C2A supplies cleanup recovery and P0-C2B1 supplies the
additive key lifecycle registry. Docker daemon availability must be checked before live validation.

The base P0-C1 Runner still creates its sealed output only after the provider lifecycle and
attestation finish and therefore does not claim crash recovery by itself. The additive
[P0-C2A recovery layer](P0-C2A-durable-target-operation-recovery.md) now supplies durable
provider-operation journaling, fencing, startup reconciliation, cleanup retry, and a sealed
measurement-ineligible failure authority. The
[P0-C2B1 registry](P0-C2B1-benchmark-measurement-trust-registry.md) now supplies active, retired,
and revoked measurement-key admission, and P0-C2B2A1 adds signed durable local activation.
P0-C2B2A2 adds mandatory governed admission. Live provider evidence/network enforcement remains
P0-C2B2B.

## Related documents

- [BENCH-003B1 contract](BENCH-003B1-walking-measurement-admission.md)
- [BENCH-003B2 contract](BENCH-003B2-walking-shadow-policy-binding.md)
- [BENCH-001 contract](BENCH-001-benchmark-contract.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
