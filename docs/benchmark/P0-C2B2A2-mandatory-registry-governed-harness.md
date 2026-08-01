# P0-C2B2A2: Mandatory Sealed Registry-Governed Benchmark Harness

- Status: Implemented contract and Harness
- Authority: `pajin.dev/benchmark-registry-governed-harness/v1alpha1`
- Decision: [ADR-0085](../adr/0085-mandatory-registry-governed-benchmark-harness.md)
- Predecessors: [P0-C2B1](P0-C2B1-benchmark-measurement-trust-registry.md),
  [P0-C2B2A1](P0-C2B2A1-signed-measurement-registry-distribution.md)

## Scope

P0-C2B2A2 provides the only API that returns a `registry-governed` Benchmark Observation. It first
activates a currently valid signed distribution bundle in the durable P0-C2B2A1 store, then runs the
P0-C2B1 active-key wrapper over a P0-C1 or P0-C2A target runner. It returns no governed outcome
until the target Run, registry Admission Run, and new Harness Authority Run are all sealed and
reopened successfully.

Direct P0-C1/P0-C2A runners and the additive P0-C2B1 wrapper remain compatible, but their outcomes
do not carry this authority and cannot be passed to the governed reader.

## Fresh execution boundary

Before provider reset, the Harness verifies distribution signature, current bundle lifetime,
distribution-key lifecycle, durable activation order, and active measurement-key identity. A stale,
forged, expired, unknown-key, revoked-key, rollback, gap, or equivocated bundle fails before provider
side effects.

After provider cleanup and measurement attestation, the Harness reopens the target and registry
Admission Runs, re-verifies the bundle at seal time, and requires the same activation to remain the
durable latest head observed for that seal timestamp. Rotation during provider execution prevents a
governed result from being published; the already completed provider lifecycle remains available
only through its lower-level, non-governed compatibility artifacts.

## Sealed authority

`BenchmarkRegistryGovernedHarnessAuthority` binds the complete signed activation and distribution
Trust Anchor, complete P0-C2B1 Admission Authority, Manifest digest, target Run/root/artifact
SHA-256/authority/attestation/Observation digests, admission Run/root/artifact SHA-256, seal time,
and `measurementAdmissionEligible=true` into one domain-separated authority digest.

The Harness Run stores the exact activation and authority and publishes exactly three audit events:
start, governed admission, and completion. The admission event repeats activation, bundle, registry,
target, admission, and Observation identities.

## Mandatory reader and historical semantics

`load_registry_governed_benchmark_observation` is the only reader that returns the governed
Observation. It reopens all three sealed Runs, verifies their exact artifacts and audit events,
requires the activation store to contain the exact accepted revision, and re-verifies the bundle
against the caller-supplied current out-of-band distribution Trust Anchor.

A later measurement-registry rotation does not invalidate an already sealed result: the reader uses
the exact durable historical activation, not the latest head. A later distribution signing-key
revocation does invalidate it because the current Trust Anchor is mandatory. General distribution
Trust Anchor rotation remains unsupported; any non-revocation anchor substitution fails closed.

## Negative boundaries

Provider preflight bypass, stale activation, forged distribution signature, mid-run rotation,
missing durable revision, current distribution-key revocation, cross-bundle substitution, target or
Admission source mutation, Harness activation/authority mutation, and audit event mutation fail
closed before a governed Observation is returned.

## Compatibility and provider integration

No P0-C1, P0-C2A, P0-C2B1, BENCH-003B1, or P0-C2B2A1 wire format changes. The new Authority, runner,
outcome, and reader are additive. P0-C2B2B now supplies a real local Docker provider, retrievable
receipt-bound evidence, internal-network enforcement, stale provider-fence rejection, and live
container verification. Its recoverable runner plugs into this Harness through the existing
`BenchmarkTargetRunExecutor` protocol without a provider-specific bypass.

## Related documents

- [P0-C2B2A1 contract](P0-C2B2A1-signed-measurement-registry-distribution.md)
- [P0-C2B1 contract](P0-C2B1-benchmark-measurement-trust-registry.md)
- [P0-C2A contract](P0-C2A-durable-target-operation-recovery.md)
- [P0-C2B2B contract](P0-C2B2B-local-docker-provider-evidence.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
