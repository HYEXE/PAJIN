# P0-C2B1: Benchmark Measurement Trust Registry and Key Lifecycle Admission

- Status: Implemented contract and Harness
- Registry: `pajin.dev/benchmark-measurement-trust-registry/v1alpha1`
- Admission authority: `pajin.dev/benchmark-measurement-registry-admission/v1alpha1`
- Decision: [ADR-0083](../adr/0083-benchmark-measurement-trust-registry.md)
- Predecessors: [P0-C1](P0-C1-provider-neutral-target-factory-lifecycle.md),
  [P0-C2A](P0-C2A-durable-target-operation-recovery.md)

## Scope

P0-C2B1 replaces the implicit single measurement key configuration with an additive, versioned
out-of-band registry for one exact measurement authority ID/version. Each registry entry embeds the
existing P0-C1 public `BenchmarkMeasurementTrustAnchor` and adds `active`, `retired`, or `revoked`
lifecycle, `notBefore`, optional `notAfter`, and optional `revokedAt`.

Exactly one key is active. Key IDs and Trust Anchor digests are unique and sorted. Registry revision
one has no predecessor; every later revision binds the exact previous registry digest. The registry
itself is content-addressed and carries no private key material.

## Rotation and anti-rollback transition

`verify_benchmark_measurement_registry_transition` accepts only a same-registry, same-authority,
contiguous revision with the exact predecessor digest and a strictly later issue time. Existing keys
cannot disappear, change public Trust Anchor, change `notBefore`, or resurrect from retired/revoked
to a more privileged state. Revoked is terminal. A new key must enter as the one active key and be
valid when the new registry is issued.

An admission at revision two or later must include the exact predecessor registry inside the sealed
authority. Omitting or substituting it fails before provider execution. This proves one transition;
the operator must retain the previous registry or an equivalent durable checkpoint across restarts.

## Fresh and historical semantics

- `fresh-measurement` requires the source P0-C1 attestation to use the active registry key, fall
  within its validity window, and be issued no earlier than the registry revision. The registry
  wrapper verifies the adapter's authority digest before reset and therefore fails without provider
  side effects on an old-key adapter.
- `historical-verification` accepts active or retired keys only when the original attestation issue
  time is inside the key window. It sets `measurementAdmissionEligible=false` while preserving
  `historicalVerificationEligible=true`.
- A revoked key is rejected for both fresh and historical verification, including evidence issued
  before `revokedAt`. Revocation is a compromise response, not a soft expiry.

The common runner Protocol exposes only the adapter definition and exact coordinate `run` method.
Both the P0-C1 and P0-C2A runners implement it, so key preflight can wrap either lifecycle without
duplicating provider execution.

## Sealed source admission

The registry admission Run binds the complete registry and predecessor, source P0-C1 Run ID/root,
source authority path/SHA-256/content digest, measurement attestation digest, exact authority/key
identity and state, admission mode, and timestamps. Its reader reopens both sealed Runs and verifies
the exact three-event publication sequence before returning the authority.

The admission is a separate additive Run because P0-C1 output is already sealed. Existing
BENCH-003B1 readers remain compatible, but they do not automatically require this new admission.
An orchestration path claiming registry-governed measurement must retain and verify the combined
target/admission outcome.

## Negative boundaries

Rollback, revision gap, predecessor mismatch, cross-authority transition, key removal/substitution,
retired or revoked resurrection, unknown key, validity-window violation, revoked historical key,
old-key fresh adapter, foreign Trust Anchor, source artifact mutation, admission artifact mutation,
audit event mutation, and a registry revision admitted before its own issue time fail closed.

## Compatibility and remaining work

All P0-C1/P0-C2A models, artifacts, readers, and direct runners remain available. The registry
wrapper and admission Run are opt-in additive boundaries. This slice does not sign registry
distribution, durably persist the latest accepted revision, or claim a live Docker/provider run.
P0-C2B2 must connect the combined recovery + registry path to an actual provider, enforce network
policy, retrieve provider evidence, and make registry admission mandatory in the measured Harness.

## Related documents

- [P0-C1 contract](P0-C1-provider-neutral-target-factory-lifecycle.md)
- [P0-C2A contract](P0-C2A-durable-target-operation-recovery.md)
- [BENCH-003B1 contract](BENCH-003B1-walking-measurement-admission.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
