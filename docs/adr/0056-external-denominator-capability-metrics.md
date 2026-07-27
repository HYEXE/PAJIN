# ADR-0056: External-Denominator Capability Metrics

- Status: Accepted
- Date: 2026-07-27

## Context

CAP-001 through CAP-005 provide immutable definitions, complete code authority, deterministic
authoring, signed lifecycle verification, and a closed existing-mode compatibility bundle. They
do not define how to measure Registry coverage, contribution lead time, Oracle samples, Replay
support/execution, or lifecycle adoption.

Using the Registry contents as the expected set would let a missing registration reduce both the
numerator and denominator. Treating missing samples as zero-valued outcomes would also confuse
“not measured” with “measured and failed.” Combining evidence by Capability ID alone would permit
stale versions or authority sets to contaminate the report.

## Decision

1. CAP-006 uses a separate content-addressed `CapabilityMetricScope` as the only denominator
   authority.
2. Scope entries bind exact `CodeBackedCapabilityRef` values and declare required measurement
   dimensions. The collector never infers expected Capabilities from a Registry.
3. Every input is strict, immutable, canonical, and content-addressed. Duplicate, foreign, or
   authority-drifted evidence fails collection.
4. Benchmark mapping coverage counts exact CAP-003 mappings. Oracle observations must use a
   benchmark ID in the exact mapping.
5. Replay support must bind the registered CAP-002 Replay Strategy authority digest and a closed
   contract set. Executed observations must use one of those contracts.
6. Lifecycle coverage accepts only a CAP-004-verified head exact to the scope. Release lead time
   additionally requires delivery evidence to match its release reference and issue timestamp.
7. Ratios retain exact counts. An empty denominator has no numeric value. No threshold is embedded
   in the `v1alpha1` contract.
8. A report is `complete` only when it has no explicit evidence gaps. Completeness means all
   required measurements exist; it is not a quality or release-gate pass.
9. The report digest binds the scope, measurement time, all contributing source digests, metric
   values, and gaps.
10. The CAP-005 helper reports an honest current baseline: implemented structure and Replay
    support are counted, while absent mappings, timestamps, execution samples, and signed releases
    remain gaps.

## Rejected alternatives

- **Registry-sized denominator:** hides missing registrations.
- **Capability ID-only joins:** admits stale versions and authority substitutions.
- **Missing equals zero:** destroys the difference between absent and negative evidence.
- **Mutable dashboard counters:** cannot reproduce which source artifacts produced a value.
- **Hard-coded activation thresholds:** invents project policy before an operational baseline is
  measured.
- **Replay support inferred from a non-null plan:** fails to bind the exact authority and supported
  contract set.

## Consequences

- Coverage regressions cannot be hidden by shrinking the Registry.
- Consumers can reproduce a report and distinguish absent data from measured outcomes.
- CAP-005's local baseline is deliberately incomplete even though structural definition,
  authority, and Replay-support coverage are present.
- Report production requires callers to preserve explicit delivery, benchmark, execution, and
  release evidence.
- The collector remains offline and additive; runtime activation and the Phase 2 Web + AI exit
  gate remain separate work.

## Compatibility and rollback

No existing wire format, persistence schema, or execution path changes. Consumers opt in by
calling the collector. Removing that call restores prior behavior. Incompatible metric semantics
require a new artifact version rather than reinterpretation of stored reports.

## Related documents

- [ARCH-001 PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
- [ADR-0053 Inert Deterministic Capability Scaffolds](0053-inert-deterministic-capability-scaffolds.md)
- [ADR-0054 Signed Reviewed Capability Lifecycle](0054-signed-reviewed-capability-lifecycle.md)
- [ADR-0055 Explicit Existing Mode Capability Adapters](0055-explicit-existing-mode-capability-adapters.md)
- [CAP-006 Registry Quality Metrics](../capability/CAP-006-registry-quality-metrics.md)
