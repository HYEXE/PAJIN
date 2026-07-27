# CAP-006: Registry Coverage, Lead Time, Oracle, Replay, and Lifecycle Metrics

- Status: locally implemented
- Date: 2026-07-27
- Prerequisites: ARCH-001, BENCH-001, CAP-001 through CAP-005, ADR-0051 through ADR-0055

## Purpose

Measure the exact Capability set an operator intended to evaluate without letting the Registry
define its own denominator. CAP-006 produces a content-addressed report over an explicit immutable
scope and preserves missing evidence as named gaps rather than silently turning absence into a
successful or zero-valued measurement.

The implementation is an offline collector and CAP-005 baseline. It does not activate a
Capability, set acceptance thresholds, replace BENCH-001 execution, or complete the Phase 2 Web +
AI runtime exit gate.

## Task contract

- **Task ID:** CAP-006
- **Threat model:** self-reported Registry coverage, denominator shrinkage, stale authority or
  release evidence, duplicated samples, unmapped benchmark outcomes, unsupported Replay
  contracts, naive timestamps, fake zero rates, and mutable reports
- **Changed trust boundary:** exact CAP-001/002/004/005 identities and execution evidence to an
  auditable measurement artifact
- **Schema/API versions:**
  - `pajin.dev/capability-metric-scope/v1alpha1`
  - `pajin.dev/capability-delivery-evidence/v1alpha1`
  - `pajin.dev/capability-oracle-observation/v1alpha1`
  - `pajin.dev/capability-replay-support/v1alpha1`
  - `pajin.dev/capability-replay-observation/v1alpha1`
  - `pajin.dev/capability-metrics-report/v1alpha1`
- **Audit artifact:** `CapabilityRegistryMetricsReport`
- **Benchmark impact:** records exact benchmark mapping and Oracle evidence; it does not claim
  BENCH-001 execution where no sample exists

## External denominator

`CapabilityMetricScope` is a sorted, unique, content-addressed list of exact
`CodeBackedCapabilityRef` requirements. Each requirement explicitly declares whether benchmark,
delivery, Oracle observation, Replay, and lifecycle evidence is required. Definition and complete
code-authority coverage always use the full scope.

The collector never discovers the expected set from `CapabilityDefinitionRegistry` or
`CapabilityAuthorityRegistry`. Evidence for a different Capability definition is rejected, and
evidence with the same definition but a different authority-set digest is rejected before it can
contribute to a count.

## Measurements

| Section | Measurement |
| --- | --- |
| Registry | exact definition, authority-set, and required benchmark-mapping coverage |
| Lead time | required delivery coverage and median/p95/min/max authoring-to-code and authoring-to-release seconds |
| Oracle | Success Oracle authority coverage, required observation coverage, decision counts, and determinate rate |
| Replay | exact Replay Strategy support coverage, executed observation coverage, verdict counts, and support rate |
| Lifecycle | exact verified signed-release coverage and maturity counts |

Every ratio carries numerator and denominator. A zero denominator has `value: null`; it is not
reported as 0%. Duration summaries exist only when at least one corresponding evidence record
exists. CAP-006 defines measurement semantics, not pass/fail thresholds.

## Evidence binding

- Delivery evidence binds the exact code-backed Capability, source digest, ordered
  authoring/code-backed/release timestamps, and exact release reference when released.
- Oracle observations bind the exact Capability, a benchmark ID present in its CAP-003 mapping,
  CAP-002 decision, observation time, and evidence digest.
- Replay support binds the exact CAP-002 Replay Strategy authority digest and a closed sorted
  contract-ID set. Replay observations outside that set fail collection.
- Lifecycle coverage counts only the verified CAP-004 head whose exact
  `CodeBackedCapabilityRef` matches the scope.
- Release lead time is counted only when delivery evidence and the verified signed release agree
  on both reference and timestamp.
- Duplicate, out-of-scope, non-canonical, or semantically mismatched inputs fail closed.

The final report digest binds the scope, measurement time, every contributing definition,
authority set, benchmark mapping, delivery record, Oracle/Replay observation, Replay support
record, signed lifecycle release, metric value, and explicit gap.

## CAP-005 baseline

`existing_mode_capability_metrics_baseline()` measures the closed seven-Capability compatibility
bundle without manufacturing unavailable operational data:

| Measurement | Current local baseline |
| --- | --- |
| Definition coverage | 7/7 |
| Complete code-authority coverage | 7/7 |
| Success Oracle authority coverage | 7/7 |
| Benchmark mapping coverage | 0/7 |
| Delivery evidence coverage | 0/7 |
| Oracle observation coverage | 0/7 |
| Replay support coverage | 3/3 |
| Replay observation coverage | 0/3 |
| Signed lifecycle release coverage | 0/7 |

The baseline is therefore `incomplete` and carries 31 explicit gaps. The three Replay support
records bind the existing M03/M06/A04 contracts, but no Replay execution is claimed.

## Compatibility and rollback

CAP-006 is additive and in-memory. Existing Mode, Graph, Tool Gateway, Replay, CLI, API, and
database paths do not invoke it automatically. Not calling the collector preserves previous
behavior. An incompatible evidence or aggregation change requires a new schema version.

## Verification

- deterministic scope, evidence, observation, support, and report identities;
- exact complete and incomplete aggregation;
- zero-denominator `null` semantics;
- observation-order independence;
- signed lifecycle and release-lead binding;
- foreign, duplicate, authority-drifted, unmapped Oracle, and unsupported Replay rejection; and
- current CAP-005 baseline counts and gaps.

## Follow-up boundaries

- reviewed signed CAP-004 releases for the seven CAP-005 adapters;
- CAP-003 benchmark mappings and delivery timestamps from the real contribution workflow;
- sealed Oracle and Replay execution observations from BENCH-001 runs;
- durable metric artifact storage, retention, and trend queries;
- project-approved quantitative gates after a measured baseline exists; and
- opt-in GRAPH-006 runtime wiring plus the Web + AI Campaign exit-gate run.

## Related documents

- [ARCH-001 PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
- [BENCH-001 Benchmark Contract](../benchmark/BENCH-001-benchmark-contract.md)
- [CAP-003 Capability Authoring SDK and Scaffold](CAP-003-capability-authoring-sdk-scaffold.md)
- [CAP-004 Maturity, Signing, Review, and Deprecation](CAP-004-maturity-signing-review-deprecation.md)
- [CAP-005 Existing Mode, Tool, and Replay Adapters](CAP-005-existing-mode-tool-replay-adapters.md)
- [ADR-0056 External-Denominator Capability Metrics](../adr/0056-external-denominator-capability-metrics.md)
