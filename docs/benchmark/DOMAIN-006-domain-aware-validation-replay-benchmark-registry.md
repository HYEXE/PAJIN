# DOMAIN-006: Domain-aware Validation, Replay, and Benchmark Registry

- Status: Implemented, registry and contract only
- API versions:
  - `pajin.dev/domain-benchmark-metric/v1alpha1`
  - `pajin.dev/domain-benchmark-plan/v1alpha1`
  - `pajin.dev/domain-benchmark-registry/v1alpha1`
- Authority: `src/pajin/benchmark/domain_metrics.py`
- Decision: [ADR-0211](../adr/0211-register-domain-metrics-without-measurement-authority.md)

## Purpose

DOMAIN-006 registers a common multi-domain metric vocabulary, exact domain-specific metrics, and
one replay or deterministic re-analysis strategy for each DOMAIN-001 classification. It does not
record a numeric observation, measure detection quality, satisfy Replay or a Profile validation
floor, activate a Target Factory, confirm a Finding, or authorize execution.

The registry is additive. It binds the unchanged BENCH-001 manifest, Ground Truth, result,
comparison, and twelve-metric order and the unchanged REDTEAM-002 Profile Set, raw Observation,
report, and twelve-metric order. Existing readers and wire identities remain unchanged.

## Registered common vocabulary

The code-owned registry contains thirteen common metric definitions:

| Metric | Unit | Aggregation |
| --- | --- | --- |
| `common.ground-truth-coverage` | ratio | ratio of sums |
| `common.detection-recall` | ratio | ratio of sums |
| `common.task-success-rate` | ratio | ratio of sums |
| `common.false-positive-rate` | ratio | ratio of sums |
| `common.detection-precision` | ratio | ratio of sums |
| `common.replay-or-reanalysis-success-rate` | ratio | ratio of sums |
| `common.time-to-first-valid-result` | seconds | minimum |
| `common.total-request-units` | count | sum |
| `common.total-tool-calls` | count | sum |
| `common.total-cost-usd` | USD | sum |
| `common.evidence-completeness` | ratio | ratio of sums |
| `common.policy-denial-correctness` | ratio | ratio of sums |
| `common.cleanup-success-rate` | ratio | ratio of sums |

`detection-recall` is required for the eight initial security-testing plans. The Forensics plan
requires `task-success-rate` instead and marks detection recall, false-positive rate, and precision
as `not-applicable` because its first slice is read-only artifact analysis. The other plans mark
task success as `not-applicable` because detection recall is their primary outcome.

Request units are required only for Web, Network, Cloud, and AI. Monetary cost is required only for
Cloud and AI. The first slices are read-only and therefore register cleanup success as explicitly
`not-applicable`; later active slices must version their plan instead of treating unavailable
cleanup as a measured zero.

## Domain metrics and validation strategies

| Domain | Exact strategy registration | Required domain-specific metrics |
| --- | --- | --- |
| Web | independent Replay | HTTP operation coverage |
| Network | fresh-Worker protocol Replay | service-identification accuracy |
| System | immutable-snapshot re-analysis | configuration-control coverage |
| Application | deterministic artifact re-analysis | artifact-analysis coverage |
| Mobile | deterministic package re-analysis | manifest-component coverage |
| Cloud | fresh-credential deterministic re-evaluation | resource-policy coverage |
| AI | fresh-session independent Replay | threat-class coverage |
| Cryptography | independent recomputation | test-vector coverage; independent-recomputation success |
| Forensics | independent parser comparison | artifact coverage; parsing accuracy; provenance preservation; corrupted-input handling |

A strategy registration states what a future vertical slice must demonstrate. It is not Replay
evidence and does not satisfy a validation floor.

## Explicit applicability

Each `DomainBenchmarkMetricRequirement` is exactly `required` or `not-applicable`. A required
metric cannot carry an N/A reason. An N/A metric must carry a code-owned reason and has no numeric
`value`, `numerator`, or `denominator` field. Zero remains a measured value and cannot stand for a
missing semantic denominator.

## Identity and resolution

Metric definitions, domain plans, and the complete registry are content-addressed. Domain-specific
metrics and every plan bind an exact DOMAIN-001 classification ID, version, digest, and Domain.
Resolution accepts only the complete exact reference. Reordering membership, changing a unit,
aggregator, definition, strategy, applicability, Domain, source wire identity, or digest fails
closed.

The registry carries no Profile, Capability, Tool, Worker, Scope, Permit, measurement, or Target
Factory identity. Domain metadata cannot select any of them.

## Non-authority guarantees

The registry, metric, and plan contracts explicitly keep these claims false:

- runtime support and concrete Worker conformance;
- measurement observed or detection quality established;
- Replay, deterministic re-analysis, or Profile validation floor satisfied;
- Finding and Target Factory authority;
- Capability activation, Permit issuance, and execution authority; and
- changes to BENCH-001 or REDTEAM-002 wire identities.

Actual measurement still requires exact Ground Truth, an activated Target Factory where needed,
an admitted observation path, sealed Evidence, and the existing validation contracts. Actual
execution still requires the existing Capability, Policy/Approval, ActionPermit, Gateway, and
deployment-bound Worker path.

## Compatibility and rollback

DOMAIN-006 introduces no BENCH-001, REDTEAM-002, Graph, Capability, Permit, or artifact-reader
migration. Rollback removes the additive registry import and consumers while preserving all
existing benchmark and execution artifacts. Already serialized DOMAIN-006 objects remain
self-describing under their API versions.

## Verification

`tests/test_domain_benchmark_metrics.py` covers exact membership, wire compatibility, Forensics
semantics, explicit N/A behavior, reference substitution, order and digest drift, forbidden
authority fields, authority-marker escalation, and boolean coercion.
